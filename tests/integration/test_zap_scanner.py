"""Testes do ZAPScanner com respx.

ZAP via REST API usa ``httpx`` no client, então ``respx`` é o mock
nativo. Cada teste injeta ``poll_interval=0`` para evitar
``time.sleep`` real durante o polling.

A decisão #1 da Semana 9 fixou ``target_url="http://localhost:8080/app"``
como alvo simulado nos testes.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.zap_scanner import (
    ZAPScanner,
    ZAPScanTimeoutError,
    ZAPUnavailableError,
)


_ZAP_URL = "http://zap:8090"
_TARGET = "http://localhost:8080/app"

_OPCOES = {
    "spider_duracao": f"{_ZAP_URL}/JSON/spider/action/setOptionMaxDuration/",
    "ascan_duracao": f"{_ZAP_URL}/JSON/ascan/action/setOptionMaxScanDurationInMins/",
    "ascan_regra": f"{_ZAP_URL}/JSON/ascan/action/setOptionMaxRuleDurationInMins/",
    "ascan_threads": f"{_ZAP_URL}/JSON/ascan/action/setOptionThreadPerHost/",
}
_DISABLE_URL = f"{_ZAP_URL}/JSON/ascan/action/disableScanners/"


def _build_scanner(**overrides) -> ZAPScanner:
    # Usa httpx.Client com timeout curto e poll_interval=0 (sem sleep)
    kwargs = {
        "zap_url": _ZAP_URL,
        "api_key": "test-key",
        "poll_interval": 0,
        "max_wait": 5,
        "http_client": httpx.Client(timeout=5.0),
    }
    kwargs.update(overrides)
    return ZAPScanner(**kwargs)  # type: ignore[arg-type]


def _mock_preflight() -> dict[str, respx.Route]:
    """Handshake + aplicação dos tetos, que todo scan faz antes do spider.

    Devolve as rotas registradas: re-chamar ``respx.get(url)`` só para inspecionar
    reescreveria a rota existente, então o teste guarda a referência.
    """
    rotas = {
        "version": respx.get(f"{_ZAP_URL}/JSON/core/view/version/").mock(
            return_value=httpx.Response(200, json={"version": "2.16.1"})
        )
    }
    for nome, url in _OPCOES.items():
        rotas[nome] = respx.get(url).mock(
            return_value=httpx.Response(200, json={"Result": "OK"})
        )
    rotas["disable"] = respx.get(_DISABLE_URL).mock(
        return_value=httpx.Response(200, json={"Result": "OK"})
    )
    return rotas


_ALERTS_RESPONSE_SAMPLE = {
    "alerts": [
        {
            "name": "SQL Injection",
            "risk": "High",
            "description": "SQLi found in parameter 'id'.",
            "url": "http://localhost:8080/app/login?id=1",
            "cweid": "89",
        },
        {
            "name": "Cross Site Scripting (Reflected)",
            "risk": "High",
            "description": "Reflected XSS.",
            "url": "http://localhost:8080/app/search",
            "cweid": "79",
        },
        {
            "name": "Cookie No HttpOnly Flag",
            "risk": "Low",
            "description": "Cookie without HttpOnly.",
            "url": "http://localhost:8080/app/",
            "cweid": "1004",
        },
        {
            "name": "Information disclosure",
            "risk": "Informational",
            "description": "Server header leaks version.",
            "url": "http://localhost:8080/app/health",
        },
    ]
}


def _mock_full_scan(alerts_payload: dict | None = None) -> dict[str, respx.Route]:
    """Configura respx para um scan completo bem-sucedido.

    Sem ``@respx.mock`` aqui — o helper apenas registra rotas no
    router ativo (criado pelo decorator do teste chamador).
    """
    rotas = _mock_preflight()
    rotas["spider_action"] = respx.get(
        f"{_ZAP_URL}/JSON/spider/action/scan/"
    ).mock(return_value=httpx.Response(200, json={"scan": "1"}))
    rotas["spider_status"] = respx.get(
        f"{_ZAP_URL}/JSON/spider/view/status/"
    ).mock(return_value=httpx.Response(200, json={"status": "100"}))
    rotas["ascan_action"] = respx.get(f"{_ZAP_URL}/JSON/ascan/action/scan/").mock(
        return_value=httpx.Response(200, json={"scan": "1"})
    )
    rotas["ascan_status"] = respx.get(f"{_ZAP_URL}/JSON/ascan/view/status/").mock(
        return_value=httpx.Response(200, json={"status": "100"})
    )
    rotas["alerts"] = respx.get(f"{_ZAP_URL}/JSON/alert/view/alerts/").mock(
        return_value=httpx.Response(
            200, json=alerts_payload or _ALERTS_RESPONSE_SAMPLE
        )
    )
    return rotas


# -----------------------------------------------------------------------------
# Happy path
# -----------------------------------------------------------------------------


class TestFullScanFlow:
    @respx.mock
    def test_full_scan_returns_findings(self):
        _mock_full_scan()
        scanner = _build_scanner()

        findings = scanner.scan(
            target_url=_TARGET,
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

        assert len(findings) == 4
        assert all(f.source == "zap" for f in findings)
        assert all(f.tier == 3 for f in findings)

    @respx.mock
    def test_severity_mapping_zap_risks(self):
        _mock_full_scan()
        scanner = _build_scanner()

        findings = scanner.scan(
            target_url=_TARGET,
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

        by_name = {f.title: f.severity for f in findings}
        assert by_name["SQL Injection"] is Severity.HIGH
        assert by_name["Cookie No HttpOnly Flag"] is Severity.LOW
        assert by_name["Information disclosure"] is Severity.INFO

    @respx.mock
    def test_cwe_id_extracted_when_present(self):
        _mock_full_scan()
        scanner = _build_scanner()

        findings = scanner.scan(
            target_url=_TARGET,
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )
        sqli = next(f for f in findings if f.title == "SQL Injection")
        assert sqli.cwe_id == "89"

    @respx.mock
    def test_target_url_passed_to_actions(self):
        _mock_preflight()
        spider_route = respx.get(f"{_ZAP_URL}/JSON/spider/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        respx.get(f"{_ZAP_URL}/JSON/spider/view/status/").mock(
            return_value=httpx.Response(200, json={"status": "100"})
        )
        respx.get(f"{_ZAP_URL}/JSON/ascan/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        respx.get(f"{_ZAP_URL}/JSON/ascan/view/status/").mock(
            return_value=httpx.Response(200, json={"status": "100"})
        )
        respx.get(f"{_ZAP_URL}/JSON/alert/view/alerts/").mock(
            return_value=httpx.Response(200, json={"alerts": []})
        )
        scanner = _build_scanner()

        scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")

        sent = spider_route.calls.last.request
        assert sent.url.params["url"] == _TARGET
        assert sent.url.params["apikey"] == "test-key"


# -----------------------------------------------------------------------------
# Polling: status progride de 0 → 100
# -----------------------------------------------------------------------------


class TestPollingProgress:
    @respx.mock
    def test_status_eventually_reaches_100(self):
        _mock_preflight()
        respx.get(f"{_ZAP_URL}/JSON/spider/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        respx.get(f"{_ZAP_URL}/JSON/spider/view/status/").mock(
            side_effect=[
                httpx.Response(200, json={"status": "0"}),
                httpx.Response(200, json={"status": "50"}),
                httpx.Response(200, json={"status": "100"}),
            ]
        )
        respx.get(f"{_ZAP_URL}/JSON/ascan/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        respx.get(f"{_ZAP_URL}/JSON/ascan/view/status/").mock(
            return_value=httpx.Response(200, json={"status": "100"})
        )
        respx.get(f"{_ZAP_URL}/JSON/alert/view/alerts/").mock(
            return_value=httpx.Response(200, json={"alerts": []})
        )

        scanner = _build_scanner()
        scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")
        # Não deve levantar nem hangar

    @respx.mock
    def test_timeout_when_scan_never_completes(self):
        _mock_preflight()
        respx.get(f"{_ZAP_URL}/JSON/spider/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        # status sempre 0 — polling jamais converge
        respx.get(f"{_ZAP_URL}/JSON/spider/view/status/").mock(
            return_value=httpx.Response(200, json={"status": "0"})
        )

        scanner = _build_scanner(max_wait=2)  # estoura cedo
        with pytest.raises(ZAPScanTimeoutError, match="spider"):
            scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")

    @respx.mock
    def test_teto_de_polls_limita_o_laco(self):
        """Com ``poll_interval=0`` o relógio de parede não anda.

        O teto de tempo sozinho deixaria o laço girar indefinidamente contra
        um mock instantâneo; o teto de polls é o que fecha essa porta.
        """
        _mock_preflight()
        respx.get(f"{_ZAP_URL}/JSON/spider/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        status = respx.get(f"{_ZAP_URL}/JSON/spider/view/status/").mock(
            return_value=httpx.Response(200, json={"status": "0"})
        )

        scanner = _build_scanner(max_wait=3)
        with pytest.raises(ZAPScanTimeoutError):
            scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")

        # max_wait=3, poll_interval=0 → 3 // 1 + 1 = 4 polls
        assert status.call_count == 4

    @respx.mock
    def test_mensagem_de_timeout_diz_o_progresso(self):
        _mock_preflight()
        respx.get(f"{_ZAP_URL}/JSON/spider/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        respx.get(f"{_ZAP_URL}/JSON/spider/view/status/").mock(
            return_value=httpx.Response(200, json={"status": "42"})
        )

        scanner = _build_scanner(max_wait=2)
        with pytest.raises(ZAPScanTimeoutError, match="42%"):
            scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")


# -----------------------------------------------------------------------------
# Tetos aplicados no lado do ZAP
# -----------------------------------------------------------------------------


class TestTetosDoScan:
    @respx.mock
    def test_opcoes_enviadas_ao_zap_antes_do_spider(self):
        rotas = _mock_full_scan()
        scanner = _build_scanner(
            spider_max_duration_min=3,
            ascan_max_duration_min=10,
            ascan_max_rule_duration_min=2,
            ascan_threads_per_host=2,
        )

        scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")

        enviados = {
            nome: rotas[nome].calls.last.request.url.params["Integer"]
            for nome in _OPCOES
        }
        assert enviados == {
            "spider_duracao": "3",
            "ascan_duracao": "10",
            "ascan_regra": "2",
            "ascan_threads": "2",
        }

    @respx.mock
    def test_regras_caras_sao_desligadas(self):
        """40026 (DOM XSS) sobe Firefox headless dentro do cgroup do ZAP."""
        rotas = _mock_full_scan()
        scanner = _build_scanner(ascan_disabled_rules="40026,40027")

        scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")

        assert rotas["disable"].calls.last.request.url.params["ids"] == "40026,40027"

    @respx.mock
    def test_lista_vazia_mantem_a_politica_completa(self):
        rotas = _mock_full_scan()
        scanner = _build_scanner(ascan_disabled_rules="")

        scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")

        assert rotas["disable"].call_count == 0

    @respx.mock
    def test_spider_recebe_max_children(self):
        rotas = _mock_full_scan()
        scanner = _build_scanner(spider_max_children=7)

        scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")

        sent = rotas["spider_action"].calls.last.request
        assert sent.url.params["maxChildren"] == "7"

    @respx.mock
    def test_valor_zero_nao_envia_a_opcao(self):
        """``0`` é a semântica do próprio ZAP para "sem limite"."""
        rotas = _mock_full_scan()
        scanner = _build_scanner(spider_max_duration_min=0, spider_max_children=0)

        scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")

        assert rotas["spider_duracao"].call_count == 0
        sent = rotas["spider_action"].calls.last.request
        assert "maxChildren" not in sent.url.params

    @respx.mock
    def test_opcao_recusada_nao_derruba_o_scan(self):
        """Versão de ZAP que não conhece a opção perde o teto, não o scan."""
        rotas = _mock_full_scan()
        rotas["ascan_regra"].mock(
            return_value=httpx.Response(400, json={"code": "illegal_parameter"})
        )
        scanner = _build_scanner()

        findings = scanner.scan(
            target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
        )
        assert len(findings) == 4

    def test_max_wait_derivado_dos_tetos_do_zap(self):
        """Sem ``max_wait`` explícito, o cliente espera o teto do ZAP + folga."""
        scanner = ZAPScanner(
            zap_url=_ZAP_URL,
            api_key="k",
            spider_max_duration_min=3,
            ascan_max_duration_min=10,
            http_client=httpx.Client(),
        )
        # O cliente SEMPRE espera mais que o ZAP: se ele estourar primeiro, o
        # problema é o ZAP não respeitar o próprio limite, não o alvo.
        assert scanner.spider_max_wait > 3 * 60
        assert scanner.ascan_max_wait > 10 * 60


# -----------------------------------------------------------------------------
# Fault isolation via BaseScanner.run_safe
# -----------------------------------------------------------------------------


class TestFaultIsolation:
    @respx.mock
    def test_run_safe_returns_empty_when_zap_returns_500(self):
        _mock_preflight()
        respx.get(f"{_ZAP_URL}/JSON/spider/action/scan/").mock(
            return_value=httpx.Response(500, text="oops")
        )
        scanner = _build_scanner()

        findings = scanner.run_safe(
            target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
        )
        assert findings == []

    @respx.mock
    def test_run_safe_returns_empty_when_connection_refused(self):
        respx.get(f"{_ZAP_URL}/JSON/core/view/version/").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        scanner = _build_scanner()

        findings = scanner.run_safe(
            target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
        )
        assert findings == []

    @respx.mock
    def test_run_safe_returns_empty_when_alert_view_500(self):
        _mock_full_scan()["alerts"].mock(return_value=httpx.Response(500))
        scanner = _build_scanner()
        findings = scanner.run_safe(
            target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
        )
        assert findings == []


# -----------------------------------------------------------------------------
# Falha legível: as três causas precisam ser distinguíveis no log
# -----------------------------------------------------------------------------


class TestFalhaLegivel:
    @respx.mock
    def test_daemon_morto_vira_zap_unavailable_error(self):
        """Container derrubado por OOM: o erro do httpx é de DNS, a causa não.

        Foi exatamente essa mensagem ("No address associated with hostname")
        que fez o diagnóstico ir para DNS quando o container tinha morrido.
        """
        respx.get(f"{_ZAP_URL}/JSON/core/view/version/").mock(
            side_effect=httpx.ConnectError(
                "[Errno -5] No address associated with hostname"
            )
        )
        scanner = _build_scanner()

        with pytest.raises(ZAPUnavailableError, match="inacessível"):
            scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")

    @respx.mock
    def test_daemon_morre_no_meio_do_scan(self):
        """Poll que para de responder é ZAP morto, não scan lento."""
        _mock_preflight()
        respx.get(f"{_ZAP_URL}/JSON/spider/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        respx.get(f"{_ZAP_URL}/JSON/spider/view/status/").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        scanner = _build_scanner(max_wait=60)

        with pytest.raises(ZAPUnavailableError):
            scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")

    @respx.mock
    def test_poll_lento_isolado_nao_derruba_o_scan(self):
        """Um `ReadTimeout` num poll não pode custar o scan inteiro.

        `httpx.ReadTimeout` tem a mensagem "timed out" — foi ela que apareceu
        como `scanner_skipped error='timed out'` depois de minutos de polls
        bem-sucedidos.
        """
        rotas = _mock_full_scan()
        rotas["ascan_status"].mock(
            side_effect=[
                httpx.ReadTimeout("timed out"),
                httpx.Response(200, json={"status": "100"}),
            ]
        )
        scanner = _build_scanner(max_wait=60)

        findings = scanner.scan(
            target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
        )
        assert len(findings) == 4

    @respx.mock
    def test_run_safe_registra_o_tipo_do_erro(self):
        """`scanner_skipped` precisa dizer QUAL das três falhas aconteceu."""
        from structlog.testing import capture_logs

        respx.get(f"{_ZAP_URL}/JSON/core/view/version/").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        scanner = _build_scanner()

        with capture_logs() as logs:
            scanner.run_safe(
                target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
            )

        skipped = [e for e in logs if e["event"] == "scanner_skipped"]
        assert skipped[0]["error_type"] == "ZAPUnavailableError"

    @respx.mock
    def test_scan_sem_achados_nao_e_falha(self):
        """"Terminou sem achados" é sucesso e loga como tal."""
        from structlog.testing import capture_logs

        _mock_full_scan(alerts_payload={"alerts": []})
        scanner = _build_scanner()

        with capture_logs() as logs:
            findings = scanner.run_safe(
                target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
            )

        assert findings == []
        eventos = {e["event"] for e in logs}
        assert "scanner_skipped" not in eventos
        coletado = next(e for e in logs if e["event"] == "zap_alerts_collected")
        assert coletado["alerts_count"] == 0


# -----------------------------------------------------------------------------
# Empty / edge cases
# -----------------------------------------------------------------------------


class TestEdgeCases:
    @respx.mock
    def test_no_alerts_returns_empty_list(self):
        _mock_full_scan(alerts_payload={"alerts": []})
        scanner = _build_scanner()

        findings = scanner.scan(
            target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
        )
        assert findings == []

    @respx.mock
    def test_unknown_risk_defaults_to_low(self):
        _mock_full_scan(
            alerts_payload={
                "alerts": [
                    {
                        "name": "Mystery",
                        "risk": "UnknownLevel",  # não está no _RISK_MAP
                        "url": "x",
                    }
                ]
            }
        )
        scanner = _build_scanner()

        findings = scanner.scan(
            target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
        )
        assert findings[0].severity is Severity.LOW

    @respx.mock
    def test_alert_without_cweid_keeps_none(self):
        _mock_full_scan(
            alerts_payload={
                "alerts": [{"name": "X", "risk": "Low", "url": "y"}]
            }
        )
        scanner = _build_scanner()
        findings = scanner.scan(
            target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
        )
        assert findings[0].cwe_id is None
