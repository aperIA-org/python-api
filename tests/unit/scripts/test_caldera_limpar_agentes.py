"""Testes de `scripts/caldera_limpar_agentes.py`.

O que importa aqui é o CRITÉRIO de remoção: o script apaga agentes do Caldera, e
apagar o agente errado deixa a operação seguinte sem alvo. Por isso a regra é
conservadora — sem `last_seen` legível, o agente fica.
"""
from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# `scripts/` não é pacote; carregamos pelo caminho para poder testar as funções
# puras sem transformar o diretório de scripts em módulo importável.
_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "caldera_limpar_agentes.py"
_spec = importlib.util.spec_from_file_location("caldera_limpar_agentes", _SCRIPT)
assert _spec and _spec.loader
limpeza = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(limpeza)


AGORA = datetime(2026, 8, 2, 5, 30, 0, tzinfo=timezone.utc)


def _agente(paw: str, *, idade_s: int | None, group: str = "red") -> dict:
    visto = None if idade_s is None else (AGORA - timedelta(seconds=idade_s))
    return {
        "paw": paw,
        "group": group,
        "last_seen": None if visto is None else visto.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


class TestParseLastSeen:
    def test_aceita_sufixo_z_da_api_v2(self):
        assert limpeza.parse_last_seen("2026-08-02T05:20:34Z") == datetime(
            2026, 8, 2, 5, 20, 34, tzinfo=timezone.utc
        )

    def test_assume_utc_quando_nao_ha_timezone(self):
        dt = limpeza.parse_last_seen("2026-08-02T05:20:34")
        assert dt is not None and dt.tzinfo is timezone.utc

    @pytest.mark.parametrize("valor", ["", "   ", "ontem", None, 12345])
    def test_valores_ilegiveis_viram_none(self, valor):
        assert limpeza.parse_last_seen(valor) is None


class TestAgentesObsoletos:
    def test_remove_apenas_quem_passou_da_idade(self):
        agentes = [_agente("vivo", idade_s=30), _agente("morto", idade_s=9000)]
        alvos = limpeza.agentes_obsoletos(agentes, agora=AGORA, max_idade_s=300)
        assert [a["paw"] for a in alvos] == ["morto"]

    def test_agente_sem_last_seen_nunca_e_removido(self):
        """Na dúvida não apaga: o custo de um registro a mais é cosmético."""
        alvos = limpeza.agentes_obsoletos(
            [_agente("sem-data", idade_s=None)], agora=AGORA, max_idade_s=1
        )
        assert alvos == []

    def test_manter_paws_protege_mesmo_obsoleto(self):
        agentes = [_agente("aperia-sandbox", idade_s=9000), _agente("orfao", idade_s=9000)]
        alvos = limpeza.agentes_obsoletos(
            agentes,
            agora=AGORA,
            max_idade_s=300,
            manter_paws=frozenset({"aperia-sandbox"}),
        )
        assert [a["paw"] for a in alvos] == ["orfao"]

    def test_ignora_entradas_sem_paw_ou_malformadas(self):
        agentes = [{"last_seen": "2020-01-01T00:00:00Z"}, "lixo", _agente("ok", idade_s=9000)]
        alvos = limpeza.agentes_obsoletos(agentes, agora=AGORA, max_idade_s=300)
        assert [a["paw"] for a in alvos] == ["ok"]

    def test_limite_e_estrito_maior_que(self):
        agentes = [_agente("no-limite", idade_s=300)]
        assert limpeza.agentes_obsoletos(agentes, agora=AGORA, max_idade_s=300) == []
