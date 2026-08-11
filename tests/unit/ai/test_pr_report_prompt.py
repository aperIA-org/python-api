"""O prompt não pode estourar a janela de contexto por volume de findings.

Regressão do incidente: o relatório do Tier 3 falhou com
`prompt is too long: 357218 tokens > 200000 maximum`. A causa foi o ZAP passar
a funcionar — 369 alertas, cada um com o `raw_output` bruto serializado. O
gargalo existia desde sempre, escondido atrás de outro defeito.
"""
import json

import pytest

from app.infrastructure.ai.prompts import pr_report


def _finding(sev: str, i: int = 0, **extra):
    base = {
        "severity": sev,
        "title": f"finding-{i}",
        "description": "descricao",
        "raw_output": {"payload": "x" * 5000},
    }
    base.update(extra)
    return base


def _analise_do_prompt(prompt: str) -> dict:
    return json.loads(prompt.split("JSON):", 1)[1])


class TestTetoDeFindings:
    def test_corta_no_teto(self):
        analise = {"findings": [_finding("info", i) for i in range(300)]}
        assert len(_analise_do_prompt(pr_report.build(analise))["findings"]) == 40

    def test_mantem_os_mais_severos(self):
        """Cortar os graves para caber seria pior que não cortar."""
        analise = {
            "findings": [_finding("info", i) for i in range(100)]
            + [_finding("critical", 999)]
        }
        incluidos = _analise_do_prompt(pr_report.build(analise))["findings"]
        assert incluidos[0]["severity"] == "critical"

    def test_descarta_raw_output(self):
        """Maior contribuinte de tokens e o menos útil para o modelo."""
        analise = {"findings": [_finding("high")]}
        assert "raw_output" not in _analise_do_prompt(pr_report.build(analise))["findings"][0]

    def test_trunca_descricao_longa(self):
        analise = {"findings": [_finding("high", description="y" * 3000)]}
        desc = _analise_do_prompt(pr_report.build(analise))["findings"][0]["description"]
        assert len(desc) < 500 and desc.endswith("(truncado)")

    def test_declara_o_que_ficou_de_fora(self):
        """Silêncio faria o modelo concluir que viu tudo."""
        analise = {
            "findings": [_finding("medium", i) for i in range(45)]
            + [_finding("info", i) for i in range(20)]
        }
        resumo = _analise_do_prompt(pr_report.build(analise))["findings_resumo"]
        assert resumo["total"] == 65
        assert resumo["incluidos_no_prompt"] == 40
        assert resumo["omitidos"] == 25
        assert resumo["omitidos_por_severidade"] == {"info": 20, "medium": 5}

    def test_sem_corte_nao_inventa_resumo(self):
        analise = {"findings": [_finding("high", i) for i in range(5)]}
        assert "findings_resumo" not in _analise_do_prompt(pr_report.build(analise))

    @pytest.mark.parametrize("valor", [None, [], "texto"])
    def test_findings_ausente_ou_invalido_nao_quebra(self, valor):
        analise = {"findings": valor, "risk_score": {"score": 1}}
        assert "risk_score" in pr_report.build(analise)

    def test_reducao_real_do_caso_do_incidente(self):
        """369 alertas do ZAP com raw_output — o cenário que estourou."""
        analise = {"findings": [_finding("info", i) for i in range(369)]}
        bruto = len(json.dumps(analise))
        assert len(pr_report.build(analise)) < bruto * 0.05
