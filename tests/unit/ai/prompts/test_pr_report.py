"""Testes do prompt de relatório do Tier 2.

O rodapé "Status de inteligência" (CTI/Caldera) saiu do formato: os dois só
existem no Tier 3, então ele era fixo em `unavailable`/`unavailable`. A
blindagem contra o modelo inventar inteligência continua — virou proibição
incondicional na regra 2, testada em `TestSystemPrompt`.
"""
import json
import re

from app.infrastructure.ai.prompts import pr_report


# Espelha o schema de saída do `chain_of_events` — que não tem mais
# `cti_status`/`caldera_status`.
_ANALYSIS = {
    "event_chain": [
        {
            "step": 1,
            "technique": "T1190",
            "description": "Exploit external-facing app",
            "finding_ids": ["x"],
        }
    ],
    "risk_score": {"score": 75, "level": "high"},
    "business_impact": {
        "description": "Vazamento de dados de clientes",
        "estimated_cost_brl": 250000.0,
    },
    "attack_narrative": "...",
}


class TestBuild:
    def test_includes_context_header(self):
        prompt = pr_report.build(
            analysis=_ANALYSIS,
            context={"repo": "acme/repo", "pr_number": 42, "commit": "abc"},
        )
        assert "Repositório: acme/repo" in prompt
        assert "PR: #42" in prompt
        assert "Commit: abc" in prompt

    def test_includes_analysis_as_json(self):
        prompt = pr_report.build(analysis=_ANALYSIS)
        # Embedded JSON deve ser parseable
        json_start = prompt.find("{")
        embedded = prompt[json_start:]
        parsed = json.loads(embedded)
        assert parsed["risk_score"]["score"] == 75

    def test_defaults_when_no_context(self):
        prompt = pr_report.build(analysis=_ANALYSIS)
        assert "Repositório: N/A" in prompt
        assert "PR: #—" in prompt


class TestSystemPrompt:
    def test_forbids_invention(self):
        assert "NÃO infira" in pr_report.SYSTEM

    def test_proibe_mencionar_campanhas_atores_e_grupos(self):
        """Substitui `test_handles_unavailable_cti`: a proibição não depende
        mais de um `cti_status` no payload, é incondicional."""
        assert (
            "NÃO mencione campanhas, atores ou grupos de ameaça"
            in pr_report.SYSTEM
        )

    def test_proibe_afirmar_exploracao_validada(self):
        """Substitui `test_handles_unavailable_caldera`."""
        assert "NÃO afirme que uma exploração foi validada" in pr_report.SYSTEM

    def test_formato_nao_tem_rodape_de_status_de_inteligencia(self):
        assert "Status de inteligência" not in pr_report.SYSTEM
        assert "cti_status" not in pr_report.SYSTEM
        assert "caldera_status" not in pr_report.SYSTEM
        assert "unavailable" not in pr_report.SYSTEM

    def test_formato_termina_no_impacto_de_negocio(self):
        assert pr_report.SYSTEM.rstrip().endswith(
            "**Impacto de negócio:**\n<business_impact.description>"
        )

    def test_regras_numeradas_em_sequencia(self):
        """As regras foram renumeradas ao fundir as de CTI/Caldera numa só; o
        bloco "Formato:" também tem linhas numeradas, então é recortado fora."""
        inicio = pr_report.SYSTEM.index("REGRAS:") + len("REGRAS:")
        bloco = pr_report.SYSTEM[inicio : pr_report.SYSTEM.index("Formato:", inicio)]
        numeros = [int(n) for n in re.findall(r"^(\d+)\. ", bloco, re.MULTILINE)]
        assert numeros == list(range(1, len(numeros) + 1))
        assert len(numeros) == 5
