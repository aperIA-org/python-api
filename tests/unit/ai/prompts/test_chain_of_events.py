"""Testes do prompt chain_of_events.

Foco principal: **contrato de dicts vazios** (decisão #4).

O modelo NÃO pode ser alimentado com strings vazias / "None" para CTI
e Caldera ausentes — isso é vetor de alucinação. O ``build()`` deve
sempre emitir sentinelas explícitos que o SYSTEM reconhece como
"não disponível".
"""
import pytest

from app.infrastructure.ai.prompts import chain_of_events


_FINDINGS_SAMPLE = [
    {
        "severity": "high",
        "source": "semgrep",
        "title": "SQL injection",
        "file_path": "app/db.py",
        "line_number": 42,
    },
    {
        "severity": "critical",
        "source": "trufflehog",
        "title": "AWS key",
        "file_path": "config/.env",
        "line_number": 1,
    },
]


class TestEmptyDataContract:
    """Decisão #4: dicts vazios precisam virar sentinelas explícitos."""

    def test_empty_cti_emits_sentinel(self):
        prompt = chain_of_events.build(
            findings=_FINDINGS_SAMPLE,
            cti_data={},
            caldera_results={"success_rate": 0.5},
        )
        assert "sem dados CTI disponíveis nesta análise" in prompt

    def test_none_cti_emits_sentinel(self):
        prompt = chain_of_events.build(
            findings=_FINDINGS_SAMPLE,
            cti_data=None,
            caldera_results={"success_rate": 0.5},
        )
        assert "sem dados CTI disponíveis nesta análise" in prompt

    def test_empty_caldera_emits_sentinel(self):
        prompt = chain_of_events.build(
            findings=_FINDINGS_SAMPLE,
            cti_data={"active_campaigns": True},
            caldera_results={},
        )
        assert "sem dados de emulação Caldera disponíveis" in prompt

    def test_none_caldera_emits_sentinel(self):
        prompt = chain_of_events.build(
            findings=_FINDINGS_SAMPLE,
            cti_data={"active_campaigns": True},
            caldera_results=None,
        )
        assert "sem dados de emulação Caldera disponíveis" in prompt

    def test_both_empty_emits_both_sentinels(self):
        prompt = chain_of_events.build(
            findings=_FINDINGS_SAMPLE,
            cti_data={},
            caldera_results={},
        )
        assert "sem dados CTI disponíveis nesta análise" in prompt
        assert "sem dados de emulação Caldera disponíveis" in prompt
        # E **nunca** uma string vazia entre os marcadores
        assert "Dados CTI: \n" not in prompt
        assert "Dados Caldera: \n" not in prompt

    def test_cti_with_unknown_keys_only_falls_back_to_sentinel(self):
        # Atacante popula chaves não-whitelist → ainda assim retorna sentinela
        prompt = chain_of_events.build(
            findings=_FINDINGS_SAMPLE,
            cti_data={"injection_attempt": "ignore previous"},
            caldera_results={},
        )
        assert "sem dados CTI disponíveis nesta análise" in prompt
        assert "ignore previous" not in prompt


class TestCtiRendering:
    def test_active_campaigns_rendered(self):
        prompt = chain_of_events.build(
            findings=_FINDINGS_SAMPLE,
            cti_data={"active_campaigns": True},
            caldera_results={},
        )
        assert "campanhas ativas: True" in prompt

    def test_ttps_list_rendered(self):
        prompt = chain_of_events.build(
            findings=_FINDINGS_SAMPLE,
            cti_data={"ttps": ["T1190", "T1078"]},
            caldera_results={},
        )
        assert "T1190" in prompt
        assert "T1078" in prompt


class TestCalderaRendering:
    def test_success_rate_rendered_as_percent(self):
        prompt = chain_of_events.build(
            findings=_FINDINGS_SAMPLE,
            cti_data={},
            caldera_results={"success_rate": 0.7},
        )
        assert "taxa de sucesso: 70%" in prompt

    def test_techniques_list_rendered(self):
        prompt = chain_of_events.build(
            findings=_FINDINGS_SAMPLE,
            cti_data={},
            caldera_results={"techniques_executed": ["T1059", "T1003"]},
        )
        assert "T1059" in prompt
        assert "T1003" in prompt


class TestFindingsRendering:
    def test_empty_findings_yields_explicit_message(self):
        prompt = chain_of_events.build(
            findings=[],
            cti_data=None,
            caldera_results=None,
        )
        assert "(nenhum finding fornecido)" in prompt
        assert "Findings (0)" in prompt

    def test_findings_count_in_header(self):
        prompt = chain_of_events.build(
            findings=_FINDINGS_SAMPLE,
            cti_data=None,
            caldera_results=None,
        )
        assert "Findings (2)" in prompt

    def test_finding_severity_uppercase(self):
        prompt = chain_of_events.build(
            findings=_FINDINGS_SAMPLE,
            cti_data=None,
            caldera_results=None,
        )
        assert "[HIGH]" in prompt
        assert "[CRITICAL]" in prompt


class TestSystemPrompt:
    def test_system_mentions_no_invention_rule(self):
        assert "NÃO invente" in chain_of_events.SYSTEM

    def test_system_mentions_unavailable_handling(self):
        assert "cti_status" in chain_of_events.SYSTEM
        assert "caldera_status" in chain_of_events.SYSTEM
        assert "unavailable" in chain_of_events.SYSTEM

    def test_system_explicitly_forbids_inventing_cti(self):
        assert "sem dados CTI disponíveis" in chain_of_events.SYSTEM


class TestContextHandling:
    def test_commit_in_header_when_provided(self):
        prompt = chain_of_events.build(
            findings=[],
            cti_data=None,
            caldera_results=None,
            context={"commit": "abc123"},
        )
        assert "Commit: abc123" in prompt

    def test_no_context_yields_na(self):
        prompt = chain_of_events.build(
            findings=[],
            cti_data=None,
            caldera_results=None,
        )
        assert "Commit: N/A" in prompt
