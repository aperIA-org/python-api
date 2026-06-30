"""Testes do prompt attack_path (Tier 3, Sonnet).

Foco: blindagem contra alucinação no padrão da Semana 6 — dicts
vazios viram sentinelas explícitos, payloads de scanners não vazam
para o prompt sem normalização.
"""
from __future__ import annotations

from app.infrastructure.ai.prompts import attack_path


_FINDINGS = [
    {
        "severity": "critical",
        "source": "trivy",
        "title": "log4j-core",
        "file_path": "lib/log4j-core.jar",
        "line_number": None,
        "cve_id": "CVE-2021-44228",
    }
]


# -----------------------------------------------------------------------------
# Contrato de dicts vazios (decisão #3 Semana 10)
# -----------------------------------------------------------------------------


class TestEmptyDataContract:
    def test_empty_cti_emits_sentinel(self):
        prompt = attack_path.build(
            findings=_FINDINGS,
            cti_data={},
            caldera_results={"success_rate": 0.5},
        )
        assert "sem dados CTI disponíveis nesta análise" in prompt

    def test_none_cti_emits_sentinel(self):
        prompt = attack_path.build(
            findings=_FINDINGS,
            cti_data=None,
            caldera_results={"success_rate": 0.5, "caldera_validated": True},
        )
        assert "sem dados CTI disponíveis nesta análise" in prompt

    def test_empty_caldera_emits_sentinel(self):
        prompt = attack_path.build(
            findings=_FINDINGS,
            cti_data={"active_threat": True},
            caldera_results={},
        )
        assert "sem dados de emulação Caldera disponíveis" in prompt

    def test_failed_caldera_treated_as_unavailable(self):
        """status='failed' (do run_safe) deve virar sentinela."""
        prompt = attack_path.build(
            findings=_FINDINGS,
            cti_data={"active_threat": True},
            caldera_results={
                "status": "failed",
                "reason": "timeout",
                "success_rate": 0.0,
                "caldera_validated": False,
            },
        )
        assert "sem dados de emulação Caldera disponíveis" in prompt

    def test_both_empty_emits_both_sentinels(self):
        prompt = attack_path.build(
            findings=_FINDINGS, cti_data={}, caldera_results={}
        )
        assert "sem dados CTI disponíveis nesta análise" in prompt
        assert "sem dados de emulação Caldera disponíveis" in prompt
        # E nunca string vazia entre os marcadores
        assert "Dados CTI: \n" not in prompt
        assert "Dados Caldera: \n" not in prompt


class TestCtiRendering:
    def test_active_threat_rendered(self):
        prompt = attack_path.build(
            _FINDINGS, {"active_threat": True}, {}
        )
        assert "ameaça ativa: True" in prompt

    def test_mitre_techniques_rendered(self):
        prompt = attack_path.build(
            _FINDINGS,
            {"mitre_techniques": ["T1190", "T1059"]},
            {},
        )
        assert "T1190" in prompt
        assert "T1059" in prompt


class TestCalderaRendering:
    def test_success_rate_as_percent(self):
        prompt = attack_path.build(
            _FINDINGS, {}, {"success_rate": 0.66, "caldera_validated": True}
        )
        assert "taxa de sucesso: 66%" in prompt
        assert "validado por emulação: True" in prompt

    def test_ttps_used_rendered(self):
        prompt = attack_path.build(
            _FINDINGS, {}, {"ttps_used": ["T1190", None, "T1059"]}
        )
        # Filtra None silenciosamente
        assert "T1190" in prompt
        assert "T1059" in prompt
        assert "None" not in prompt.split("Dados Caldera:")[1]


class TestFindings:
    def test_count_in_header(self):
        prompt = attack_path.build(_FINDINGS, None, None)
        assert "Findings (1)" in prompt

    def test_cve_included(self):
        prompt = attack_path.build(_FINDINGS, None, None)
        assert "CVE-2021-44228" in prompt

    def test_severity_uppercase(self):
        prompt = attack_path.build(_FINDINGS, None, None)
        assert "[CRITICAL]" in prompt


class TestSystemPrompt:
    def test_forbids_inventing_data(self):
        assert "NÃO invente" in attack_path.SYSTEM

    def test_unavailable_handling_in_system(self):
        assert "cti_status" in attack_path.SYSTEM
        assert "caldera_status" in attack_path.SYSTEM
        assert "unavailable" in attack_path.SYSTEM

    def test_mentions_mitre_attack(self):
        assert "MITRE ATT&CK" in attack_path.SYSTEM
        assert "TXXXX" in attack_path.SYSTEM


class TestContext:
    def test_commit_in_header(self):
        prompt = attack_path.build(_FINDINGS, None, None, {"commit": "abc123"})
        assert "Commit: abc123" in prompt

    def test_no_context_yields_na(self):
        prompt = attack_path.build(_FINDINGS, None, None)
        assert "Commit: N/A" in prompt
