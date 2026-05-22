import json

from app.infrastructure.ai.prompts import pr_report


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
    "cti_status": "unavailable",
    "caldera_status": "unavailable",
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

    def test_handles_unavailable_cti(self):
        assert "cti_status" in pr_report.SYSTEM
        assert "unavailable" in pr_report.SYSTEM

    def test_handles_unavailable_caldera(self):
        assert "caldera_status" in pr_report.SYSTEM
