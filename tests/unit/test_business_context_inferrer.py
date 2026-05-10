"""
Testes unitários para BusinessContextInferrer.
Testa o fallback heurístico (sem LLM) e a conversão do response Claude.
"""
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from domain.shared.value_objects import AssetCriticality, BusinessContext
from infrastructure.analysis.business_context_inferrer import (
    BusinessContextInferrer,
    _from_claude_response,
    _heuristic_context,
)
from infrastructure.analysis._repo_signals import extract_repo_signals


def _write(tmp: Path, rel: str, content: str) -> None:
    fp = tmp / rel
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content, encoding="utf-8")


# ── Testes do fallback heurístico ─────────────────────────────────────────


class TestHeuristicContext:
    def test_financial_repo_gets_critical_and_pcidss(self, tmp_path):
        _write(tmp_path, "requirements.txt", "stripe==5.0\nfastapi==0.115.0\n")
        signals = extract_repo_signals(str(tmp_path))
        ctx = _heuristic_context(signals, "billing-service")

        assert ctx.asset_criticality == AssetCriticality.CRITICAL
        assert ctx.contains_financial_data is True
        assert "PCI-DSS" in ctx.compliance_scope
        assert ctx.inference_confidence < 0.5  # heurístico tem confiança baixa

    def test_health_repo_gets_critical_and_hipaa(self, tmp_path):
        _write(tmp_path, "models.py", "class Patient(Base):\n    medical_record = Column(String)\n")
        signals = extract_repo_signals(str(tmp_path))
        ctx = _heuristic_context(signals, "patient-portal")

        assert ctx.asset_criticality == AssetCriticality.CRITICAL
        assert ctx.contains_health_data is True
        assert "HIPAA" in ctx.compliance_scope

    def test_pii_internet_repo_gets_high(self, tmp_path):
        _write(tmp_path, "requirements.txt", "fastapi==0.115.0\nsendgrid==6.0\n")
        _write(tmp_path, "models.py", "class User(Base):\n    cpf = Column(String)\n")
        signals = extract_repo_signals(str(tmp_path))
        ctx = _heuristic_context(signals, "user-api")

        assert ctx.asset_criticality in (AssetCriticality.HIGH, AssetCriticality.CRITICAL)
        assert ctx.contains_pii is True
        assert "LGPD" in ctx.compliance_scope

    def test_empty_repo_gets_low_criticality(self, tmp_path):
        signals = extract_repo_signals(str(tmp_path))
        ctx = _heuristic_context(signals, "unknown")

        assert ctx.asset_criticality == AssetCriticality.LOW
        assert ctx.contains_pii is False
        assert ctx.contains_financial_data is False

    def test_breach_cost_populated_for_critical(self, tmp_path):
        _write(tmp_path, "requirements.txt", "stripe==5.0\n")
        signals = extract_repo_signals(str(tmp_path))
        ctx = _heuristic_context(signals, "payments")

        assert ctx.breach_cost_brl_min > 0
        assert ctx.breach_cost_brl_max > ctx.breach_cost_brl_min

    def test_asset_name_is_repo_name(self, tmp_path):
        signals = extract_repo_signals(str(tmp_path))
        ctx = _heuristic_context(signals, "myorg/my-service")

        assert ctx.asset_name == "myorg/my-service"

    def test_compliance_scope_deduplicates(self, tmp_path):
        _write(tmp_path, "requirements.txt", "stripe==5.0\n")
        _write(tmp_path, "models.py", "class User:\n    cpf = Column(String)\n")
        signals = extract_repo_signals(str(tmp_path))
        ctx = _heuristic_context(signals, "x")

        # Tuple sem duplicatas
        assert len(ctx.compliance_scope) == len(set(ctx.compliance_scope))


# ── Testes da conversão do response Claude ────────────────────────────────


class TestFromClaudeResponse:
    def test_maps_all_fields(self):
        raw = {
            "app_type": "web_api",
            "domain": "fintech",
            "asset_criticality": "critical",
            "contains_pii": True,
            "contains_financial_data": True,
            "contains_health_data": False,
            "internet_facing": True,
            "compliance_scope": ["LGPD", "PCI-DSS"],
            "estimated_users": "enterprise",
            "breach_cost_brl_min": 500_000,
            "breach_cost_brl_max": 5_000_000,
            "key_assets": ["payment service", "user database"],
            "confidence": 0.90,
        }

        ctx = _from_claude_response(raw, "billing-api")

        assert ctx.app_type == "web_api"
        assert ctx.domain == "fintech"
        assert ctx.asset_criticality == AssetCriticality.CRITICAL
        assert ctx.contains_pii is True
        assert ctx.contains_financial_data is True
        assert ctx.contains_health_data is False
        assert ctx.internet_facing is True
        assert "LGPD" in ctx.compliance_scope
        assert "PCI-DSS" in ctx.compliance_scope
        assert ctx.estimated_users == "enterprise"
        assert ctx.breach_cost_brl_min == 500_000
        assert ctx.breach_cost_brl_max == 5_000_000
        assert "payment service" in ctx.key_assets
        assert ctx.inference_confidence == 0.90

    def test_unknown_criticality_defaults_to_medium(self):
        raw = {"asset_criticality": "garbage_value"}
        ctx = _from_claude_response(raw, "x")
        assert ctx.asset_criticality == AssetCriticality.MEDIUM

    def test_missing_cost_uses_criticality_default(self):
        raw = {"asset_criticality": "high"}
        ctx = _from_claude_response(raw, "x")
        assert ctx.breach_cost_brl_min > 0
        assert ctx.breach_cost_brl_max > ctx.breach_cost_brl_min


# ── Testes do inferrer completo (mocking Claude) ──────────────────────────


class TestBusinessContextInferrer:
    def test_uses_claude_response_when_available(self, tmp_path):
        mock_claude = MagicMock()
        mock_claude.call_json.return_value = {
            "app_type": "web_api",
            "domain": "ecommerce",
            "asset_criticality": "high",
            "contains_pii": True,
            "contains_financial_data": False,
            "contains_health_data": False,
            "internet_facing": True,
            "compliance_scope": ["LGPD"],
            "estimated_users": "smb",
            "breach_cost_brl_min": 100_000,
            "breach_cost_brl_max": 500_000,
            "key_assets": [],
            "confidence": 0.82,
        }

        inferrer = BusinessContextInferrer(claude=mock_claude)
        ctx = inferrer.infer(str(tmp_path), "a" * 40, "org/shop")

        assert ctx.domain == "ecommerce"
        assert ctx.inference_confidence == 0.82
        mock_claude.call_json.assert_called_once()

    def test_falls_back_to_heuristic_when_claude_fails(self, tmp_path):
        _write(tmp_path, "requirements.txt", "stripe==5.0\n")
        mock_claude = MagicMock()
        mock_claude.call_json.side_effect = Exception("API unavailable")

        inferrer = BusinessContextInferrer(claude=mock_claude)
        ctx = inferrer.infer(str(tmp_path), "a" * 40, "org/payments")

        # Deve retornar contexto heurístico (não levanta exceção)
        assert isinstance(ctx, BusinessContext)
        assert ctx.inference_confidence < 0.5
        assert ctx.contains_financial_data is True

    def test_infer_without_llm_uses_only_heuristics(self, tmp_path):
        _write(tmp_path, "requirements.txt", "fastapi==0.115.0\nstripe==5.0\n")
        inferrer = BusinessContextInferrer()  # Claude real — não será chamado

        ctx = inferrer.infer_without_llm(str(tmp_path), "payments-service")

        assert ctx.contains_financial_data is True
        assert ctx.inference_confidence < 0.5


# ── Testes do RiskScorer com BusinessContext ──────────────────────────────


class TestRiskScorerWithBusinessContext:
    def test_critical_financial_raises_business_component(self):
        from domain.finding.entities import Finding, RiskScore
        from domain.finding.services import RiskScorer
        from domain.finding.value_objects import Severity

        scorer = RiskScorer()
        findings = [Finding(
            source="semgrep", severity=Severity.MEDIUM,
            title="XSS", description="Cross-site scripting",
            commit_sha="a" * 40, repo_url="https://github.com/x/y",
        )]
        ctx = BusinessContext(
            asset_name="payment-api",
            asset_criticality=AssetCriticality.CRITICAL,
            team_owner="",
            compliance_scope=("PCI-DSS", "LGPD"),
            contains_financial_data=True,
            contains_pii=True,
            internet_facing=True,
        )

        score_with_ctx = scorer.calculate(findings, {}, {}, ctx)
        score_without = scorer.calculate(findings, {}, {}, None)

        # Com contexto de pagamentos crítico, o score deve ser mais alto
        assert score_with_ctx.business_component > score_without.business_component

    def test_low_criticality_context_reduces_business_component(self):
        from domain.finding.entities import Finding
        from domain.finding.services import RiskScorer
        from domain.finding.value_objects import Severity

        scorer = RiskScorer()
        findings = [Finding(
            source="semgrep", severity=Severity.CRITICAL,
            title="SQLi", description="SQL Injection",
            commit_sha="b" * 40, repo_url="https://github.com/x/y",
        )]
        ctx_low = BusinessContext(
            asset_name="internal-tool",
            asset_criticality=AssetCriticality.LOW,
            team_owner="",
            compliance_scope=(),
        )
        ctx_critical = BusinessContext(
            asset_name="payment-api",
            asset_criticality=AssetCriticality.CRITICAL,
            team_owner="",
            compliance_scope=("PCI-DSS",),
            contains_financial_data=True,
            internet_facing=True,
        )

        score_low = scorer.calculate(findings, {}, {}, ctx_low)
        score_critical = scorer.calculate(findings, {}, {}, ctx_critical)

        assert score_critical.business_component > score_low.business_component
