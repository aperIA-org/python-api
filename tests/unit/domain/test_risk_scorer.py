"""RiskScorer com dados reais de CTI (Semana 8).

Esta suite valida o ``RiskScorer`` no domain consumindo dicts no
formato que ``ThreatIntelClient.enrich_cve`` produz. Inclui o teste
manual do checklist da Semana 8:

- ``secret_verified=True`` → score ≥ 90 (regra hard inviolável)
- ``active_campaigns`` (via ``active_threat`` do enrich) eleva o
  componente CTI
"""
from __future__ import annotations

from app.domain.finding.entities import Finding
from app.domain.finding.services import RiskScorer
from app.domain.finding.value_objects import CVEId, Severity


def _f(**overrides) -> Finding:
    base = {
        "source": "semgrep",
        "severity": Severity.MEDIUM,
        "title": "x",
        "description": "x",
        "commit_sha": "a" * 40,
        "repo_url": "https://github.com/x/y",
    }
    base.update(overrides)
    return Finding(**base)


# -----------------------------------------------------------------------------
# Hard rule: secret_verified=True → score ≥ 90
# -----------------------------------------------------------------------------


class TestVerifiedSecretFloor:
    def test_secret_verified_critical_forces_score_above_90(self):
        f = _f(
            source="trufflehog",
            severity=Severity.CRITICAL,
            secret_verified=True,
        )
        score = RiskScorer().calculate(
            findings=[f],
            cti_data={"active_campaigns": False},
            caldera_results={"success_rate": 0.0},
        )
        assert score >= 90

    def test_secret_verified_with_zero_cti_and_caldera_still_90(self):
        """Hard floor mesmo se CTI/Caldera vazios — secret é evidência forte."""
        f = _f(
            source="trufflehog",
            severity=Severity.CRITICAL,
            secret_verified=True,
        )
        score = RiskScorer().calculate(
            findings=[f],
            cti_data={},
            caldera_results={},
        )
        assert score == 90

    def test_secret_high_severity_not_critical_no_floor(self):
        """Só CRITICAL+verified dispara o floor — HIGH+verified não."""
        f = _f(
            source="trufflehog",
            severity=Severity.HIGH,
            secret_verified=True,
        )
        score = RiskScorer().calculate(
            findings=[f],
            cti_data={},
            caldera_results={},
        )
        assert score < 90

    def test_unverified_secret_no_floor(self):
        f = _f(
            source="trufflehog",
            severity=Severity.CRITICAL,
            secret_verified=False,
        )
        score = RiskScorer().calculate(
            findings=[f],
            cti_data={},
            caldera_results={},
        )
        assert score < 90


# -----------------------------------------------------------------------------
# CTI integration — ativa campaigns eleva risk
# -----------------------------------------------------------------------------


class TestCtiComponent:
    def test_active_campaigns_boosts_score(self):
        f = _f(severity=Severity.HIGH, cve_id=CVEId("CVE-2021-44228"))
        cti_no = {"active_campaigns": False}
        cti_yes = {"active_campaigns": True}
        scorer = RiskScorer()
        no_threat = scorer.calculate([f], cti_no, {"success_rate": 0.0})
        with_threat = scorer.calculate([f], cti_yes, {"success_rate": 0.0})
        assert with_threat > no_threat

    def test_empty_cti_uses_low_component(self):
        f = _f(severity=Severity.HIGH, cve_id=CVEId("CVE-2021-44228"))
        score = RiskScorer().calculate([f], {}, {})
        # CVSS=75*0.25=18.75; CTI=25*0.25=6.25; Caldera=0; Business=40*0.20=8 → 33
        assert 30 <= score <= 35


class TestCalderaComponent:
    def test_high_success_rate_dominates(self):
        f = _f(severity=Severity.LOW)
        score = RiskScorer().calculate(
            [f],
            {"active_campaigns": False},
            {"success_rate": 1.0},
        )
        # CVSS=25*0.25=6.25; CTI=25*0.25=6.25; Caldera=100*0.30=30; Business=8 → 50
        assert 45 <= score <= 55

    def test_zero_success_rate_neutral(self):
        f = _f(severity=Severity.HIGH)
        score = RiskScorer().calculate(
            [f],
            {"active_campaigns": False},
            {"success_rate": 0.0},
        )
        # CVSS=18.75; CTI=6.25; Caldera=0; Business=8 → 33
        assert 30 <= score <= 35


# -----------------------------------------------------------------------------
# Worst-case e cenário "limpo"
# -----------------------------------------------------------------------------


class TestExtremes:
    def test_full_blown_attack_path_maxes_score(self):
        f = _f(
            severity=Severity.CRITICAL,
            asset_criticality="critical",
            cve_id=CVEId("CVE-2021-44228"),
        )
        score = RiskScorer().calculate(
            [f],
            {"active_campaigns": True},
            {"success_rate": 1.0},
        )
        assert score == 100

    def test_no_findings_yields_baseline(self):
        score = RiskScorer().calculate([], {}, {})
        # CVSS=0; CTI=25*0.25=6.25; Caldera=0; Business=40*0.20=8 → 14
        assert 0 <= score <= 20

    def test_only_info_severity_score_low(self):
        f = _f(severity=Severity.INFO)
        score = RiskScorer().calculate([f], {}, {})
        # CVSS=0*0.25=0; CTI=6.25; Caldera=0; Business=8 → 14
        assert 0 <= score <= 20
