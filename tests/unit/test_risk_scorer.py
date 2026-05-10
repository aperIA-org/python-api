from domain.finding.entities import Finding
from domain.finding.services import RiskScorer
from domain.finding.value_objects import Severity

_COMMIT = "e" * 40
_REPO = "https://github.com/example/repo"


def _finding(severity: Severity, verified: bool = False) -> Finding:
    return Finding(
        source="trufflehog" if verified else "semgrep",
        severity=severity,
        title="test finding",
        description="desc",
        commit_sha=_COMMIT,
        repo_url=_REPO,
        secret_verified=verified,
        secret_type="aws" if verified else None,
    )


def test_verified_secret_score_minimum_90():
    findings = [_finding(Severity.CRITICAL, verified=True)]
    score = RiskScorer().calculate(findings, {}, {})
    assert score.value >= 90
    assert score.level in ("critical", "high")


def test_no_findings_returns_low_score():
    score = RiskScorer().calculate([], {}, {})
    assert score.value == 0


def test_score_capped_at_100():
    findings = [_finding(Severity.CRITICAL, verified=True)] * 5
    score = RiskScorer().calculate(findings, {"active_campaigns": 100}, {"success_rate": 1.0})
    assert score.value <= 100


def test_critical_finding_raises_score():
    findings = [_finding(Severity.CRITICAL)]
    score_crit = RiskScorer().calculate(findings, {}, {})

    findings_low = [_finding(Severity.LOW)]
    score_low = RiskScorer().calculate(findings_low, {}, {})

    assert score_crit.value > score_low.value
