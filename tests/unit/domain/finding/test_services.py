from app.domain.finding.entities import Finding
from app.domain.finding.services import FindingDeduplicator, RiskScorer
from app.domain.finding.value_objects import Severity


def _make_finding(**overrides) -> Finding:
    base = {
        "source": "semgrep",
        "severity": Severity.HIGH,
        "title": "SQL injection",
        "description": "x",
        "commit_sha": "a" * 40,
        "repo_url": "https://github.com/acme/repo",
        "file_path": "app/db.py",
        "line_number": 42,
    }
    base.update(overrides)
    return Finding(**base)


class TestFindingDeduplicator:
    def test_empty_list(self):
        result = FindingDeduplicator().deduplicate([])
        assert result == []

    def test_three_identical_become_one(self):
        f1 = _make_finding()
        f2 = _make_finding(id=f1.id)
        f3 = _make_finding(id=f1.id)
        # Mesmos campos relevantes para dedup_key
        result = FindingDeduplicator().deduplicate([f1, f2, f3])
        assert len(result) == 1

    def test_preserves_first_seen(self):
        f1 = _make_finding(title="primeiro")
        f2 = _make_finding(title="primeiro")  # mesma dedup_key
        result = FindingDeduplicator().deduplicate([f1, f2])
        assert len(result) == 1
        assert result[0] is f1

    def test_different_commits_kept_separate(self):
        f1 = _make_finding(commit_sha="a" * 40)
        f2 = _make_finding(commit_sha="b" * 40)
        result = FindingDeduplicator().deduplicate([f1, f2])
        assert len(result) == 2

    def test_different_files_kept_separate(self):
        f1 = _make_finding(file_path="a.py")
        f2 = _make_finding(file_path="b.py")
        result = FindingDeduplicator().deduplicate([f1, f2])
        assert len(result) == 2


class TestRiskScorerVerifiedSecretFloor:
    def test_verified_secret_forces_minimum_90(self):
        f = _make_finding(
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

    def test_verified_secret_overrides_all_low_components(self):
        f = _make_finding(
            source="trufflehog",
            severity=Severity.CRITICAL,
            secret_verified=True,
            asset_criticality=None,
        )
        score = RiskScorer().calculate(
            findings=[f],
            cti_data={},
            caldera_results={},
        )
        # Componentes calculados manualmente:
        # CVSS=100*0.25=25; CTI=25*0.25=6.25; Caldera=0; Business=40*0.20=8 → 39
        # Mas verified_secret → max(39, 90) = 90
        assert score == 90

    def test_high_severity_secret_not_critical_no_floor(self):
        # secret_verified=True mas severity=HIGH (não critical) → não dispara o floor
        f = _make_finding(
            source="trufflehog",
            severity=Severity.HIGH,
            secret_verified=True,
        )
        score = RiskScorer().calculate(
            findings=[f],
            cti_data={},
            caldera_results={},
        )
        # Sem floor: CVSS=75*0.25=18.75; CTI=6.25; Caldera=0; Business=8 → 32 (int)
        assert score < 90


class TestRiskScorerComponents:
    def test_empty_findings_returns_low_score(self):
        score = RiskScorer().calculate(
            findings=[],
            cti_data={},
            caldera_results={},
        )
        # CVSS=0; CTI=25*0.25=6.25; Caldera=0; Business=40*0.20=8 → 14
        assert 0 <= score <= 20

    def test_critical_finding_active_campaigns_high_caldera_critical_asset(self):
        f = _make_finding(
            severity=Severity.CRITICAL,
            asset_criticality="critical",
        )
        score = RiskScorer().calculate(
            findings=[f],
            cti_data={"active_campaigns": True},
            caldera_results={"success_rate": 1.0},
        )
        # CVSS=100*0.25=25; CTI=100*0.25=25; Caldera=100*0.30=30; Business=100*0.20=20 → 100
        assert score == 100

    def test_caldera_dominates_via_30_percent_weight(self):
        f = _make_finding(severity=Severity.LOW)
        score = RiskScorer().calculate(
            findings=[f],
            cti_data={},
            caldera_results={"success_rate": 1.0},
        )
        # CVSS=25*0.25=6.25; CTI=6.25; Caldera=30; Business=8 → 50
        assert 45 <= score <= 55
