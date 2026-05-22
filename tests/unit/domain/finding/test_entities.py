from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity, CVEId


def _make_finding(**overrides) -> Finding:
    base = {
        "source": "semgrep",
        "severity": Severity.HIGH,
        "title": "SQL injection",
        "description": "Query construída com f-string",
        "commit_sha": "a" * 40,
        "repo_url": "https://github.com/acme/repo",
        "file_path": "app/db.py",
        "line_number": 42,
    }
    base.update(overrides)
    return Finding(**base)


class TestFindingDefaults:
    def test_default_tier_is_1(self):
        f = _make_finding()
        assert f.tier == 1

    def test_default_secret_verified_is_false(self):
        f = _make_finding()
        assert f.secret_verified is False

    def test_id_is_generated(self):
        f1 = _make_finding()
        f2 = _make_finding()
        assert f1.id != f2.id

    def test_raw_output_defaults_to_empty_dict(self):
        f = _make_finding()
        assert f.raw_output == {}


class TestDedupKey:
    def test_includes_commit_sha(self):
        sha_a = "a" * 40
        sha_b = "b" * 40
        f1 = _make_finding(commit_sha=sha_a)
        f2 = _make_finding(commit_sha=sha_b)
        assert f1.dedup_key() != f2.dedup_key()
        assert sha_a in f1.dedup_key()
        assert sha_b in f2.dedup_key()

    def test_same_attributes_same_key(self):
        f1 = _make_finding(commit_sha="c" * 40)
        f2 = _make_finding(commit_sha="c" * 40)
        assert f1.dedup_key() == f2.dedup_key()

    def test_different_file_path_different_key(self):
        f1 = _make_finding(file_path="a.py")
        f2 = _make_finding(file_path="b.py")
        assert f1.dedup_key() != f2.dedup_key()

    def test_different_line_number_different_key(self):
        f1 = _make_finding(line_number=10)
        f2 = _make_finding(line_number=20)
        assert f1.dedup_key() != f2.dedup_key()

    def test_uses_cve_id_when_present(self):
        f = _make_finding(cve_id=CVEId("CVE-2021-44228"))
        assert "CVE-2021-44228" in f.dedup_key()


class TestIsCriticalSecret:
    def test_true_when_verified_and_critical(self):
        f = _make_finding(secret_verified=True, severity=Severity.CRITICAL)
        assert f.is_critical_secret() is True

    def test_false_when_not_verified(self):
        f = _make_finding(secret_verified=False, severity=Severity.CRITICAL)
        assert f.is_critical_secret() is False

    def test_false_when_not_critical(self):
        f = _make_finding(secret_verified=True, severity=Severity.HIGH)
        assert f.is_critical_secret() is False
