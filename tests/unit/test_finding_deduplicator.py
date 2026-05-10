from domain.finding.entities import Finding
from domain.finding.services import FindingDeduplicator
from domain.finding.value_objects import Severity

_COMMIT = "d" * 40
_REPO = "https://github.com/example/repo"


def _make_finding(source: str, title: str, file_path: str | None = None) -> Finding:
    return Finding(
        source=source,
        severity=Severity.HIGH,
        title=title,
        description="test",
        commit_sha=_COMMIT,
        repo_url=_REPO,
        file_path=file_path,
        line_number=10,
    )


def test_identical_findings_deduplicated():
    f1 = _make_finding("semgrep", "sql-injection", "src/db.py")
    f2 = _make_finding("semgrep", "sql-injection", "src/db.py")

    result = FindingDeduplicator().deduplicate([f1, f2])

    assert len(result) == 1


def test_different_sources_kept():
    f1 = _make_finding("semgrep", "sql-injection", "src/db.py")
    f2 = _make_finding("trivy", "sql-injection", "src/db.py")

    result = FindingDeduplicator().deduplicate([f1, f2])

    assert len(result) == 2


def test_different_titles_kept():
    f1 = _make_finding("semgrep", "sql-injection", "src/db.py")
    f2 = _make_finding("semgrep", "xss-vulnerability", "src/db.py")

    result = FindingDeduplicator().deduplicate([f1, f2])

    assert len(result) == 2


def test_empty_list_returns_empty():
    assert FindingDeduplicator().deduplicate([]) == []


def test_order_preserved():
    f1 = _make_finding("semgrep", "finding-a", "a.py")
    f2 = _make_finding("trivy", "finding-b", "b.py")
    f3 = _make_finding("semgrep", "finding-a", "a.py")  # duplicate of f1

    result = FindingDeduplicator().deduplicate([f1, f2, f3])

    assert len(result) == 2
    assert result[0].title == "finding-a"
    assert result[1].title == "finding-b"
