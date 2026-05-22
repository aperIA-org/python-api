from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.semgrep_scanner import SemgrepScanner


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


def _completed(stdout: str):
    proc = MagicMock()
    proc.stdout = stdout
    proc.returncode = 0
    return proc


@pytest.fixture
def security_audit_json() -> str:
    return (FIXTURES_DIR / "semgrep_security_audit.json").read_text("utf-8")


@pytest.fixture
def auto_with_cve_json() -> str:
    return (FIXTURES_DIR / "semgrep_auto_with_cve.json").read_text("utf-8")


class TestScanChanged:
    def test_returns_empty_when_no_changed_files(self):
        findings = SemgrepScanner().scan_changed(
            repo_path="/tmp/repo",
            changed_files=[],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
        )
        assert findings == []

    def test_does_not_invoke_subprocess_when_no_changed_files(self):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run"
        ) as run_mock:
            SemgrepScanner().scan_changed(
                repo_path="/tmp/repo",
                changed_files=[],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
            run_mock.assert_not_called()

    def test_parses_security_audit_results(self, security_audit_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(security_audit_json),
        ):
            findings = SemgrepScanner().scan_changed(
                repo_path="/tmp/repo",
                changed_files=["app/db.py", "app/runner.py", "app/util.py"],
                commit_sha="a" * 40,
                repo_url="https://github.com/acme/repo",
            )

        assert len(findings) == 3
        # All should have tier=1
        assert all(f.tier == 1 for f in findings)

        sql = next(f for f in findings if "sql-injection" in f.title)
        assert sql.severity is Severity.HIGH
        assert sql.file_path == "app/db.py"
        assert sql.line_number == 42
        assert sql.cwe_id == "CWE-89: SQL Injection"
        assert sql.cve_id is None

    def test_severity_mapping_warning_to_medium(self, security_audit_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(security_audit_json),
        ):
            findings = SemgrepScanner().scan_changed(
                repo_path="/tmp/repo",
                changed_files=["app/runner.py"],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
        warning = next(f for f in findings if "subprocess" in f.title)
        assert warning.severity is Severity.MEDIUM

    def test_severity_mapping_info_to_low(self, security_audit_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(security_audit_json),
        ):
            findings = SemgrepScanner().scan_changed(
                repo_path="/tmp/repo",
                changed_files=["app/util.py"],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
        info = next(f for f in findings if "print-statement" in f.title)
        assert info.severity is Severity.LOW

    def test_command_uses_security_audit_config_at_tier1(self, security_audit_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(security_audit_json),
        ) as run_mock:
            SemgrepScanner().scan_changed(
                repo_path="/tmp/repo",
                changed_files=["a.py", "b.py"],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )

        args = run_mock.call_args[0][0]
        assert args[0] == "semgrep"
        assert "--config=p/security-audit" in args
        assert "--json" in args
        # changed_files appended
        assert "a.py" in args and "b.py" in args
        # cwd usado
        assert run_mock.call_args[1]["cwd"] == "/tmp/repo"

    def test_empty_stdout_returns_empty(self):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(""),
        ):
            findings = SemgrepScanner().scan_changed(
                repo_path="/tmp/repo",
                changed_files=["a.py"],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
        assert findings == []


class TestScanExpanded:
    def test_uses_config_auto_at_tier2(self, auto_with_cve_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(auto_with_cve_json),
        ) as run_mock:
            findings = SemgrepScanner().scan_expanded(
                repo_path="/tmp/repo",
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )

        args = run_mock.call_args[0][0]
        assert "--config=auto" in args
        assert "." in args
        assert all(f.tier == 2 for f in findings)

    def test_extracts_cve_id_when_metadata_has_cve(self, auto_with_cve_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(auto_with_cve_json),
        ):
            findings = SemgrepScanner().scan_expanded(
                repo_path="/tmp/repo",
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
        log4shell = findings[0]
        assert log4shell.cve_id is not None
        assert str(log4shell.cve_id) == "CVE-2021-44228"

    def test_uses_300s_timeout(self, auto_with_cve_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(auto_with_cve_json),
        ) as run_mock:
            SemgrepScanner().scan_expanded(
                repo_path="/tmp/repo",
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
        assert run_mock.call_args[1]["timeout"] == 300


class TestScanDispatch:
    def test_scan_dispatches_to_scan_changed(self, security_audit_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(security_audit_json),
        ):
            findings = SemgrepScanner().scan(
                repo_path="/tmp/repo",
                changed_files=["app/db.py"],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
        assert all(f.tier == 1 for f in findings)
