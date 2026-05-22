from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.trivy_scanner import TrivyScanner


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _completed(stdout: str):
    proc = MagicMock()
    proc.stdout = stdout
    proc.returncode = 0
    return proc


@pytest.fixture
def trivy_json() -> str:
    return (FIXTURES / "trivy_results.json").read_text("utf-8")


def test_parses_vulnerabilities_and_misconfigs(trivy_json):
    with patch(
        "app.infrastructure.scanners.trivy_scanner.subprocess.run",
        return_value=_completed(trivy_json),
    ):
        findings = TrivyScanner().scan(
            target="/tmp/repo",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

    assert len(findings) == 4  # 3 vulns + 1 misc


def test_critical_vuln_mapped_correctly(trivy_json):
    with patch(
        "app.infrastructure.scanners.trivy_scanner.subprocess.run",
        return_value=_completed(trivy_json),
    ):
        findings = TrivyScanner().scan(
            target="/tmp/repo",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )
    log4j = next(f for f in findings if "Log4j" in f.title)
    assert log4j.severity is Severity.CRITICAL
    assert log4j.cve_id is not None
    assert str(log4j.cve_id) == "CVE-2021-44228"
    assert log4j.source == "trivy"
    assert log4j.tier == 2


def test_non_cve_advisory_keeps_cve_none(trivy_json):
    with patch(
        "app.infrastructure.scanners.trivy_scanner.subprocess.run",
        return_value=_completed(trivy_json),
    ):
        findings = TrivyScanner().scan(
            target="/tmp/repo",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )
    ghsa = next(f for f in findings if "Non-CVE" in f.title)
    assert ghsa.cve_id is None
    assert ghsa.severity is Severity.MEDIUM


def test_misconfiguration_has_file_path(trivy_json):
    with patch(
        "app.infrastructure.scanners.trivy_scanner.subprocess.run",
        return_value=_completed(trivy_json),
    ):
        findings = TrivyScanner().scan(
            target="/tmp/repo",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )
    misc = next(f for f in findings if "root" in f.title.lower())
    assert misc.file_path == "Dockerfile"
    assert misc.severity is Severity.MEDIUM


def test_empty_stdout_returns_empty():
    with patch(
        "app.infrastructure.scanners.trivy_scanner.subprocess.run",
        return_value=_completed(""),
    ):
        findings = TrivyScanner().scan(
            target="/tmp/repo",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )
    assert findings == []


def test_command_uses_json_quiet_no_shell(trivy_json):
    with patch(
        "app.infrastructure.scanners.trivy_scanner.subprocess.run",
        return_value=_completed(trivy_json),
    ) as run_mock:
        TrivyScanner().scan(
            target="/tmp/repo",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )
    args = run_mock.call_args[0][0]
    assert args[0] == "trivy"
    assert "--format" in args and "json" in args
    assert "--quiet" in args
    assert "--exit-code" in args and "0" in args
    assert run_mock.call_args[1]["timeout"] == TrivyScanner.TIMEOUT
    assert run_mock.call_args[1].get("shell") in (None, False)
