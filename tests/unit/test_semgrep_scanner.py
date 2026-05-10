import json
from unittest.mock import MagicMock, patch

import pytest

from domain.finding.value_objects import Severity
from infrastructure.scanners.semgrep_scanner import SemgrepScanner

_COMMIT = "b" * 40
_REPO = "https://github.com/example/repo"

_SEMGREP_OUTPUT = json.dumps({
    "results": [
        {
            "check_id": "python.lang.security.audit.formatted-sql-query",
            "path": "src/db.py",
            "start": {"line": 15, "col": 5},
            "extra": {
                "severity": "ERROR",
                "message": "Formatted SQL query detected.",
                "metadata": {"cwe": ["CWE-89"]},
            },
        },
        {
            "check_id": "python.lang.security.deserialization.pickle",
            "path": "src/utils.py",
            "start": {"line": 30},
            "extra": {
                "severity": "WARNING",
                "message": "Use of pickle.",
                "metadata": {},
            },
        },
    ],
    "errors": [],
})


def _mock_run(stdout: str, returncode: int = 0):
    m = MagicMock()
    m.stdout = stdout
    m.returncode = returncode
    return m


@patch("infrastructure.scanners.semgrep_scanner.safe_repo_path")
@patch("subprocess.run")
def test_parses_two_findings(mock_run, mock_path, tmp_path):
    mock_path.return_value = tmp_path
    mock_run.return_value = _mock_run(_SEMGREP_OUTPUT)

    findings = SemgrepScanner().scan(str(tmp_path), ["."], _COMMIT, _REPO)

    assert len(findings) == 2


@patch("infrastructure.scanners.semgrep_scanner.safe_repo_path")
@patch("subprocess.run")
def test_error_severity_maps_to_critical(mock_run, mock_path, tmp_path):
    mock_path.return_value = tmp_path
    mock_run.return_value = _mock_run(_SEMGREP_OUTPUT)

    findings = SemgrepScanner().scan(str(tmp_path), ["."], _COMMIT, _REPO)

    sql_f = next(f for f in findings if "sql" in f.title.lower())
    assert sql_f.severity == Severity.CRITICAL
    assert str(sql_f.cwe_id) == "CWE-89"


@patch("infrastructure.scanners.semgrep_scanner.safe_repo_path")
@patch("subprocess.run")
def test_warning_maps_to_high(mock_run, mock_path, tmp_path):
    mock_path.return_value = tmp_path
    mock_run.return_value = _mock_run(_SEMGREP_OUTPUT)

    findings = SemgrepScanner().scan(str(tmp_path), ["."], _COMMIT, _REPO)

    pickle_f = next(f for f in findings if "pickle" in f.title.lower())
    assert pickle_f.severity == Severity.HIGH


@patch("infrastructure.scanners.semgrep_scanner.safe_repo_path")
@patch("subprocess.run")
def test_shell_false_enforced(mock_run, mock_path, tmp_path):
    mock_path.return_value = tmp_path
    mock_run.return_value = _mock_run("{}")

    SemgrepScanner().scan(str(tmp_path), ["."], _COMMIT, _REPO)

    kwargs = mock_run.call_args[1]
    assert not kwargs.get("shell", False)


@patch("infrastructure.scanners.semgrep_scanner.safe_repo_path")
@patch("subprocess.run")
def test_empty_output_returns_empty_list(mock_run, mock_path, tmp_path):
    mock_path.return_value = tmp_path
    mock_run.return_value = _mock_run("")

    findings = SemgrepScanner().scan(str(tmp_path), ["."], _COMMIT, _REPO)
    assert findings == []
