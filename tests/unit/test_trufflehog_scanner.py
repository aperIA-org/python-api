import json
from unittest.mock import MagicMock, patch

import pytest

from domain.finding.value_objects import Severity
from infrastructure.scanners.trufflehog_scanner import TruffleHogScanner

_COMMIT = "a" * 40
_REPO = "https://github.com/example/repo"

_VERIFIED_OUTPUT = json.dumps({
    "DetectorName": "AWS",
    "Verified": True,
    "SourceMetadata": {
        "Data": {"Git": {"file": "config.py", "line": 42}}
    },
})

_UNVERIFIED_OUTPUT = json.dumps({
    "DetectorName": "GitHub",
    "Verified": False,
    "SourceMetadata": {
        "Data": {"Git": {"file": "secrets.py", "line": 10}}
    },
})


def _mock_run(stdout: str, returncode: int = 0):
    mock = MagicMock()
    mock.stdout = stdout
    mock.returncode = returncode
    return mock


@patch("infrastructure.scanners.trufflehog_scanner.safe_repo_path")
@patch("subprocess.run")
def test_verified_secret_returns_critical_finding(mock_run, mock_path, tmp_path):
    mock_path.return_value = tmp_path
    mock_run.return_value = _mock_run(_VERIFIED_OUTPUT)

    findings = TruffleHogScanner().scan(
        str(tmp_path), _COMMIT, _COMMIT, _COMMIT, _REPO
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.source == "trufflehog"
    assert f.severity == Severity.CRITICAL
    assert f.secret_verified is True
    assert f.secret_type == "aws"
    assert f.file_path == "config.py"
    assert f.line_number == 42


@patch("infrastructure.scanners.trufflehog_scanner.safe_repo_path")
@patch("subprocess.run")
def test_only_verified_flag_is_used(mock_run, mock_path, tmp_path):
    mock_path.return_value = tmp_path
    mock_run.return_value = _mock_run("")

    TruffleHogScanner().scan(str(tmp_path), _COMMIT, _COMMIT, _COMMIT, _REPO)

    args = mock_run.call_args[0][0]
    assert "--only-verified" in args
    assert "--json" in args
    # shell=True nunca deve aparecer
    kwargs = mock_run.call_args[1]
    assert not kwargs.get("shell", False)


@patch("infrastructure.scanners.trufflehog_scanner.safe_repo_path")
@patch("subprocess.run")
def test_malformed_line_is_skipped(mock_run, mock_path, tmp_path):
    mock_path.return_value = tmp_path
    output = "not json\n" + _VERIFIED_OUTPUT
    mock_run.return_value = _mock_run(output)

    findings = TruffleHogScanner().scan(
        str(tmp_path), _COMMIT, _COMMIT, _COMMIT, _REPO
    )
    assert len(findings) == 1  # apenas a linha válida


@patch("infrastructure.scanners.trufflehog_scanner.safe_repo_path")
@patch("subprocess.run")
def test_empty_output_returns_no_findings(mock_run, mock_path, tmp_path):
    mock_path.return_value = tmp_path
    mock_run.return_value = _mock_run("")

    findings = TruffleHogScanner().scan(
        str(tmp_path), _COMMIT, _COMMIT, _COMMIT, _REPO
    )
    assert findings == []


@patch("infrastructure.scanners.trufflehog_scanner.safe_repo_path")
@patch("subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("trufflehog", 120))
def test_timeout_raises_scanner_timeout_error(mock_run, mock_path, tmp_path):
    from core.exceptions import ScannerTimeoutError
    mock_path.return_value = tmp_path

    with pytest.raises(ScannerTimeoutError):
        TruffleHogScanner().scan(str(tmp_path), _COMMIT, _COMMIT, _COMMIT, _REPO)
