import json
from unittest.mock import MagicMock, patch

from domain.finding.value_objects import Severity
from infrastructure.scanners.trivy_scanner import TrivyScanner

_COMMIT = "c" * 40
_REPO = "https://github.com/example/repo"

_TRIVY_OUTPUT = json.dumps({
    "Results": [
        {
            "Target": "requirements.txt",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-32681",
                    "PkgName": "requests",
                    "Severity": "MEDIUM",
                    "Title": "Requests proxy auth leak",
                    "Description": "Proxy auth forwarded unintentionally.",
                    "FixedVersion": "2.31.0",
                }
            ],
        },
        {
            "Target": "Dockerfile",
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image user should not be root",
                    "Description": "Running as root is dangerous.",
                    "Severity": "HIGH",
                    "Type": "Dockerfile Security Check",
                    "Resolution": "Add USER directive.",
                }
            ],
        },
    ]
})


def _mock_run(stdout: str):
    m = MagicMock()
    m.stdout = stdout
    m.returncode = 0
    return m


@patch("subprocess.run")
def test_parses_vuln_and_misconfiguration(mock_run, tmp_path):
    mock_run.return_value = _mock_run(_TRIVY_OUTPUT)

    findings = TrivyScanner().scan(str(tmp_path), _COMMIT, _REPO)

    assert len(findings) == 2
    sources = {f.source for f in findings}
    assert sources == {"trivy"}


@patch("subprocess.run")
def test_cve_id_parsed_correctly(mock_run, tmp_path):
    mock_run.return_value = _mock_run(_TRIVY_OUTPUT)

    findings = TrivyScanner().scan(str(tmp_path), _COMMIT, _REPO)

    vuln_f = next(f for f in findings if f.cve_id is not None)
    assert str(vuln_f.cve_id) == "CVE-2023-32681"
    assert vuln_f.severity == Severity.MEDIUM


@patch("subprocess.run")
def test_misconfiguration_severity_high(mock_run, tmp_path):
    mock_run.return_value = _mock_run(_TRIVY_OUTPUT)

    findings = TrivyScanner().scan(str(tmp_path), _COMMIT, _REPO)

    misc_f = next(f for f in findings if f.cve_id is None)
    assert misc_f.severity == Severity.HIGH
    assert misc_f.file_path == "Dockerfile"


@patch("subprocess.run")
def test_no_shell_true(mock_run, tmp_path):
    mock_run.return_value = _mock_run("{}")

    TrivyScanner().scan(str(tmp_path), _COMMIT, _REPO)

    kwargs = mock_run.call_args[1]
    assert not kwargs.get("shell", False)
