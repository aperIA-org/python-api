from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.prowler_scanner import (
    ProwlerScanner,
    has_iac_files,
)


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _completed(stdout: str):
    proc = MagicMock()
    proc.stdout = stdout
    proc.returncode = 0
    return proc


@pytest.fixture
def prowler_jsonl() -> str:
    return (FIXTURES / "prowler_results.jsonl").read_text("utf-8")


class TestHasIacFiles:
    def test_terraform(self):
        assert has_iac_files(["main.tf"]) is True

    def test_terraform_vars(self):
        assert has_iac_files(["vars.tfvars"]) is True

    def test_yaml(self):
        assert has_iac_files(["k8s/deploy.yaml"]) is True

    def test_dockerfile(self):
        assert has_iac_files(["Dockerfile"]) is True

    def test_docker_compose(self):
        assert has_iac_files(["docker-compose.yml"]) is True

    def test_only_python_returns_false(self):
        assert has_iac_files(["app.py", "test_app.py"]) is False

    def test_empty_returns_false(self):
        assert has_iac_files([]) is False

    def test_mixed(self):
        assert has_iac_files(["main.tf", "app.py"]) is True


class TestProwlerScanner:
    def test_only_failed_checks_become_findings(self, prowler_jsonl):
        with patch(
            "app.infrastructure.scanners.prowler_scanner.subprocess.run",
            return_value=_completed(prowler_jsonl),
        ):
            findings = ProwlerScanner().scan(
                provider="aws",
                commit_sha="a" * 40,
                repo_url="https://github.com/acme/repo",
            )
        # fixture tem 2 FAIL e 1 PASS
        assert len(findings) == 2
        titles = {f.title for f in findings}
        assert "Ensure MFA is enabled for the root user" in titles
        assert "S3 bucket should not be public" in titles

    def test_severity_mapping(self, prowler_jsonl):
        with patch(
            "app.infrastructure.scanners.prowler_scanner.subprocess.run",
            return_value=_completed(prowler_jsonl),
        ):
            findings = ProwlerScanner().scan(
                provider="aws",
                commit_sha="a" * 40,
                repo_url="https://github.com/acme/repo",
            )
        by_title = {f.title: f for f in findings}
        assert by_title["S3 bucket should not be public"].severity is Severity.CRITICAL
        assert by_title["Ensure MFA is enabled for the root user"].severity is Severity.HIGH

    def test_resource_id_stored_as_asset(self, prowler_jsonl):
        with patch(
            "app.infrastructure.scanners.prowler_scanner.subprocess.run",
            return_value=_completed(prowler_jsonl),
        ):
            findings = ProwlerScanner().scan(
                provider="aws",
                commit_sha="a" * 40,
                repo_url="https://github.com/acme/repo",
            )
        s3 = next(f for f in findings if "S3" in f.title)
        assert s3.asset == "arn:aws:s3:::my-public-bucket"

    def test_handles_invalid_json_line(self):
        bad = (
            '{"CheckTitle":"Good","Status":"FAIL","Severity":"high","ResourceId":"x"}\n'
            "this is not json\n"
            '{"CheckTitle":"Also good","Status":"FAIL","Severity":"low","ResourceId":"y"}\n'
        )
        with patch(
            "app.infrastructure.scanners.prowler_scanner.subprocess.run",
            return_value=_completed(bad),
        ):
            findings = ProwlerScanner().scan(
                provider="aws",
                commit_sha="b" * 40,
                repo_url="https://github.com/x/y",
            )
        assert len(findings) == 2

    def test_command_uses_no_banner_quiet(self, prowler_jsonl):
        with patch(
            "app.infrastructure.scanners.prowler_scanner.subprocess.run",
            return_value=_completed(prowler_jsonl),
        ) as run_mock:
            ProwlerScanner().scan(
                provider="aws",
                commit_sha="a" * 40,
                repo_url="https://github.com/acme/repo",
            )
        args = run_mock.call_args[0][0]
        assert args[0] == "prowler"
        assert "aws" in args
        assert "--no-banner" in args
        assert "--quiet" in args
        assert "-M" in args and "json" in args
        assert run_mock.call_args[1]["timeout"] == ProwlerScanner.TIMEOUT

    def test_services_filter(self, prowler_jsonl):
        with patch(
            "app.infrastructure.scanners.prowler_scanner.subprocess.run",
            return_value=_completed(prowler_jsonl),
        ) as run_mock:
            ProwlerScanner().scan(
                provider="aws",
                commit_sha="a" * 40,
                repo_url="https://github.com/acme/repo",
                services=["s3", "iam"],
            )
        args = run_mock.call_args[0][0]
        assert "-s" in args and "s3" in args and "iam" in args
