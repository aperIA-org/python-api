from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.trufflehog_scanner import TruffleHogScanner


FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "trufflehog_verified.jsonl"
)


def _fake_completed_process(stdout: str, returncode: int = 0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.returncode = returncode
    return proc


@pytest.fixture
def fixture_jsonl() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def test_returns_only_verified_findings(fixture_jsonl):
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(fixture_jsonl),
    ):
        findings = TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha="abc",
            head_sha="def",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

    # Fixture tem 3 entradas: 2 com Verified=true, 1 com Verified=false
    assert len(findings) == 2
    assert all(f.secret_verified for f in findings)


def test_finding_metadata(fixture_jsonl):
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(fixture_jsonl),
    ):
        findings = TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha="abc",
            head_sha="def",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

    aws = next(f for f in findings if f.secret_type == "AWS")
    assert aws.severity is Severity.CRITICAL
    assert aws.source == "trufflehog"
    assert aws.tier == 1
    assert aws.file_path == "config/secrets.env"
    assert aws.line_number == 12
    assert aws.commit_sha == "a" * 40
    assert aws.title == "Secret verificado: AWS"
    assert aws.is_critical_secret() is True


def test_handles_invalid_json_line_silently():
    bad_stdout = (
        '{"Verified":true,"DetectorName":"AWS","SourceMetadata":{"Data":{"Git":{}}}}\n'
        "this is not json\n"
        '{"Verified":true,"DetectorName":"GitHub","SourceMetadata":{"Data":{"Git":{}}}}\n'
    )
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(bad_stdout),
    ):
        findings = TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha="x",
            head_sha="y",
            commit_sha="b" * 40,
            repo_url="https://github.com/x/y",
        )
    assert len(findings) == 2


def test_empty_stdout_returns_empty():
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(""),
    ):
        findings = TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha="x",
            head_sha="y",
            commit_sha="c" * 40,
            repo_url="https://github.com/x/y",
        )
    assert findings == []


def test_command_uses_only_verified_and_json(fixture_jsonl):
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(fixture_jsonl),
    ) as run_mock:
        TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha="aaa",
            head_sha="bbb",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

    args = run_mock.call_args[0][0]
    assert args[0] == "trufflehog"
    assert "--only-verified" in args
    assert "--json" in args
    assert "--no-update" in args
    assert "file:///tmp/repo" in args
    assert "--since-commit" in args and "aaa" in args
    assert "--branch" in args and "bbb" in args
    # Sem shell=True
    assert run_mock.call_args[1].get("shell") in (None, False)
    # Timeout configurado
    assert run_mock.call_args[1]["timeout"] == TruffleHogScanner.TIMEOUT


def test_run_safe_returns_empty_on_subprocess_timeout():
    import subprocess as sp

    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        side_effect=sp.TimeoutExpired(cmd="trufflehog", timeout=120),
    ):
        findings = TruffleHogScanner().run_safe(
            repo_path="/tmp/repo",
            base_sha="x",
            head_sha="y",
            commit_sha="d" * 40,
            repo_url="https://github.com/x/y",
        )
    assert findings == []
