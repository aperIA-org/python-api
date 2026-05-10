import json
import subprocess
from pathlib import Path

import structlog

from domain.finding.entities import Finding
from domain.finding.value_objects import Severity
from core.exceptions import ScannerError, ScannerTimeoutError, ScannerParseError

logger = structlog.get_logger()


class TruffleHogScanner:
    TIMEOUT_SECONDS = 120

    def scan(
        self,
        repo_path: str,
        base_sha: str,
        head_sha: str,
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        safe_path = self._validate_repo_path(repo_path)
        log = logger.bind(commit_sha=commit_sha, repo_url=repo_url)
        log.info("trufflehog_scan_started")

        try:
            result = subprocess.run(
                [
                    "trufflehog", "git",
                    f"file://{safe_path}",
                    "--since-commit", base_sha,
                    "--branch", head_sha,
                    "--json",
                    "--no-update",
                ],
                capture_output=True,
                text=True,
                timeout=self.TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            raise ScannerTimeoutError(f"TruffleHog timeout após {self.TIMEOUT_SECONDS}s")
        except FileNotFoundError:
            raise ScannerError("trufflehog não encontrado — instale o CLI")

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parsed = self._parse_line(line, commit_sha, repo_url, log)
            if parsed:
                findings.append(parsed)

        log.info("trufflehog_scan_completed", findings_count=len(findings))
        return findings

    def _validate_repo_path(self, repo_path: str) -> Path:
        path = Path(repo_path).resolve()
        if not path.exists():
            raise ValueError(f"Repo path inválido: {repo_path}")
        if not path.is_dir():
            raise ValueError(f"Repo path não é diretório: {repo_path}")
        return path

    def _parse_line(
        self, line: str, commit_sha: str, repo_url: str, log
    ) -> Finding | None:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            log.warning("trufflehog_parse_error", line=line[:200])
            return None

        try:
            detector = str(data.get("DetectorName", "unknown"))[:100]
            verified = bool(data.get("Verified", False))
            git_meta = data.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
            file_path = str(git_meta.get("file", ""))[:500]
            line_number_raw = git_meta.get("line")
            line_number = int(line_number_raw) if line_number_raw else None

            severity = Severity.CRITICAL if verified else Severity.HIGH

            return Finding(
                source="trufflehog",
                severity=severity,
                title=f"Secret detected: {detector}",
                description=f"{'Verified' if verified else 'Unverified'} secret of type {detector}",
                commit_sha=commit_sha,
                repo_url=repo_url,
                file_path=file_path if file_path else None,
                line_number=line_number,
                secret_verified=verified,
                secret_type=detector,
                raw_output={
                    "detector": detector,
                    "verified": verified,
                    "file": file_path,
                },
            )
        except Exception as exc:
            log.warning("trufflehog_finding_build_error", error=str(exc))
            return None
