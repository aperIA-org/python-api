import json
import subprocess
import time

import structlog

from core.security import safe_repo_path
from core.exceptions import ScannerError, ScannerTimeoutError
from domain.finding.entities import Finding
from domain.finding.value_objects import Severity

logger = structlog.get_logger()


class TruffleHogScanner:
    TIMEOUT = 120

    def scan(
        self,
        repo_path: str,
        base_sha: str,
        head_sha: str,
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        path = safe_repo_path(repo_path)
        start = time.monotonic()

        try:
            result = subprocess.run(
                [
                    "trufflehog", "git",
                    f"file://{path}",
                    "--since-commit", base_sha,
                    "--branch", head_sha,
                    "--only-verified",
                    "--json",
                    "--no-update",
                ],
                capture_output=True,
                text=True,
                timeout=self.TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            raise ScannerTimeoutError(f"TruffleHog timeout após {self.TIMEOUT}s")
        except FileNotFoundError:
            raise ScannerError("trufflehog não encontrado no PATH")

        findings: list[Finding] = []
        for line in result.stdout.strip().splitlines():
            parsed = self._safe_parse(line)
            if parsed:
                findings.append(self._to_finding(parsed, commit_sha, repo_url))

        logger.info(
            "trufflehog_scan_done",
            commit_sha=commit_sha,
            repo_url=repo_url,
            findings_count=len(findings),
            duration_ms=int((time.monotonic() - start) * 1000),
        )
        return findings

    def health_check(self) -> bool:
        try:
            result = subprocess.run(
                ["trufflehog", "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _safe_parse(self, line: str) -> dict | None:
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            logger.warning("trufflehog_parse_error", line=line[:200])
            return None

    def _to_finding(self, raw: dict, commit_sha: str, repo_url: str) -> Finding:
        git_meta = raw.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
        detector = str(raw.get("DetectorName", "unknown"))
        secret_type = detector.lower().replace(" ", "_")[:100]

        line_raw = git_meta.get("line")
        return Finding(
            source="trufflehog",
            severity=Severity.CRITICAL,
            title=f"Secret verificado: {detector}",
            description=(
                f"Credencial ativa confirmada do tipo {detector}. "
                "Acesso ao serviço real verificado pelo TruffleHog."
            ),
            file_path=str(git_meta.get("file", ""))[:500] or None,
            line_number=int(line_raw) if line_raw else None,
            secret_verified=bool(raw.get("Verified", False)),
            secret_type=secret_type,
            raw_output=raw,
            commit_sha=commit_sha,
            repo_url=repo_url,
        )
