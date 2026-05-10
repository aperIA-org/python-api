import json
import subprocess
import time

import structlog

from core.security import safe_repo_path
from core.exceptions import ScannerError, ScannerTimeoutError
from domain.finding.entities import Finding
from domain.finding.value_objects import Severity, CWEId

logger = structlog.get_logger()

_SEVERITY_MAP = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,
    "INFO": Severity.MEDIUM,
}


class SemgrepScanner:
    TIMEOUT = 300

    def scan(
        self,
        repo_path: str,
        files: list[str],
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        path = safe_repo_path(repo_path)
        start = time.monotonic()

        cmd = ["semgrep", "--config=auto", "--json", "--quiet"] + (files or ["."])
        try:
            result = subprocess.run(
                cmd,
                cwd=str(path),
                capture_output=True,
                text=True,
                timeout=self.TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            raise ScannerTimeoutError(f"Semgrep timeout após {self.TIMEOUT}s")
        except FileNotFoundError:
            raise ScannerError("semgrep não encontrado no PATH")

        raw: dict = {}
        if result.stdout:
            try:
                raw = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                logger.warning("semgrep_json_parse_error", error=str(exc))

        findings = [
            self._to_finding(r, commit_sha, repo_url)
            for r in raw.get("results", [])
        ]

        logger.info(
            "semgrep_scan_done",
            commit_sha=commit_sha,
            repo_url=repo_url,
            findings_count=len(findings),
            duration_ms=int((time.monotonic() - start) * 1000),
        )
        return findings

    def health_check(self) -> bool:
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _to_finding(self, r: dict, commit_sha: str, repo_url: str) -> Finding:
        extra = r.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe_list = metadata.get("cwe", [])

        cwe = None
        if cwe_list:
            raw_cwe = str(cwe_list[0])
            if not raw_cwe.startswith("CWE-"):
                raw_cwe = f"CWE-{raw_cwe}"
            try:
                cwe = CWEId(raw_cwe)
            except ValueError:
                cwe = None

        return Finding(
            source="semgrep",
            severity=_SEVERITY_MAP.get(
                str(extra.get("severity", "INFO")).upper(), Severity.INFO
            ),
            title=str(r.get("check_id", "unknown"))[:255],
            description=str(extra.get("message", ""))[:2000],
            cwe_id=cwe,
            file_path=str(r.get("path", ""))[:500] or None,
            line_number=r.get("start", {}).get("line"),
            raw_output=r,
            commit_sha=commit_sha,
            repo_url=repo_url,
        )
