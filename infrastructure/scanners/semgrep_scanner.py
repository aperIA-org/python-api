import json
import subprocess
from pathlib import Path

import structlog

from domain.finding.entities import Finding
from domain.finding.value_objects import Severity
from core.exceptions import ScannerError, ScannerTimeoutError

logger = structlog.get_logger()

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepScanner:
    TIMEOUT_SECONDS = 300

    def scan(self, repo_path: str, commit_sha: str, repo_url: str) -> list[Finding]:
        safe_path = self._validate_repo_path(repo_path)
        log = logger.bind(commit_sha=commit_sha, repo_url=repo_url)
        log.info("semgrep_scan_started")

        try:
            result = subprocess.run(
                [
                    "semgrep", "scan",
                    "--config", "auto",
                    "--json",
                    "--quiet",
                    str(safe_path),
                ],
                capture_output=True,
                text=True,
                timeout=self.TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            raise ScannerTimeoutError(f"Semgrep timeout após {self.TIMEOUT_SECONDS}s")
        except FileNotFoundError:
            raise ScannerError("semgrep não encontrado — instale o CLI")

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            log.warning("semgrep_parse_error", error=str(exc))
            return []

        findings = []
        for result_item in data.get("results", []):
            finding = self._build_finding(result_item, commit_sha, repo_url, log)
            if finding:
                findings.append(finding)

        log.info("semgrep_scan_completed", findings_count=len(findings))
        return findings

    def _validate_repo_path(self, repo_path: str) -> Path:
        path = Path(repo_path).resolve()
        if not path.exists() or not path.is_dir():
            raise ValueError(f"Repo path inválido: {repo_path}")
        return path

    def _build_finding(
        self, item: dict, commit_sha: str, repo_url: str, log
    ) -> Finding | None:
        # TODO: validar com doc oficial — formato baseado em semgrep OSS 1.x
        try:
            check_id = str(item.get("check_id", "unknown"))[:200]
            message = str(item.get("extra", {}).get("message", ""))[:1000]
            severity_raw = str(item.get("extra", {}).get("severity", "INFO")).upper()
            severity = _SEVERITY_MAP.get(severity_raw, Severity.INFO)
            file_path = str(item.get("path", ""))[:500]
            line_number = item.get("start", {}).get("line")
            cwe_raw = item.get("extra", {}).get("metadata", {}).get("cwe", [])
            cwe_str = cwe_raw[0] if isinstance(cwe_raw, list) and cwe_raw else None

            return Finding(
                source="semgrep",
                severity=severity,
                title=check_id,
                description=message,
                commit_sha=commit_sha,
                repo_url=repo_url,
                file_path=file_path if file_path else None,
                line_number=int(line_number) if line_number else None,
                raw_output={
                    "check_id": check_id,
                    "severity": severity_raw,
                    "cwe": cwe_str,
                },
            )
        except Exception as exc:
            log.warning("semgrep_finding_build_error", error=str(exc))
            return None
