import json
import subprocess

import structlog

from domain.finding.entities import Finding
from domain.finding.value_objects import Severity
from core.exceptions import ScannerError, ScannerTimeoutError

logger = structlog.get_logger()

# TODO: validar com doc oficial — Prowler 4.x output JSON format
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}


class ProwlerScanner:
    TIMEOUT_SECONDS = 600

    def scan(self, commit_sha: str, repo_url: str) -> list[Finding]:
        log = logger.bind(commit_sha=commit_sha, repo_url=repo_url)
        log.info("prowler_scan_started")

        try:
            result = subprocess.run(
                ["prowler", "aws", "--output-formats", "json", "--quiet"],
                capture_output=True,
                text=True,
                timeout=self.TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            raise ScannerTimeoutError(f"Prowler timeout após {self.TIMEOUT_SECONDS}s")
        except FileNotFoundError:
            raise ScannerError("prowler não encontrado — instale o CLI")

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            finding = self._parse_line(line, commit_sha, repo_url, log)
            if finding:
                findings.append(finding)

        log.info("prowler_scan_completed", findings_count=len(findings))
        return findings

    def _parse_line(self, line: str, commit_sha: str, repo_url: str, log) -> Finding | None:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        try:
            status = str(data.get("Status", "")).upper()
            if status != "FAIL":
                return None

            severity_raw = str(data.get("Severity", "low")).lower()
            severity = _SEVERITY_MAP.get(severity_raw, Severity.INFO)

            return Finding(
                source="prowler",
                severity=severity,
                title=str(data.get("CheckTitle", "Unknown Prowler Check"))[:300],
                description=str(data.get("Description", ""))[:2000],
                commit_sha=commit_sha,
                repo_url=repo_url,
                asset=str(data.get("ResourceId", ""))[:500],
                raw_output={
                    "check_id": data.get("CheckID", ""),
                    "service": data.get("ServiceName", ""),
                    "region": data.get("Region", ""),
                    "status": status,
                },
            )
        except Exception as exc:
            log.warning("prowler_finding_build_error", error=str(exc))
            return None
