import json
import subprocess
import time

import structlog

from core.exceptions import ScannerError, ScannerTimeoutError
from domain.finding.entities import Finding
from domain.finding.value_objects import Severity

logger = structlog.get_logger()

# TODO: validar com doc oficial — Prowler 4.x
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}


class ProwlerScanner:
    TIMEOUT = 600

    def scan(
        self,
        provider: str,
        commit_sha: str,
        repo_url: str,
        services: list[str] | None = None,
    ) -> list[Finding]:
        start = time.monotonic()

        cmd = ["prowler", provider, "-M", "json", "--no-banner", "--quiet"]
        if services:
            cmd += ["-s"] + services

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            raise ScannerTimeoutError(f"Prowler timeout após {self.TIMEOUT}s")
        except FileNotFoundError:
            raise ScannerError("prowler não encontrado no PATH")

        findings: list[Finding] = []
        for line in result.stdout.splitlines():
            parsed = self._safe_parse(line)
            if parsed and parsed.get("Status") == "FAIL":
                findings.append(self._to_finding(parsed, commit_sha, repo_url))

        logger.info(
            "prowler_scan_done",
            commit_sha=commit_sha,
            repo_url=repo_url,
            findings_count=len(findings),
            duration_ms=int((time.monotonic() - start) * 1000),
        )
        return findings

    def health_check(self) -> bool:
        try:
            result = subprocess.run(
                ["prowler", "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _safe_parse(self, line: str) -> dict | None:
        line = line.strip()
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    def _to_finding(self, item: dict, commit_sha: str, repo_url: str) -> Finding:
        severity_raw = str(item.get("Severity", "low")).lower()
        return Finding(
            source="prowler",
            severity=_SEVERITY_MAP.get(severity_raw, Severity.LOW),
            title=str(item.get("CheckTitle", "Prowler Check"))[:255],
            description=str(item.get("Description", ""))[:2000],
            asset=str(item.get("ResourceArn") or item.get("ResourceId", ""))[:500] or None,
            raw_output={
                "check_id": item.get("CheckID", ""),
                "service": item.get("ServiceName", ""),
                "region": item.get("Region", ""),
                "status": item.get("Status", ""),
            },
            commit_sha=commit_sha,
            repo_url=repo_url,
        )
