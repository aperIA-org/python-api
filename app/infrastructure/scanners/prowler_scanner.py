import json
import subprocess
from pathlib import Path

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.base_scanner import BaseScanner


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}

IAC_EXTENSIONS = {".tf", ".tfvars", ".yaml", ".yml", ".json"}
IAC_FILENAMES = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}


def has_iac_files(changed_files: list[str]) -> bool:
    return any(
        Path(f).suffix in IAC_EXTENSIONS or Path(f).name in IAC_FILENAMES
        for f in changed_files
    )


class ProwlerScanner(BaseScanner):
    TIMEOUT = 600

    def scan(
        self,
        provider: str,
        commit_sha: str,
        repo_url: str,
        services: list[str] | None = None,
    ) -> list[Finding]:
        cmd = ["prowler", provider, "-M", "json", "--no-banner", "--quiet"]
        if services:
            cmd += ["-s", *services]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.TIMEOUT,
        )
        findings: list[Finding] = []
        for line in result.stdout.splitlines():
            parsed = self._safe_parse(line)
            if parsed and parsed.get("Status") == "FAIL":
                findings.append(self._to_finding(parsed, commit_sha, repo_url))
        return findings

    def _safe_parse(self, line: str) -> dict | None:
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    def _to_finding(
        self,
        item: dict,
        commit_sha: str,
        repo_url: str,
    ) -> Finding:
        severity_raw = str(item.get("Severity", "informational")).lower()
        return Finding(
            source="prowler",
            severity=SEVERITY_MAP.get(severity_raw, Severity.INFO),
            title=str(item.get("CheckTitle", "Prowler Check"))[:255],
            description=str(item.get("StatusExtended", ""))[:2000],
            commit_sha=commit_sha,
            repo_url=repo_url,
            asset=str(item.get("ResourceId", ""))[:500],
            raw_output=item,
            tier=2,
        )
