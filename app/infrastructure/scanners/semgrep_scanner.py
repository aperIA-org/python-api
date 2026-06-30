import json
import subprocess

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity, CVEId
from app.infrastructure.scanners.base_scanner import BaseScanner


class SemgrepScanner(BaseScanner):
    TIMEOUT = 180

    def scan(
        self,
        repo_path: str,
        changed_files: list[str],
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        return self.scan_changed(repo_path, changed_files, commit_sha, repo_url)

    def scan_changed(
        self,
        repo_path: str,
        changed_files: list[str],
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        if not changed_files:
            return []
        result = subprocess.run(
            ["semgrep", "--config=p/security-audit", "--json", "--quiet"]
            + changed_files,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=self.TIMEOUT,
        )
        raw = json.loads(result.stdout) if result.stdout else {"results": []}
        return [
            self._to_finding(r, commit_sha, repo_url, tier=1)
            for r in raw.get("results", [])
        ]

    def scan_expanded(
        self,
        repo_path: str,
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        result = subprocess.run(
            ["semgrep", "--config=auto", "--json", "--quiet", "."],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=300,
        )
        raw = json.loads(result.stdout) if result.stdout else {"results": []}
        return [
            self._to_finding(r, commit_sha, repo_url, tier=2)
            for r in raw.get("results", [])
        ]

    def _to_finding(
        self, r: dict, commit_sha: str, repo_url: str, tier: int
    ) -> Finding:
        severity_map = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        extra = r.get("extra", {})
        metadata = extra.get("metadata", {})
        cve_raw = metadata.get("cve")
        return Finding(
            source="semgrep",
            severity=severity_map.get(extra.get("severity", "INFO"), Severity.INFO),
            title=r.get("check_id", "unknown"),
            description=extra.get("message", ""),
            commit_sha=commit_sha,
            repo_url=repo_url,
            cve_id=CVEId(cve_raw) if cve_raw else None,
            cwe_id=metadata.get("cwe"),
            file_path=r.get("path"),
            line_number=r.get("start", {}).get("line"),
            raw_output=r,
            tier=tier,
        )
