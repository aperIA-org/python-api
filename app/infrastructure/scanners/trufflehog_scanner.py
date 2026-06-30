import json
import subprocess

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.base_scanner import BaseScanner


class TruffleHogScanner(BaseScanner):
    TIMEOUT = 120

    def scan(
        self,
        repo_path: str,
        base_sha: str,
        head_sha: str,
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        result = subprocess.run(
            [
                "trufflehog",
                "git",
                f"file://{repo_path}",
                "--since-commit",
                base_sha,
                "--branch",
                head_sha,
                "--only-verified",
                "--json",
                "--no-update",
            ],
            capture_output=True,
            text=True,
            timeout=self.TIMEOUT,
        )
        findings: list[Finding] = []
        for line in result.stdout.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("Verified"):
                findings.append(self._to_finding(item, commit_sha, repo_url))
        return findings

    def _to_finding(self, item: dict, commit_sha: str, repo_url: str) -> Finding:
        git_meta = (
            item.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
        )
        return Finding(
            source="trufflehog",
            severity=Severity.CRITICAL,
            title=f"Secret verificado: {item.get('DetectorName', 'unknown')}",
            description=item.get("Raw", ""),
            commit_sha=commit_sha,
            repo_url=repo_url,
            file_path=git_meta.get("file"),
            line_number=git_meta.get("line"),
            secret_verified=True,
            secret_type=item.get("DetectorName"),
            raw_output=item,
            tier=1,
        )
