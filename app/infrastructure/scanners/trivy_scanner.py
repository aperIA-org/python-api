import json
import subprocess

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import CVEId, Severity
from app.infrastructure.scanners.base_scanner import BaseScanner


SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyScanner(BaseScanner):
    TIMEOUT = 180

    def scan(
        self,
        target: str,
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        result = subprocess.run(
            ["trivy", target, "--format", "json", "--quiet", "--exit-code", "0"],
            capture_output=True,
            text=True,
            timeout=self.TIMEOUT,
        )
        raw = json.loads(result.stdout) if result.stdout else {}
        findings: list[Finding] = []
        for result_obj in raw.get("Results", []) or []:
            for vuln in result_obj.get("Vulnerabilities", []) or []:
                findings.append(
                    self._vuln_to_finding(vuln, result_obj, commit_sha, repo_url)
                )
            for misc in result_obj.get("Misconfigurations", []) or []:
                findings.append(
                    self._misc_to_finding(misc, result_obj, commit_sha, repo_url)
                )
        return findings

    def _vuln_to_finding(
        self,
        vuln: dict,
        result_obj: dict,
        commit_sha: str,
        repo_url: str,
    ) -> Finding:
        cve_raw = vuln.get("VulnerabilityID", "") or ""
        cve_id: CVEId | None = None
        if cve_raw.startswith("CVE-"):
            try:
                cve_id = CVEId(cve_raw)
            except ValueError:
                cve_id = None
        return Finding(
            source="trivy",
            severity=SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), Severity.INFO),
            title=str(vuln.get("Title", vuln.get("VulnerabilityID", "unknown")))[:255],
            description=str(vuln.get("Description", ""))[:2000],
            commit_sha=commit_sha,
            repo_url=repo_url,
            cve_id=cve_id,
            asset=str(result_obj.get("Target", ""))[:500],
            raw_output=vuln,
            tier=2,
        )

    def _misc_to_finding(
        self,
        misc: dict,
        result_obj: dict,
        commit_sha: str,
        repo_url: str,
    ) -> Finding:
        return Finding(
            source="trivy",
            severity=SEVERITY_MAP.get(misc.get("Severity", "UNKNOWN"), Severity.INFO),
            title=str(misc.get("Title", "IaC Misconfiguration"))[:255],
            description=str(misc.get("Description", ""))[:2000],
            commit_sha=commit_sha,
            repo_url=repo_url,
            file_path=str(result_obj.get("Target", ""))[:500],
            raw_output=misc,
            tier=2,
        )
