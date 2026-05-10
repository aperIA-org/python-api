import json
import subprocess
import time

import structlog

from core.exceptions import ScannerError, ScannerTimeoutError
from domain.finding.entities import Finding
from domain.finding.value_objects import Severity, CVEId

logger = structlog.get_logger()

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyScanner:
    TIMEOUT = 180

    def scan(self, target: str, commit_sha: str, repo_url: str) -> list[Finding]:
        """target: path de repo, imagem Docker ou arquivo IaC."""
        start = time.monotonic()
        try:
            result = subprocess.run(
                [
                    "trivy", target,
                    "--format", "json",
                    "--quiet",
                    "--exit-code", "0",
                ],
                capture_output=True,
                text=True,
                timeout=self.TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            raise ScannerTimeoutError(f"Trivy timeout após {self.TIMEOUT}s")
        except FileNotFoundError:
            raise ScannerError("trivy não encontrado no PATH")

        raw: dict = {}
        if result.stdout:
            try:
                raw = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                logger.warning("trivy_json_parse_error", error=str(exc))

        findings: list[Finding] = []
        for result_obj in raw.get("Results", []):
            for vuln in result_obj.get("Vulnerabilities", []) or []:
                findings.append(self._vuln_to_finding(vuln, result_obj, commit_sha, repo_url))
            for misc in result_obj.get("Misconfigurations", []) or []:
                findings.append(self._misc_to_finding(misc, result_obj, commit_sha, repo_url))

        logger.info(
            "trivy_scan_done",
            commit_sha=commit_sha,
            repo_url=repo_url,
            findings_count=len(findings),
            duration_ms=int((time.monotonic() - start) * 1000),
        )
        return findings

    def health_check(self) -> bool:
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _vuln_to_finding(
        self, vuln: dict, result_obj: dict, commit_sha: str, repo_url: str
    ) -> Finding:
        cve_raw = str(vuln.get("VulnerabilityID", ""))
        cve_id = None
        if cve_raw.startswith("CVE-"):
            try:
                cve_id = CVEId(cve_raw)
            except ValueError:
                pass

        return Finding(
            source="trivy",
            severity=_SEVERITY_MAP.get(
                str(vuln.get("Severity", "UNKNOWN")).upper(), Severity.INFO
            ),
            title=str(vuln.get("Title") or vuln.get("VulnerabilityID", "unknown"))[:255],
            description=str(vuln.get("Description", ""))[:2000],
            cve_id=cve_id,
            asset=str(result_obj.get("Target", ""))[:500] or None,
            raw_output={
                "vuln_id": cve_raw,
                "pkg": vuln.get("PkgName", ""),
                "severity": vuln.get("Severity", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
            },
            commit_sha=commit_sha,
            repo_url=repo_url,
        )

    def _misc_to_finding(
        self, misc: dict, result_obj: dict, commit_sha: str, repo_url: str
    ) -> Finding:
        return Finding(
            source="trivy",
            severity=_SEVERITY_MAP.get(
                str(misc.get("Severity", "UNKNOWN")).upper(), Severity.INFO
            ),
            title=str(misc.get("Title", "IaC Misconfiguration"))[:255],
            description=str(misc.get("Description", ""))[:2000],
            file_path=str(result_obj.get("Target", ""))[:500] or None,
            raw_output={
                "id": misc.get("ID", ""),
                "type": misc.get("Type", ""),
                "resolution": misc.get("Resolution", ""),
            },
            commit_sha=commit_sha,
            repo_url=repo_url,
        )
