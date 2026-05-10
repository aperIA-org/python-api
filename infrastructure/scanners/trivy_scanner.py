import json
import subprocess
from pathlib import Path

import structlog

from domain.finding.entities import Finding
from domain.finding.value_objects import Severity, CVEId
from core.exceptions import ScannerError, ScannerTimeoutError

logger = structlog.get_logger()

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyScanner:
    TIMEOUT_SECONDS = 180

    def scan(self, repo_path: str, commit_sha: str, repo_url: str) -> list[Finding]:
        safe_path = self._validate_repo_path(repo_path)
        log = logger.bind(commit_sha=commit_sha, repo_url=repo_url)
        log.info("trivy_scan_started")

        try:
            result = subprocess.run(
                [
                    "trivy", "fs",
                    "--format", "json",
                    "--quiet",
                    str(safe_path),
                ],
                capture_output=True,
                text=True,
                timeout=self.TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            raise ScannerTimeoutError(f"Trivy timeout após {self.TIMEOUT_SECONDS}s")
        except FileNotFoundError:
            raise ScannerError("trivy não encontrado — instale o CLI")

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            log.warning("trivy_parse_error", error=str(exc))
            return []

        findings: list[Finding] = []
        for report in data.get("Results", []):
            target = str(report.get("Target", ""))[:500]
            for vuln in report.get("Vulnerabilities", []) or []:
                finding = self._build_finding(vuln, target, commit_sha, repo_url, log)
                if finding:
                    findings.append(finding)

        log.info("trivy_scan_completed", findings_count=len(findings))
        return findings

    def _validate_repo_path(self, repo_path: str) -> Path:
        path = Path(repo_path).resolve()
        if not path.exists() or not path.is_dir():
            raise ValueError(f"Repo path inválido: {repo_path}")
        return path

    def _build_finding(
        self, vuln: dict, target: str, commit_sha: str, repo_url: str, log
    ) -> Finding | None:
        # TODO: validar com doc oficial — formato baseado em trivy OSS 0.55+
        try:
            vuln_id = str(vuln.get("VulnerabilityID", ""))[:50]
            title = str(vuln.get("Title", vuln_id))[:300]
            description = str(vuln.get("Description", ""))[:2000]
            severity_raw = str(vuln.get("Severity", "UNKNOWN")).upper()
            severity = _SEVERITY_MAP.get(severity_raw, Severity.INFO)
            pkg_name = str(vuln.get("PkgName", ""))[:200]

            cve = None
            if vuln_id.startswith("CVE-"):
                try:
                    cve = CVEId(vuln_id)
                except ValueError:
                    cve = None

            return Finding(
                source="trivy",
                severity=severity,
                title=title or vuln_id,
                description=description,
                commit_sha=commit_sha,
                repo_url=repo_url,
                file_path=target if target else None,
                cve_id=cve,
                asset=pkg_name if pkg_name else None,
                raw_output={
                    "vuln_id": vuln_id,
                    "pkg": pkg_name,
                    "severity": severity_raw,
                    "fixed_version": vuln.get("FixedVersion", ""),
                },
            )
        except Exception as exc:
            log.warning("trivy_finding_build_error", error=str(exc))
            return None
