import time

import structlog

from core.config import settings
from core.exceptions import ScannerError, ScannerTimeoutError
from domain.finding.entities import Finding
from domain.finding.value_objects import Severity, CVEId

logger = structlog.get_logger()

FULL_FAST_SCAN_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"
_POLL_INTERVAL = 15
_TIMEOUT_POLL = 900


class OpenVASScanner:
    def __init__(self) -> None:
        self.host = settings.OPENVAS_HOST
        self.port = settings.OPENVAS_PORT
        self._username = settings.OPENVAS_USERNAME
        self._password = settings.OPENVAS_PASSWORD

    def scan(self, target_ip: str, commit_sha: str, repo_url: str) -> list[Finding]:
        log = logger.bind(commit_sha=commit_sha, target_ip=target_ip)
        log.info("openvas_scan_started")

        try:
            from gvm.connections import TLSConnection
            from gvm.protocols.gmp import Gmp
        except ImportError:
            raise ScannerError("python-gvm não instalado — adicionar ao requirements.txt")

        try:
            with Gmp(TLSConnection(hostname=self.host, port=self.port)) as gmp:
                gmp.authenticate(self._username, self._password)
                target_id = self._create_target(gmp, target_ip, commit_sha)
                task_id = self._create_task(gmp, target_id, commit_sha)
                gmp.start_task(task_id)
                self._wait_for_task(gmp, task_id)
                results = gmp.get_results(task_id=task_id)
                findings = self._parse_results(results, commit_sha, repo_url)
        except Exception as exc:
            if isinstance(exc, (ScannerError, ScannerTimeoutError)):
                raise
            raise ScannerError(f"OpenVAS error: {exc}") from exc

        log.info("openvas_scan_done", findings_count=len(findings))
        return findings

    def health_check(self) -> bool:
        try:
            from gvm.connections import TLSConnection
            from gvm.protocols.gmp import Gmp
            with Gmp(TLSConnection(hostname=self.host, port=self.port)) as gmp:
                gmp.get_version()
            return True
        except Exception:
            return False

    def _create_target(self, gmp, target_ip: str, commit_sha: str) -> str:
        resp = gmp.create_target(
            name=f"aperia-{commit_sha[:8]}-{target_ip}",
            hosts=target_ip,
        )
        return resp.get("id")

    def _create_task(self, gmp, target_id: str, commit_sha: str) -> str:
        resp = gmp.create_task(
            name=f"aperia-scan-{commit_sha[:8]}",
            config_id=FULL_FAST_SCAN_CONFIG,
            target_id=target_id,
        )
        return resp.get("id")

    def _wait_for_task(self, gmp, task_id: str) -> None:
        for _ in range(_TIMEOUT_POLL // _POLL_INTERVAL):
            task = gmp.get_task(task_id=task_id)
            status_nodes = task.xpath("//status/text()")
            if status_nodes and status_nodes[0] == "Done":
                return
            time.sleep(_POLL_INTERVAL)
        raise ScannerTimeoutError(f"OpenVAS task {task_id} não finalizou em {_TIMEOUT_POLL}s")

    def _parse_results(self, results, commit_sha: str, repo_url: str) -> list[Finding]:
        findings: list[Finding] = []
        for r in results.xpath("//result"):
            severity_score_raw = r.findtext("severity") or "0"
            try:
                severity_score = float(severity_score_raw)
            except ValueError:
                severity_score = 0.0

            cve_id = None
            cve_text = r.findtext(".//ref[@type='cve']/@id")
            if cve_text:
                try:
                    cve_id = CVEId(cve_text)
                except ValueError:
                    pass

            findings.append(
                Finding(
                    source="openvas",
                    severity=Severity.from_cvss(severity_score),
                    title=str(r.findtext("name") or "OpenVAS Finding")[:255],
                    description=str(r.findtext("description") or "")[:2000],
                    cve_id=cve_id,
                    asset=str(r.findtext("host") or "")[:255] or None,
                    raw_output={
                        "nvt_oid": r.findtext("nvt/@oid"),
                        "severity": severity_score,
                    },
                    commit_sha=commit_sha,
                    repo_url=repo_url,
                )
            )
        return findings
