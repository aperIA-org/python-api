import structlog
import httpx

from core.config import settings
from core.exceptions import ScannerError
from domain.finding.entities import Finding
from domain.finding.value_objects import Severity, CVEId

logger = structlog.get_logger()

# TODO: validar com doc oficial — Wazuh REST API 4.x
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class WazuhScanner:
    def __init__(self) -> None:
        self._base_url = settings.WAZUH_BASE_URL.rstrip("/")
        self._token = self._authenticate()
        self._client = httpx.Client(
            headers={"Authorization": f"Bearer {self._token}"},
            verify=False,  # DEBT: configurar CA bundle em produção
            timeout=30.0,
        )

    def _authenticate(self) -> str:
        try:
            r = httpx.post(
                f"{self._base_url}/security/user/authenticate",
                auth=(settings.WAZUH_USERNAME, settings.WAZUH_PASSWORD),
                verify=False,
                timeout=10.0,
            )
            r.raise_for_status()
            return r.json()["data"]["token"]
        except httpx.HTTPError as exc:
            raise ScannerError(f"Wazuh autenticação falhou: {exc}") from exc

    def get_vulnerabilities(
        self, agent_id: str, commit_sha: str, repo_url: str
    ) -> list[Finding]:
        log = logger.bind(commit_sha=commit_sha, agent_id=agent_id)
        log.info("wazuh_scan_started")

        try:
            r = self._client.get(
                f"{self._base_url}/vulnerability/{agent_id}",
                params={"limit": 500, "severity": "critical,high,medium"},
            )
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise ScannerError(f"Wazuh API error: {exc}") from exc

        findings: list[Finding] = []
        for vuln in r.json().get("data", {}).get("affected_items", []):
            finding = self._to_finding(vuln, agent_id, commit_sha, repo_url)
            if finding:
                findings.append(finding)

        log.info("wazuh_scan_done", findings_count=len(findings))
        return findings

    def health_check(self) -> bool:
        try:
            r = self._client.get(f"{self._base_url}/")
            return r.status_code in (200, 401)
        except Exception:
            return False

    def _to_finding(
        self, vuln: dict, agent_id: str, commit_sha: str, repo_url: str
    ) -> Finding | None:
        try:
            severity_raw = str(vuln.get("severity", "low")).lower()
            severity = _SEVERITY_MAP.get(severity_raw, Severity.LOW)

            cve_id = None
            cve_raw = str(vuln.get("cve", ""))
            if cve_raw.startswith("CVE-"):
                try:
                    cve_id = CVEId(cve_raw)
                except ValueError:
                    pass

            return Finding(
                source="wazuh",
                severity=severity,
                title=str(vuln.get("name") or cve_raw or "Wazuh Finding")[:255],
                description=str(vuln.get("condition", ""))[:2000],
                cve_id=cve_id,
                asset=str(agent_id)[:255],
                raw_output=vuln,
                commit_sha=commit_sha,
                repo_url=repo_url,
            )
        except Exception as exc:
            logger.warning("wazuh_finding_build_error", error=str(exc))
            return None
