import structlog
import httpx

from domain.finding.entities import Finding
from domain.finding.value_objects import Severity
from core.config import settings
from core.exceptions import ScannerError

logger = structlog.get_logger()

# TODO: validar com doc oficial — ZAP REST API 2.x
_RISK_MAP = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}


class ZAPScanner:
    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=settings.ZAP_BASE_URL,
            params={"apikey": settings.ZAP_API_KEY},
            timeout=httpx.Timeout(30.0, connect=5.0),
        )

    async def scan(self, target_url: str, commit_sha: str, repo_url: str) -> list[Finding]:
        log = logger.bind(commit_sha=commit_sha, target_url=target_url)
        log.info("zap_scan_started")
        # DEBT: implementar spider + active scan full na Fase 2
        return []

    async def get_alerts(self, commit_sha: str, repo_url: str) -> list[Finding]:
        try:
            response = await self._client.get("/JSON/alert/view/alerts/")
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as exc:
            raise ScannerError(f"ZAP API error: {exc}") from exc

        findings = []
        for alert in data.get("alerts", []):
            finding = self._build_finding(alert, commit_sha, repo_url)
            if finding:
                findings.append(finding)
        return findings

    def _build_finding(self, alert: dict, commit_sha: str, repo_url: str) -> Finding | None:
        try:
            risk = str(alert.get("riskcode", "0"))
            severity = _RISK_MAP.get(risk, Severity.INFO)
            return Finding(
                source="zap",
                severity=severity,
                title=str(alert.get("name", "Unknown ZAP Alert"))[:300],
                description=str(alert.get("description", ""))[:2000],
                commit_sha=commit_sha,
                repo_url=repo_url,
                raw_output={
                    "alert_id": alert.get("alertRef", ""),
                    "url": str(alert.get("url", ""))[:500],
                    "solution": str(alert.get("solution", ""))[:1000],
                },
            )
        except Exception:
            return None
