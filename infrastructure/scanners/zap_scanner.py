import time

import httpx
import structlog

from core.config import settings
from core.exceptions import ScannerError, ScannerTimeoutError
from domain.finding.entities import Finding
from domain.finding.value_objects import Severity

logger = structlog.get_logger()

_RISK_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}

_POLL_INTERVAL = 10
_SPIDER_TIMEOUT = 300
_ASCAN_TIMEOUT = 600


class ZAPScanner:
    def __init__(self) -> None:
        self._zap_url = settings.ZAP_BASE_URL.rstrip("/")
        self._api_key = settings.ZAP_API_KEY
        self._client = httpx.Client(timeout=30.0)

    def scan(self, target_url: str, commit_sha: str, repo_url: str) -> list[Finding]:
        start = time.monotonic()
        log = logger.bind(commit_sha=commit_sha, target_url=target_url)
        log.info("zap_scan_started")

        try:
            self._spider(target_url)
            self._active_scan(target_url)
            findings = self._collect_alerts(target_url, commit_sha, repo_url)
        except httpx.HTTPError as exc:
            raise ScannerError(f"ZAP API error: {exc}") from exc

        log.info(
            "zap_scan_done",
            repo_url=repo_url,
            findings_count=len(findings),
            duration_ms=int((time.monotonic() - start) * 1000),
        )
        return findings

    def health_check(self) -> bool:
        try:
            r = self._client.get(
                f"{self._zap_url}/JSON/core/view/version/",
                params={"apikey": self._api_key},
                timeout=5.0,
            )
            return r.status_code == 200
        except Exception:
            return False

    def _spider(self, target_url: str) -> None:
        r = self._client.get(
            f"{self._zap_url}/JSON/spider/action/scan/",
            params={"url": target_url, "apikey": self._api_key},
        )
        r.raise_for_status()
        scan_id = r.json()["scan"]
        self._poll_status(
            f"{self._zap_url}/JSON/spider/view/status/",
            scan_id,
            label="spider",
            max_wait=_SPIDER_TIMEOUT,
        )

    def _active_scan(self, target_url: str) -> None:
        r = self._client.get(
            f"{self._zap_url}/JSON/ascan/action/scan/",
            params={"url": target_url, "apikey": self._api_key},
        )
        r.raise_for_status()
        scan_id = r.json()["scan"]
        self._poll_status(
            f"{self._zap_url}/JSON/ascan/view/status/",
            scan_id,
            label="ascan",
            max_wait=_ASCAN_TIMEOUT,
        )

    def _poll_status(self, url: str, scan_id: str, label: str, max_wait: int) -> None:
        elapsed = 0
        while elapsed < max_wait:
            r = self._client.get(
                url,
                params={"scanId": scan_id, "apikey": self._api_key},
            )
            if int(r.json().get("status", 0)) >= 100:
                return
            time.sleep(_POLL_INTERVAL)
            elapsed += _POLL_INTERVAL
        raise ScannerTimeoutError(f"ZAP {label} não finalizou em {max_wait}s")

    def _collect_alerts(
        self, target_url: str, commit_sha: str, repo_url: str
    ) -> list[Finding]:
        r = self._client.get(
            f"{self._zap_url}/JSON/alert/view/alerts/",
            params={"baseurl": target_url, "apikey": self._api_key},
        )
        r.raise_for_status()
        return [
            Finding(
                source="zap",
                severity=_RISK_MAP.get(
                    str(alert.get("risk", "Low")), Severity.LOW
                ),
                title=str(alert.get("name", "ZAP Alert"))[:255],
                description=str(alert.get("description", ""))[:2000],
                asset=str(alert.get("url", ""))[:500] or None,
                raw_output={
                    "alert_ref": alert.get("alertRef", ""),
                    "url": str(alert.get("url", ""))[:500],
                    "solution": str(alert.get("solution", ""))[:1000],
                },
                commit_sha=commit_sha,
                repo_url=repo_url,
            )
            for alert in r.json().get("alerts", [])
        ]
