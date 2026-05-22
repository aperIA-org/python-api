"""ZAP — DAST ativo via REST API.

Pipeline:
    spider(target_url) → ativa o crawler do ZAP para mapear endpoints
    active_scan(target_url) → envia payloads reais (SQLi, XSS, CSRF, …)
    collect_alerts(target_url) → coleta findings e normaliza para ``Finding``

Por que ativo, não passivo: passivo só analisa tráfego capturado;
para um ASPM precisamos de evidência de exploração, então payloads
reais via active scan são obrigatórios.

Sandbox/preview: o ``target_url`` precisa apontar para um deploy
acessível (ex: preview do Render/Railway, container efêmero). Se não
houver target válido, ``run_safe()`` do ``BaseScanner`` absorve a
falha e retorna ``[]`` — pipeline continua.

``poll_interval`` e ``max_wait`` são configuráveis para testes
(``poll_interval=0`` evita ``time.sleep`` real).
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from app.config import settings
from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.base_scanner import BaseScanner

logger = structlog.get_logger()


_RISK_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}


class ZAPScanner(BaseScanner):
    TIMEOUT = 600  # 10 min — DAST é lento

    def __init__(
        self,
        zap_url: str | None = None,
        api_key: str | None = None,
        poll_interval: int = 10,
        max_wait: int = 600,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.zap_url = (zap_url or settings.ZAP_BASE_URL).rstrip("/")
        self.api_key = api_key or settings.ZAP_API_KEY
        self.poll_interval = poll_interval
        self.max_wait = max_wait
        self.client = http_client or httpx.Client(timeout=30.0)

    def scan(
        self,
        target_url: str,
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        self._spider(target_url)
        self._active_scan(target_url)
        return self._collect_alerts(target_url, commit_sha, repo_url)

    # ----- spider / active scan -----

    def _spider(self, target_url: str) -> None:
        resp = self.client.get(
            f"{self.zap_url}/JSON/spider/action/scan/",
            params={"url": target_url, "apikey": self.api_key},
        )
        resp.raise_for_status()
        scan_id = resp.json()["scan"]
        self._poll_status(
            f"{self.zap_url}/JSON/spider/view/status/",
            scan_id,
            label="spider",
        )

    def _active_scan(self, target_url: str) -> None:
        resp = self.client.get(
            f"{self.zap_url}/JSON/ascan/action/scan/",
            params={"url": target_url, "apikey": self.api_key},
        )
        resp.raise_for_status()
        scan_id = resp.json()["scan"]
        self._poll_status(
            f"{self.zap_url}/JSON/ascan/view/status/",
            scan_id,
            label="ascan",
        )

    def _poll_status(self, url: str, scan_id: str, label: str) -> None:
        elapsed = 0
        while elapsed < self.max_wait:
            resp = self.client.get(
                url, params={"scanId": scan_id, "apikey": self.api_key}
            )
            try:
                status = int(resp.json().get("status", 0))
            except (ValueError, TypeError):
                status = 0
            if status >= 100:
                return
            # poll_interval=0 desativa o sleep (útil em testes)
            if self.poll_interval > 0:
                time.sleep(self.poll_interval)
            elapsed += max(self.poll_interval, 1)
        raise TimeoutError(f"ZAP {label} não finalizou em {self.max_wait}s")

    # ----- alerts -----

    def _collect_alerts(
        self,
        target_url: str,
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        resp = self.client.get(
            f"{self.zap_url}/JSON/alert/view/alerts/",
            params={"baseurl": target_url, "apikey": self.api_key},
        )
        resp.raise_for_status()
        alerts: list[dict[str, Any]] = resp.json().get("alerts", []) or []
        findings: list[Finding] = []
        for alert in alerts:
            findings.append(self._to_finding(alert, commit_sha, repo_url))
        logger.info(
            "zap_alerts_collected",
            commit_sha=commit_sha,
            target_url=target_url,
            alerts_count=len(findings),
        )
        return findings

    def _to_finding(
        self,
        alert: dict[str, Any],
        commit_sha: str,
        repo_url: str,
    ) -> Finding:
        risk = alert.get("risk", "Low")
        return Finding(
            source="zap",
            severity=_RISK_MAP.get(risk, Severity.LOW),
            title=str(alert.get("name", "ZAP Alert"))[:255],
            description=str(alert.get("description", ""))[:2000],
            commit_sha=commit_sha,
            repo_url=repo_url,
            asset=str(alert.get("url", ""))[:500],
            cwe_id=str(alert.get("cweid")) if alert.get("cweid") else None,
            raw_output=alert,
            tier=3,
        )
