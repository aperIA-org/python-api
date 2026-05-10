import structlog
import httpx

from domain.finding.entities import Finding
from domain.finding.value_objects import Severity
from core.config import settings
from core.exceptions import ScannerError

logger = structlog.get_logger()

# TODO: validar com doc oficial — Wazuh REST API 4.x


class WazuhScanner:
    def __init__(self) -> None:
        self._token: str | None = None
        self._client = httpx.AsyncClient(
            base_url=settings.WAZUH_BASE_URL,
            verify=False,  # DEBT: habilitar verify=True com cert bundle em produção
            timeout=httpx.Timeout(30.0, connect=5.0),
        )

    async def get_vulnerabilities(self, commit_sha: str, repo_url: str) -> list[Finding]:
        logger.bind(commit_sha=commit_sha).info("wazuh_scan_started")
        # DEBT: implementar autenticação JWT + query vulnerabilities na Fase 2
        return []
