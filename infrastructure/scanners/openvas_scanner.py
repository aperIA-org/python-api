import structlog

from domain.finding.entities import Finding
from core.config import settings

logger = structlog.get_logger()

# TODO: validar com doc oficial — GMP (Greenbone Management Protocol) XML API
# DEBT: implementar cliente GMP completo na Fase 2


class OpenVASScanner:
    def __init__(self) -> None:
        self.host = settings.OPENVAS_HOST
        self.port = settings.OPENVAS_PORT

    async def scan(self, target_host: str, commit_sha: str, repo_url: str) -> list[Finding]:
        logger.bind(commit_sha=commit_sha, target_host=target_host).info("openvas_scan_started")
        # DEBT: implementar GMP scan + parse XML na Fase 2
        return []
