import structlog
import httpx

from core.config import settings
from core.exceptions import SandboxViolationError

logger = structlog.get_logger()

# TODO: validar com doc oficial — Caldera REST API 5.x


class MitreCalderaClient:
    def __init__(self) -> None:
        if not settings.CALDERA_SANDBOX_MODE:
            raise SandboxViolationError(
                "Caldera só pode ser instanciado com CALDERA_SANDBOX_MODE=True"
            )
        self._client = httpx.AsyncClient(
            base_url=settings.CALDERA_URL,
            headers={"KEY": settings.CALDERA_API_KEY},
            timeout=httpx.Timeout(60.0, connect=5.0),
        )

    async def run_operation(self, ttp_ids: list[str], commit_sha: str) -> dict:
        if not settings.CALDERA_SANDBOX_MODE:
            raise SandboxViolationError("CALDERA_SANDBOX_MODE must be True")

        logger.bind(commit_sha=commit_sha, ttps=ttp_ids).info("caldera_operation_started")
        # DEBT: implementar criação de operação + polling de status na Fase 2
        return {"success_rate": 0.0, "techniques_executed": []}
