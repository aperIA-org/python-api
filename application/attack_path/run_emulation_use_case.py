import structlog

from core.config import settings
from core.exceptions import SandboxViolationError

logger = structlog.get_logger()


class RunEmulationUseCase:
    """Dispara emulação de adversário no Caldera. Exige sandbox obrigatório."""

    def __init__(self, caldera_client) -> None:
        self.caldera = caldera_client

    async def execute(self, ttp_ids: list[str], commit_sha: str) -> dict:
        if not settings.CALDERA_SANDBOX_MODE:
            raise SandboxViolationError(
                "Caldera só pode ser executado com CALDERA_SANDBOX_MODE=True"
            )
        log = logger.bind(commit_sha=commit_sha, ttps=ttp_ids)
        log.info("caldera_emulation_started")
        # DEBT: implementar na Fase 2 com caldera_client real
        return {}
