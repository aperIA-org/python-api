import structlog

from core.config import settings
from core.exceptions import SandboxViolationError
from infrastructure.intelligence.mitre_caldera_client import MitreCalderaClient

logger = structlog.get_logger()


class RunEmulationUseCase:
    """
    Dispara emulação de adversário no Caldera.
    CALDERA_SANDBOX_MODE=True é obrigatório — verificado aqui e no cliente.
    """

    def __init__(self, caldera: MitreCalderaClient | None = None) -> None:
        self.caldera = caldera or MitreCalderaClient()

    def execute(
        self,
        cti_data: dict,
        commit_sha: str,
        has_verified_secrets: bool = False,
    ) -> dict:
        if not settings.CALDERA_SANDBOX_MODE:
            raise SandboxViolationError(
                "Caldera só pode ser executado com CALDERA_SANDBOX_MODE=True"
            )

        ttp_ids = cti_data.get("techniques", [])
        log = logger.bind(commit_sha=commit_sha, ttp_count=len(ttp_ids))

        if not ttp_ids:
            log.info("caldera_skipped_no_ttps")
            return {
                "techniques_executed": 0,
                "techniques_successful": 0,
                "success_rate": 0.0,
                "ttps_used": [],
                "caldera_validated": False,
            }

        log.info("caldera_emulation_started")
        return self.caldera.run_emulation(
            ttp_ids=ttp_ids,
            commit_sha=commit_sha,
            has_verified_secrets=has_verified_secrets,
        )
