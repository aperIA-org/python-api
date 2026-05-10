import structlog

from domain.remediation.entities import Remediation

logger = structlog.get_logger()


class SuggestPatchUseCase:
    """
    Entrega patches como GitHub code suggestions — NUNCA auto-apply.
    PR permanece bloqueado até aprovação humana.
    """

    def __init__(self, github_client) -> None:
        self.github = github_client

    async def execute(self, remediation: Remediation) -> list[int]:
        log = logger.bind(
            commit_sha=remediation.commit_sha,
            pr_number=remediation.pr_number,
            patches_count=len(remediation.patches),
        )
        log.info("patch_suggestion_started")
        # DEBT: implementar na Fase 3 com github_client real
        return []
