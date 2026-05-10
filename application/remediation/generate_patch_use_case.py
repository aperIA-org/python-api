import structlog

from domain.finding.entities import Finding, AttackPath

logger = structlog.get_logger()


class GeneratePatchUseCase:
    """Usa Claude (via LLM Guard) para gerar patches para os findings."""

    def __init__(self, claude_client) -> None:
        self.claude = claude_client

    async def execute(
        self,
        findings: list[Finding],
        attack_path: AttackPath,
        commit_sha: str,
    ) -> list[dict]:
        log = logger.bind(commit_sha=commit_sha, findings_count=len(findings))
        log.info("patch_generation_started")
        # DEBT: implementar na Fase 3 com claude_client real
        return []
