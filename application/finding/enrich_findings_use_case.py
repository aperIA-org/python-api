import structlog

from domain.finding.entities import Finding

logger = structlog.get_logger()


class EnrichFindingsUseCase:
    """Enriquece findings com dados de CTI do OpenCTI (TTPs MITRE, campanhas ativas)."""

    def __init__(self, opencti_client) -> None:
        self.opencti = opencti_client

    async def execute(self, findings: list[Finding], commit_sha: str) -> dict:
        log = logger.bind(commit_sha=commit_sha, findings_count=len(findings))
        # DEBT: implementar na Fase 2 com opencti_client
        log.info("enrichment_started")
        return {}
