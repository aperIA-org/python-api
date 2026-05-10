import structlog

from domain.finding.entities import Finding
from domain.finding.repositories import FindingRepository
from domain.finding.services import FindingDeduplicator

logger = structlog.get_logger()


class NormalizeFindingsUseCase:
    def __init__(self, repo: FindingRepository, deduplicator: FindingDeduplicator) -> None:
        self.repo = repo
        self.deduplicator = deduplicator

    async def execute(self, raw_findings: list[Finding]) -> list[Finding]:
        log = logger.bind(
            raw_count=len(raw_findings),
            commit_sha=raw_findings[0].commit_sha if raw_findings else "",
        )
        deduplicated = self.deduplicator.deduplicate(raw_findings)
        await self.repo.bulk_save(deduplicated)
        log.info("findings_normalized", deduplicated_count=len(deduplicated))
        return deduplicated
