from uuid import UUID

import structlog

from domain.scan.repositories import ScanJobRepository
from core.exceptions import ScanJobNotFoundError

logger = structlog.get_logger()


class CancelScanUseCase:
    def __init__(self, repo: ScanJobRepository) -> None:
        self.repo = repo

    async def execute(self, scan_job_id: UUID) -> None:
        scan_job = await self.repo.get_by_id(scan_job_id)
        if not scan_job:
            raise ScanJobNotFoundError(f"ScanJob {scan_job_id} não encontrado")

        scan_job.cancel()
        await self.repo.update(scan_job)
        logger.bind(scan_id=str(scan_job_id)).info("scan_cancelled")
