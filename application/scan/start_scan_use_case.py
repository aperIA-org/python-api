import structlog

from domain.scan.entities import ScanJob
from domain.scan.repositories import ScanJobRepository
from core.exceptions import DuplicateScanError

logger = structlog.get_logger()


class StartScanUseCase:
    def __init__(self, repo: ScanJobRepository) -> None:
        self.repo = repo

    async def execute(
        self,
        commit_sha: str,
        repo_url: str,
        pr_number: int | None = None,
        installation_id: int | None = None,
    ) -> ScanJob:
        log = logger.bind(commit_sha=commit_sha, repo_url=repo_url)

        existing = await self.repo.get_by_commit(commit_sha)
        if existing and existing.status.value in ("pending", "running"):
            log.warning("scan_already_running", scan_id=str(existing.id))
            raise DuplicateScanError(f"Scan já em execução para commit {commit_sha}")

        scan_job = ScanJob(
            commit_sha=commit_sha,
            repo_url=repo_url,
            pr_number=pr_number,
            installation_id=installation_id,
        )
        await self.repo.save(scan_job)
        log.info("scan_job_created", scan_id=str(scan_job.id))
        return scan_job
