from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from domain.scan.entities import ScanJob, ScanStatus
from domain.scan.repositories import ScanJobRepository
from infrastructure.persistence.models.scan_model import ScanJobModel


class SQLAlchemyScanRepository(ScanJobRepository):
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def save(self, scan_job: ScanJob) -> None:
        model = ScanJobModel.from_entity(scan_job)
        self.db.add(model)

    async def update(self, scan_job: ScanJob) -> None:
        result = await self.db.execute(
            select(ScanJobModel).where(ScanJobModel.id == scan_job.id)
        )
        model = result.scalar_one_or_none()
        if model:
            model.status = scan_job.status.value
            model.error_message = scan_job.error_message
            model.findings_count = scan_job.findings_count
            model.risk_score = scan_job.risk_score
            model.started_at = scan_job.started_at
            model.completed_at = scan_job.completed_at

    async def get_by_id(self, scan_job_id: UUID) -> ScanJob | None:
        result = await self.db.execute(
            select(ScanJobModel).where(ScanJobModel.id == scan_job_id)
        )
        model = result.scalar_one_or_none()
        return model.to_entity() if model else None

    async def get_by_commit(self, commit_sha: str) -> ScanJob | None:
        result = await self.db.execute(
            select(ScanJobModel).where(ScanJobModel.commit_sha == commit_sha)
        )
        model = result.scalar_one_or_none()
        return model.to_entity() if model else None

    async def get_running_scans(self) -> list[ScanJob]:
        result = await self.db.execute(
            select(ScanJobModel).where(ScanJobModel.status == ScanStatus.RUNNING.value)
        )
        return [m.to_entity() for m in result.scalars().all()]
