from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.scan.entities import ScanJob
from app.domain.scan.value_objects import TierStatus, ScanTier


class ScanJobRepository(ABC):
    @abstractmethod
    async def save(self, job: ScanJob) -> None: ...

    @abstractmethod
    async def get_by_id(self, job_id: UUID) -> ScanJob | None: ...

    @abstractmethod
    async def get_by_commit(self, commit_sha: str) -> ScanJob | None: ...

    @abstractmethod
    async def update_tier_status(
        self, job_id: UUID, tier: ScanTier, status: TierStatus
    ) -> None: ...

    @abstractmethod
    async def set_blocked(self, job_id: UUID, blocked_at: ScanTier) -> None: ...
