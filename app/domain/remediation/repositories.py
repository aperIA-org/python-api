from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.remediation.entities import Remediation, RemediationStatus


class RemediationRepository(ABC):
    @abstractmethod
    async def save(self, remediation: Remediation) -> None: ...

    @abstractmethod
    async def get_by_scan_job(self, scan_job_id: UUID) -> list[Remediation]: ...

    @abstractmethod
    async def update_status(
        self,
        remediation_id: UUID,
        status: RemediationStatus,
        approved_by: str | None = None,
    ) -> None: ...
