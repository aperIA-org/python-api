from abc import ABC, abstractmethod
from uuid import UUID

from domain.remediation.entities import Remediation


class RemediationRepository(ABC):
    @abstractmethod
    async def save(self, remediation: Remediation) -> None: ...

    @abstractmethod
    async def update(self, remediation: Remediation) -> None: ...

    @abstractmethod
    async def get_by_id(self, remediation_id: UUID) -> Remediation | None: ...

    @abstractmethod
    async def get_by_scan_job(self, scan_job_id: UUID) -> Remediation | None: ...

    @abstractmethod
    async def get_pending(self) -> list[Remediation]: ...
