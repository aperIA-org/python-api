from abc import ABC, abstractmethod
from uuid import UUID

from domain.scan.entities import ScanJob, ScanResult


class ScanJobRepository(ABC):
    @abstractmethod
    async def save(self, scan_job: ScanJob) -> None: ...

    @abstractmethod
    async def update(self, scan_job: ScanJob) -> None: ...

    @abstractmethod
    async def get_by_id(self, scan_job_id: UUID) -> ScanJob | None: ...

    @abstractmethod
    async def get_by_commit(self, commit_sha: str) -> ScanJob | None: ...

    @abstractmethod
    async def get_running_scans(self) -> list[ScanJob]: ...

    @abstractmethod
    async def list_recent(self, limit: int = 20) -> list[ScanJob]: ...


class ScanResultRepository(ABC):
    @abstractmethod
    async def save(self, result: ScanResult) -> None: ...

    @abstractmethod
    async def get_by_scan_job(self, scan_job_id: UUID) -> list[ScanResult]: ...
