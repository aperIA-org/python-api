from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.remediation.entities import (
    Remediation,
    RemediationComContexto,
    RemediationStatus,
)


class RemediationRepository(ABC):
    @abstractmethod
    def save(self, remediation: Remediation) -> None: ...

    @abstractmethod
    def get_by_scan_job(self, scan_job_id: UUID) -> list[Remediation]: ...

    @abstractmethod
    def get_by_id(self, remediation_id: UUID) -> Remediation | None: ...

    @abstractmethod
    def query(
        self,
        *,
        user_id: UUID,
        remediation_id: UUID | None = None,
        scan_job_id: UUID | None = None,
        status: RemediationStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[RemediationComContexto]: ...

    @abstractmethod
    def count(
        self,
        *,
        user_id: UUID,
        scan_job_id: UUID | None = None,
        status: RemediationStatus | None = None,
    ) -> int: ...
