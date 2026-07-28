from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.finding.entities import Finding


class FindingRepository(ABC):
    @abstractmethod
    def save(self, finding: Finding) -> None: ...

    @abstractmethod
    def bulk_save(self, findings: list[Finding]) -> None: ...

    @abstractmethod
    def get_by_commit(self, commit_sha: str) -> list[Finding]: ...

    @abstractmethod
    def get_verified_secrets(self, commit_sha: str) -> list[Finding]: ...

    @abstractmethod
    def find_duplicate(self, dedup_key: str) -> Finding | None: ...

    @abstractmethod
    def get_by_id(self, finding_id: UUID) -> Finding | None:
        """Busca um finding pelo seu identificador único."""
        ...

    @abstractmethod
    def query(
        self,
        *,
        commit_sha: str | None = None,
        severity: str | None = None,
        tier: int | None = None,
        source: str | None = None,
        secret_verified: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Finding]:
        """Lista findings com filtros opcionais e paginação."""
        ...

    @abstractmethod
    def count(
        self,
        *,
        commit_sha: str | None = None,
        severity: str | None = None,
        tier: int | None = None,
        source: str | None = None,
        secret_verified: bool | None = None,
    ) -> int:
        """Conta findings que atendem aos filtros opcionais informados."""
        ...
