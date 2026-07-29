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
        user_id: UUID | None = None,
        repository_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Finding]:
        """Lista findings com filtros opcionais e paginação.

        ``user_id``/``repository_id`` restringem o resultado aos findings
        cujo ``commit_sha`` pertence a um scan job daquele usuário/repositório
        (escopo multi-tenant, via subquery em ``scan_jobs``).
        """
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
        user_id: UUID | None = None,
        repository_id: UUID | None = None,
    ) -> int:
        """Conta findings que atendem aos filtros opcionais informados.

        ``user_id``/``repository_id`` restringem a contagem ao escopo
        multi-tenant (via subquery em ``scan_jobs``), assim como em ``query``.
        """
        ...
