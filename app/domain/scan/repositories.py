from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.scan.entities import ScanJob
from app.domain.scan.value_objects import TierStatus, ScanTier


class ScanJobRepository(ABC):
    """Interface síncrona de persistência para ``ScanJob``."""

    @abstractmethod
    def save(self, job: ScanJob) -> None:
        """Persiste um novo scan job de forma idempotente por ``commit_sha``."""
        ...

    @abstractmethod
    def get_by_id(self, job_id: UUID) -> ScanJob | None:
        """Busca um scan job pelo seu identificador único."""
        ...

    @abstractmethod
    def get_by_commit(self, commit_sha: str) -> ScanJob | None:
        """Busca um scan job pelo commit SHA (chave natural do pipeline)."""
        ...

    @abstractmethod
    def update_tier_status(
        self, commit_sha: str, tier: ScanTier, status: TierStatus
    ) -> None:
        """Atualiza o status (e timestamps) de um tier do scan job."""
        ...

    @abstractmethod
    def set_blocked(self, commit_sha: str, blocked_at: ScanTier) -> None:
        """Marca o scan job como bloqueado no tier informado."""
        ...

    @abstractmethod
    def set_final_risk(self, commit_sha: str, score: int | None, level: str | None) -> None:
        """Grava o score e o nível de risco final do scan job."""
        ...

    @abstractmethod
    def list_recent(self, *, limit: int = 50, offset: int = 0) -> list[ScanJob]:
        """Lista os scan jobs mais recentes, com paginação."""
        ...

    @abstractmethod
    def count(self) -> int:
        """Conta o total de scan jobs persistidos."""
        ...
