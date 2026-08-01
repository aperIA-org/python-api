from abc import ABC, abstractmethod
from datetime import datetime
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
    def list_in_progress(self) -> list[ScanJob]:
        """Lista os jobs com algum tier ainda ``queued``/``running``.

        Conjunto naturalmente pequeno (só o que está em voo) — é a entrada da
        varredura de jobs travados, que aplica a regra de "sem progresso"
        (``ScanJob.esta_travado``) no domínio, não em SQL.
        """
        ...

    @abstractmethod
    def fail_pending_tiers(self, commit_sha: str) -> None:
        """Marca como ``failed`` todo tier ainda ``queued``/``running``.

        Usado para liberar jobs travados: preserva os tiers já concluídos e
        carimba ``tier*_completed_at`` só nos que foram encerrados agora.
        """
        ...

    @abstractmethod
    def restart_execution(self, commit_sha: str, *, started_at: datetime) -> None:
        """Reinicia o estado de execução de uma linha já existente.

        Existe porque ``scan_jobs`` tem UNIQUE em ``commit_sha``: um redisparo
        do mesmo commit reaproveita a linha. Sem reset, os timestamps da
        execução anterior sobrevivem e a duração exibida vira ficção.
        """
        ...

    @abstractmethod
    def list_recent(self, *, limit: int = 50, offset: int = 0) -> list[ScanJob]:
        """Lista os scan jobs mais recentes, com paginação."""
        ...

    @abstractmethod
    def count(self) -> int:
        """Conta o total de scan jobs persistidos."""
        ...

    @abstractmethod
    def list_by_user(self, user_id: UUID, *, limit: int = 50, offset: int = 0) -> list[ScanJob]:
        """Lista os scan jobs de um usuário, do mais recente para o mais antigo, com paginação."""
        ...

    @abstractmethod
    def count_by_user(self, user_id: UUID) -> int:
        """Conta o total de scan jobs de um usuário."""
        ...

    @abstractmethod
    def list_by_repository(
        self, repository_id: UUID, *, limit: int = 50, offset: int = 0
    ) -> list[ScanJob]:
        """Lista os scan jobs de um repositório, do mais recente para o mais antigo, com paginação."""
        ...

    @abstractmethod
    def count_by_repository(self, repository_id: UUID) -> int:
        """Conta o total de scan jobs de um repositório."""
        ...
