from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.github.entities import GithubAccount, Repository


class GithubAccountRepository(ABC):
    """Interface síncrona de persistência para ``GithubAccount``."""

    @abstractmethod
    def save(self, account: GithubAccount) -> None:
        """Persiste uma conta de forma idempotente por ``installation_id``."""
        ...

    @abstractmethod
    def get_by_id(self, account_id: UUID) -> GithubAccount | None:
        """Busca uma conta pelo seu identificador único."""
        ...

    @abstractmethod
    def get_by_installation(self, installation_id: int) -> GithubAccount | None:
        """Busca uma conta pelo ID da instalação do GitHub App."""
        ...

    @abstractmethod
    def list_by_user(self, user_id: UUID) -> list[GithubAccount]:
        """Lista as contas GitHub vinculadas a um usuário."""
        ...

    @abstractmethod
    def delete(self, account_id: UUID) -> None:
        """Remove uma conta GitHub pelo seu identificador único."""
        ...


class RepositoryRepository(ABC):
    """Interface síncrona de persistência para ``Repository``."""

    @abstractmethod
    def save(self, repository: Repository) -> None:
        """Persiste um repositório de forma idempotente por ``(user_id, github_repo_id)``."""
        ...

    @abstractmethod
    def get_by_id(self, repository_id: UUID) -> Repository | None:
        """Busca um repositório pelo seu identificador único."""
        ...

    @abstractmethod
    def list_by_user(self, user_id: UUID) -> list[Repository]:
        """Lista os repositórios conectados por um usuário."""
        ...

    @abstractmethod
    def get_by_installation_and_repo(
        self, installation_id: int, github_repo_id: int
    ) -> Repository | None:
        """Busca um repositório pelo par (instalação, ID do repositório no GitHub)."""
        ...

    @abstractmethod
    def set_active(self, repository_id: UUID, active: bool) -> None:
        """Ativa ou desativa o monitoramento de um repositório."""
        ...

    @abstractmethod
    def delete(self, repository_id: UUID) -> None:
        """Remove um repositório pelo seu identificador único."""
        ...
