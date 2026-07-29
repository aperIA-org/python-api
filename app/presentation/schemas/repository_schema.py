"""Schemas das rotas de repositórios GitHub ativados para análise."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class RepositoryResponse(BaseModel):
    """Repositório GitHub conectado ao aperIA, pertencente a um usuário."""

    id: UUID
    github_account_id: UUID
    installation_id: int
    github_repo_id: int
    full_name: str
    url: str | None
    default_branch: str
    active: bool
    created_at: datetime

    @classmethod
    def from_entity(cls, repo) -> "RepositoryResponse":
        return cls(
            id=repo.id,
            github_account_id=repo.github_account_id,
            installation_id=repo.installation_id,
            github_repo_id=repo.github_repo_id,
            full_name=repo.full_name,
            url=repo.url,
            default_branch=repo.default_branch,
            active=repo.active,
            created_at=repo.created_at,
        )


class RepositoryCreate(BaseModel):
    """Payload para ativar um repositório GitHub para análise."""

    github_account_id: UUID
    github_repo_id: int
    full_name: str
    url: str
    default_branch: str = "main"


class RepositoryUpdate(BaseModel):
    """Payload para ativar/desativar um repositório."""

    active: bool
