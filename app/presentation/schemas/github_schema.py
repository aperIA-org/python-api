"""Schemas das rotas de conexão da conta GitHub."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class ConnectResponse(BaseModel):
    """URL de instalação do GitHub App para onde o front deve redirecionar."""

    install_url: str


class GithubAccountResponse(BaseModel):
    """Conta GitHub (instalação do App) conectada por um usuário."""

    id: UUID
    installation_id: int
    github_login: str | None
    account_type: str | None
    created_at: datetime

    @classmethod
    def from_entity(cls, account) -> "GithubAccountResponse":
        return cls(
            id=account.id,
            installation_id=account.installation_id,
            github_login=account.github_login,
            account_type=account.account_type,
            created_at=account.created_at,
        )


class AvailableRepo(BaseModel):
    """Repositório visível pela instalação, para a tela de ativação.

    ``active`` indica se já foi ativado para análise pelo usuário.
    ``github_account_id`` é o que o front envia depois em ``POST /repositories``.
    """

    github_account_id: UUID
    github_repo_id: int
    full_name: str
    url: str
    default_branch: str
    active: bool
