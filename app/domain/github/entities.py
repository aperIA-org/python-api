from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4


@dataclass
class GithubAccount:
    """Vínculo entre um usuário aperIA e uma instalação do GitHub App."""

    user_id: UUID
    installation_id: int
    github_login: str
    account_type: str  # "User" | "Organization"
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Repository:
    """Repositório GitHub conectado ao aperIA, pertencente a um usuário."""

    user_id: UUID
    github_account_id: UUID
    installation_id: int
    github_repo_id: int
    full_name: str
    url: str
    id: UUID = field(default_factory=uuid4)
    default_branch: str = "main"
    active: bool = True
    # URL onde ESTE repositório está publicado (staging/preview). É o alvo do
    # DAST (ZAP) no Tier 3; `None` — o caso comum — significa "sem deploy
    # conhecido", e o Tier 3 pula o ZAP registrando `reason="no_target_url"`.
    # Não confundir com `url`, que é o endereço do repositório no GitHub.
    # Validada por `app.domain.github.target_url.validar_target_url`.
    target_url: str | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)
