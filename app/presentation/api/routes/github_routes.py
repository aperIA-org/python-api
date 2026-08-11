"""Rotas de conexão da conta GitHub (instalação do GitHub App).

Fluxo:
1. ``GET /github/connect`` (JWT) devolve a URL de instalação do App com um
   ``state`` assinado que amarra o redirect ao usuário logado.
2. O usuário instala o App no GitHub e é redirecionado para
   ``GET /github/callback`` (sem JWT — a identidade vem do ``state``), que
   vincula a instalação ao usuário.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.domain.github.entities import GithubAccount
from app.infrastructure.database.sqlalchemy import get_db
from app.infrastructure.git import github_auth
from app.infrastructure.git.github_client import GitHubClient
from app.infrastructure.repositories.sqlalchemy_github_account_repository import (
    SQLAlchemyGithubAccountRepository,
)
from app.infrastructure.repositories.sqlalchemy_repository_repository import (
    SQLAlchemyRepositoryRepository,
)
from app.infrastructure.security.github_state import (
    create_connect_state,
    decode_connect_state,
)
from app.presentation.api.dependencies.auth import get_current_user
from app.presentation.schemas.github_schema import (
    AvailableRepo,
    ConnectResponse,
    GithubAccountResponse,
)

logger = structlog.get_logger()

_UNAUTHORIZED_RESPONSE = {
    401: {
        "description": "Token ausente, invalido ou expirado.",
        "content": {"application/json": {"example": {"detail": "Credenciais invalidas ou token expirado."}}},
    }
}

router = APIRouter(prefix="/github", tags=["github"])


def _com_query(base_url: str, **params: str) -> str:
    """Mescla ``params`` na query string de ``base_url``.

    A URL configurada em ``GITHUB_CONNECT_REDIRECT_URL`` já costuma trazer
    query (ex.: ``/dash/repositorios?github=conectado``), então concatenar
    ``?...`` produziria URL inválida — usamos ``urllib.parse`` e sobrescrevemos
    as chaves informadas (``github=conectado`` vira ``github=erro``).
    """
    parts = urlsplit(base_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(params)
    return urlunsplit(parts._replace(query=urlencode(query)))


@router.get(
    "/connect",
    response_model=ConnectResponse,
    summary="Iniciar conexão com o GitHub",
    dependencies=[Depends(get_current_user)],
    responses=_UNAUTHORIZED_RESPONSE,
)
def connect(user_id=Depends(get_current_user)) -> ConnectResponse:
    """Gera a URL de instalação do App com um `state` assinado (10 min).

    O front-end deve redirecionar o usuário para `install_url`. Retorna 503
    enquanto o App não estiver configurado (`GITHUB_APP_SLUG` vazio).
    """
    if not settings.GITHUB_APP_SLUG:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitHub App nao configurado (GITHUB_APP_SLUG ausente).",
        )
    state = create_connect_state(user_id, settings.SECRET_KEY)
    install_url = (
        f"https://github.com/apps/{settings.GITHUB_APP_SLUG}"
        f"/installations/new?state={state}"
    )
    return ConnectResponse(install_url=install_url)


@router.get(
    "/callback",
    summary="Callback da instalação do GitHub App",
    responses={
        302: {
            "description": (
                "Redirect para `GITHUB_CONNECT_REDIRECT_URL` quando configurada. "
                "Em erro de `state`, com `github=erro&motivo=state` na query."
            )
        },
        400: {"description": "state ausente ou inválido (sem URL de redirect configurada)."},
    },
)
def callback(
    installation_id: int = Query(...),
    state: str = Query(...),
    setup_action: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """Recebe o redirect pós-instalação e vincula a instalação ao usuário.

    A identidade vem do `state` assinado (não do header JWT — é o browser do
    usuário que chega aqui). Faz upsert da `GithubAccount`.

    Quem chega aqui é um **browser**, não um cliente de API: com
    `GITHUB_CONNECT_REDIRECT_URL` configurada, um `state` inválido/expirado
    também redireciona (302) para o front, com `github=erro&motivo=state`, em
    vez de deixar o usuário num JSON de erro no host da API. Sem a URL
    configurada mantemos o `400`.
    """
    try:
        user_id = decode_connect_state(state, settings.SECRET_KEY)
    except ValueError as exc:
        if settings.GITHUB_CONNECT_REDIRECT_URL:
            logger.warning("github_callback_state_invalido", installation_id=installation_id)
            return RedirectResponse(
                url=_com_query(
                    settings.GITHUB_CONNECT_REDIRECT_URL, github="erro", motivo="state"
                ),
                status_code=302,
            )
        raise HTTPException(status_code=400, detail="state invalido ou expirado") from exc

    # Metadados da instalação (login/tipo) — best-effort.
    login, account_type = None, None
    try:
        account = github_auth.get_installation_metadata(installation_id)
        login = account.get("login")
        account_type = account.get("type")
    except Exception as exc:  # noqa: BLE001 — não falha a conexão por metadado
        logger.warning("github_installation_metadata_failed", installation_id=installation_id, error=str(exc))

    repo = SQLAlchemyGithubAccountRepository(db)
    repo.save(
        GithubAccount(
            user_id=user_id,
            installation_id=installation_id,
            github_login=login,
            account_type=account_type,
        )
    )
    db.commit()
    logger.info("github_account_connected", user_id=str(user_id), installation_id=installation_id)

    if settings.GITHUB_CONNECT_REDIRECT_URL:
        return RedirectResponse(url=settings.GITHUB_CONNECT_REDIRECT_URL, status_code=302)
    return {"status": "connected", "installation_id": installation_id}


@router.get(
    "/repos",
    response_model=list[AvailableRepo],
    summary="Listar repositórios disponíveis nas instalações do usuário",
    dependencies=[Depends(get_current_user)],
    responses=_UNAUTHORIZED_RESPONSE,
)
def list_available_repos(
    user_id=Depends(get_current_user), db: Session = Depends(get_db)
) -> list[AvailableRepo]:
    """Lista, ao vivo, os repositórios que as instalações do usuário enxergam.

    Para cada conta conectada, consulta o GitHub (installation token) e marca
    `active=True` nos repos que o usuário já ativou para análise. Falha ao
    consultar uma instalação é logada e ignorada (best-effort).
    """
    accounts = SQLAlchemyGithubAccountRepository(db).list_by_user(user_id)
    active_ids = {
        r.github_repo_id
        for r in SQLAlchemyRepositoryRepository(db).list_by_user(user_id)
        if r.active
    }
    out: list[AvailableRepo] = []
    for acc in accounts:
        try:
            repos = GitHubClient(acc.installation_id).list_repositories()
        except Exception as exc:  # noqa: BLE001 — best-effort por instalação
            logger.warning(
                "github_list_repos_failed",
                installation_id=acc.installation_id,
                error=str(exc),
            )
            continue
        for r in repos:
            out.append(
                AvailableRepo(
                    github_account_id=acc.id,
                    github_repo_id=r["id"],
                    full_name=r["full_name"],
                    url=r.get("html_url", ""),
                    default_branch=r.get("default_branch", "main"),
                    active=r["id"] in active_ids,
                    # Metadados opcionais do payload da instalação — ``.get()``
                    # porque nem todo payload (nem os fakes de teste) os traz.
                    private=bool(r.get("private", False)),
                    language=r.get("language"),
                    pushed_at=r.get("pushed_at"),
                )
            )
    return out


@router.get(
    "/accounts",
    response_model=list[GithubAccountResponse],
    summary="Listar contas GitHub conectadas",
    dependencies=[Depends(get_current_user)],
    responses=_UNAUTHORIZED_RESPONSE,
)
def list_accounts(user_id=Depends(get_current_user), db: Session = Depends(get_db)) -> list[GithubAccountResponse]:
    """Lista as contas GitHub (instalações) conectadas pelo usuário logado."""
    accounts = SQLAlchemyGithubAccountRepository(db).list_by_user(user_id)
    return [GithubAccountResponse.from_entity(a) for a in accounts]


@router.delete(
    "/accounts/{account_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Desconectar conta GitHub",
    dependencies=[Depends(get_current_user)],
    responses={**_UNAUTHORIZED_RESPONSE, 404: {"description": "Conta nao encontrada."}},
)
def delete_account(account_id: UUID, user_id=Depends(get_current_user), db: Session = Depends(get_db)):
    """Remove o vínculo da conta GitHub. 404 se não pertencer ao usuário.

    Remove **na mesma transação** os `repositories` vinculados a essa conta.
    Não existe `ForeignKey` entre `github_accounts` e `repositories`, então a
    limpeza é explícita: sem ela os repositórios ficariam fantasmas —
    `GET /repositories` os listaria como ativos enquanto `GET /github/repos`
    não os mostraria mais (a instalação deixou de existir).

    **Findings, scans e relatórios são preservados.** O histórico de segurança
    já coletado é o produto: apagá-lo ao desconectar destruiria auditoria por
    uma ação reversível (o usuário pode reinstalar o App). Esses registros
    continuam acessíveis por `GET /findings` e `GET /scans` (escopo do
    usuário); apenas as rotas `/repositories/{id}/…` deixam de resolver,
    porque o vínculo com o repositório desapareceu.
    """
    repo = SQLAlchemyGithubAccountRepository(db)
    account = repo.get_by_id(account_id)
    if account is None or account.user_id != user_id:
        raise HTTPException(status_code=404, detail="Conta nao encontrada")

    removidos = SQLAlchemyRepositoryRepository(db).delete_by_github_account(
        account_id, user_id
    )
    repo.delete(account_id)
    db.commit()
    logger.info(
        "github_account_disconnected",
        user_id=str(user_id),
        account_id=str(account_id),
        repositories_removed=removidos,
    )
