"""Rotas de gerenciamento de repositórios GitHub ativados para análise.

Um repositório só pode ser ativado/gerenciado pelo usuário dono da conta
GitHub (instalação) à qual ele está vinculado. Ownership é sempre validado
comparando `user_id` — quando não pertence ao usuário logado, respondemos
404 (nunca 403) para não vazar a existência do recurso.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.domain.github.entities import Repository
from app.infrastructure.database.sqlalchemy import get_db
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)
from app.infrastructure.repositories.sqlalchemy_github_account_repository import (
    SQLAlchemyGithubAccountRepository,
)
from app.infrastructure.repositories.sqlalchemy_repository_repository import (
    SQLAlchemyRepositoryRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_report_repository import (
    SQLAlchemyScanReportRepository,
)
from app.presentation.api.dependencies.auth import get_current_user
from app.presentation.schemas.finding_schema import (
    FindingPage,
    FindingResponse,
    FindingSeverity,
)
from app.presentation.schemas.repository_schema import (
    RepositoryCreate,
    RepositoryResponse,
    RepositoryUpdate,
)
from app.presentation.schemas.scan_schema import (
    ScanJobPage,
    ScanJobSummary,
    ScanReportResponse,
)

_UNAUTHORIZED_RESPONSE = {
    401: {
        "description": "Token ausente, invalido ou expirado.",
        "content": {"application/json": {"example": {"detail": "Credenciais invalidas ou token expirado."}}},
    }
}

router = APIRouter(
    prefix="/repositories",
    tags=["repositories"],
    dependencies=[Depends(get_current_user)],
    responses=_UNAUTHORIZED_RESPONSE,
)


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=RepositoryResponse,
    summary="Ativar repositório para análise",
    responses={**_UNAUTHORIZED_RESPONSE, 404: {"description": "Conta GitHub nao encontrada."}},
)
def create_repository(
    payload: RepositoryCreate,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RepositoryResponse:
    """Ativa um repositório GitHub para análise, vinculado a uma conta do usuário.

    A conta GitHub (`github_account_id`) precisa pertencer ao usuário logado;
    caso contrário retorna 404 (sem revelar se a conta existe para outro
    usuário).
    """
    account = SQLAlchemyGithubAccountRepository(db).get_by_id(payload.github_account_id)
    if account is None or account.user_id != user_id:
        raise HTTPException(status_code=404, detail="Conta GitHub nao encontrada")

    repo = Repository(
        user_id=user_id,
        github_account_id=payload.github_account_id,
        installation_id=account.installation_id,
        github_repo_id=payload.github_repo_id,
        full_name=payload.full_name,
        url=payload.url,
        default_branch=payload.default_branch,
        active=True,
    )
    SQLAlchemyRepositoryRepository(db).save(repo)
    db.commit()
    return RepositoryResponse.from_entity(repo)


@router.get(
    "",
    response_model=list[RepositoryResponse],
    summary="Listar repositórios ativados",
)
def list_repositories(
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[RepositoryResponse]:
    """Lista os repositórios GitHub ativados para análise pelo usuário logado."""
    repos = SQLAlchemyRepositoryRepository(db).list_by_user(user_id)
    return [RepositoryResponse.from_entity(r) for r in repos]


@router.get(
    "/{repository_id}",
    response_model=RepositoryResponse,
    summary="Detalhe de um repositório",
    responses={**_UNAUTHORIZED_RESPONSE, 404: {"description": "Repositorio nao encontrado."}},
)
def get_repository(
    repository_id: UUID,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RepositoryResponse:
    """Retorna o detalhe de um repositório. 404 se não pertencer ao usuário."""
    repo = SQLAlchemyRepositoryRepository(db).get_by_id(repository_id)
    if repo is None or repo.user_id != user_id:
        raise HTTPException(status_code=404, detail="Repositorio nao encontrado")
    return RepositoryResponse.from_entity(repo)


@router.patch(
    "/{repository_id}",
    response_model=RepositoryResponse,
    summary="Ativar/desativar repositório",
    responses={**_UNAUTHORIZED_RESPONSE, 404: {"description": "Repositorio nao encontrado."}},
)
def update_repository(
    repository_id: UUID,
    payload: RepositoryUpdate,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RepositoryResponse:
    """Ativa ou desativa um repositório. 404 se não pertencer ao usuário."""
    repo_store = SQLAlchemyRepositoryRepository(db)
    repo = repo_store.get_by_id(repository_id)
    if repo is None or repo.user_id != user_id:
        raise HTTPException(status_code=404, detail="Repositorio nao encontrado")

    repo_store.set_active(repository_id, payload.active)
    db.commit()

    updated = repo_store.get_by_id(repository_id)
    return RepositoryResponse.from_entity(updated)


@router.delete(
    "/{repository_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remover repositório",
    responses={**_UNAUTHORIZED_RESPONSE, 404: {"description": "Repositorio nao encontrado."}},
)
def delete_repository(
    repository_id: UUID,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Remove o vínculo do repositório. 404 se não pertencer ao usuário."""
    repo_store = SQLAlchemyRepositoryRepository(db)
    repo = repo_store.get_by_id(repository_id)
    if repo is None or repo.user_id != user_id:
        raise HTTPException(status_code=404, detail="Repositorio nao encontrado")

    repo_store.delete(repository_id)
    db.commit()


def _owned_repo_or_404(db: Session, repository_id: UUID, user_id: UUID) -> Repository:
    """Retorna o repositório se pertencer ao usuário; senão 404."""
    repo = SQLAlchemyRepositoryRepository(db).get_by_id(repository_id)
    if repo is None or repo.user_id != user_id:
        raise HTTPException(status_code=404, detail="Repositorio nao encontrado")
    return repo


@router.get(
    "/{repository_id}/scans",
    response_model=ScanJobPage,
    summary="Listar scans do repositório",
    responses={**_UNAUTHORIZED_RESPONSE, 404: {"description": "Repositorio nao encontrado."}},
)
def list_repository_scans(
    repository_id: UUID,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> ScanJobPage:
    """Lista os scans (ScanJob) do repositório. 404 se não pertencer ao usuário."""
    _owned_repo_or_404(db, repository_id, user_id)
    repo = SQLAlchemyScanJobRepository(db)
    items = repo.list_by_repository(repository_id, limit=limit, offset=offset)
    total = repo.count_by_repository(repository_id)
    return ScanJobPage(
        items=[ScanJobSummary.from_entity(j) for j in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{repository_id}/findings",
    response_model=FindingPage,
    summary="Listar findings do repositório",
    responses={**_UNAUTHORIZED_RESPONSE, 404: {"description": "Repositorio nao encontrado."}},
)
def list_repository_findings(
    repository_id: UUID,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
    severity: FindingSeverity | None = Query(None),
    tier: int | None = Query(None, ge=1, le=3),
    source: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> FindingPage:
    """Lista os findings do repositório (todos os commits). 404 se não for do usuário."""
    _owned_repo_or_404(db, repository_id, user_id)
    repo = SQLAlchemyFindingRepository(db)
    sev = severity.value if severity else None
    items = repo.query(
        severity=sev, tier=tier, source=source,
        repository_id=repository_id, limit=limit, offset=offset,
    )
    total = repo.count(severity=sev, tier=tier, source=source, repository_id=repository_id)
    return FindingPage(
        items=[FindingResponse.from_entity(f) for f in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{repository_id}/reports",
    response_model=list[ScanReportResponse],
    summary="Listar relatórios do repositório",
    responses={**_UNAUTHORIZED_RESPONSE, 404: {"description": "Repositorio nao encontrado."}},
)
def list_repository_reports(
    repository_id: UUID,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[ScanReportResponse]:
    """Lista os relatórios (por commit/tier) do repositório. 404 se não for do usuário."""
    _owned_repo_or_404(db, repository_id, user_id)
    reports = SQLAlchemyScanReportRepository(db).list_by_repository(repository_id)
    return [ScanReportResponse.from_entity(r) for r in reports]
