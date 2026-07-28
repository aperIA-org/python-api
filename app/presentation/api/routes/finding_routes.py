"""Rotas de consumo de findings de seguranca.

Endpoints de LEITURA (protegidos por JWT) sobre os findings persistidos
pelo pipeline. Reaproveitam o ``SQLAlchemyFindingRepository`` sincrono via
``Depends(get_db)``.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.infrastructure.database.sqlalchemy import get_db
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)
from app.presentation.api.dependencies.auth import get_current_user
from app.presentation.schemas.finding_schema import (
    FindingDetail,
    FindingPage,
    FindingResponse,
    FindingSeverity,
)

# Resposta 401 comum a todas as rotas (a dependency get_current_user protege
# o router inteiro). Documentada aqui para aparecer no OpenAPI.
_UNAUTHORIZED_RESPONSE = {
    401: {
        "description": "Token ausente, invalido ou expirado.",
        "content": {
            "application/json": {
                "example": {"detail": "Credenciais invalidas ou token expirado."}
            }
        },
    }
}

router = APIRouter(
    prefix="/findings",
    tags=["findings"],
    dependencies=[Depends(get_current_user)],
    responses=_UNAUTHORIZED_RESPONSE,
)


@router.get(
    "",
    response_model=FindingPage,
    summary="Listar findings",
    response_description="Pagina de findings que atendem aos filtros.",
)
def list_findings(
    db: Session = Depends(get_db),
    commit_sha: str | None = Query(None, description="Filtra pelo SHA do commit."),
    severity: FindingSeverity | None = Query(None, description="Filtra pela severidade."),
    tier: int | None = Query(None, ge=1, le=3, description="Filtra pelo tier (1-3)."),
    source: str | None = Query(None, description="Filtra pela ferramenta de origem (ex.: semgrep)."),
    secret_verified: bool | None = Query(None, description="Filtra secrets verificados."),
    limit: int = Query(50, ge=1, le=200, description="Tamanho da pagina."),
    offset: int = Query(0, ge=0, description="Deslocamento para paginacao."),
) -> FindingPage:
    """
    Lista findings persistidos, com filtros opcionais e paginacao.

    Os resultados vem ordenados do mais recente para o mais antigo. O
    campo `raw_output` (potencialmente grande) e omitido aqui — use
    `GET /findings/{finding_id}` para o detalhe completo.
    """
    repo = SQLAlchemyFindingRepository(db)
    sev = severity.value if severity else None
    items = repo.query(
        commit_sha=commit_sha,
        severity=sev,
        tier=tier,
        source=source,
        secret_verified=secret_verified,
        limit=limit,
        offset=offset,
    )
    total = repo.count(
        commit_sha=commit_sha,
        severity=sev,
        tier=tier,
        source=source,
        secret_verified=secret_verified,
    )
    return FindingPage(
        items=[FindingResponse.from_entity(f) for f in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{finding_id}",
    response_model=FindingDetail,
    summary="Consultar finding por ID",
    response_description="Detalhe do finding, incluindo `raw_output`.",
    responses={
        404: {
            "description": "Finding nao encontrado.",
            "content": {"application/json": {"example": {"detail": "Finding nao encontrado"}}},
        }
    },
)
def get_finding(finding_id: UUID, db: Session = Depends(get_db)) -> FindingDetail:
    """Retorna o detalhe completo de um finding a partir do seu UUID."""
    repo = SQLAlchemyFindingRepository(db)
    finding = repo.get_by_id(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding nao encontrado")
    return FindingDetail.from_entity(finding)
