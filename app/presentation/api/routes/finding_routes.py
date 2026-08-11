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
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.presentation.api.dependencies.auth import get_current_user
from app.presentation.schemas.finding_schema import (
    FindingDetail,
    FindingGroupList,
    FindingGroupResponse,
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
    user_id: UUID = Depends(get_current_user),
    commit_sha: str | None = Query(None, description="Filtra pelo SHA do commit."),
    severity: FindingSeverity | None = Query(None, description="Filtra pela severidade."),
    tier: int | None = Query(None, ge=1, le=3, description="Filtra pelo tier (1-3)."),
    source: str | None = Query(None, description="Filtra pela ferramenta de origem (ex.: semgrep)."),
    secret_verified: bool | None = Query(None, description="Filtra secrets verificados."),
    title: str | None = Query(
        None,
        description=(
            "Filtra pelo titulo EXATO. E o drill-down de um grupo de "
            "`GET /findings/groups` — nao e busca por texto livre."
        ),
    ),
    limit: int = Query(50, ge=1, le=200, description="Tamanho da pagina."),
    offset: int = Query(0, ge=0, description="Deslocamento para paginacao."),
) -> FindingPage:
    """
    Lista findings do USUÁRIO logado, com filtros opcionais e paginacao.

    Isolado por dono: só retorna findings de commits cujos scans pertencem ao
    usuário autenticado. Ordenados do mais recente para o mais antigo; o campo
    `raw_output` é omitido aqui — use `GET /findings/{finding_id}` para o detalhe.
    """
    repo = SQLAlchemyFindingRepository(db)
    sev = severity.value if severity else None
    items = repo.query(
        commit_sha=commit_sha,
        severity=sev,
        tier=tier,
        source=source,
        secret_verified=secret_verified,
        title=title,
        user_id=user_id,
        limit=limit,
        offset=offset,
    )
    total = repo.count(
        commit_sha=commit_sha,
        severity=sev,
        tier=tier,
        source=source,
        secret_verified=secret_verified,
        title=title,
        user_id=user_id,
    )
    return FindingPage(
        items=[FindingResponse.from_entity(f) for f in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/groups",
    response_model=FindingGroupList,
    summary="Listar findings agrupados por tipo",
    response_description="Tipos de vulnerabilidade com a contagem de ocorrencias.",
)
def list_finding_groups(
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_current_user),
    commit_sha: str | None = Query(None, description="Filtra pelo SHA do commit."),
    amostra: int = Query(
        8, ge=0, le=50, description="Quantos caminhos de exemplo trazer por grupo."
    ),
) -> FindingGroupList:
    """
    Agrupa os findings do usuario por tipo de vulnerabilidade.

    Existe porque a listagem plana e' ilegivel com DAST: o mesmo alerta do ZAP
    aparece uma vez por rota, e um scan vira milhares de linhas que sao dezenas
    de problemas. Aqui cada linha e' um problema, com quantas vezes ele ocorre e
    em quantos caminhos distintos.

    Sem paginacao de proposito: o agrupamento derruba a cardinalidade em tres
    ordens de grandeza (12 mil findings -> 14 grupos), entao a resposta inteira
    cabe numa tela. O teto de 500 grupos e' so uma trava de seguranca.

    Para as ocorrencias de um grupo, use `GET /findings?title=<titulo exato>`.
    """
    teto = 500
    grupos = SQLAlchemyFindingRepository(db).group_by_type(
        commit_sha=commit_sha, user_id=user_id, amostra_por_grupo=amostra, limit=teto
    )
    return FindingGroupList(
        items=[FindingGroupResponse.from_group(g) for g in grupos],
        total_findings=sum(g.ocorrencias for g in grupos),
        truncado=len(grupos) >= teto,
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
def get_finding(
    finding_id: UUID,
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_current_user),
) -> FindingDetail:
    """Retorna o detalhe de um finding do usuário. 404 se não existir ou não
    pertencer a um scan do usuário autenticado (não vaza existência)."""
    finding = SQLAlchemyFindingRepository(db).get_by_id(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding nao encontrado")
    # Ownership: o finding só é visível se o scan do seu commit for do usuário.
    job = SQLAlchemyScanJobRepository(db).get_by_commit(finding.commit_sha)
    if job is None or job.user_id != user_id:
        raise HTTPException(status_code=404, detail="Finding nao encontrado")
    return FindingDetail.from_entity(finding)
