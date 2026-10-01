"""Rota de consumo de remediacoes — somente leitura.

**Nao existe endpoint de aprovacao, e isso e' deliberado.** Houve um
``PATCH /remediations/{id}/status``; ele saiu porque criava uma segunda
superficie de decisao que nunca conversava com a primeira. A premissa do
produto e' que todo patch sai como GitHub code suggestion e so' um humano o
aplica, pelo proprio GitHub — entao aprovar no dashboard registrava uma
decisao que nao mexia em nada, enquanto um "Apply suggestion" de verdade
deixava o card dizendo "sugerido" para sempre.

O dashboard e' o INVENTARIO: mostra todo patch que o pipeline gerou, inclusive
os que nao viraram comentario (scan manual nao tem PR; arquivo fora do diff e'
recusado pelo GitHub com 422). O ``github_comment_id`` diz qual e' qual.

**Posse vem do scan_job.** ``remediations`` nao tem ``user_id``: o dono de uma
remediacao e' o dono do scan que a gerou, e o join em ``query``/``count`` e'
que prova isso.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.domain.remediation.entities import RemediationStatus
from app.infrastructure.database.sqlalchemy import get_db
from app.infrastructure.repositories.sqlalchemy_remediation_repository import (
    SQLAlchemyRemediationRepository,
)
from app.presentation.api.dependencies.auth import get_current_user
from app.presentation.schemas.remediation_schema import (
    RemediationPage,
    RemediationResponse,
    RemediationStatusSchema,
)

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
    prefix="/remediations",
    tags=["remediations"],
    dependencies=[Depends(get_current_user)],
    responses=_UNAUTHORIZED_RESPONSE,
)


@router.get(
    "",
    response_model=RemediationPage,
    summary="Listar remediacoes",
    response_description="Pagina de remediacoes que atendem aos filtros.",
)
def list_remediations(
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_current_user),
    scan_job_id: UUID | None = Query(
        None, description="Escopa a lista a uma unica execucao de scan."
    ),
    status: RemediationStatusSchema | None = Query(
        None, description="Filtra pelo status da remediacao."
    ),
    limit: int = Query(50, ge=1, le=200, description="Tamanho da pagina."),
    offset: int = Query(0, ge=0, description="Deslocamento para paginacao."),
) -> RemediationPage:
    """
    Lista as remediacoes do USUARIO logado, da mais recente para a mais antiga.

    Cada item vem com o contexto do finding de origem e do scan — titulo,
    severidade, arquivo, repositorio e PR — porque e' o que o card do
    dashboard mostra, e buscar isso a parte significaria varrer o conjunto
    inteiro de findings do usuario.
    """
    repo = SQLAlchemyRemediationRepository(db)
    dominio = RemediationStatus(status.value) if status else None
    itens = repo.query(
        user_id=user_id,
        scan_job_id=scan_job_id,
        status=dominio,
        limit=limit,
        offset=offset,
    )
    total = repo.count(user_id=user_id, scan_job_id=scan_job_id, status=dominio)
    return RemediationPage(
        items=[RemediationResponse.from_contexto(c) for c in itens],
        total=total,
        limit=limit,
        offset=offset,
    )
