"""
Rotas de leitura do status de scans (`ScanJob`), protegidas por JWT.

Apenas consulta: listagem paginada de scans recentes e detalhe de um scan
por commit (com resumo agregado de findings). Nenhuma escrita acontece
aqui — o ciclo de vida do `ScanJob` e' gerenciado pelo pipeline Celery
(`app/core/orchestrator.py`).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy.orm import Session

from app.domain.finding.entities import Finding
from app.infrastructure.database.sqlalchemy import get_db
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_report_repository import (
    SQLAlchemyScanReportRepository,
)
from app.presentation.api.dependencies.auth import get_current_user
from app.presentation.schemas.scan_schema import (
    FindingsSummary,
    ScanJobPage,
    ScanJobResponse,
    ScanJobSummary,
    ScanReportResponse,
    ScanReportsResponse,
)

router = APIRouter(
    prefix="/scans",
    tags=["scans"],
    dependencies=[Depends(get_current_user)],
    responses={
        401: {
            "description": "Token ausente, invalido ou expirado.",
            "content": {
                "application/json": {
                    "example": {"detail": "Credenciais invalidas ou token expirado."}
                }
            },
        }
    },
)


def _build_summary(findings: list[Finding]) -> FindingsSummary:
    """Agrega uma lista de `Finding` em contagens por severidade e por tier."""
    by_severity: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        by_tier[str(f.tier)] = by_tier.get(str(f.tier), 0) + 1
    return FindingsSummary(by_severity=by_severity, by_tier=by_tier, total=len(findings))


@router.get(
    "",
    response_model=ScanJobPage,
    summary="Listar scans recentes",
)
def list_scans(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> ScanJobPage:
    """Lista scans recentes de forma paginada, ordenados do mais recente para o mais antigo."""
    repo = SQLAlchemyScanJobRepository(db)
    items = repo.list_recent(limit=limit, offset=offset)
    total = repo.count()
    return ScanJobPage(
        items=[ScanJobSummary.from_entity(j) for j in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{commit_sha}",
    response_model=ScanJobResponse,
    summary="Consultar status de um scan por commit",
    responses={
        404: {
            "description": "Scan nao encontrado.",
            "content": {"application/json": {"example": {"detail": "Scan nao encontrado"}}},
        }
    },
)
def get_scan(commit_sha: str, db: Session = Depends(get_db)) -> ScanJobResponse:
    """Retorna o status detalhado de um scan pelo `commit_sha`, com resumo de findings."""
    job = SQLAlchemyScanJobRepository(db).get_by_commit(commit_sha)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan nao encontrado")

    findings = SQLAlchemyFindingRepository(db).get_by_commit(commit_sha)
    summary = _build_summary(findings)
    return ScanJobResponse.from_entity(job, summary)


@router.get(
    "/{commit_sha}/report",
    response_model=ScanReportsResponse,
    summary="Listar relatorios de um scan (todos os tiers)",
    responses={
        404: {
            "description": "Scan nao encontrado.",
            "content": {"application/json": {"example": {"detail": "Scan nao encontrado"}}},
        }
    },
)
def get_scan_reports(commit_sha: str, db: Session = Depends(get_db)) -> ScanReportsResponse:
    """Retorna todos os relatorios (um por tier) gerados para o `commit_sha`.

    Se ainda nao houver relatorios persistidos mas o scan existir, retorna
    lista vazia (scan em andamento). 404 somente se o scan nao existir.
    """
    reports = SQLAlchemyScanReportRepository(db).get_by_commit(commit_sha)
    if not reports:
        if SQLAlchemyScanJobRepository(db).get_by_commit(commit_sha) is None:
            raise HTTPException(status_code=404, detail="Scan nao encontrado")

    return ScanReportsResponse(
        commit_sha=commit_sha,
        reports=[ScanReportResponse.from_entity(r) for r in reports],
    )


@router.get(
    "/{commit_sha}/tiers/{tier}/report",
    response_model=ScanReportResponse,
    summary="Consultar relatorio de um tier especifico",
    responses={
        404: {
            "description": "Relatorio nao encontrado.",
            "content": {
                "application/json": {"example": {"detail": "Relatorio nao encontrado"}}
            },
        }
    },
)
def get_scan_report_by_tier(
    commit_sha: str,
    tier: int = Path(..., ge=1, le=3),
    db: Session = Depends(get_db),
) -> ScanReportResponse:
    """Retorna o relatorio markdown de um tier especifico (1, 2 ou 3) para o `commit_sha`."""
    report = SQLAlchemyScanReportRepository(db).get_by_commit_and_tier(commit_sha, tier)
    if report is None:
        raise HTTPException(status_code=404, detail="Relatorio nao encontrado")

    return ScanReportResponse.from_entity(report)
