"""
Rotas de leitura do status de scans (`ScanJob`), protegidas por JWT.

Apenas consulta: listagem paginada de scans recentes e detalhe de um scan
por commit (com resumo agregado de findings). Nenhuma escrita acontece
aqui — o ciclo de vida do `ScanJob` e' gerenciado pelo pipeline Celery
(`app/core/orchestrator.py`).
"""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy.orm import Session

from app.domain.finding.entities import Finding
from app.domain.scan.tool_catalog import TIER_TOOLS
from app.application.exceptions import ScanNotCancellableError
from app.application.use_cases.cancel_scan_use_case import CancelScanUseCase
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
from app.infrastructure.repositories.sqlalchemy_scan_tool_run_repository import (
    SQLAlchemyScanToolRunRepository,
)
from app.presentation.api.dependencies.auth import get_current_user
from app.presentation.schemas.scan_schema import (
    CancelScanResponse,
    FindingsSummary,
    ScanIaSummary,
    ScanJobPage,
    ScanJobResponse,
    ScanJobSummary,
    ScanReportResponse,
    ScanReportsResponse,
    ScanToolRunResponse,
    ScanToolsResponse,
)

logger = structlog.get_logger()

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


def _owned_job_or_404(db: Session, scan_id: str, user_id: UUID):
    """Resolve ``scan_id`` para um ScanJob do usuário; senão 404.

    Aceita duas formas, e a distinção importa desde que o mesmo commit pode ter
    várias execuções:

    - **uuid** → aquela execução específica. É o que endereça o histórico.
    - **commit sha** → a execução **corrente** daquele commit. Mantido porque é
      o que o disparo manual devolve (``ManualScanResponse.commit_sha``) e o que
      links antigos usam; responde "como está este commit agora".

    Isolamento: um usuário nunca enxerga o scan de outro. Usamos 404 (não 403)
    para não vazar a existência do commit.
    """
    repo = SQLAlchemyScanJobRepository(db)
    job = None
    try:
        job = repo.get_by_id(UUID(scan_id))
    except ValueError:
        pass
    if job is None:
        # Não é `else`: ``UUID()`` aceita 32 hex sem hífen, então um sha
        # abreviado entraria no ramo do uuid e sairia como 404 sem nunca ter
        # sido procurado como commit.
        job = repo.get_by_commit(scan_id)
    if job is None or job.user_id != user_id:
        raise HTTPException(status_code=404, detail="Scan nao encontrado")
    return job


@router.get(
    "",
    response_model=ScanJobPage,
    summary="Listar scans recentes",
)
def list_scans(
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> ScanJobPage:
    """Lista os scans do usuário logado, paginados (mais recentes primeiro)."""
    repo = SQLAlchemyScanJobRepository(db)
    items = repo.list_by_user(user_id, limit=limit, offset=offset)
    total = repo.count_by_user(user_id)
    # UMA query agregada para a pagina inteira, nao um count por card: sao ate'
    # 200 execucoes aqui. O numero e' o mesmo que `GET /scans/{id}` devolve em
    # `findings_summary.total`, porque as duas contam findings do COMMIT.
    contagens = SQLAlchemyFindingRepository(db).count_by_commits(
        [j.commit_sha for j in items], user_id=user_id
    )
    return ScanJobPage(
        items=[
            ScanJobSummary.from_entity(j, findings_total=contagens.get(j.commit_sha, 0))
            for j in items
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanJobResponse,
    summary="Consultar um scan por id de execucao (ou commit)",
    responses={
        404: {
            "description": "Scan nao encontrado.",
            "content": {"application/json": {"example": {"detail": "Scan nao encontrado"}}},
        }
    },
)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_current_user),
) -> ScanJobResponse:
    """Retorna uma execução (uuid) ou a execução corrente de um commit (sha),
    com resumo de findings.

    O resumo é dos findings do **commit** — eles não são escopados por execução
    (reexecutar o mesmo commit analisa o mesmo código), então duas execuções do
    mesmo commit devolvem a mesma contagem e diferem só no desfecho por
    ferramenta, no risco e no status dos tiers. Com DAST ligado isso deixa de
    ser verdade, porque o alvo pode ter mudado entre as duas.
    """
    job = _owned_job_or_404(db, scan_id, user_id)

    findings = SQLAlchemyFindingRepository(db).get_by_commit(job.commit_sha)
    summary = _build_summary(findings)
    return ScanJobResponse.from_entity(job, summary)


@router.get(
    "/{scan_id}/report",
    response_model=ScanReportsResponse,
    summary="Listar relatorios de um scan (todos os tiers)",
    responses={
        404: {
            "description": "Scan nao encontrado.",
            "content": {"application/json": {"example": {"detail": "Scan nao encontrado"}}},
        }
    },
)
def get_scan_reports(
    scan_id: str,
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_current_user),
) -> ScanReportsResponse:
    """Retorna os relatorios (um por tier) **daquela execução**.

    Passar o sha devolve os da execução corrente; passar o uuid devolve os
    daquela execução do histórico — é a diferença que torna o histórico útil.

    404 se o scan não existir ou não pertencer ao usuário. Lista vazia se o
    scan existe mas ainda não há relatórios (pipeline em andamento).
    """
    job = _owned_job_or_404(db, scan_id, user_id)
    reports = SQLAlchemyScanReportRepository(db).get_by_scan_job(job.id)
    return ScanReportsResponse(
        scan_id=job.id,
        commit_sha=job.commit_sha,
        reports=[ScanReportResponse.from_entity(r) for r in reports],
    )


@router.get(
    "/{scan_id}/tools",
    response_model=ScanToolsResponse,
    summary="Listar o status de cada ferramenta do pipeline nesta execucao",
    responses={
        404: {
            "description": "Scan nao encontrado.",
            "content": {"application/json": {"example": {"detail": "Scan nao encontrado"}}},
        }
    },
)
def get_scan_tools(
    scan_id: str,
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_current_user),
) -> ScanToolsResponse:
    """Retorna uma linha por ferramenta ja' executada (ou pulada) nesta execucao.

    Complementa `tier{1,2,3}_status` do scan: o tier diz em que etapa o pipeline
    esta, isto diz o que aconteceu com cada ferramenta dentro dela — inclusive
    a diferenca entre "rodou e nao achou nada" (`status=done`,
    `findings_count=0`) e "quebrou" (`status=failed`, `reason` com o tipo da
    excecao), que antes se perdia no `return []` do `run_safe`.

    **Lista vazia e' resposta legitima**, e significa uma de duas coisas: o
    pipeline ainda nao chegou a nenhuma ferramenta, ou a execucao e' anterior a
    migration que criou a tabela (nada foi backfillado). Em ambos os casos o
    cliente cai para o status do tier — por isso `expected` sempre vem
    preenchido, mesmo quando `tools` esta vazio.

    `ia` traz o resumo da camada de I.A do Tier 3 quando existe relatorio desse
    tier (`None` caso contrario). E' um resumo, nao o `analysis_json`: o blob
    carrega o array `findings` completo com `raw_output`, e esta rota e' chamada
    uma vez por card da lista de Scans.
    """
    job = _owned_job_or_404(db, scan_id, user_id)
    runs = SQLAlchemyScanToolRunRepository(db).list_by_scan_job(job.id)
    # Reaproveita o repositorio de relatorios: o resumo de I.A e' derivado do
    # relatorio de tier 3 desta execucao, sem estado proprio em lugar nenhum.
    relatorio_tier3 = SQLAlchemyScanReportRepository(db).get_by_scan_job_and_tier(job.id, 3)
    return ScanToolsResponse(
        scan_id=job.id,
        commit_sha=job.commit_sha,
        tools=[ScanToolRunResponse.from_entity(r) for r in runs],
        expected={str(tier): list(tools) for tier, tools in sorted(TIER_TOOLS.items())},
        ia=(
            ScanIaSummary.from_analysis(relatorio_tier3.analysis_json)
            if relatorio_tier3 is not None
            else None
        ),
    )


@router.get(
    "/{scan_id}/tiers/{tier}/report",
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
    scan_id: str,
    tier: int = Path(..., ge=1, le=3),
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_current_user),
) -> ScanReportResponse:
    """Retorna o relatorio de um tier (1-3) daquela execução, se for do usuário."""
    job = _owned_job_or_404(db, scan_id, user_id)
    report = SQLAlchemyScanReportRepository(db).get_by_scan_job_and_tier(job.id, tier)
    if report is None:
        raise HTTPException(status_code=404, detail="Relatorio nao encontrado")

    return ScanReportResponse.from_entity(report)


@router.get(
    "/{scan_id}/history",
    response_model=ScanJobPage,
    summary="Listar execucoes anteriores do mesmo commit",
    responses={
        404: {
            "description": "Scan nao encontrado.",
            "content": {"application/json": {"example": {"detail": "Scan nao encontrado"}}},
        }
    },
)
def get_scan_history(
    scan_id: str,
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_current_user),
) -> ScanJobPage:
    """Todas as execuções daquele commit, da mais recente para a mais antiga.

    Existe porque rescanear a mesma branch deixou de sobrescrever a execução
    anterior. A lista inclui a própria execução consultada.
    """
    job = _owned_job_or_404(db, scan_id, user_id)
    execucoes = [
        j
        for j in SQLAlchemyScanJobRepository(db).list_by_commit(job.commit_sha)
        if j.user_id == user_id
    ]
    return ScanJobPage(
        items=[ScanJobSummary.from_entity(j) for j in execucoes],
        total=len(execucoes),
        limit=len(execucoes),
        offset=0,
    )


@router.post(
    "/{scan_id}/cancel",
    response_model=CancelScanResponse,
    summary="Cancelar uma execucao em andamento",
    responses={
        404: {"description": "Scan nao encontrado."},
        409: {
            "description": "Execucao ja' encerrada, ou disparada antes do cancelamento existir.",
            "content": {"application/json": {"example": {"detail": "Esta execucao ja' terminou."}}},
        },
    },
)
def cancel_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_current_user),
) -> CancelScanResponse:
    """Interrompe o pipeline: revoga o canvas e fecha os tiers pendentes.

    Os findings ja' gravados permanecem — o codigo foi analisado de verdade nas
    etapas que concluiram. Cancelar interrompe o que falta, nao invalida o que
    passou.
    """
    job = _owned_job_or_404(db, scan_id, user_id)
    repo = SQLAlchemyScanJobRepository(db)
    try:
        tiers = CancelScanUseCase(repo, SQLAlchemyScanToolRunRepository(db)).execute(job)
        db.commit()
    except ScanNotCancellableError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        logger.error("scan_cancel_falhou", scan_id=scan_id, error=str(exc))
        raise HTTPException(
            status_code=503, detail="Nao foi possivel cancelar agora. Tente novamente."
        ) from exc

    return CancelScanResponse(
        status="cancelled", scan_id=str(job.id), tiers_cancelados=tiers
    )
