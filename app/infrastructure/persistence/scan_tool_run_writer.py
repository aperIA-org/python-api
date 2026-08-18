"""Persistência best-effort do status por ferramenta (``scan_tool_runs``).

Mesmo contrato dos demais writers deste pacote: gated por
``settings.SCAN_PERSISTENCE_ENABLED``, envolvido em ``try/except`` e **nunca**
interrompe o pipeline. Um scanner que rodou e um banco que não respondeu são
problemas independentes — o segundo não pode transformar o primeiro em falha.

Por que existe: ``ScanJob`` só tem status por TIER, e ``BaseScanner.run_safe``
devolve ``[]`` tanto quando a ferramenta não achou nada quanto quando ela
estourou. O desfecho de cada ferramenta existia apenas na linha do structlog.
Esta tabela é a projeção consumível dessa informação.
"""
from __future__ import annotations

from datetime import datetime

import structlog

from app.config import settings
from app.domain.scan.tool_run_entities import ScanToolRun
from app.domain.scan.value_objects import ToolStatus
from app.infrastructure.database.sqlalchemy import SessionLocal
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_tool_run_repository import (
    SQLAlchemyScanToolRunRepository,
)

logger = structlog.get_logger()

# Limite da coluna. Um traceback inteiro em `reason` não cabe e não ajuda: o
# detalhe completo continua no structlog.
_REASON_MAX = 200


def record_tool_run(
    *,
    commit_sha: str,
    tier: int,
    tool: str,
    status: ToolStatus,
    reason: str | None = None,
    findings_count: int | None = None,
    duration_ms: int | None = None,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
) -> None:
    """Registra (upsert) o desfecho de uma ferramenta. Best-effort."""
    if not settings.SCAN_PERSISTENCE_ENABLED or not commit_sha or not tool:
        return
    try:
        with SessionLocal() as db:
            # A execução corrente do commit é a dona da linha. Sem ela não há
            # onde pendurar (``scan_job_id`` é NOT NULL) — e uma linha órfã não
            # seria alcançável por rota nenhuma.
            job = SQLAlchemyScanJobRepository(db).get_by_commit(commit_sha)
            if job is None:
                logger.warning(
                    "scan_tool_run_sem_execucao", commit_sha=commit_sha, tool=tool
                )
                return
            SQLAlchemyScanToolRunRepository(db).save(
                ScanToolRun(
                    commit_sha=commit_sha,
                    tier=tier,
                    tool=tool,
                    status=status,
                    scan_job_id=job.id,
                    reason=(reason or None) and reason[:_REASON_MAX],
                    findings_count=findings_count,
                    duration_ms=duration_ms,
                    started_at=started_at,
                    completed_at=completed_at,
                )
            )
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort: nunca quebra o scan
        logger.warning(
            "scan_tool_run_persist_failed",
            commit_sha=commit_sha,
            tool=tool,
            error=str(exc),
        )
