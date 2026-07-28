"""Persistência best-effort dos relatórios de tier (``scan_reports``).

Chamado pelo ``reporting_worker`` depois de montar o markdown e postar no
PR. Mesmo racional dos demais writers: escrita gated por
``settings.SCAN_PERSISTENCE_ENABLED`` e envolvida em ``try/except`` — uma
falha de banco é logada mas NUNCA interrompe o pipeline (o relatório já foi
postado no PR; o banco é só a projeção consumível via API).

Idempotente: o ``save`` do repositório faz ON CONFLICT (commit_sha, tier)
DO UPDATE — um replay do canvas (acks_late) substitui o relatório.
"""
from __future__ import annotations

from typing import Any

import structlog

from app.config import settings
from app.domain.scan.report_entities import ScanReport
from app.infrastructure.database.sqlalchemy import SessionLocal
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_report_repository import (
    SQLAlchemyScanReportRepository,
)

logger = structlog.get_logger()


def persist_report(
    *,
    commit_sha: str,
    tier: int,
    report_markdown: str,
    analysis_json: dict[str, Any] | None,
    degraded: bool,
    comment_id: int | None,
    posted: bool,
) -> None:
    """Persiste (upsert) o relatório de um tier. Best-effort."""
    if not settings.SCAN_PERSISTENCE_ENABLED or not commit_sha:
        return
    try:
        with SessionLocal() as db:
            # Vincula ao ScanJob do commit, se existir (best-effort).
            job = SQLAlchemyScanJobRepository(db).get_by_commit(commit_sha)
            report = ScanReport(
                commit_sha=commit_sha,
                tier=tier,
                report_markdown=report_markdown,
                scan_job_id=job.id if job else None,
                analysis_json=analysis_json or {},
                degraded=degraded,
                comment_id=comment_id,
                posted=posted,
            )
            SQLAlchemyScanReportRepository(db).save(report)
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort: nunca quebra o reporting
        logger.warning(
            "scan_report_persist_failed",
            commit_sha=commit_sha,
            tier=tier,
            error=str(exc),
        )
        return
    logger.info("scan_report_persisted", commit_sha=commit_sha, tier=tier)
