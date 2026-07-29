"""Persistência best-effort do ciclo de vida do ``ScanJob``.

Mesmo racional do ``finding_writer``: os workers Celery são síncronos e
abrem a própria ``Session`` via ``SessionLocal``. A escrita é
**best-effort** — qualquer falha de banco é logada mas NUNCA interrompe o
pipeline. O canvas Celery opera sobre os dicts que trafegam entre as
tasks, não sobre o banco; o ``scan_jobs`` é apenas a projeção consumível
via API (``GET /scans``).

Tudo é chaveado por ``commit_sha`` (a chave natural que já flui no canvas)
e gated por ``settings.SCAN_PERSISTENCE_ENABLED`` (testes desligam).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import structlog

from app.config import settings
from app.domain.scan.entities import ScanJob
from app.domain.scan.value_objects import ScanTier, TierStatus
from app.infrastructure.database.sqlalchemy import SessionLocal
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)

logger = structlog.get_logger()


def create_scan_job(
    *,
    commit_sha: str,
    repo_url: str,
    installation_id: int,
    pr_number: int | None = None,
    repo_full_name: str | None = None,
    user_id: UUID | None = None,
    repository_id: UUID | None = None,
) -> None:
    """Cria (idempotente) o ``ScanJob`` no início do pipeline, com o Tier 1
    já em ``running``. Re-execuções (acks_late replay) não duplicam — o
    ``save`` usa ON CONFLICT na UNIQUE de ``commit_sha``.

    ``user_id``/``repository_id`` atribuem o scan ao dono (multi-tenant); ficam
    ``None`` para webhooks de repositórios não cadastrados (scan órfão, que não
    aparece na leitura isolada de nenhum usuário).
    """
    if not settings.SCAN_PERSISTENCE_ENABLED:
        return
    try:
        job = ScanJob(
            commit_sha=commit_sha,
            repo_url=repo_url,
            installation_id=installation_id,
            pr_number=pr_number,
            repo_full_name=repo_full_name,
            tier1_status=TierStatus.RUNNING,
            tier1_started_at=datetime.utcnow(),
            user_id=user_id,
            repository_id=repository_id,
        )
        with SessionLocal() as db:
            SQLAlchemyScanJobRepository(db).save(job)
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort: nunca quebra o pipeline
        logger.warning("scan_job_create_failed", commit_sha=commit_sha, error=str(exc))
        return
    logger.info("scan_job_created", commit_sha=commit_sha)


def mark_tier(commit_sha: str, tier: int, status: str) -> None:
    """Atualiza o status de um tier (best-effort). ``tier`` 1..3, ``status``
    é o valor de ``TierStatus`` (ex.: "running", "done", "skipped").
    """
    if not settings.SCAN_PERSISTENCE_ENABLED or not commit_sha:
        return
    try:
        with SessionLocal() as db:
            SQLAlchemyScanJobRepository(db).update_tier_status(
                commit_sha, ScanTier(tier), TierStatus(status)
            )
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.warning(
            "scan_job_tier_update_failed",
            commit_sha=commit_sha,
            tier=tier,
            status=status,
            error=str(exc),
        )


def mark_blocked(commit_sha: str, tier: int) -> None:
    """Registra em qual tier o pipeline foi bloqueado (best-effort)."""
    if not settings.SCAN_PERSISTENCE_ENABLED or not commit_sha:
        return
    try:
        with SessionLocal() as db:
            SQLAlchemyScanJobRepository(db).set_blocked(commit_sha, ScanTier(tier))
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.warning(
            "scan_job_block_update_failed", commit_sha=commit_sha, tier=tier, error=str(exc)
        )


def set_final_risk_from_analysis(commit_sha: str, analysis: dict[str, Any] | None) -> None:
    """Extrai o risco da análise do Claude e persiste no ``ScanJob``.

    Aceita tanto o formato do Tier 2 (``risk_score``) quanto o do Tier 3
    (``risk_score_adjusted``), ambos no shape ``{"score": int, "level": str}``.
    Best-effort: se o dado não existe, apenas não escreve.
    """
    if not settings.SCAN_PERSISTENCE_ENABLED or not commit_sha or not analysis:
        return
    risk = analysis.get("risk_score_adjusted") or analysis.get("risk_score")
    if not isinstance(risk, dict):
        return
    score = risk.get("score")
    level = risk.get("level")
    try:
        with SessionLocal() as db:
            SQLAlchemyScanJobRepository(db).set_final_risk(commit_sha, score, level)
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.warning(
            "scan_job_final_risk_update_failed", commit_sha=commit_sha, error=str(exc)
        )
