"""Persistência best-effort de findings a partir dos scan workers.

Os workers Celery são síncronos e rodam fora do request cycle — abrem
a própria ``Session`` via ``SessionLocal``. A escrita é **best-effort**:
uma falha de banco é logada mas NÃO interrompe o pipeline. O scan já
produziu o resultado em memória, e o gate / análise do Claude operam
sobre os dicts que trafegam no canvas Celery, não sobre o banco.

Dedup cross-tier: ``bulk_save`` usa ``ON CONFLICT DO NOTHING`` na UNIQUE
``findings_dedup_key`` — T1, T2 e T3 podem persistir o mesmo finding
(mesma ``dedup_key``) sem duplicar linhas. É exatamente a "segunda
barreira" descrita no docstring do ``tier2_scan_worker``.
"""
from __future__ import annotations

import structlog

from app.config import settings
from app.domain.finding.entities import Finding
from app.infrastructure.database.sqlalchemy import SessionLocal
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)

logger = structlog.get_logger()


def persist_findings(findings: list[Finding], *, commit_sha: str, tier: int) -> int:
    """Persiste ``findings`` de forma idempotente. Retorna o nº persistido.

    Best-effort por design: qualquer erro (banco indisponível, schema
    desalinhado) é logado como warning e engolido — o scan nunca falha
    por causa da persistência.
    """
    if not settings.FINDINGS_PERSISTENCE_ENABLED:
        return 0
    if not findings:
        return 0

    try:
        with SessionLocal() as db:
            SQLAlchemyFindingRepository(db).bulk_save(findings)
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort: nunca quebra o scan
        logger.warning(
            "finding_persistence_failed",
            commit_sha=commit_sha,
            tier=tier,
            count=len(findings),
            error=str(exc),
        )
        return 0

    logger.info(
        "findings_persisted",
        commit_sha=commit_sha,
        tier=tier,
        count=len(findings),
    )
    return len(findings)
