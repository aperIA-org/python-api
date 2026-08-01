"""Persistência de findings a partir dos scan workers.

Os workers Celery são síncronos e rodam fora do request cycle — abrem
a própria ``Session`` via ``SessionLocal``.

**Não é best-effort, e isso é deliberado.** A escrita já foi best-effort e o
custo apareceu: um ``cwe_id`` de 93 caracteres numa coluna de 50 fez o
``INSERT`` estourar, o erro virou warning, e o pipeline concluiu anunciando
sucesso. O finding existia no payload do canvas e alimentou o Tier 2 — mas
nunca chegou ao banco, e o dashboard, que lê de ``GET /findings``, mostrava
zero. Indistinguível de repositório limpo.

O argumento antigo era que o gate e a análise operam sobre os dicts do canvas,
não sobre o banco. É verdade e continua valendo — mas descreve o *pipeline*, não
o *produto*. Quem usa o aperIA lê o banco. Perder findings em silêncio é pior
do que falhar: a falha é visível e o scan pode ser reexecutado.

Dedup cross-tier: ``bulk_save`` usa ``ON CONFLICT DO NOTHING`` na UNIQUE
``findings_dedup_key`` — T1, T2 e T3 podem persistir o mesmo finding
(mesma ``dedup_key``) sem duplicar linhas. É exatamente a "segunda
barreira" descrita no docstring do ``tier2_scan_worker``.
"""
from __future__ import annotations

import structlog

from app.config import settings
from app.core.exceptions import FindingPersistenceError
from app.domain.finding.entities import Finding
from app.infrastructure.database.sqlalchemy import SessionLocal
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)

logger = structlog.get_logger()


def persist_findings(findings: list[Finding], *, commit_sha: str, tier: int) -> int:
    """Persiste ``findings`` de forma idempotente. Retorna o nº persistido.

    Levanta ``FindingPersistenceError`` se havia findings e a gravação falhou —
    banco indisponível, schema desalinhado, valor fora do tamanho da coluna.

    Dois casos continuam devolvendo ``0`` sem erro, porque em nenhum deles há
    perda: persistência desligada por configuração
    (``FINDINGS_PERSISTENCE_ENABLED``) e lista vazia.
    """
    if not settings.FINDINGS_PERSISTENCE_ENABLED:
        return 0
    if not findings:
        return 0

    try:
        with SessionLocal() as db:
            SQLAlchemyFindingRepository(db).bulk_save(findings)
            db.commit()
    except Exception as exc:
        logger.error(
            "finding_persistence_failed",
            commit_sha=commit_sha,
            tier=tier,
            count=len(findings),
            error=str(exc),
        )
        raise FindingPersistenceError(
            f"nao foi possivel gravar {len(findings)} finding(s) do tier {tier}: {exc}"
        ) from exc

    logger.info(
        "findings_persisted",
        commit_sha=commit_sha,
        tier=tier,
        count=len(findings),
    )
    return len(findings)
