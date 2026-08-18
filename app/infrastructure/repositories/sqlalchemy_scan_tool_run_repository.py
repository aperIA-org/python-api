from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.scan.tool_run_entities import ScanToolRun
from app.domain.scan.tool_run_repository import ScanToolRunRepository
from app.infrastructure.persistence.models.scan_tool_run_model import ScanToolRunModel

# Colunas reescritas no conflito. NÃO inclui id/scan_job_id/tool — essas
# identificam a linha. `created_at` fica de fora de propósito: ela marca quando
# a ferramenta apareceu nesta execução, e um replay não deve reescrever isso
# (é `started_at`/`completed_at` que descrevem a rodada).
_SET_COLUMNS = (
    "commit_sha",
    "tier",
    "status",
    "reason",
    "findings_count",
    "duration_ms",
    "started_at",
    "completed_at",
)


class SQLAlchemyScanToolRunRepository(ScanToolRunRepository):
    """Repositório síncrono — usado pelos workers Celery via ``SessionLocal`` e
    pelas rotas via a ``Session`` do request.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, run: ScanToolRun) -> None:
        model = ScanToolRunModel.from_entity(run)
        row = {col: getattr(model, col) for col in ScanToolRunModel.__table__.columns.keys()}
        dialect = self.db.bind.dialect.name if self.db.bind else "postgresql"

        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            stmt = pg_insert(ScanToolRunModel).values(row)
            stmt = stmt.on_conflict_do_update(
                constraint="scan_tool_runs_job_tool_key",
                set_={c: getattr(stmt.excluded, c) for c in _SET_COLUMNS},
            )
            self.db.execute(stmt)
            return

        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            stmt = sqlite_insert(ScanToolRunModel).values(row)
            stmt = stmt.on_conflict_do_update(
                index_elements=["scan_job_id", "tool"],
                set_={c: getattr(stmt.excluded, c) for c in _SET_COLUMNS},
            )
            self.db.execute(stmt)
            return

        # Fallback para dialetos sem ON CONFLICT (defense-in-depth, igual ao
        # repositório de relatórios).
        from sqlalchemy import update
        from sqlalchemy.exc import IntegrityError

        try:
            self.db.add(ScanToolRunModel.from_entity(run))
            self.db.flush()
        except IntegrityError:
            self.db.rollback()
            self.db.execute(
                update(ScanToolRunModel)
                .where(
                    ScanToolRunModel.scan_job_id == run.scan_job_id,
                    ScanToolRunModel.tool == run.tool,
                )
                .values(**{c: row[c] for c in _SET_COLUMNS})
            )

    def list_by_scan_job(self, scan_job_id: UUID) -> list[ScanToolRun]:
        result = self.db.execute(
            select(ScanToolRunModel)
            .where(ScanToolRunModel.scan_job_id == scan_job_id)
            .order_by(ScanToolRunModel.tier, ScanToolRunModel.tool)
        )
        return [m.to_entity() for m in result.scalars().all()]
