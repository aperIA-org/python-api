from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.domain.scan.entities import ScanJob
from app.domain.scan.repositories import ScanJobRepository
from app.domain.scan.value_objects import ScanTier, TierStatus
from app.infrastructure.persistence.models.scan_job_model import ScanJobModel


_TIER_PREFIX = {
    ScanTier.ONE: "tier1",
    ScanTier.TWO: "tier2",
    ScanTier.THREE: "tier3",
}

_INSERT_COLUMNS = tuple(ScanJobModel.__table__.columns.keys())


def _to_row(job: ScanJob) -> dict:
    model = ScanJobModel.from_entity(job)
    return {col: getattr(model, col) for col in _INSERT_COLUMNS}


class SQLAlchemyScanJobRepository(ScanJobRepository):
    """Repositório síncrono — consumido pelos workers Celery (sync) via
    ``SessionLocal`` e pelos testes via uma ``Session`` sqlite.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, job: ScanJob) -> None:
        row = _to_row(job)
        dialect = self.db.bind.dialect.name if self.db.bind else "postgresql"

        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            stmt = pg_insert(ScanJobModel).values(row).on_conflict_do_nothing(
                constraint="scan_jobs_commit_sha_key"
            )
            self.db.execute(stmt)
            return

        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            stmt = sqlite_insert(ScanJobModel).values(row).on_conflict_do_nothing(
                index_elements=["commit_sha"]
            )
            self.db.execute(stmt)
            return

        # Fallback: insere e engole IntegrityError (defense-in-depth).
        from sqlalchemy.exc import IntegrityError

        try:
            self.db.add(ScanJobModel.from_entity(job))
            self.db.flush()
        except IntegrityError:
            self.db.rollback()

    def get_by_id(self, job_id: UUID) -> ScanJob | None:
        result = self.db.execute(
            select(ScanJobModel).where(ScanJobModel.id == job_id)
        )
        model = result.scalars().first()
        return model.to_entity() if model else None

    def get_by_commit(self, commit_sha: str) -> ScanJob | None:
        result = self.db.execute(
            select(ScanJobModel).where(ScanJobModel.commit_sha == commit_sha)
        )
        model = result.scalars().first()
        return model.to_entity() if model else None

    def update_tier_status(
        self, commit_sha: str, tier: ScanTier, status: TierStatus
    ) -> None:
        prefix = _TIER_PREFIX[tier]
        values: dict = {f"{prefix}_status": status.value}
        if status == TierStatus.RUNNING:
            values[f"{prefix}_started_at"] = datetime.utcnow()
        elif status in (TierStatus.DONE, TierStatus.SKIPPED, TierStatus.FAILED):
            values[f"{prefix}_completed_at"] = datetime.utcnow()

        self.db.execute(
            update(ScanJobModel)
            .where(ScanJobModel.commit_sha == commit_sha)
            .values(**values)
        )
        self.db.flush()

    def set_blocked(self, commit_sha: str, blocked_at: ScanTier) -> None:
        self.db.execute(
            update(ScanJobModel)
            .where(ScanJobModel.commit_sha == commit_sha)
            .values(blocked_at_tier=blocked_at.value)
        )
        self.db.flush()

    def set_final_risk(self, commit_sha: str, score: int | None, level: str | None) -> None:
        self.db.execute(
            update(ScanJobModel)
            .where(ScanJobModel.commit_sha == commit_sha)
            .values(final_risk_score=score, final_risk_level=level)
        )
        self.db.flush()

    def list_recent(self, *, limit: int = 50, offset: int = 0) -> list[ScanJob]:
        result = self.db.execute(
            select(ScanJobModel)
            .order_by(ScanJobModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return [m.to_entity() for m in result.scalars().all()]

    def count(self) -> int:
        stmt = select(func.count()).select_from(ScanJobModel)
        return self.db.execute(stmt).scalar_one()
