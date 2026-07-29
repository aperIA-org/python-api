from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.scan.report_entities import ScanReport
from app.domain.scan.report_repository import ScanReportRepository
from app.infrastructure.persistence.models.scan_job_model import ScanJobModel
from app.infrastructure.persistence.models.scan_report_model import ScanReportModel


# Colunas atualizadas em caso de conflito (re-execução do pipeline substitui o
# relatório). NÃO inclui id/commit_sha/tier — essas identificam a linha.
_SET_COLUMNS = (
    "report_markdown",
    "analysis_json",
    "degraded",
    "comment_id",
    "posted",
    "scan_job_id",
    "created_at",
)


class SQLAlchemyScanReportRepository(ScanReportRepository):
    """Repositório síncrono — consumido pelos workers Celery (sync) via
    ``SessionLocal`` e pelos testes via uma ``Session`` sqlite.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, report: ScanReport) -> None:
        row = {
            col: getattr(ScanReportModel.from_entity(report), col)
            for col in ScanReportModel.__table__.columns.keys()
        }
        dialect = self.db.bind.dialect.name if self.db.bind else "postgresql"

        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            stmt = pg_insert(ScanReportModel).values(row)
            stmt = stmt.on_conflict_do_update(
                constraint="scan_reports_commit_tier_key",
                set_={c: getattr(stmt.excluded, c) for c in _SET_COLUMNS},
            )
            self.db.execute(stmt)
            return

        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            stmt = sqlite_insert(ScanReportModel).values(row)
            stmt = stmt.on_conflict_do_update(
                index_elements=["commit_sha", "tier"],
                set_={c: getattr(stmt.excluded, c) for c in _SET_COLUMNS},
            )
            self.db.execute(stmt)
            return

        # Fallback: insere e, em caso de conflito, faz UPDATE manual
        # (defense-in-depth para dialetos sem suporte a ON CONFLICT).
        from sqlalchemy import update
        from sqlalchemy.exc import IntegrityError

        try:
            self.db.add(ScanReportModel.from_entity(report))
            self.db.flush()
        except IntegrityError:
            self.db.rollback()
            self.db.execute(
                update(ScanReportModel)
                .where(
                    ScanReportModel.commit_sha == report.commit_sha,
                    ScanReportModel.tier == report.tier,
                )
                .values(**{c: row[c] for c in _SET_COLUMNS})
            )

    def get_by_commit(self, commit_sha: str) -> list[ScanReport]:
        result = self.db.execute(
            select(ScanReportModel)
            .where(ScanReportModel.commit_sha == commit_sha)
            .order_by(ScanReportModel.tier)
        )
        return [m.to_entity() for m in result.scalars().all()]

    def get_by_commit_and_tier(self, commit_sha: str, tier: int) -> ScanReport | None:
        result = self.db.execute(
            select(ScanReportModel).where(
                ScanReportModel.commit_sha == commit_sha,
                ScanReportModel.tier == tier,
            )
        )
        model = result.scalars().first()
        return model.to_entity() if model else None

    def list_by_repository(self, repository_id: UUID) -> list[ScanReport]:
        result = self.db.execute(
            select(ScanReportModel)
            .where(
                ScanReportModel.commit_sha.in_(
                    select(ScanJobModel.commit_sha).where(
                        ScanJobModel.repository_id == repository_id
                    )
                )
            )
            .order_by(ScanReportModel.tier)
        )
        return [m.to_entity() for m in result.scalars().all()]
