from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.scan.report_entities import ScanReport
from app.domain.scan.report_repository import ScanReportRepository
from app.infrastructure.persistence.models.scan_job_model import ScanJobModel
from app.infrastructure.persistence.models.scan_report_model import ScanReportModel


# Colunas atualizadas em caso de conflito. O conflito agora só acontece dentro
# da MESMA execução — replay do canvas (acks_late) reescrevendo o relatório do
# mesmo tier. Uma reexecução tem outro ``scan_job_id`` e por isso insere uma
# linha nova em vez de apagar a anterior.
# NÃO inclui id/scan_job_id/tier — essas identificam a linha.
_SET_COLUMNS = (
    "report_markdown",
    "analysis_json",
    "degraded",
    "comment_id",
    "posted",
    "commit_sha",
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
                constraint="scan_reports_job_tier_key",
                set_={c: getattr(stmt.excluded, c) for c in _SET_COLUMNS},
            )
            self.db.execute(stmt)
            return

        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            stmt = sqlite_insert(ScanReportModel).values(row)
            stmt = stmt.on_conflict_do_update(
                index_elements=["scan_job_id", "tier"],
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
                    ScanReportModel.scan_job_id == report.scan_job_id,
                    ScanReportModel.tier == report.tier,
                )
                .values(**{c: row[c] for c in _SET_COLUMNS})
            )

    def get_by_scan_job(self, scan_job_id: UUID) -> list[ScanReport]:
        """Os relatórios de UMA execução (um por tier). É a leitura correta
        agora que o mesmo commit pode ter várias."""
        result = self.db.execute(
            select(ScanReportModel)
            .where(ScanReportModel.scan_job_id == scan_job_id)
            .order_by(ScanReportModel.tier)
        )
        return [m.to_entity() for m in result.scalars().all()]

    def get_by_scan_job_and_tier(self, scan_job_id: UUID, tier: int) -> ScanReport | None:
        result = self.db.execute(
            select(ScanReportModel).where(
                ScanReportModel.scan_job_id == scan_job_id,
                ScanReportModel.tier == tier,
            )
        )
        model = result.scalars().first()
        return model.to_entity() if model else None

    def list_by_repository(self, repository_id: UUID) -> list[ScanReport]:
        """Relatórios de todas as execuções de um repositório.

        A junção é por ``scan_job_id``, não por ``commit_sha``: com histórico, o
        mesmo commit tem várias execuções e filtrar pelo sha traria os
        relatórios de todas elas mesmo que só uma execução pertencesse ao
        repositório. A ordenação leva a execução junto para que relatórios do
        mesmo tier de execuções diferentes não fiquem intercalados.
        """
        result = self.db.execute(
            select(ScanReportModel)
            .where(
                ScanReportModel.scan_job_id.in_(
                    select(ScanJobModel.id).where(
                        ScanJobModel.repository_id == repository_id
                    )
                )
            )
            .order_by(ScanReportModel.scan_job_id, ScanReportModel.tier)
        )
        return [m.to_entity() for m in result.scalars().all()]
