from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import case, func, or_, select, update
from sqlalchemy.orm import Session

from app.domain.scan.entities import STATUS_EM_ANDAMENTO, ScanJob
from app.domain.scan.repositories import ScanJobRepository
from app.domain.scan.value_objects import ScanTier, TierStatus
from app.infrastructure.persistence.models.scan_job_model import ScanJobModel


_TIER_PREFIX = {
    ScanTier.ONE: "tier1",
    ScanTier.TWO: "tier2",
    ScanTier.THREE: "tier3",
}

_INSERT_COLUMNS = tuple(ScanJobModel.__table__.columns.keys())

# Valores gravados na coluna de status dos tiers ainda não concluídos.
_VALORES_EM_ANDAMENTO = tuple(status.value for status in STATUS_EM_ANDAMENTO)

_TIER_PREFIXES = ("tier1", "tier2", "tier3")


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

    def list_in_progress(self) -> list[ScanJob]:
        result = self.db.execute(
            select(ScanJobModel)
            .where(
                or_(
                    *(
                        getattr(ScanJobModel, f"{prefix}_status").in_(
                            _VALORES_EM_ANDAMENTO
                        )
                        for prefix in _TIER_PREFIXES
                    )
                )
            )
            .order_by(ScanJobModel.created_at.asc())
        )
        return [m.to_entity() for m in result.scalars().all()]

    def fail_pending_tiers(self, commit_sha: str) -> None:
        agora = datetime.utcnow()
        values: dict = {}
        for prefix in _TIER_PREFIXES:
            coluna_status = getattr(ScanJobModel, f"{prefix}_status")
            coluna_fim = getattr(ScanJobModel, f"{prefix}_completed_at")
            pendente = coluna_status.in_(_VALORES_EM_ANDAMENTO)
            # CASE em vez de um UPDATE por tier: um único statement e os tiers
            # já concluídos ficam intactos (não reescrevemos done/skipped).
            values[f"{prefix}_status"] = case(
                (pendente, TierStatus.FAILED.value), else_=coluna_status
            )
            values[f"{prefix}_completed_at"] = case(
                (pendente, agora), else_=coluna_fim
            )

        self.db.execute(
            update(ScanJobModel)
            .where(ScanJobModel.commit_sha == commit_sha)
            .values(**values)
        )
        self.db.flush()

    def restart_execution(self, commit_sha: str, *, started_at: datetime) -> None:
        # Zera tudo que descreve a execução anterior e recoloca o Tier 1 em
        # "running" — o mesmo estado com que a linha nasceria se fosse nova.
        # ``created_at`` NÃO é tocado: ele marca quando o commit entrou no
        # sistema pela primeira vez.
        self.db.execute(
            update(ScanJobModel)
            .where(ScanJobModel.commit_sha == commit_sha)
            .values(
                tier1_status=TierStatus.RUNNING.value,
                tier1_started_at=started_at,
                tier1_completed_at=None,
                tier2_status=None,
                tier2_started_at=None,
                tier2_completed_at=None,
                tier3_status=None,
                tier3_started_at=None,
                tier3_completed_at=None,
                blocked_at_tier=None,
                final_risk_score=None,
                final_risk_level=None,
            )
        )
        self.db.flush()

    # Ordenar por ``created_at`` afundaria uma reexecução: ``restart_execution``
    # preserva o ``created_at`` (entrada do commit no sistema) e só reseta os
    # timestamps de tier, então rescanear um commit antigo o deixava no fim da
    # lista mesmo tendo acabado de rodar. O COALESCE cobre jobs enfileirados que
    # ainda não iniciaram o Tier 1.
    _EXECUTADO_EM = func.coalesce(ScanJobModel.tier1_started_at, ScanJobModel.created_at)

    def list_recent(self, *, limit: int = 50, offset: int = 0) -> list[ScanJob]:
        result = self.db.execute(
            select(ScanJobModel)
            .order_by(self._EXECUTADO_EM.desc())
            .limit(limit)
            .offset(offset)
        )
        return [m.to_entity() for m in result.scalars().all()]

    def count(self) -> int:
        stmt = select(func.count()).select_from(ScanJobModel)
        return self.db.execute(stmt).scalar_one()

    def list_by_user(self, user_id: UUID, *, limit: int = 50, offset: int = 0) -> list[ScanJob]:
        result = self.db.execute(
            select(ScanJobModel)
            .where(ScanJobModel.user_id == user_id)
            .order_by(self._EXECUTADO_EM.desc())
            .limit(limit)
            .offset(offset)
        )
        return [m.to_entity() for m in result.scalars().all()]

    def count_by_user(self, user_id: UUID) -> int:
        stmt = (
            select(func.count())
            .select_from(ScanJobModel)
            .where(ScanJobModel.user_id == user_id)
        )
        return self.db.execute(stmt).scalar_one()

    def list_by_repository(
        self, repository_id: UUID, *, limit: int = 50, offset: int = 0
    ) -> list[ScanJob]:
        result = self.db.execute(
            select(ScanJobModel)
            .where(ScanJobModel.repository_id == repository_id)
            .order_by(self._EXECUTADO_EM.desc())
            .limit(limit)
            .offset(offset)
        )
        return [m.to_entity() for m in result.scalars().all()]

    def count_by_repository(self, repository_id: UUID) -> int:
        stmt = (
            select(func.count())
            .select_from(ScanJobModel)
            .where(ScanJobModel.repository_id == repository_id)
        )
        return self.db.execute(stmt).scalar_one()
