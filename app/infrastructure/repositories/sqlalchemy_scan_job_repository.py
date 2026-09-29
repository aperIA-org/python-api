from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import case, func, or_, select, text, update
from sqlalchemy.orm import Session

from app.domain.scan.entities import STATUS_EM_ANDAMENTO, ScanJob
from app.domain.scan.repositories import ScanJobRepository
from app.domain.scan.value_objects import ScanTier, TierStatus
from app.infrastructure.persistence.models.scan_job_model import (
    EM_ANDAMENTO_SQL,
    ScanJobModel,
)


_TIER_PREFIX = {
    ScanTier.ONE: "tier1",
    ScanTier.TWO: "tier2",
    ScanTier.THREE: "tier3",
}

_INSERT_COLUMNS = tuple(ScanJobModel.__table__.columns.keys())

# Valores gravados na coluna de status dos tiers ainda não concluídos.
_VALORES_EM_ANDAMENTO = tuple(status.value for status in STATUS_EM_ANDAMENTO)

_TIER_PREFIXES = ("tier1", "tier2", "tier3")


# Quando a execução rodou. ``created_at`` marca a entrada do commit no sistema
# e é copiado nas reexecuções, então não serve para ordenar histórico.
_EXECUTADO_EM = func.coalesce(ScanJobModel.tier1_started_at, ScanJobModel.created_at)


def _id_execucao_corrente(commit_sha: str):
    """Subquery com o id da execução corrente daquele commit.

    Nenhuma task Celery conhece o id da execução — o canvas só carrega o
    ``commit_sha``. Enquanto havia uma linha por commit isso bastava; com
    histórico, um ``WHERE commit_sha = X`` atingiria TODAS as execuções de uma
    vez e reescreveria o passado. Aqui o alvo é sempre uma linha: a execução
    mais recente daquele commit, que é necessariamente a que está rodando — o
    índice unique parcial impede duas vivas ao mesmo tempo e uma nova só nasce
    depois que a anterior encerra.

    Ressalva conhecida: se um redisparo acontecer no intervalo entre o último
    tier encerrar e uma task atrasada da execução anterior escrever, a escrita
    atrasada cai na execução nova. Fechar isso exige levar o id da execução no
    canvas (ver docs/pendencias.md).
    """
    return (
        select(ScanJobModel.id)
        .where(ScanJobModel.commit_sha == commit_sha)
        .order_by(_EXECUTADO_EM.desc(), ScanJobModel.id.desc())
        .limit(1)
        .scalar_subquery()
    )


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

            # Alvo é o índice unique PARCIAL: só conflita com uma execução do
            # mesmo commit que ainda esteja em andamento. Uma execução encerrada
            # não impede a próxima — é isso que cria o histórico.
            stmt = pg_insert(ScanJobModel).values(row).on_conflict_do_nothing(
                index_elements=["commit_sha"], index_where=text(EM_ANDAMENTO_SQL)
            )
            self.db.execute(stmt)
            return

        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            stmt = sqlite_insert(ScanJobModel).values(row).on_conflict_do_nothing(
                index_elements=["commit_sha"], index_where=text(EM_ANDAMENTO_SQL)
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
        """A execução **mais recente** daquele commit.

        Com histórico o commit deixou de ter uma linha só; quem pergunta "como
        está o commit X" quer o estado corrente, e é isso que volta aqui. Para o
        histórico inteiro, ``list_by_commit``.
        """
        result = self.db.execute(
            select(ScanJobModel)
            .where(ScanJobModel.commit_sha == commit_sha)
            .order_by(_EXECUTADO_EM.desc(), ScanJobModel.id.desc())
            .limit(1)
        )
        model = result.scalars().first()
        return model.to_entity() if model else None

    def list_by_commit(self, commit_sha: str) -> list[ScanJob]:
        """Todas as execuções daquele commit, da mais recente para a mais antiga."""
        result = self.db.execute(
            select(ScanJobModel)
            .where(ScanJobModel.commit_sha == commit_sha)
            .order_by(_EXECUTADO_EM.desc(), ScanJobModel.id.desc())
        )
        return [m.to_entity() for m in result.scalars().all()]

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
            .where(ScanJobModel.id == _id_execucao_corrente(commit_sha))
            .values(**values)
        )
        self.db.flush()

    def set_blocked(self, commit_sha: str, blocked_at: ScanTier) -> None:
        self.db.execute(
            update(ScanJobModel)
            .where(ScanJobModel.id == _id_execucao_corrente(commit_sha))
            .values(blocked_at_tier=blocked_at.value)
        )
        self.db.flush()

    def set_final_risk(self, commit_sha: str, score: int | None, level: str | None) -> None:
        self.db.execute(
            update(ScanJobModel)
            .where(ScanJobModel.id == _id_execucao_corrente(commit_sha))
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
            .where(ScanJobModel.id == _id_execucao_corrente(commit_sha))
            .values(**values)
        )
        self.db.flush()

    def set_celery_task_id(self, commit_sha: str, task_id: str) -> None:
        """Guarda a raiz do canvas da execução corrente daquele commit."""
        self.db.execute(
            update(ScanJobModel)
            .where(ScanJobModel.id == _id_execucao_corrente(commit_sha))
            .values(celery_task_id=task_id)
        )
        self.db.flush()

    def cancel_pending_tiers(self, job_id: UUID) -> int:
        """Encerra como ``cancelled`` todo tier ainda ``queued``/``running``.

        Gêmeo de ``fail_pending_tiers``, com dois desvios deliberados: fecha em
        ``cancelled`` (nada quebrou — alguém parou) e é endereçado por **id de
        execução**, não por commit, porque quem cancela está olhando uma
        execução concreta na tela.

        Devolve quantos tiers foram de fato interrompidos: zero significa que a
        execução já havia terminado, e aí a rota responde 409 em vez de fingir
        que cancelou.
        """
        agora = datetime.utcnow()
        values: dict = {}
        for prefix in _TIER_PREFIXES:
            coluna_status = getattr(ScanJobModel, f"{prefix}_status")
            coluna_fim = getattr(ScanJobModel, f"{prefix}_completed_at")
            pendente = coluna_status.in_(_VALORES_EM_ANDAMENTO)
            values[f"{prefix}_status"] = case(
                (pendente, TierStatus.CANCELLED.value), else_=coluna_status
            )
            values[f"{prefix}_completed_at"] = case((pendente, agora), else_=coluna_fim)

        resultado = self.db.execute(
            update(ScanJobModel)
            .where(
                ScanJobModel.id == job_id,
                # Só conta como cancelamento se havia o que cancelar.
                or_(*[
                    getattr(ScanJobModel, f"{p}_status").in_(_VALORES_EM_ANDAMENTO)
                    for p in _TIER_PREFIXES
                ]),
            )
            .values(**values)
        )
        self.db.flush()
        return resultado.rowcount or 0

    def list_recent(self, *, limit: int = 50, offset: int = 0) -> list[ScanJob]:
        result = self.db.execute(
            select(ScanJobModel)
            .order_by(_EXECUTADO_EM.desc())
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
            .order_by(_EXECUTADO_EM.desc())
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
            .order_by(_EXECUTADO_EM.desc())
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
