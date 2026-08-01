from __future__ import annotations

from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.domain.github.entities import GithubAccount
from app.domain.github.repositories import GithubAccountRepository
from app.infrastructure.persistence.models.github_account_model import GithubAccountModel

_UPDATE_COLUMNS = ("user_id", "github_login", "account_type")
_INSERT_COLUMNS = tuple(GithubAccountModel.__table__.columns.keys())


def _to_row(account: GithubAccount) -> dict:
    model = GithubAccountModel.from_entity(account)
    return {col: getattr(model, col) for col in _INSERT_COLUMNS}


class SQLAlchemyGithubAccountRepository(GithubAccountRepository):
    """Repositório síncrono — consumido pelas rotas/serviços via ``Session``."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, account: GithubAccount) -> None:
        row = _to_row(account)
        dialect = self.db.bind.dialect.name if self.db.bind else "postgresql"

        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            stmt = pg_insert(GithubAccountModel).values(row)
            stmt = stmt.on_conflict_do_update(
                constraint="github_accounts_installation_key",
                set_={col: getattr(stmt.excluded, col) for col in _UPDATE_COLUMNS},
            )
            self.db.execute(stmt)
            return

        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            stmt = sqlite_insert(GithubAccountModel).values(row)
            stmt = stmt.on_conflict_do_update(
                index_elements=["installation_id"],
                set_={col: getattr(stmt.excluded, col) for col in _UPDATE_COLUMNS},
            )
            self.db.execute(stmt)
            return

        # Fallback (dialeto sem ON CONFLICT): insere dentro de um SAVEPOINT e,
        # em caso de conflito, atualiza a linha existente — mesma semântica de
        # upsert dos dialetos acima.
        #
        # O `self.db.rollback()` que estava aqui derrubava a transação INTEIRA
        # do caller, não só o insert que falhou: o callback do GitHub faz mais
        # escritas depois deste `save`, e todas se perdiam em silêncio. É o
        # mesmo defeito já corrigido em `sqlalchemy_repository_repository.py`;
        # `begin_nested()` desfaz apenas o SAVEPOINT.
        from sqlalchemy.exc import IntegrityError

        try:
            with self.db.begin_nested():
                self.db.add(GithubAccountModel.from_entity(account))
                self.db.flush()
        except IntegrityError:
            existente = self.get_by_installation(account.installation_id)
            if existente is None:
                raise
            self.db.execute(
                update(GithubAccountModel)
                .where(GithubAccountModel.installation_id == account.installation_id)
                .values({col: row[col] for col in _UPDATE_COLUMNS})
            )
            self.db.flush()

    def get_by_id(self, account_id: UUID) -> GithubAccount | None:
        result = self.db.execute(
            select(GithubAccountModel).where(GithubAccountModel.id == account_id)
        )
        model = result.scalars().first()
        return model.to_entity() if model else None

    def get_by_installation(self, installation_id: int) -> GithubAccount | None:
        result = self.db.execute(
            select(GithubAccountModel).where(
                GithubAccountModel.installation_id == installation_id
            )
        )
        model = result.scalars().first()
        return model.to_entity() if model else None

    def list_by_user(self, user_id: UUID) -> list[GithubAccount]:
        result = self.db.execute(
            select(GithubAccountModel)
            .where(GithubAccountModel.user_id == user_id)
            .order_by(GithubAccountModel.created_at.desc())
        )
        return [m.to_entity() for m in result.scalars().all()]

    def delete(self, account_id: UUID) -> None:
        self.db.execute(
            delete(GithubAccountModel).where(GithubAccountModel.id == account_id)
        )
        self.db.flush()
