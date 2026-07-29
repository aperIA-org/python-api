from __future__ import annotations

from uuid import UUID

from sqlalchemy import delete, select
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

        # Fallback: insere e engole IntegrityError (defense-in-depth).
        from sqlalchemy.exc import IntegrityError

        try:
            self.db.add(GithubAccountModel.from_entity(account))
            self.db.flush()
        except IntegrityError:
            self.db.rollback()

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
