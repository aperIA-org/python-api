from __future__ import annotations

from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.domain.github.entities import Repository
from app.domain.github.repositories import RepositoryRepository
from app.infrastructure.persistence.models.repository_model import RepositoryModel

_UPDATE_COLUMNS = (
    "installation_id",
    "github_account_id",
    "full_name",
    "url",
    "default_branch",
    "active",
)
_INSERT_COLUMNS = tuple(RepositoryModel.__table__.columns.keys())


def _to_row(repository: Repository) -> dict:
    model = RepositoryModel.from_entity(repository)
    return {col: getattr(model, col) for col in _INSERT_COLUMNS}


class SQLAlchemyRepositoryRepository(RepositoryRepository):
    """Repositório síncrono — consumido pelas rotas/serviços via ``Session``."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, repository: Repository) -> None:
        row = _to_row(repository)
        dialect = self.db.bind.dialect.name if self.db.bind else "postgresql"

        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            stmt = pg_insert(RepositoryModel).values(row)
            stmt = stmt.on_conflict_do_update(
                constraint="repositories_user_repo_key",
                set_={col: getattr(stmt.excluded, col) for col in _UPDATE_COLUMNS},
            )
            self.db.execute(stmt)
            return

        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            stmt = sqlite_insert(RepositoryModel).values(row)
            stmt = stmt.on_conflict_do_update(
                index_elements=["user_id", "github_repo_id"],
                set_={col: getattr(stmt.excluded, col) for col in _UPDATE_COLUMNS},
            )
            self.db.execute(stmt)
            return

        # Fallback: insere e engole IntegrityError (defense-in-depth).
        from sqlalchemy.exc import IntegrityError

        try:
            self.db.add(RepositoryModel.from_entity(repository))
            self.db.flush()
        except IntegrityError:
            self.db.rollback()

    def get_by_id(self, repository_id: UUID) -> Repository | None:
        result = self.db.execute(
            select(RepositoryModel).where(RepositoryModel.id == repository_id)
        )
        model = result.scalars().first()
        return model.to_entity() if model else None

    def list_by_user(self, user_id: UUID) -> list[Repository]:
        result = self.db.execute(
            select(RepositoryModel)
            .where(RepositoryModel.user_id == user_id)
            .order_by(RepositoryModel.created_at.desc())
        )
        return [m.to_entity() for m in result.scalars().all()]

    def get_by_installation_and_repo(
        self, installation_id: int, github_repo_id: int
    ) -> Repository | None:
        result = self.db.execute(
            select(RepositoryModel).where(
                RepositoryModel.installation_id == installation_id,
                RepositoryModel.github_repo_id == github_repo_id,
            )
        )
        model = result.scalars().first()
        return model.to_entity() if model else None

    def set_active(self, repository_id: UUID, active: bool) -> None:
        self.db.execute(
            update(RepositoryModel)
            .where(RepositoryModel.id == repository_id)
            .values(active=active)
        )
        self.db.flush()

    def delete(self, repository_id: UUID) -> None:
        self.db.execute(
            delete(RepositoryModel).where(RepositoryModel.id == repository_id)
        )
        self.db.flush()
