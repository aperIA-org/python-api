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

    def save(self, repository: Repository) -> Repository:
        """Faz upsert por ``(user_id, github_repo_id)`` e devolve a linha REAL.

        O ``id`` da entidade em memória é um ``uuid4()`` novo a cada chamada;
        quando o repositório já existia, o ``ON CONFLICT DO UPDATE`` preserva o
        ``id`` original da linha. Sem ``RETURNING`` o caller devolveria um id
        inexistente no banco (e um ``PATCH``/``DELETE`` com ele daria 404) —
        por isso lemos de volta o que foi efetivamente persistido.
        """
        row = _to_row(repository)
        dialect = self.db.bind.dialect.name if self.db.bind else "postgresql"

        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            stmt = pg_insert(RepositoryModel).values(row)
            stmt = stmt.on_conflict_do_update(
                constraint="repositories_user_repo_key",
                set_={col: getattr(stmt.excluded, col) for col in _UPDATE_COLUMNS},
            )
            return self._execute_returning(stmt)

        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            stmt = sqlite_insert(RepositoryModel).values(row)
            stmt = stmt.on_conflict_do_update(
                index_elements=["user_id", "github_repo_id"],
                set_={col: getattr(stmt.excluded, col) for col in _UPDATE_COLUMNS},
            )
            return self._execute_returning(stmt)

        # Fallback (dialeto sem ON CONFLICT): insere dentro de um SAVEPOINT e,
        # em caso de conflito, atualiza a linha existente — mesma semântica de
        # upsert dos dialetos acima, sem derrubar a transação do caller.
        from sqlalchemy.exc import IntegrityError

        try:
            with self.db.begin_nested():
                self.db.add(RepositoryModel.from_entity(repository))
                self.db.flush()
            return repository
        except IntegrityError:
            existing = self._get_by_user_and_repo(
                repository.user_id, repository.github_repo_id
            )
            if existing is None:
                raise
            self.db.execute(
                update(RepositoryModel)
                .where(RepositoryModel.id == existing.id)
                .values(**{col: row[col] for col in _UPDATE_COLUMNS})
            )
            self.db.flush()
            return self.get_by_id(existing.id)

    def _execute_returning(self, stmt) -> Repository:
        """Executa o upsert com ``RETURNING *`` e devolve a entidade persistida."""
        result = self.db.execute(
            stmt.returning(*RepositoryModel.__table__.columns)
        )
        row = result.mappings().one()
        self.db.flush()
        return RepositoryModel(**row).to_entity()

    def _get_by_user_and_repo(
        self, user_id: UUID, github_repo_id: int
    ) -> Repository | None:
        result = self.db.execute(
            select(RepositoryModel).where(
                RepositoryModel.user_id == user_id,
                RepositoryModel.github_repo_id == github_repo_id,
            )
        )
        model = result.scalars().first()
        return model.to_entity() if model else None

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

    def delete_by_github_account(
        self, github_account_id: UUID, user_id: UUID
    ) -> int:
        """Remove os repositórios de uma conta GitHub e devolve quantos saíram.

        Não existe ``ForeignKey`` entre ``github_accounts`` e ``repositories``,
        então a limpeza é explícita (chamada pelo ``DELETE /github/accounts``).
        O filtro por ``user_id`` é defensivo: garante que a remoção nunca
        atravesse a fronteira do dono, mesmo se o ``github_account_id`` vier
        errado.
        """
        result = self.db.execute(
            delete(RepositoryModel).where(
                RepositoryModel.github_account_id == github_account_id,
                RepositoryModel.user_id == user_id,
            )
        )
        self.db.flush()
        return result.rowcount or 0
