from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.domain.finding.entities import Finding
from app.domain.finding.repositories import FindingRepository
from app.infrastructure.persistence.models.finding_model import FindingModel


_INSERT_COLUMNS = (
    "id",
    "source",
    "severity",
    "tier",
    "title",
    "description",
    "cve_id",
    "cwe_id",
    "file_path",
    "line_number",
    "asset",
    "asset_criticality",
    "secret_verified",
    "secret_type",
    "raw_output",
    "commit_sha",
    "repo_url",
    "dedup_key",
    "created_at",
)


def _to_row(finding: Finding) -> dict:
    model = FindingModel.from_entity(finding)
    return {col: getattr(model, col) for col in _INSERT_COLUMNS}


def _build_filters(
    *,
    commit_sha: str | None,
    severity: str | None,
    tier: int | None,
    source: str | None,
    secret_verified: bool | None,
) -> list:
    """Monta a lista de condições WHERE a partir dos filtros opcionais.

    Só inclui a condição quando o argumento correspondente não é ``None``.
    """
    filters = []
    if commit_sha is not None:
        filters.append(FindingModel.commit_sha == commit_sha)
    if severity is not None:
        filters.append(FindingModel.severity == severity)
    if tier is not None:
        filters.append(FindingModel.tier == tier)
    if source is not None:
        filters.append(FindingModel.source == source)
    if secret_verified is not None:
        filters.append(FindingModel.secret_verified.is_(secret_verified))
    return filters


class SQLAlchemyFindingRepository(FindingRepository):
    """Repositório síncrono — consumido pelos workers Celery (sync) via
    ``SessionLocal`` e pelos testes via uma ``Session`` sqlite.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, finding: Finding) -> None:
        self.db.add(FindingModel.from_entity(finding))
        self.db.flush()

    def bulk_save(self, findings: list[Finding]) -> None:
        if not findings:
            return

        rows = [_to_row(f) for f in findings]
        dialect = self.db.bind.dialect.name if self.db.bind else "postgresql"

        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            stmt = pg_insert(FindingModel).values(rows).on_conflict_do_nothing(
                constraint="findings_dedup_key"
            )
            self.db.execute(stmt)
            return

        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            stmt = sqlite_insert(FindingModel).values(rows).on_conflict_do_nothing(
                index_elements=["dedup_key"]
            )
            self.db.execute(stmt)
            return

        # Fallback: insere um a um, ignora IntegrityError (defense-in-depth).
        from sqlalchemy.exc import IntegrityError

        for finding in findings:
            try:
                self.db.add(FindingModel.from_entity(finding))
                self.db.flush()
            except IntegrityError:
                self.db.rollback()

    def get_by_commit(self, commit_sha: str) -> list[Finding]:
        result = self.db.execute(
            select(FindingModel).where(FindingModel.commit_sha == commit_sha)
        )
        return [m.to_entity() for m in result.scalars().all()]

    def get_verified_secrets(self, commit_sha: str) -> list[Finding]:
        result = self.db.execute(
            select(FindingModel).where(
                FindingModel.commit_sha == commit_sha,
                FindingModel.secret_verified.is_(True),
            )
        )
        return [m.to_entity() for m in result.scalars().all()]

    def find_duplicate(self, dedup_key: str) -> Finding | None:
        # dedup_key format: "source:cve_or_title:file_path:line_number:commit_sha"
        # Implementação simples: faz parse e busca. Em produção este método
        # raramente é chamado — bulk_save com ON CONFLICT é o caminho principal.
        parts = dedup_key.split(":", 4)
        if len(parts) != 5:
            return None
        source, key, file_path, line_str, commit_sha = parts
        try:
            line_number = int(line_str) if line_str != "None" else None
        except ValueError:
            return None
        result = self.db.execute(
            select(FindingModel).where(
                FindingModel.source == source,
                FindingModel.commit_sha == commit_sha,
                FindingModel.file_path == (file_path if file_path != "None" else None),
                FindingModel.line_number == line_number,
            )
        )
        model = result.scalars().first()
        return model.to_entity() if model else None

    def get_by_id(self, finding_id: UUID) -> Finding | None:
        """Busca um finding pelo seu identificador único."""
        result = self.db.execute(
            select(FindingModel).where(FindingModel.id == finding_id)
        )
        model = result.scalars().first()
        return model.to_entity() if model else None

    def query(
        self,
        *,
        commit_sha: str | None = None,
        severity: str | None = None,
        tier: int | None = None,
        source: str | None = None,
        secret_verified: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Finding]:
        """Lista findings com filtros opcionais, ordenados do mais recente
        para o mais antigo, com paginação via ``limit``/``offset``.
        """
        filters = _build_filters(
            commit_sha=commit_sha,
            severity=severity,
            tier=tier,
            source=source,
            secret_verified=secret_verified,
        )
        stmt = (
            select(FindingModel)
            .where(*filters)
            .order_by(FindingModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = self.db.execute(stmt)
        return [m.to_entity() for m in result.scalars().all()]

    def count(
        self,
        *,
        commit_sha: str | None = None,
        severity: str | None = None,
        tier: int | None = None,
        source: str | None = None,
        secret_verified: bool | None = None,
    ) -> int:
        """Conta findings que atendem aos filtros opcionais informados."""
        filters = _build_filters(
            commit_sha=commit_sha,
            severity=severity,
            tier=tier,
            source=source,
            secret_verified=secret_verified,
        )
        stmt = select(func.count()).select_from(FindingModel).where(*filters)
        return self.db.execute(stmt).scalar_one()
