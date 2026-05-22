from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

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


class SQLAlchemyFindingRepository(FindingRepository):
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def save(self, finding: Finding) -> None:
        self.db.add(FindingModel.from_entity(finding))
        await self.db.flush()

    async def bulk_save(self, findings: list[Finding]) -> None:
        if not findings:
            return

        rows = [_to_row(f) for f in findings]
        dialect = self.db.bind.dialect.name if self.db.bind else "postgresql"

        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            stmt = pg_insert(FindingModel).values(rows).on_conflict_do_nothing(
                constraint="findings_dedup_key"
            )
            await self.db.execute(stmt)
            return

        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            stmt = sqlite_insert(FindingModel).values(rows).on_conflict_do_nothing(
                index_elements=["dedup_key"]
            )
            await self.db.execute(stmt)
            return

        # Fallback: insere um a um, ignora IntegrityError (defense-in-depth).
        from sqlalchemy.exc import IntegrityError

        for finding in findings:
            try:
                self.db.add(FindingModel.from_entity(finding))
                await self.db.flush()
            except IntegrityError:
                await self.db.rollback()

    async def get_by_commit(self, commit_sha: str) -> list[Finding]:
        result = await self.db.execute(
            select(FindingModel).where(FindingModel.commit_sha == commit_sha)
        )
        return [m.to_entity() for m in result.scalars().all()]

    async def get_verified_secrets(self, commit_sha: str) -> list[Finding]:
        result = await self.db.execute(
            select(FindingModel).where(
                FindingModel.commit_sha == commit_sha,
                FindingModel.secret_verified.is_(True),
            )
        )
        return [m.to_entity() for m in result.scalars().all()]

    async def find_duplicate(self, dedup_key: str) -> Finding | None:
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
        result = await self.db.execute(
            select(FindingModel).where(
                FindingModel.source == source,
                FindingModel.commit_sha == commit_sha,
                FindingModel.file_path == (file_path if file_path != "None" else None),
                FindingModel.line_number == line_number,
            )
        )
        model = result.scalars().first()
        return model.to_entity() if model else None
