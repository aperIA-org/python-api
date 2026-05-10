from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from domain.finding.entities import Finding, AttackPath
from domain.finding.repositories import FindingRepository, AttackPathRepository
from infrastructure.persistence.models.finding_model import FindingModel


class SQLAlchemyFindingRepository(FindingRepository):
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def save(self, finding: Finding) -> None:
        model = FindingModel.from_entity(finding)
        self.db.add(model)

    async def bulk_save(self, findings: list[Finding]) -> None:
        models = [FindingModel.from_entity(f) for f in findings]
        self.db.add_all(models)

    async def get_by_id(self, finding_id: UUID) -> Finding | None:
        result = await self.db.execute(
            select(FindingModel).where(FindingModel.id == finding_id)
        )
        model = result.scalar_one_or_none()
        return model.to_entity() if model else None

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

    async def find_duplicate(self, dedup_key: str, commit_sha: str) -> Finding | None:
        # DEBT: implementar coluna dedup_key indexada para performance em produção
        all_findings = await self.get_by_commit(commit_sha)
        for f in all_findings:
            if f.dedup_key() == dedup_key:
                return f
        return None
