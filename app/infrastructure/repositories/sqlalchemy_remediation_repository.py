"""Implementação SQLAlchemy do RemediationRepository.

Por que não há ``bulk_save`` aqui: remediações são geradas uma a
uma pela Claude — não há cenário de inserção em massa. Cada
``save`` adiciona e faz flush; commit fica a cargo do orquestrador.

``update_status`` atualiza apenas os campos relevantes (status +
approved_by + approved_at) — não substitui a entidade inteira para
preservar ``created_at``.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.remediation.entities import Remediation, RemediationStatus
from app.domain.remediation.repositories import RemediationRepository
from app.infrastructure.persistence.models.remediation_model import (
    RemediationModel,
)


class SQLAlchemyRemediationRepository(RemediationRepository):
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def save(self, remediation: Remediation) -> None:
        self.db.add(RemediationModel.from_entity(remediation))
        await self.db.flush()

    async def get_by_scan_job(
        self, scan_job_id: UUID
    ) -> list[Remediation]:
        result = await self.db.execute(
            select(RemediationModel).where(
                RemediationModel.scan_job_id == scan_job_id
            )
        )
        return [m.to_entity() for m in result.scalars().all()]

    async def update_status(
        self,
        remediation_id: UUID,
        status: RemediationStatus,
        approved_by: str | None = None,
    ) -> None:
        values: dict = {"status": status.value}
        if approved_by is not None:
            values["approved_by"] = approved_by
            values["approved_at"] = datetime.utcnow()
        await self.db.execute(
            update(RemediationModel)
            .where(RemediationModel.id == remediation_id)
            .values(**values)
        )
        await self.db.flush()
