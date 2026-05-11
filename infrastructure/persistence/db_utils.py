"""
Utilitários síncronos de persistência para Celery workers.
Workers são sync — usam asyncio.run() para chamar os repos async.
"""
import asyncio
from uuid import UUID

from core.database import AsyncSessionLocal
from domain.finding.entities import Finding
from domain.scan.entities import ScanJob
from infrastructure.persistence.repositories.sqlalchemy_finding_repository import SQLAlchemyFindingRepository
from infrastructure.persistence.repositories.sqlalchemy_scan_repository import SQLAlchemyScanRepository


# ── async helpers ──────────────────────────────────────────────────────────


async def _save_scan_job(scan_job: ScanJob) -> None:
    async with AsyncSessionLocal() as session:
        await SQLAlchemyScanRepository(session).save(scan_job)
        await session.commit()


async def _update_scan_job(scan_job: ScanJob) -> None:
    async with AsyncSessionLocal() as session:
        await SQLAlchemyScanRepository(session).update(scan_job)
        await session.commit()


async def _bulk_save_findings(findings: list[Finding]) -> None:
    async with AsyncSessionLocal() as session:
        await SQLAlchemyFindingRepository(session).bulk_save(findings)
        await session.commit()


async def _load_scan_job(scan_job_id: UUID) -> ScanJob | None:
    async with AsyncSessionLocal() as session:
        return await SQLAlchemyScanRepository(session).get_by_id(scan_job_id)


async def _load_findings_by_commit(commit_sha: str) -> list[Finding]:
    async with AsyncSessionLocal() as session:
        return await SQLAlchemyFindingRepository(session).get_by_commit(commit_sha)


# ── sync API (usada pelos workers) ────────────────────────────────────────


def save_scan_job(scan_job: ScanJob) -> None:
    asyncio.run(_save_scan_job(scan_job))


def update_scan_job(scan_job: ScanJob) -> None:
    asyncio.run(_update_scan_job(scan_job))


def bulk_save_findings(findings: list[Finding]) -> None:
    asyncio.run(_bulk_save_findings(findings))


def load_scan_job(scan_job_id: str | UUID) -> ScanJob | None:
    uid = UUID(scan_job_id) if isinstance(scan_job_id, str) else scan_job_id
    return asyncio.run(_load_scan_job(uid))


def load_findings_by_commit(commit_sha: str) -> list[Finding]:
    return asyncio.run(_load_findings_by_commit(commit_sha))
