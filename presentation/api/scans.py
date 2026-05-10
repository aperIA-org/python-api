from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from core.database import get_db
from infrastructure.persistence.repositories.sqlalchemy_scan_repository import SQLAlchemyScanRepository

router = APIRouter()


class ScanStatusResponse(BaseModel):
    id: UUID
    commit_sha: str
    repo_url: str
    status: str
    findings_count: int | None = None
    risk_score: int | None = None


@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> ScanStatusResponse:
    repo = SQLAlchemyScanRepository(db)
    scan = await repo.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanStatusResponse(
        id=scan.id,
        commit_sha=scan.commit_sha,
        repo_url=scan.repo_url,
        status=scan.status.value,
        findings_count=scan.findings_count,
        risk_score=scan.risk_score,
    )
