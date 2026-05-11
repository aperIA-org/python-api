from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from core.database import get_db
from infrastructure.persistence.repositories.sqlalchemy_scan_repository import SQLAlchemyScanRepository

router = APIRouter()


class ScanStatusResponse(BaseModel):
    id: UUID
    commit_sha: str
    repo_url: str
    pr_number: int | None = None
    status: str
    findings_count: int | None = None
    risk_score: int | None = None
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None


def _fmt_dt(dt) -> str | None:
    return dt.isoformat() if dt else None


def _to_response(scan) -> ScanStatusResponse:
    return ScanStatusResponse(
        id=scan.id,
        commit_sha=scan.commit_sha,
        repo_url=scan.repo_url,
        pr_number=scan.pr_number,
        status=scan.status.value,
        findings_count=scan.findings_count,
        risk_score=scan.risk_score,
        created_at=_fmt_dt(scan.created_at) or "",
        started_at=_fmt_dt(scan.started_at),
        completed_at=_fmt_dt(scan.completed_at),
    )


@router.get("/", response_model=list[ScanStatusResponse])
async def list_scans(
    limit: int = Query(default=20, le=100),
    db: AsyncSession = Depends(get_db),
) -> list[ScanStatusResponse]:
    repo = SQLAlchemyScanRepository(db)
    scans = await repo.list_recent(limit=limit)
    return [_to_response(s) for s in scans]


@router.get("/commit/{commit_sha}", response_model=ScanStatusResponse)
async def get_scan_by_commit(
    commit_sha: str,
    db: AsyncSession = Depends(get_db),
) -> ScanStatusResponse:
    repo = SQLAlchemyScanRepository(db)
    scan = await repo.get_by_commit(commit_sha)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _to_response(scan)


@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> ScanStatusResponse:
    repo = SQLAlchemyScanRepository(db)
    scan = await repo.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _to_response(scan)
