from collections import Counter
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from infrastructure.persistence.repositories.sqlalchemy_finding_repository import SQLAlchemyFindingRepository
from infrastructure.persistence.repositories.sqlalchemy_scan_repository import SQLAlchemyScanRepository

router = APIRouter()


class _FindingSummary(BaseModel):
    id: str
    source: str
    severity: str
    title: str
    file_path: str | None = None
    line_number: int | None = None
    cve_id: str | None = None
    secret_verified: bool = False


class _ScanSummary(BaseModel):
    id: str
    status: str
    findings_count: int | None = None
    risk_score: int | None = None
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None


class ReportResponse(BaseModel):
    commit_sha: str
    scan: _ScanSummary | None = None
    findings_count: int
    verified_secrets: int
    severity_breakdown: dict[str, int]
    findings: list[_FindingSummary]


def _fmt_dt(dt) -> str | None:
    return dt.isoformat() if dt else None


@router.get("/commit/{commit_sha}", response_model=ReportResponse)
async def get_report_by_commit(
    commit_sha: str,
    db: AsyncSession = Depends(get_db),
) -> ReportResponse:
    scan_repo = SQLAlchemyScanRepository(db)
    finding_repo = SQLAlchemyFindingRepository(db)

    scan = await scan_repo.get_by_commit(commit_sha)
    findings = await finding_repo.get_by_commit(commit_sha)

    scan_summary = None
    if scan:
        scan_summary = _ScanSummary(
            id=str(scan.id),
            status=scan.status.value,
            findings_count=scan.findings_count,
            risk_score=scan.risk_score,
            created_at=_fmt_dt(scan.created_at) or "",
            started_at=_fmt_dt(scan.started_at),
            completed_at=_fmt_dt(scan.completed_at),
        )

    return ReportResponse(
        commit_sha=commit_sha,
        scan=scan_summary,
        findings_count=len(findings),
        verified_secrets=sum(1 for f in findings if f.secret_verified),
        severity_breakdown=dict(Counter(f.severity.value for f in findings)),
        findings=[
            _FindingSummary(
                id=str(f.id),
                source=f.source,
                severity=f.severity.value,
                title=f.title,
                file_path=f.file_path,
                line_number=f.line_number,
                cve_id=str(f.cve_id) if f.cve_id else None,
                secret_verified=f.secret_verified,
            )
            for f in findings
        ],
    )


@router.get("/scan/{scan_id}", response_model=ReportResponse)
async def get_report_by_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> ReportResponse:
    scan_repo = SQLAlchemyScanRepository(db)
    scan = await scan_repo.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return await get_report_by_commit(scan.commit_sha, db)
