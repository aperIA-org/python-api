from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from core.database import get_db
from infrastructure.persistence.repositories.sqlalchemy_finding_repository import SQLAlchemyFindingRepository

router = APIRouter()


class FindingResponse(BaseModel):
    id: str
    source: str
    severity: str
    title: str
    description: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    cve_id: str | None = None
    cwe_id: str | None = None
    secret_verified: bool = False
    secret_type: str | None = None
    ttp_ids: list[str] = []
    commit_sha: str
    repo_url: str


def _to_response(f) -> FindingResponse:
    return FindingResponse(
        id=str(f.id),
        source=f.source,
        severity=f.severity.value,
        title=f.title,
        description=f.description,
        file_path=f.file_path,
        line_number=f.line_number,
        cve_id=str(f.cve_id) if f.cve_id else None,
        cwe_id=str(f.cwe_id) if f.cwe_id else None,
        secret_verified=f.secret_verified,
        secret_type=f.secret_type,
        ttp_ids=f.ttp_ids or [],
        commit_sha=f.commit_sha,
        repo_url=f.repo_url,
    )


@router.get("/commit/{commit_sha}", response_model=list[FindingResponse])
async def get_findings_by_commit(
    commit_sha: str,
    db: AsyncSession = Depends(get_db),
) -> list[FindingResponse]:
    repo = SQLAlchemyFindingRepository(db)
    findings = await repo.get_by_commit(commit_sha)
    return [_to_response(f) for f in findings]


@router.get("/commit/{commit_sha}/secrets", response_model=list[FindingResponse])
async def get_verified_secrets(
    commit_sha: str,
    db: AsyncSession = Depends(get_db),
) -> list[FindingResponse]:
    repo = SQLAlchemyFindingRepository(db)
    findings = await repo.get_verified_secrets(commit_sha)
    return [_to_response(f) for f in findings]


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    repo = SQLAlchemyFindingRepository(db)
    finding = await repo.get_by_id(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _to_response(finding)
