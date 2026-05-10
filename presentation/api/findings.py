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
    file_path: str | None = None
    line_number: int | None = None
    secret_verified: bool = False
    commit_sha: str


@router.get("/commit/{commit_sha}", response_model=list[FindingResponse])
async def get_findings_by_commit(
    commit_sha: str,
    db: AsyncSession = Depends(get_db),
) -> list[FindingResponse]:
    repo = SQLAlchemyFindingRepository(db)
    findings = await repo.get_by_commit(commit_sha)
    return [
        FindingResponse(
            id=str(f.id),
            source=f.source,
            severity=f.severity.value,
            title=f.title,
            file_path=f.file_path,
            line_number=f.line_number,
            secret_verified=f.secret_verified,
            commit_sha=f.commit_sha,
        )
        for f in findings
    ]
