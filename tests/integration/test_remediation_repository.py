"""Testes do SQLAlchemyRemediationRepository (SQLite em memória)."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.domain.remediation.entities import Remediation, RemediationStatus
from app.infrastructure.persistence.models import (  # noqa: F401 bind metadata
    finding_model,
    remediation_model,
    scan_job_model,
    scan_tool_run_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.persistence.models.finding_model import FindingModel
from app.infrastructure.persistence.models.scan_job_model import ScanJobModel
from app.infrastructure.repositories.sqlalchemy_remediation_repository import (
    SQLAlchemyRemediationRepository,
)


@pytest_asyncio.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture
async def session(engine):
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    async with factory() as s:
        yield s


@pytest_asyncio.fixture
async def fixtures(session):
    """Cria findings + scan_jobs necessários para FK das remediations."""
    finding_id = uuid4()
    scan_job_id = uuid4()
    # Adiciona um finding e um scan_job mínimos para satisfazer FKs
    session.add(
        FindingModel(
            id=finding_id,
            source="semgrep",
            severity="high",
            tier=2,
            title="SQL injection",
            description="x",
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
            secret_verified=False,
            dedup_key="key1",
            created_at=datetime.utcnow(),
        )
    )
    session.add(
        ScanJobModel(
            id=scan_job_id,
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
            installation_id=1,
            created_at=datetime.utcnow(),
        )
    )
    await session.flush()
    return {"finding_id": finding_id, "scan_job_id": scan_job_id}


def _make_remediation(finding_id, scan_job_id, **overrides) -> Remediation:
    base = {
        "finding_id": finding_id,
        "scan_job_id": scan_job_id,
        "patch_diff": "- bad\n+ good",
        "explanation": "fix",
    }
    base.update(overrides)
    return Remediation(**base)


@pytest.mark.asyncio
async def test_save_and_get_by_scan_job(session, fixtures):
    repo = SQLAlchemyRemediationRepository(session)
    r = _make_remediation(fixtures["finding_id"], fixtures["scan_job_id"])
    await repo.save(r)
    await session.commit()

    result = await repo.get_by_scan_job(fixtures["scan_job_id"])
    assert len(result) == 1
    assert result[0].patch_diff == "- bad\n+ good"
    assert result[0].status is RemediationStatus.SUGGESTED


@pytest.mark.asyncio
async def test_get_by_scan_job_returns_empty_when_no_remediations(session, fixtures):
    repo = SQLAlchemyRemediationRepository(session)
    result = await repo.get_by_scan_job(fixtures["scan_job_id"])
    assert result == []


@pytest.mark.asyncio
async def test_get_by_scan_job_only_returns_target_scan(session, fixtures):
    """Remediations de outros scans não devem vazar."""
    repo = SQLAlchemyRemediationRepository(session)
    other_scan = uuid4()
    other_finding = uuid4()
    # Cria um segundo scan_job + finding para isolar
    session.add(
        FindingModel(
            id=other_finding,
            source="semgrep",
            severity="low",
            tier=1,
            title="y",
            commit_sha="b" * 40,
            repo_url="x",
            secret_verified=False,
            dedup_key="key2",
            created_at=datetime.utcnow(),
        )
    )
    session.add(
        ScanJobModel(
            id=other_scan,
            commit_sha="b" * 40,
            repo_url="x",
            installation_id=1,
            created_at=datetime.utcnow(),
        )
    )
    await session.flush()

    await repo.save(
        _make_remediation(fixtures["finding_id"], fixtures["scan_job_id"])
    )
    await repo.save(_make_remediation(other_finding, other_scan))
    await session.commit()

    result = await repo.get_by_scan_job(fixtures["scan_job_id"])
    assert len(result) == 1
    assert result[0].finding_id == fixtures["finding_id"]


@pytest.mark.asyncio
async def test_update_status_to_approved(session, fixtures):
    repo = SQLAlchemyRemediationRepository(session)
    r = _make_remediation(fixtures["finding_id"], fixtures["scan_job_id"])
    await repo.save(r)
    await session.commit()

    await repo.update_status(r.id, RemediationStatus.APPROVED, approved_by="alice@x")
    await session.commit()

    result = await repo.get_by_scan_job(fixtures["scan_job_id"])
    assert result[0].status is RemediationStatus.APPROVED
    assert result[0].approved_by == "alice@x"
    assert result[0].approved_at is not None


@pytest.mark.asyncio
async def test_update_status_to_rejected_without_approver(session, fixtures):
    repo = SQLAlchemyRemediationRepository(session)
    r = _make_remediation(fixtures["finding_id"], fixtures["scan_job_id"])
    await repo.save(r)
    await session.commit()

    await repo.update_status(r.id, RemediationStatus.REJECTED)
    await session.commit()

    result = await repo.get_by_scan_job(fixtures["scan_job_id"])
    assert result[0].status is RemediationStatus.REJECTED
    assert result[0].approved_by is None


@pytest.mark.asyncio
async def test_preserves_secret_rotation_metadata(session, fixtures):
    repo = SQLAlchemyRemediationRepository(session)
    r = _make_remediation(
        fixtures["finding_id"],
        fixtures["scan_job_id"],
        requires_secret_rotation=True,
        rotation_instructions="Rotar via AWS IAM Console.",
        github_comment_id=12345,
    )
    await repo.save(r)
    await session.commit()

    result = await repo.get_by_scan_job(fixtures["scan_job_id"])
    assert result[0].requires_secret_rotation is True
    assert result[0].rotation_instructions == "Rotar via AWS IAM Console."
    assert result[0].github_comment_id == 12345
