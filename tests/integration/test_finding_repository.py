import asyncio
from datetime import datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import CVEId, Severity
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.persistence.models import (  # noqa: F401 — needed for metadata
    finding_model,
    remediation_model,
    scan_job_model,
)
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
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
async def session(engine) -> AsyncSession:
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    async with factory() as s:
        yield s


def _make_finding(**overrides) -> Finding:
    base = {
        "source": "semgrep",
        "severity": Severity.HIGH,
        "title": "SQL injection",
        "description": "f-string em query",
        "commit_sha": "a" * 40,
        "repo_url": "https://github.com/acme/repo",
        "file_path": "app/db.py",
        "line_number": 42,
        "tier": 1,
    }
    base.update(overrides)
    return Finding(**base)


@pytest.mark.asyncio
async def test_save_and_get_by_commit(session):
    repo = SQLAlchemyFindingRepository(session)
    f = _make_finding()
    await repo.save(f)
    await session.commit()

    result = await repo.get_by_commit("a" * 40)
    assert len(result) == 1
    assert result[0].title == "SQL injection"
    assert result[0].severity is Severity.HIGH


@pytest.mark.asyncio
async def test_bulk_save_persists_all(session):
    repo = SQLAlchemyFindingRepository(session)
    findings = [
        _make_finding(file_path="a.py", line_number=1),
        _make_finding(file_path="b.py", line_number=2),
        _make_finding(file_path="c.py", line_number=3),
    ]
    await repo.bulk_save(findings)
    await session.commit()

    result = await repo.get_by_commit("a" * 40)
    assert len(result) == 3


@pytest.mark.asyncio
async def test_bulk_save_is_idempotent_via_unique_constraint(session):
    """Re-scan do mesmo commit não duplica via ON CONFLICT DO NOTHING."""
    repo = SQLAlchemyFindingRepository(session)
    findings = [_make_finding(id=uuid4()) for _ in range(3)]
    # Mesmo finding (mesma dedup_key) repetido 3 vezes
    findings[0].file_path = "dup.py"
    findings[1].file_path = "dup.py"
    findings[2].file_path = "dup.py"
    findings[0].line_number = 10
    findings[1].line_number = 10
    findings[2].line_number = 10

    await repo.bulk_save(findings)
    await session.commit()

    result = await repo.get_by_commit("a" * 40)
    assert len(result) == 1


@pytest.mark.asyncio
async def test_bulk_save_empty_list_is_noop(session):
    repo = SQLAlchemyFindingRepository(session)
    await repo.bulk_save([])
    await session.commit()
    assert await repo.get_by_commit("a" * 40) == []


@pytest.mark.asyncio
async def test_bulk_save_then_again_does_not_duplicate(session):
    """Re-scan completo do mesmo commit: dois bulk_save consecutivos = 1 finding."""
    repo = SQLAlchemyFindingRepository(session)
    f = _make_finding()

    await repo.bulk_save([f])
    await session.commit()

    # Re-scan — outra UUID para o mesmo dedup_key
    f2 = _make_finding(id=uuid4())
    await repo.bulk_save([f2])
    await session.commit()

    assert len(await repo.get_by_commit("a" * 40)) == 1


@pytest.mark.asyncio
async def test_get_verified_secrets_only_returns_verified(session):
    repo = SQLAlchemyFindingRepository(session)
    findings = [
        _make_finding(
            source="trufflehog",
            severity=Severity.CRITICAL,
            secret_verified=True,
            secret_type="AWS",
            file_path="config/secrets.env",
            line_number=10,
        ),
        _make_finding(
            source="trufflehog",
            severity=Severity.HIGH,
            secret_verified=False,
            file_path="other.env",
            line_number=11,
        ),
        _make_finding(
            source="semgrep",
            severity=Severity.HIGH,
            file_path="x.py",
            line_number=1,
        ),
    ]
    await repo.bulk_save(findings)
    await session.commit()

    secrets = await repo.get_verified_secrets("a" * 40)
    assert len(secrets) == 1
    assert secrets[0].secret_verified is True
    assert secrets[0].secret_type == "AWS"


@pytest.mark.asyncio
async def test_cve_id_round_trip(session):
    repo = SQLAlchemyFindingRepository(session)
    f = _make_finding(cve_id=CVEId("CVE-2021-44228"))
    await repo.save(f)
    await session.commit()

    result = await repo.get_by_commit("a" * 40)
    assert result[0].cve_id is not None
    assert str(result[0].cve_id) == "CVE-2021-44228"


@pytest.mark.asyncio
async def test_raw_output_roundtrip(session):
    repo = SQLAlchemyFindingRepository(session)
    f = _make_finding(raw_output={"DetectorName": "AWS", "Verified": True})
    await repo.save(f)
    await session.commit()

    result = await repo.get_by_commit("a" * 40)
    assert result[0].raw_output["DetectorName"] == "AWS"
    assert result[0].raw_output["Verified"] is True


@pytest.mark.asyncio
async def test_different_commits_stored_independently(session):
    repo = SQLAlchemyFindingRepository(session)
    f1 = _make_finding(commit_sha="a" * 40)
    f2 = _make_finding(commit_sha="b" * 40)
    await repo.bulk_save([f1, f2])
    await session.commit()

    assert len(await repo.get_by_commit("a" * 40)) == 1
    assert len(await repo.get_by_commit("b" * 40)) == 1
