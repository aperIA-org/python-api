"""Testes do repositório síncrono de ScanJob (sqlite in-memory)."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.domain.scan.entities import ScanJob
from app.domain.scan.value_objects import ScanTier, TierStatus
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    refresh_token_model,
    remediation_model,
    scan_job_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(eng)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def session(engine):
    factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    with factory() as s:
        yield s


def _make_job(commit_sha: str = "a" * 40, **overrides) -> ScanJob:
    base = {
        "commit_sha": commit_sha,
        "repo_url": "https://github.com/acme/repo",
        "installation_id": 123,
        "pr_number": 7,
        "repo_full_name": "acme/repo",
        "tier1_status": TierStatus.RUNNING,
    }
    base.update(overrides)
    return ScanJob(**base)


def test_save_and_get_by_commit(session):
    repo = SQLAlchemyScanJobRepository(session)
    repo.save(_make_job())
    session.commit()

    job = repo.get_by_commit("a" * 40)
    assert job is not None
    assert job.repo_full_name == "acme/repo"
    assert job.tier1_status == TierStatus.RUNNING


def test_save_is_idempotent_on_commit(session):
    repo = SQLAlchemyScanJobRepository(session)
    repo.save(_make_job())
    session.commit()
    repo.save(_make_job())  # mesmo commit_sha — ON CONFLICT DO NOTHING
    session.commit()
    assert repo.count() == 1


def test_update_tier_status_sets_timestamps(session):
    repo = SQLAlchemyScanJobRepository(session)
    repo.save(_make_job())
    session.commit()

    repo.update_tier_status("a" * 40, ScanTier.TWO, TierStatus.RUNNING)
    session.commit()
    job = repo.get_by_commit("a" * 40)
    assert job.tier2_status == TierStatus.RUNNING
    assert job.tier2_started_at is not None
    assert job.tier2_completed_at is None

    repo.update_tier_status("a" * 40, ScanTier.TWO, TierStatus.DONE)
    session.commit()
    job = repo.get_by_commit("a" * 40)
    assert job.tier2_status == TierStatus.DONE
    assert job.tier2_completed_at is not None


def test_set_blocked(session):
    repo = SQLAlchemyScanJobRepository(session)
    repo.save(_make_job())
    session.commit()
    repo.set_blocked("a" * 40, ScanTier.ONE)
    session.commit()
    assert repo.get_by_commit("a" * 40).blocked_at_tier == ScanTier.ONE


def test_set_final_risk(session):
    repo = SQLAlchemyScanJobRepository(session)
    repo.save(_make_job())
    session.commit()
    repo.set_final_risk("a" * 40, 82, "high")
    session.commit()
    job = repo.get_by_commit("a" * 40)
    assert job.final_risk_score == 82
    assert job.final_risk_level == "high"


def test_list_recent_and_count(session):
    repo = SQLAlchemyScanJobRepository(session)
    repo.save(_make_job("a" * 40))
    repo.save(_make_job("b" * 40))
    session.commit()
    assert repo.count() == 2
    items = repo.list_recent(limit=1, offset=0)
    assert len(items) == 1
