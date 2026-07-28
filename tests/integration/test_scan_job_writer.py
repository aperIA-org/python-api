"""Testes do writer best-effort de ScanJob.

O autouse ``disable_scan_persistence`` (conftest) desliga a escrita por
padrão — aqui religamos via ``persistence_on`` e apontamos o ``SessionLocal``
do writer para um sqlite in-memory.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.infrastructure.persistence import scan_job_writer
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    refresh_token_model,
    remediation_model,
    scan_job_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.domain.scan.value_objects import TierStatus
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)


@pytest.fixture
def sqlite_factory():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(eng)
    factory = sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
    try:
        yield factory
    finally:
        eng.dispose()


@pytest.fixture
def persistence_on(sqlite_factory):
    original = settings.SCAN_PERSISTENCE_ENABLED
    settings.SCAN_PERSISTENCE_ENABLED = True
    with patch.object(scan_job_writer, "SessionLocal", sqlite_factory):
        yield sqlite_factory
    settings.SCAN_PERSISTENCE_ENABLED = original


def _read(factory, commit_sha="a" * 40):
    with factory() as s:
        return SQLAlchemyScanJobRepository(s).get_by_commit(commit_sha)


def test_create_scan_job(persistence_on):
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
        pr_number=3, repo_full_name="acme/repo",
    )
    job = _read(persistence_on)
    assert job is not None
    assert job.tier1_status == TierStatus.RUNNING
    assert job.tier1_started_at is not None


def test_mark_tier(persistence_on):
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
    )
    scan_job_writer.mark_tier("a" * 40, 2, "done")
    job = _read(persistence_on)
    assert job.tier2_status == TierStatus.DONE
    assert job.tier2_completed_at is not None


def test_mark_blocked(persistence_on):
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
    )
    scan_job_writer.mark_blocked("a" * 40, 1)
    assert _read(persistence_on).blocked_at_tier.value == 1


def test_set_final_risk_from_analysis_tier2(persistence_on):
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
    )
    scan_job_writer.set_final_risk_from_analysis(
        "a" * 40, {"risk_score": {"score": 70, "level": "high"}}
    )
    job = _read(persistence_on)
    assert job.final_risk_score == 70
    assert job.final_risk_level == "high"


def test_set_final_risk_from_analysis_tier3_adjusted(persistence_on):
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
    )
    scan_job_writer.set_final_risk_from_analysis(
        "a" * 40, {"risk_score_adjusted": {"score": 95, "level": "critical"}}
    )
    assert _read(persistence_on).final_risk_score == 95


def test_disabled_is_noop(sqlite_factory):
    # Flag desligada (default do autouse) → não grava nada, mesmo com SessionLocal apontado.
    with patch.object(scan_job_writer, "SessionLocal", sqlite_factory):
        scan_job_writer.create_scan_job(
            commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
        )
    assert _read(sqlite_factory) is None
