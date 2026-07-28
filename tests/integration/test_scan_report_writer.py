"""Testes do writer best-effort de ScanReport.

Religa ``SCAN_PERSISTENCE_ENABLED`` (o autouse desliga por padrão) e aponta
o ``SessionLocal`` do writer para um sqlite in-memory.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.domain.scan.entities import ScanJob
from app.infrastructure.persistence import scan_report_writer
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    refresh_token_model,
    remediation_model,
    scan_job_model,
    scan_report_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_report_repository import (
    SQLAlchemyScanReportRepository,
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
    with patch.object(scan_report_writer, "SessionLocal", sqlite_factory):
        yield sqlite_factory
    settings.SCAN_PERSISTENCE_ENABLED = original


def test_persist_report(persistence_on):
    scan_report_writer.persist_report(
        commit_sha="a" * 40, tier=2, report_markdown="## r",
        analysis_json={"risk_score": {"score": 60, "level": "medium"}},
        degraded=False, comment_id=42, posted=True,
    )
    with persistence_on() as s:
        r = SQLAlchemyScanReportRepository(s).get_by_commit_and_tier("a" * 40, 2)
    assert r is not None
    assert r.comment_id == 42
    assert r.scan_job_id is None  # sem ScanJob associado


def test_persist_report_links_scan_job(persistence_on):
    # cria o ScanJob antes → o writer deve vincular scan_job_id
    with persistence_on() as s:
        job = ScanJob(commit_sha="a" * 40, repo_url="https://github.com/acme/r", installation_id=1)
        SQLAlchemyScanJobRepository(s).save(job)
        s.commit()
        job_id = job.id

    scan_report_writer.persist_report(
        commit_sha="a" * 40, tier=3, report_markdown="## r3",
        analysis_json={}, degraded=True, comment_id=None, posted=False,
    )
    with persistence_on() as s:
        r = SQLAlchemyScanReportRepository(s).get_by_commit_and_tier("a" * 40, 3)
    assert r.scan_job_id == job_id
    assert r.degraded is True


def test_disabled_is_noop(sqlite_factory):
    with patch.object(scan_report_writer, "SessionLocal", sqlite_factory):
        scan_report_writer.persist_report(
            commit_sha="a" * 40, tier=2, report_markdown="x",
            analysis_json={}, degraded=False, comment_id=None, posted=False,
        )
    with sqlite_factory() as s:
        assert SQLAlchemyScanReportRepository(s).get_by_commit_and_tier("a" * 40, 2) is None
