"""Testes do repositório síncrono de ScanReport (sqlite in-memory)."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.domain.scan.report_entities import ScanReport
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    refresh_token_model,
    remediation_model,
    scan_job_model,
    scan_report_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.repositories.sqlalchemy_scan_report_repository import (
    SQLAlchemyScanReportRepository,
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


def _report(tier: int = 2, **overrides) -> ScanReport:
    base = {
        "commit_sha": "a" * 40,
        "tier": tier,
        "report_markdown": f"## relatorio tier {tier}",
        "analysis_json": {"risk_score": {"score": 70, "level": "high"}},
        "degraded": False,
        "comment_id": 555,
        "posted": True,
    }
    base.update(overrides)
    return ScanReport(**base)


def test_save_and_get_by_commit_and_tier(session):
    repo = SQLAlchemyScanReportRepository(session)
    repo.save(_report(2))
    session.commit()

    r = repo.get_by_commit_and_tier("a" * 40, 2)
    assert r is not None
    assert r.report_markdown == "## relatorio tier 2"
    assert r.analysis_json["risk_score"]["score"] == 70
    assert r.posted is True


def test_get_by_commit_orders_by_tier(session):
    repo = SQLAlchemyScanReportRepository(session)
    repo.save(_report(3, report_markdown="t3"))
    repo.save(_report(2, report_markdown="t2"))
    session.commit()

    reports = repo.get_by_commit("a" * 40)
    assert [r.tier for r in reports] == [2, 3]


def test_save_upserts_on_conflict(session):
    repo = SQLAlchemyScanReportRepository(session)
    repo.save(_report(2, report_markdown="antigo", posted=False))
    session.commit()
    # mesmo (commit_sha, tier) → substitui (DO UPDATE)
    repo.save(_report(2, report_markdown="novo", posted=True, comment_id=999))
    session.commit()

    reports = repo.get_by_commit("a" * 40)
    assert len(reports) == 1
    assert reports[0].report_markdown == "novo"
    assert reports[0].posted is True
    assert reports[0].comment_id == 999


def test_get_by_commit_and_tier_missing(session):
    repo = SQLAlchemyScanReportRepository(session)
    assert repo.get_by_commit_and_tier("z" * 40, 2) is None
