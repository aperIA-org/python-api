from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

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


@pytest.fixture
def engine():
    # StaticPool + single connection: garante que create_all e as sessions
    # enxerguem o MESMO banco sqlite em memória.
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


def test_save_and_get_by_commit(session):
    repo = SQLAlchemyFindingRepository(session)
    f = _make_finding()
    repo.save(f)
    session.commit()

    result = repo.get_by_commit("a" * 40)
    assert len(result) == 1
    assert result[0].title == "SQL injection"
    assert result[0].severity is Severity.HIGH


def test_bulk_save_persists_all(session):
    repo = SQLAlchemyFindingRepository(session)
    findings = [
        _make_finding(file_path="a.py", line_number=1),
        _make_finding(file_path="b.py", line_number=2),
        _make_finding(file_path="c.py", line_number=3),
    ]
    repo.bulk_save(findings)
    session.commit()

    result = repo.get_by_commit("a" * 40)
    assert len(result) == 3


def test_bulk_save_is_idempotent_via_unique_constraint(session):
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

    repo.bulk_save(findings)
    session.commit()

    result = repo.get_by_commit("a" * 40)
    assert len(result) == 1


def test_bulk_save_empty_list_is_noop(session):
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save([])
    session.commit()
    assert repo.get_by_commit("a" * 40) == []


def test_bulk_save_then_again_does_not_duplicate(session):
    """Re-scan completo do mesmo commit: dois bulk_save consecutivos = 1 finding."""
    repo = SQLAlchemyFindingRepository(session)
    f = _make_finding()

    repo.bulk_save([f])
    session.commit()

    # Re-scan — outra UUID para o mesmo dedup_key
    f2 = _make_finding(id=uuid4())
    repo.bulk_save([f2])
    session.commit()

    assert len(repo.get_by_commit("a" * 40)) == 1


def test_get_verified_secrets_only_returns_verified(session):
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
    repo.bulk_save(findings)
    session.commit()

    secrets = repo.get_verified_secrets("a" * 40)
    assert len(secrets) == 1
    assert secrets[0].secret_verified is True
    assert secrets[0].secret_type == "AWS"


def test_cve_id_round_trip(session):
    repo = SQLAlchemyFindingRepository(session)
    f = _make_finding(cve_id=CVEId("CVE-2021-44228"))
    repo.save(f)
    session.commit()

    result = repo.get_by_commit("a" * 40)
    assert result[0].cve_id is not None
    assert str(result[0].cve_id) == "CVE-2021-44228"


def test_raw_output_roundtrip(session):
    repo = SQLAlchemyFindingRepository(session)
    f = _make_finding(raw_output={"DetectorName": "AWS", "Verified": True})
    repo.save(f)
    session.commit()

    result = repo.get_by_commit("a" * 40)
    assert result[0].raw_output["DetectorName"] == "AWS"
    assert result[0].raw_output["Verified"] is True


def test_different_commits_stored_independently(session):
    repo = SQLAlchemyFindingRepository(session)
    f1 = _make_finding(commit_sha="a" * 40)
    f2 = _make_finding(commit_sha="b" * 40)
    repo.bulk_save([f1, f2])
    session.commit()

    assert len(repo.get_by_commit("a" * 40)) == 1
    assert len(repo.get_by_commit("b" * 40)) == 1
