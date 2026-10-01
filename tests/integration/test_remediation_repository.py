"""Testes do SQLAlchemyRemediationRepository (SQLite em memória)."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

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


@pytest.fixture
def engine():
    # StaticPool + conexão única: create_all e as sessions enxergam o MESMO
    # banco em memória.
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


#: Dono dos scan_jobs das fixtures. `remediations` não tem `user_id` — a posse
#: vem do join, então toda consulta escopada precisa de um usuário concreto.
USER_ID = uuid4()


@pytest.fixture
def fixtures(session):
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
            user_id=USER_ID,
            created_at=datetime.utcnow(),
        )
    )
    session.flush()
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


def test_save_and_get_by_scan_job(session, fixtures):
    repo = SQLAlchemyRemediationRepository(session)
    r = _make_remediation(fixtures["finding_id"], fixtures["scan_job_id"])
    repo.save(r)
    session.commit()

    result = repo.get_by_scan_job(fixtures["scan_job_id"])
    assert len(result) == 1
    assert result[0].patch_diff == "- bad\n+ good"
    assert result[0].status is RemediationStatus.SUGGESTED


def test_get_by_scan_job_returns_empty_when_no_remediations(session, fixtures):
    repo = SQLAlchemyRemediationRepository(session)
    result = repo.get_by_scan_job(fixtures["scan_job_id"])
    assert result == []


def test_get_by_scan_job_only_returns_target_scan(session, fixtures):
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
            user_id=USER_ID,
            created_at=datetime.utcnow(),
        )
    )
    session.flush()

    repo.save(
        _make_remediation(fixtures["finding_id"], fixtures["scan_job_id"])
    )
    repo.save(_make_remediation(other_finding, other_scan))
    session.commit()

    result = repo.get_by_scan_job(fixtures["scan_job_id"])
    assert len(result) == 1
    assert result[0].finding_id == fixtures["finding_id"]




def test_preserves_secret_rotation_metadata(session, fixtures):
    repo = SQLAlchemyRemediationRepository(session)
    r = _make_remediation(
        fixtures["finding_id"],
        fixtures["scan_job_id"],
        requires_secret_rotation=True,
        rotation_instructions="Rotar via AWS IAM Console.",
        github_comment_id=12345,
    )
    repo.save(r)
    session.commit()

    result = repo.get_by_scan_job(fixtures["scan_job_id"])
    assert result[0].requires_secret_rotation is True
    assert result[0].rotation_instructions == "Rotar via AWS IAM Console."
    assert result[0].github_comment_id == 12345


# ---------------------------------------------------------------- query/count
#
# `remediations` não tem `user_id`: quem é dono é o dono do `scan_job`. Estes
# testes existem porque um erro no join não quebra nada visível — ele apenas
# mostra a remediação de outra pessoa.


def _outro_scan(session, *, user_id):
    """Um scan_job de outro dono, com um finding e uma remediação."""
    finding_id, scan_job_id = uuid4(), uuid4()
    session.add(
        FindingModel(
            id=finding_id,
            source="trufflehog",
            severity="critical",
            tier=1,
            title="AWS key",
            commit_sha="c" * 40,
            repo_url="https://github.com/z/w",
            secret_verified=True,
            dedup_key=f"key-{finding_id}",
            created_at=datetime.utcnow(),
        )
    )
    session.add(
        ScanJobModel(
            id=scan_job_id,
            commit_sha="c" * 40,
            repo_url="https://github.com/z/w",
            installation_id=2,
            pr_number=7,
            repo_full_name="z/w",
            user_id=user_id,
            created_at=datetime.utcnow(),
        )
    )
    session.flush()
    return finding_id, scan_job_id


def test_query_escopa_ao_dono(session, fixtures):
    repo = SQLAlchemyRemediationRepository(session)
    intruso = uuid4()
    outro_finding, outro_scan = _outro_scan(session, user_id=intruso)

    repo.save(_make_remediation(fixtures["finding_id"], fixtures["scan_job_id"]))
    repo.save(_make_remediation(outro_finding, outro_scan))
    session.commit()

    meus = repo.query(user_id=USER_ID)
    assert len(meus) == 1
    assert meus[0].remediation.finding_id == fixtures["finding_id"]
    assert repo.count(user_id=USER_ID) == 1

    # O outro usuário enxerga só a dele.
    assert len(repo.query(user_id=intruso)) == 1
    assert repo.count(user_id=intruso) == 1

    # Um terceiro não enxerga nada.
    assert repo.query(user_id=uuid4()) == []
    assert repo.count(user_id=uuid4()) == 0


def test_query_traz_o_contexto_do_finding_e_do_scan(session):
    """O card do dashboard vive desses campos — eles vêm do mesmo join."""
    repo = SQLAlchemyRemediationRepository(session)
    dono = uuid4()
    finding_id, scan_job_id = _outro_scan(session, user_id=dono)
    repo.save(_make_remediation(finding_id, scan_job_id))
    session.commit()

    ctx = repo.query(user_id=dono)[0]
    assert ctx.finding_title == "AWS key"
    assert ctx.finding_severity == "critical"
    assert ctx.finding_repo_url == "https://github.com/z/w"
    assert ctx.repo_full_name == "z/w"
    assert ctx.pr_number == 7
    assert ctx.commit_sha == "c" * 40


def test_query_filtra_por_scan_por_status_e_por_id(session, fixtures):
    repo = SQLAlchemyRemediationRepository(session)
    outro_finding, outro_scan = _outro_scan(session, user_id=USER_ID)

    minha = _make_remediation(fixtures["finding_id"], fixtures["scan_job_id"])
    # `status` só muda se for gravado assim na criação: não há mais
    # `update_status` — a decisão voltou a ser exclusiva do GitHub.
    outra = _make_remediation(
        outro_finding, outro_scan, status=RemediationStatus.APPROVED
    )
    repo.save(minha)
    repo.save(outra)
    session.commit()

    por_scan = repo.query(user_id=USER_ID, scan_job_id=outro_scan)
    assert [c.remediation.id for c in por_scan] == [outra.id]
    assert repo.count(user_id=USER_ID, scan_job_id=outro_scan) == 1

    sugeridas = repo.query(user_id=USER_ID, status=RemediationStatus.SUGGESTED)
    assert [c.remediation.id for c in sugeridas] == [minha.id]
    assert repo.count(user_id=USER_ID, status=RemediationStatus.SUGGESTED) == 1

    # Filtro por id herda o join: é assim que o PATCH prova a posse.
    assert len(repo.query(user_id=USER_ID, remediation_id=minha.id)) == 1
    assert repo.query(user_id=uuid4(), remediation_id=minha.id) == []
