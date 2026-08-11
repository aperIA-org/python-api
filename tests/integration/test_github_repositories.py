"""Testes dos repositórios síncronos de GithubAccount e Repository (sqlite)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.domain.github.entities import GithubAccount, Repository
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    github_account_model,
    refresh_token_model,
    remediation_model,
    repository_model,
    scan_job_model,
    scan_report_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.repositories.sqlalchemy_github_account_repository import (
    SQLAlchemyGithubAccountRepository,
)
from app.infrastructure.repositories.sqlalchemy_repository_repository import (
    SQLAlchemyRepositoryRepository,
)


@pytest.fixture
def session():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(eng)
    factory = sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
    with factory() as s:
        yield s
    eng.dispose()


# ------------------------------------------------------------- GithubAccount


def test_account_save_and_get_by_installation(session):
    repo = SQLAlchemyGithubAccountRepository(session)
    user_id = uuid4()
    repo.save(GithubAccount(user_id=user_id, installation_id=999, github_login="acme", account_type="Organization"))
    session.commit()

    acc = repo.get_by_installation(999)
    assert acc is not None
    assert acc.user_id == user_id
    assert acc.github_login == "acme"


def test_account_save_upserts_owner(session):
    repo = SQLAlchemyGithubAccountRepository(session)
    u1, u2 = uuid4(), uuid4()
    repo.save(GithubAccount(user_id=u1, installation_id=999, github_login="old", account_type="User"))
    session.commit()
    repo.save(GithubAccount(user_id=u2, installation_id=999, github_login="new", account_type="User"))
    session.commit()

    accs = repo.list_by_user(u2)
    assert len(accs) == 1
    assert repo.get_by_installation(999).github_login == "new"


def test_account_delete(session):
    repo = SQLAlchemyGithubAccountRepository(session)
    acc = GithubAccount(user_id=uuid4(), installation_id=1, github_login="x", account_type="User")
    repo.save(acc)
    session.commit()
    # get_by_installation traz a entidade com o mesmo id? Recuperamos pelo id real.
    stored = repo.get_by_installation(1)
    repo.delete(stored.id)
    session.commit()
    assert repo.get_by_installation(1) is None


# --------------------------------------------------------------- Repository


def _repo_entity(user_id, **overrides) -> Repository:
    base = {
        "user_id": user_id,
        "github_account_id": uuid4(),
        "installation_id": 42,
        "github_repo_id": 100,
        "full_name": "acme/api",
        "url": "https://github.com/acme/api",
    }
    base.update(overrides)
    return Repository(**base)


def test_repository_save_and_list_by_user(session):
    repo = SQLAlchemyRepositoryRepository(session)
    user_id = uuid4()
    repo.save(_repo_entity(user_id, github_repo_id=100, full_name="acme/api"))
    repo.save(_repo_entity(user_id, github_repo_id=200, full_name="acme/web"))
    session.commit()

    items = repo.list_by_user(user_id)
    assert {r.full_name for r in items} == {"acme/api", "acme/web"}


def test_repository_get_by_installation_and_repo(session):
    repo = SQLAlchemyRepositoryRepository(session)
    repo.save(_repo_entity(uuid4(), installation_id=42, github_repo_id=100))
    session.commit()
    found = repo.get_by_installation_and_repo(42, 100)
    assert found is not None
    assert repo.get_by_installation_and_repo(42, 999) is None


def test_repository_set_active_and_delete(session):
    repo = SQLAlchemyRepositoryRepository(session)
    user_id = uuid4()
    repo.save(_repo_entity(user_id))
    session.commit()
    rid = repo.list_by_user(user_id)[0].id

    repo.set_active(rid, False)
    session.commit()
    assert repo.get_by_id(rid).active is False

    repo.delete(rid)
    session.commit()
    assert repo.get_by_id(rid) is None


def test_repository_upsert_on_user_repo(session):
    repo = SQLAlchemyRepositoryRepository(session)
    user_id = uuid4()
    repo.save(_repo_entity(user_id, github_repo_id=100, full_name="old/name", active=True))
    session.commit()
    repo.save(_repo_entity(user_id, github_repo_id=100, full_name="new/name", active=False))
    session.commit()
    items = repo.list_by_user(user_id)
    assert len(items) == 1
    assert items[0].full_name == "new/name"
    assert items[0].active is False
