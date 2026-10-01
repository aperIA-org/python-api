"""Testes da rota de remediação (`GET /remediations`) — só leitura.

Caminho HTTP real (TestClient), JWT real, SQLite in-memory via override de
``get_db`` — mesmo desenho de ``test_finding_routes``.

O que mais importa aqui é o isolamento por dono. ``remediations`` não tem
``user_id``: a posse vem do join com ``scan_jobs``. Um erro nesse join não
quebra nada visível — apenas mostra o patch de outra empresa.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.domain.remediation.entities import Remediation
from app.infrastructure.database.sqlalchemy import get_db
from app.infrastructure.persistence.models import (  # noqa: F401 — registra metadata
    finding_model,
    refresh_token_model,
    remediation_model,
    scan_job_model,
    scan_tool_run_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.persistence.models.finding_model import FindingModel
from app.infrastructure.persistence.models.scan_job_model import ScanJobModel
from app.infrastructure.persistence.models.user_model import UserModel
from app.infrastructure.repositories.sqlalchemy_remediation_repository import (
    SQLAlchemyRemediationRepository,
)
from app.infrastructure.security.jwt_handler import create_access_token
from app.main import app


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
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


@pytest.fixture
def client(session_factory):
    def _override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


def _headers(user_id) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {create_access_token(user_id, settings.SECRET_KEY, 15)}"
    }


def _cenario(session, *, email: str, commit: str, pr_number: int | None = 7):
    """Um usuário, um scan seu, um finding e uma remediação sugerida."""
    user_id, finding_id, job_id = uuid4(), uuid4(), uuid4()
    session.add(
        UserModel(
            id=user_id,
            username=email.split("@")[0],
            password="hash",
            email=email,
            created_at=datetime.utcnow(),
        )
    )
    session.add(
        FindingModel(
            id=finding_id,
            source="semgrep",
            severity="critical",
            tier=2,
            title="SQL injection",
            description="x",
            file_path="app/db.py",
            line_number=42,
            commit_sha=commit,
            repo_url="https://github.com/acme/repo",
            secret_verified=False,
            dedup_key=f"key-{finding_id}",
            created_at=datetime.utcnow(),
        )
    )
    session.add(
        ScanJobModel(
            id=job_id,
            commit_sha=commit,
            repo_url="https://github.com/acme/repo",
            repo_full_name="acme/repo",
            pr_number=pr_number,
            installation_id=42,
            user_id=user_id,
            created_at=datetime.utcnow(),
        )
    )
    session.flush()

    remediation = Remediation(
        finding_id=finding_id,
        scan_job_id=job_id,
        patch_diff="-bad\n+good",
        explanation="Parametrize a query.",
    )
    SQLAlchemyRemediationRepository(session).save(remediation)
    session.commit()
    return {"user_id": user_id, "job_id": job_id, "remediation": remediation}


# ------------------------------------------------------------------- GET


def test_lista_traz_a_remediacao_com_contexto(client, session_factory):
    with session_factory() as s:
        dados = _cenario(s, email="alice@acme.io", commit="a" * 40)

    resposta = client.get("/remediations", headers=_headers(dados["user_id"]))
    assert resposta.status_code == 200
    corpo = resposta.json()
    assert corpo["total"] == 1

    item = corpo["items"][0]
    assert item["id"] == str(dados["remediation"].id)
    assert item["status"] == "suggested"
    assert item["patch_diff"] == "-bad\n+good"
    # Contexto do join — é o que o card do dashboard renderiza.
    assert item["finding_title"] == "SQL injection"
    assert item["finding_severity"] == "critical"
    assert item["finding_file_path"] == "app/db.py"
    assert item["repo_full_name"] == "acme/repo"
    assert item["pr_number"] == 7


def test_lista_nao_vaza_remediacao_de_outro_usuario(client, session_factory):
    with session_factory() as s:
        minha = _cenario(s, email="alice@acme.io", commit="a" * 40)
        _cenario(s, email="bob@outra.io", commit="b" * 40)

    corpo = client.get("/remediations", headers=_headers(minha["user_id"])).json()
    assert corpo["total"] == 1
    assert corpo["items"][0]["id"] == str(minha["remediation"].id)


def test_lista_filtra_por_scan_e_por_status(client, session_factory):
    with session_factory() as s:
        dados = _cenario(s, email="alice@acme.io", commit="a" * 40)

    headers = _headers(dados["user_id"])
    assert (
        client.get(
            f"/remediations?scan_job_id={dados['job_id']}", headers=headers
        ).json()["total"]
        == 1
    )
    assert (
        client.get(f"/remediations?scan_job_id={uuid4()}", headers=headers).json()[
            "total"
        ]
        == 0
    )
    assert (
        client.get("/remediations?status=suggested", headers=headers).json()["total"]
        == 1
    )
    assert (
        client.get("/remediations?status=approved", headers=headers).json()["total"]
        == 0
    )


def test_lista_exige_token(client):
    assert client.get("/remediations").status_code == 401





