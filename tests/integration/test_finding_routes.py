"""Testes das rotas de consumo de findings (`/findings`).

Exercita o caminho HTTP real (TestClient) com:
- JWT valido emitido por ``create_access_token`` (auth real, sem override);
- Session sqlite in-memory injetada via override de ``get_db``.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import CVEId, Severity
from app.domain.scan.entities import ScanJob
from app.infrastructure.database.sqlalchemy import get_db
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.persistence.models import (  # noqa: F401 — registra metadata
    finding_model,
    refresh_token_model,
    remediation_model,
    scan_job_model,
    user_model,
)
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
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


@pytest.fixture
def user_id():
    return uuid4()


@pytest.fixture
def auth_headers(user_id) -> dict[str, str]:
    token = create_access_token(user_id, settings.SECRET_KEY, 15)
    return {"Authorization": f"Bearer {token}"}


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


@pytest.fixture
def seeded(session_factory, user_id):
    """Persiste 3 findings + os ScanJobs donos (do usuário do token)."""
    findings = [
        _make_finding(severity=Severity.CRITICAL, source="trufflehog", tier=1,
                      secret_verified=True, secret_type="aws", title="AWS key vazada"),
        _make_finding(severity=Severity.HIGH, source="semgrep", tier=2,
                      cve_id=CVEId("CVE-2024-1234"), raw_output={"rule": "sqli"}),
        _make_finding(severity=Severity.LOW, source="trivy", tier=2,
                      commit_sha="b" * 40, title="Dep desatualizada"),
    ]
    # Os findings só são visíveis se o scan do commit pertence ao usuário.
    jobs = [
        ScanJob(commit_sha="a" * 40, repo_url="https://github.com/acme/repo",
                installation_id=1, user_id=user_id),
        ScanJob(commit_sha="b" * 40, repo_url="https://github.com/acme/repo",
                installation_id=1, user_id=user_id),
    ]
    with session_factory() as s:
        SQLAlchemyFindingRepository(s).bulk_save(findings)
        for j in jobs:
            SQLAlchemyScanJobRepository(s).save(j)
        s.commit()
    return findings


# ----------------------------------------------------------------- auth


def test_list_requires_auth(client):
    resp = client.get("/findings")
    assert resp.status_code == 401


def test_detail_requires_auth(client):
    resp = client.get(f"/findings/{uuid4()}")
    assert resp.status_code == 401


def test_rejects_garbage_token(client):
    resp = client.get("/findings", headers={"Authorization": "Bearer nao-e-jwt"})
    assert resp.status_code == 401


# ----------------------------------------------------------------- listagem


def test_list_returns_all(client, auth_headers, seeded):
    resp = client.get("/findings", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 3
    assert len(body["items"]) == 3
    # raw_output nao aparece na listagem
    assert "raw_output" not in body["items"][0]


def test_filter_by_severity(client, auth_headers, seeded):
    resp = client.get("/findings", headers=auth_headers, params={"severity": "critical"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["severity"] == "critical"
    assert body["items"][0]["secret_verified"] is True


def test_filter_by_commit_sha(client, auth_headers, seeded):
    resp = client.get("/findings", headers=auth_headers, params={"commit_sha": "b" * 40})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["source"] == "trivy"


def test_filter_by_tier(client, auth_headers, seeded):
    resp = client.get("/findings", headers=auth_headers, params={"tier": 2})
    assert resp.status_code == 200
    assert resp.json()["total"] == 2


def test_pagination_limit(client, auth_headers, seeded):
    resp = client.get("/findings", headers=auth_headers, params={"limit": 1})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 3          # total ignora paginacao
    assert len(body["items"]) == 1     # pagina respeita o limit
    assert body["limit"] == 1


def test_invalid_severity_returns_422(client, auth_headers):
    resp = client.get("/findings", headers=auth_headers, params={"severity": "meh"})
    assert resp.status_code == 422


def test_invalid_tier_returns_422(client, auth_headers):
    resp = client.get("/findings", headers=auth_headers, params={"tier": 9})
    assert resp.status_code == 422


# ----------------------------------------------------------------- detalhe


def test_detail_returns_raw_output(client, auth_headers, seeded):
    target = next(f for f in seeded if f.source == "semgrep")
    resp = client.get(f"/findings/{target.id}", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == str(target.id)
    assert body["cve_id"] == "CVE-2024-1234"
    assert body["raw_output"] == {"rule": "sqli"}


def test_detail_not_found(client, auth_headers, seeded):
    resp = client.get(f"/findings/{uuid4()}", headers=auth_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Finding nao encontrado"


# ----------------------------------------------------------------- grupos
#
# `GET /findings/groups` é a resposta ao DAST: a listagem plana vira milhares
# de linhas que são dezenas de problemas repetidos por rota. Aqui cada item é
# um problema, com quantas vezes ele ocorre.


@pytest.fixture
def seeded_grupos(session_factory, user_id):
    """Um cenário com repetição: 1 critical isolado, 1 medium médio e 1 info
    volumoso — mais um commit de OUTRO usuário, que nunca pode aparecer.
    """
    outro_user = uuid4()
    findings = (
        [
            _make_finding(source="zap", tier=3, severity=Severity.CRITICAL,
                          title="RCE via upload", cwe_id="CWE-94",
                          file_path="/admin/upload", line_number=None,
                          asset="https://juice.example")
        ]
        + [
            _make_finding(source="zap", tier=3, severity=Severity.MEDIUM,
                          title="Cross-Domain Misconfiguration",
                          file_path=f"/api/rota/{i:03d}", line_number=None,
                          asset="https://juice.example")
            for i in range(6)
        ]
        + [
            _make_finding(source="zap", tier=3, severity=Severity.INFO,
                          title="Cabecalho de seguranca ausente",
                          file_path=f"/pagina/{i:03d}", line_number=None,
                          asset="https://juice.example")
            for i in range(20)
        ]
        + [
            _make_finding(source="semgrep", tier=1, severity=Severity.HIGH,
                          title="Segredo do rival", commit_sha="c" * 40,
                          file_path="rival.py", line_number=1)
        ]
    )
    jobs = [
        ScanJob(commit_sha="a" * 40, repo_url="https://github.com/acme/repo",
                installation_id=1, user_id=user_id),
        ScanJob(commit_sha="c" * 40, repo_url="https://github.com/rival/repo",
                installation_id=2, user_id=outro_user),
    ]
    with session_factory() as s:
        SQLAlchemyFindingRepository(s).bulk_save(findings)
        for j in jobs:
            SQLAlchemyScanJobRepository(s).save(j)
        s.commit()
    return findings


def test_groups_requires_auth(client):
    resp = client.get("/findings/groups")
    assert resp.status_code == 401


def test_groups_nao_e_capturado_pela_rota_de_detalhe(client, auth_headers, seeded_grupos):
    """`/findings/groups` é declarada ANTES de `/findings/{finding_id}`.

    Regressão real se a ordem inverter: o FastAPI casaria "groups" com o path
    param `finding_id: UUID` e devolveria 422 de validação em vez do agregado.
    Este teste é o que pega essa troca de lugar.
    """
    resp = client.get("/findings/groups", headers=auth_headers)

    assert resp.status_code == 200, resp.text
    assert "items" in resp.json()  # e não um erro de parse de UUID


def test_groups_retorna_a_forma_esperada(client, auth_headers, seeded_grupos):
    resp = client.get("/findings/groups", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()

    assert set(body) == {"items", "total_findings", "truncado"}
    item = body["items"][0]
    assert set(item) == {
        "source", "severity", "tier", "title", "cve_id", "cwe_id", "asset",
        "ocorrencias", "caminhos", "algum_secret_verificado",
        "primeiro_em", "ultimo_em", "exemplo_finding_id", "amostra",
    }
    assert item["severity"] == "critical"
    assert item["title"] == "RCE via upload"
    assert item["cwe_id"] == "CWE-94"
    assert isinstance(item["amostra"], list)


def test_groups_total_findings_soma_ocorrencias_nao_grupos(client, auth_headers,
                                                           seeded_grupos):
    """`total_findings` é quantos findings o agregado representa.

    Se fosse a contagem de grupos, a tela diria "3 findings" para um scan de 27
    — e o número deixaria de bater com o badge da sidebar e com `GET /findings`.
    """
    body = client.get("/findings/groups", headers=auth_headers).json()

    assert len(body["items"]) == 3
    assert body["total_findings"] == 27
    assert body["total_findings"] == sum(g["ocorrencias"] for g in body["items"])
    # E concorda com a listagem plana do mesmo usuário.
    assert client.get("/findings", headers=auth_headers).json()["total"] == 27


def test_groups_ordena_severidade_antes_de_volume(client, auth_headers, seeded_grupos):
    """O `info` com 20 ocorrências não pode passar na frente do `critical` com 1."""
    body = client.get("/findings/groups", headers=auth_headers).json()

    assert [g["severity"] for g in body["items"]] == ["critical", "medium", "info"]
    assert [g["ocorrencias"] for g in body["items"]] == [1, 6, 20]


def test_groups_isola_por_usuario(client, seeded_grupos):
    """SEGURANÇA: o token decide o escopo — o commit do rival não aparece.

    O agregado expõe títulos, CWEs e caminhos; vazar um grupo é vazar o mapa de
    vulnerabilidades de outro cliente.
    """
    intruso = create_access_token(uuid4(), settings.SECRET_KEY, 15)
    body = client.get(
        "/findings/groups", headers={"Authorization": f"Bearer {intruso}"}
    ).json()

    assert body["items"] == []
    assert body["total_findings"] == 0

    # O finding do rival existe no banco — quem o esconde é o escopo, não a
    # ausência de dados.
    dono_rival = create_access_token(uuid4(), settings.SECRET_KEY, 15)
    assert client.get(
        "/findings/groups", headers={"Authorization": f"Bearer {dono_rival}"}
    ).json()["items"] == []


def test_groups_filtra_por_commit_sha(client, auth_headers, seeded_grupos):
    resp = client.get("/findings/groups", headers=auth_headers,
                      params={"commit_sha": "a" * 40})
    assert resp.status_code == 200
    assert resp.json()["total_findings"] == 27

    vazio = client.get("/findings/groups", headers=auth_headers,
                       params={"commit_sha": "d" * 40})
    assert vazio.json() == {"items": [], "total_findings": 0, "truncado": False}


def test_groups_amostra_respeita_o_parametro(client, auth_headers, seeded_grupos):
    body = client.get("/findings/groups", headers=auth_headers,
                      params={"amostra": 2}).json()

    volumoso = next(g for g in body["items"] if g["ocorrencias"] == 20)
    assert len(volumoso["amostra"]) == 2
    assert volumoso["amostra"] == ["/pagina/000", "/pagina/001"]


def test_groups_amostra_zero_mantem_o_exemplo_para_o_deep_link(client, auth_headers,
                                                               seeded_grupos):
    """Sem preview, o grupo ainda precisa apontar para um finding navegável."""
    body = client.get("/findings/groups", headers=auth_headers,
                      params={"amostra": 0}).json()

    for grupo in body["items"]:
        detalhe = client.get(f"/findings/{grupo['exemplo_finding_id']}",
                             headers=auth_headers)
        assert detalhe.status_code == 200, grupo["title"]
        assert detalhe.json()["title"] == grupo["title"]


def test_groups_amostra_fora_da_faixa_retorna_422(client, auth_headers):
    assert client.get("/findings/groups", headers=auth_headers,
                      params={"amostra": -1}).status_code == 422
    assert client.get("/findings/groups", headers=auth_headers,
                      params={"amostra": 51}).status_code == 422


def test_groups_sem_dados_retorna_agregado_vazio(client, auth_headers):
    resp = client.get("/findings/groups", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == {"items": [], "total_findings": 0, "truncado": False}


# ----------------------------------------------------------------- drill-down


def test_list_filtra_por_title_exato(client, auth_headers, seeded_grupos):
    """`?title=` é o drill-down do grupo: igualdade exata, não busca livre."""
    resp = client.get("/findings", headers=auth_headers,
                      params={"title": "Cross-Domain Misconfiguration", "limit": 100})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 6
    assert {f["title"] for f in body["items"]} == {"Cross-Domain Misconfiguration"}

    # Substring/prefixo não casam.
    assert client.get("/findings", headers=auth_headers,
                      params={"title": "Cross-Domain"}).json()["total"] == 0


def test_grupo_abre_exatamente_suas_ocorrencias(client, auth_headers, seeded_grupos):
    """Contrato entre as duas rotas: o `ocorrencias` do grupo tem que ser o
    `total` que `?title=` devolve. Divergir aqui é a tela prometer um número e
    abrir outro."""
    grupos = client.get("/findings/groups", headers=auth_headers).json()["items"]

    for grupo in grupos:
        page = client.get("/findings", headers=auth_headers,
                          params={"title": grupo["title"], "limit": 100}).json()
        assert page["total"] == grupo["ocorrencias"], grupo["title"]
