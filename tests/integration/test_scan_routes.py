"""Testes das rotas de status de scan (`/scans`).

Caminho HTTP real (TestClient) com JWT válido e Session sqlite injetada
via override de ``get_db``.
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
from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity
from app.domain.scan.entities import ScanJob
from app.domain.scan.report_entities import ScanReport
from app.domain.scan.tool_run_entities import ScanToolRun
from app.domain.scan.value_objects import ScanTier, TierStatus, ToolStatus
from app.infrastructure.database.sqlalchemy import get_db
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    refresh_token_model,
    remediation_model,
    scan_job_model,
    scan_tool_run_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_report_repository import (
    SQLAlchemyScanReportRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_tool_run_repository import (
    SQLAlchemyScanToolRunRepository,
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
def auth_headers(user_id) -> dict[str, str]:
    token = create_access_token(user_id, settings.SECRET_KEY, 15)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def user_id():
    return uuid4()


@pytest.fixture
def seeded(session_factory, user_id):
    """Devolve o id da execução corrente de 'a'*40.

    O relatório é gravado ligado a ela: ``scan_job_id`` é NOT NULL desde que um
    relatório passou a pertencer à execução, e não ao commit.
    """
    job = ScanJob(
        commit_sha="a" * 40,
        repo_url="https://github.com/acme/repo",
        installation_id=1,
        pr_number=9,
        repo_full_name="acme/repo",
        tier1_status=TierStatus.DONE,
        tier1_started_at=datetime(2026, 8, 1, 12, 0),
        tier2_status=TierStatus.DONE,
        blocked_at_tier=None,
        final_risk_score=80,
        final_risk_level="high",
        user_id=user_id,
    )
    other = ScanJob(
        commit_sha="b" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
        tier1_status=TierStatus.RUNNING, user_id=user_id,
    )
    findings = [
        Finding(source="semgrep", severity=Severity.HIGH, title="t1", description="d",
                commit_sha="a" * 40, repo_url="https://github.com/acme/repo", tier=2),
        Finding(source="trivy", severity=Severity.LOW, title="t2", description="d",
                commit_sha="a" * 40, repo_url="https://github.com/acme/repo", tier=2),
    ]
    report = ScanReport(
        commit_sha="a" * 40, scan_job_id=job.id, tier=2,
        report_markdown="## Relatorio Tier 2",
        analysis_json={"risk_score": {"score": 80, "level": "high"}},
        degraded=False, comment_id=123, posted=True,
    )
    with session_factory() as s:
        SQLAlchemyScanJobRepository(s).save(job)
        SQLAlchemyScanJobRepository(s).save(other)
        SQLAlchemyFindingRepository(s).bulk_save(findings)
        SQLAlchemyScanReportRepository(s).save(report)
        s.commit()
    return job.id


@pytest.fixture
def historico(session_factory, user_id, seeded):
    """Acrescenta uma execução ANTERIOR de 'a'*40, com relatório próprio.

    Devolve ``(corrente, antiga)``. A anterior tem ``tier1_started_at`` explícito
    e mais antigo — é ele, não ``created_at``, que ordena o histórico.
    """
    antiga = ScanJob(
        commit_sha="a" * 40,
        repo_url="https://github.com/acme/repo",
        installation_id=1,
        pr_number=9,
        repo_full_name="acme/repo",
        tier1_status=TierStatus.DONE,
        tier1_started_at=datetime(2026, 7, 20, 8, 0),
        created_at=datetime(2026, 7, 20, 8, 0),
        tier2_status=TierStatus.FAILED,
        final_risk_score=30,
        final_risk_level="low",
        user_id=user_id,
    )
    with session_factory() as s:
        SQLAlchemyScanJobRepository(s).save(antiga)
        SQLAlchemyScanReportRepository(s).save(
            ScanReport(
                commit_sha="a" * 40, scan_job_id=antiga.id, tier=2,
                report_markdown="## Relatorio antigo", analysis_json={},
                degraded=False, comment_id=1, posted=True,
            )
        )
        s.commit()
    return seeded, antiga.id


def test_list_requires_auth(client):
    assert client.get("/scans").status_code == 401


def test_detail_requires_auth(client):
    assert client.get("/scans/" + "a" * 40).status_code == 401


def test_list_returns_scans(client, auth_headers, seeded):
    resp = client.get("/scans", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert len(body["items"]) == 2
    # a listagem enxuta não traz o findings_summary
    assert "findings_summary" not in body["items"][0]


def test_get_by_commit_with_summary(client, auth_headers, seeded):
    resp = client.get("/scans/" + "a" * 40, headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["commit_sha"] == "a" * 40
    assert body["tier2_status"] == "done"
    assert body["final_risk_score"] == 80
    summary = body["findings_summary"]
    assert summary["total"] == 2
    assert summary["by_severity"] == {"high": 1, "low": 1}
    assert summary["by_tier"] == {"2": 2}


def test_get_not_found(client, auth_headers, seeded):
    resp = client.get("/scans/" + "c" * 40, headers=auth_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Scan nao encontrado"


# --------------------------------------------------------------- relatórios


def test_reports_requires_auth(client):
    assert client.get("/scans/" + "a" * 40 + "/report").status_code == 401


def test_list_reports(client, auth_headers, seeded):
    resp = client.get("/scans/" + "a" * 40 + "/report", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["commit_sha"] == "a" * 40
    assert len(body["reports"]) == 1
    assert body["reports"][0]["tier"] == 2
    assert body["reports"][0]["comment_id"] == 123


def test_list_reports_empty_but_scan_exists(client, auth_headers, seeded):
    # 'b' tem ScanJob mas nenhum relatório → 200 com lista vazia
    resp = client.get("/scans/" + "b" * 40 + "/report", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["reports"] == []


def test_list_reports_scan_not_found(client, auth_headers, seeded):
    resp = client.get("/scans/" + "c" * 40 + "/report", headers=auth_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Scan nao encontrado"


def test_report_by_tier(client, auth_headers, seeded):
    resp = client.get("/scans/" + "a" * 40 + "/tiers/2/report", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["tier"] == 2
    assert body["report_markdown"] == "## Relatorio Tier 2"
    assert body["analysis_json"]["risk_score"]["score"] == 80


def test_report_by_tier_not_found(client, auth_headers, seeded):
    resp = client.get("/scans/" + "a" * 40 + "/tiers/3/report", headers=auth_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Relatorio nao encontrado"


def test_report_by_tier_out_of_range(client, auth_headers, seeded):
    resp = client.get("/scans/" + "a" * 40 + "/tiers/9/report", headers=auth_headers)
    assert resp.status_code == 422


# ------------------------------------------------- histórico de execuções


def test_history_lista_execucoes_da_mais_nova_para_a_mais_antiga(
    client, auth_headers, historico
):
    corrente, antiga = historico
    body = client.get("/scans/" + "a" * 40 + "/history", headers=auth_headers).json()
    assert body["total"] == 2
    assert [i["id"] for i in body["items"]] == [str(corrente), str(antiga)]
    # a execução consultada faz parte da lista
    assert body["items"][1]["final_risk_score"] == 30

    # o histórico é do commit: entrar por qualquer execução dá a mesma lista
    por_uuid = client.get(f"/scans/{antiga}/history", headers=auth_headers).json()
    assert [i["id"] for i in por_uuid["items"]] == [str(corrente), str(antiga)]


def test_history_de_scan_sem_reexecucao_traz_apenas_ele(client, auth_headers, seeded):
    body = client.get("/scans/" + "b" * 40 + "/history", headers=auth_headers).json()
    assert body["total"] == 1
    assert body["items"][0]["commit_sha"] == "b" * 40


def test_history_scan_not_found(client, auth_headers, seeded):
    resp = client.get("/scans/" + "c" * 40 + "/history", headers=auth_headers)
    assert resp.status_code == 404


def test_history_requires_auth(client):
    assert client.get("/scans/" + "a" * 40 + "/history").status_code == 401


def test_uuid_endereca_a_execucao_e_sha_a_corrente(client, auth_headers, historico):
    """As duas formas do path param não são sinônimos quando há histórico.

    O sha responde "como está este commit agora" (execução corrente); o uuid
    endereça uma execução específica — é o que torna o histórico navegável.
    """
    corrente, antiga = historico

    por_sha = client.get("/scans/" + "a" * 40, headers=auth_headers).json()
    assert por_sha["id"] == str(corrente)
    assert por_sha["tier2_status"] == "done"
    assert por_sha["final_risk_score"] == 80

    por_uuid = client.get(f"/scans/{antiga}", headers=auth_headers).json()
    assert por_uuid["id"] == str(antiga)
    assert por_uuid["commit_sha"] == "a" * 40
    assert por_uuid["tier2_status"] == "failed"
    assert por_uuid["final_risk_score"] == 30


def test_relatorios_sao_por_execucao(client, auth_headers, historico):
    """Cada execução guarda o seu markdown — antes o rescan sobrescrevia."""
    corrente, antiga = historico

    atual = client.get("/scans/" + "a" * 40 + "/report", headers=auth_headers).json()
    assert atual["scan_id"] == str(corrente)
    assert [r["report_markdown"] for r in atual["reports"]] == ["## Relatorio Tier 2"]

    velho = client.get(f"/scans/{antiga}/report", headers=auth_headers).json()
    assert velho["scan_id"] == str(antiga)
    assert velho["commit_sha"] == "a" * 40
    assert [r["report_markdown"] for r in velho["reports"]] == ["## Relatorio antigo"]

    por_tier = client.get(f"/scans/{antiga}/tiers/2/report", headers=auth_headers).json()
    assert por_tier["report_markdown"] == "## Relatorio antigo"


def test_execucao_de_outro_usuario_por_uuid_e_404(client, auth_headers, session_factory):
    """Isolamento vale para a forma uuid tanto quanto para o sha."""
    alheio = ScanJob(
        commit_sha="e" * 40, repo_url="https://github.com/acme/repo",
        installation_id=1, tier1_status=TierStatus.DONE, user_id=uuid4(),
    )
    with session_factory() as s:
        SQLAlchemyScanJobRepository(s).save(alheio)
        s.commit()

    assert client.get(f"/scans/{alheio.id}", headers=auth_headers).status_code == 404
    assert client.get(
        f"/scans/{alheio.id}/history", headers=auth_headers
    ).status_code == 404


# ───────────────────────── GET /scans/{id}/tools ─────────────────────────
#
# O status por ferramenta é o que separa "o Trivy rodou e não achou nada" de
# "o Trivy quebrou" — no `ScanJob` as duas situações fecham o Tier 2 como
# `done` e ficam indistinguíveis.


@pytest.fixture
def com_ferramentas(session_factory, seeded):
    """Grava algumas execuções de ferramenta na execução corrente de 'a'*40."""
    runs = [
        ScanToolRun(
            commit_sha="a" * 40, scan_job_id=seeded, tier=1, tool="trufflehog",
            status=ToolStatus.DONE, findings_count=0, duration_ms=900,
        ),
        ScanToolRun(
            commit_sha="a" * 40, scan_job_id=seeded, tier=2, tool="trivy",
            status=ToolStatus.FAILED, reason="TimeoutError: sem resposta",
        ),
        ScanToolRun(
            commit_sha="a" * 40, scan_job_id=seeded, tier=2, tool="prowler",
            status=ToolStatus.SKIPPED, reason="no_iac_files",
        ),
        ScanToolRun(
            commit_sha="a" * 40, scan_job_id=seeded, tier=2, tool="ia-tier2",
            status=ToolStatus.DEGRADED, reason="CircuitOpenError",
        ),
    ]
    with session_factory() as s:
        for r in runs:
            SQLAlchemyScanToolRunRepository(s).save(r)
        s.commit()
    return seeded


def test_lista_traz_contagem_de_findings_igual_ao_detalhe(client, auth_headers, seeded):
    """A lista mostra `findings_total`, e ele bate com o detalhe da execucao.

    As duas telas do mesmo fluxo (Scans -> relatorio) mostram esse numero; se
    divergissem, o usuario veria uma contagem mudar ao clicar em "ver relatorio".
    Vem de uma query agregada, nao de um count por card.
    """
    lista = client.get("/scans", headers=auth_headers).json()
    item = next(i for i in lista["items"] if i["id"] == str(seeded))
    detalhe = client.get(f"/scans/{seeded}", headers=auth_headers).json()

    assert item["findings_total"] == detalhe["findings_summary"]["total"]
    # E o resumo por severidade continua sendo so' do detalhe.
    assert "findings_summary" not in item


def test_tools_lista_por_ferramenta(client, auth_headers, com_ferramentas):
    r = client.get(f"/scans/{com_ferramentas}/tools", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["scan_id"] == str(com_ferramentas)
    assert body["commit_sha"] == "a" * 40

    por_tool = {t["tool"]: t for t in body["tools"]}
    # Rodou e não achou nada: 0, não null. É a distinção que a tabela existe
    # para guardar.
    assert por_tool["trufflehog"]["status"] == "done"
    assert por_tool["trufflehog"]["findings_count"] == 0
    assert por_tool["trufflehog"]["duration_ms"] == 900
    # Quebrou: sem contagem, e com o tipo da exceção no motivo.
    assert por_tool["trivy"]["status"] == "failed"
    assert por_tool["trivy"]["findings_count"] is None
    assert "TimeoutError" in por_tool["trivy"]["reason"]
    # Decisão do pipeline, não falha.
    assert por_tool["prowler"]["status"] == "skipped"
    assert por_tool["prowler"]["reason"] == "no_iac_files"
    # `degraded` só existe no nível da ferramenta: o tier fechou como `done`.
    assert por_tool["ia-tier2"]["status"] == "degraded"


def test_tools_traz_o_catalogo_esperado(client, auth_headers, seeded):
    """`expected` vem preenchido mesmo sem nenhuma linha.

    É ele que permite a UI desenhar as ferramentas de um tier que ainda não
    começou, sem manter uma cópia própria do catálogo que iria divergir.
    """
    r = client.get(f"/scans/{seeded}/tools", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["tools"] == []
    assert body["expected"]["1"] == ["trufflehog", "semgrep-changed"]
    assert "prowler" in body["expected"]["2"]
    assert "zap" in body["expected"]["3"]


def test_tools_aceita_commit_sha(client, auth_headers, com_ferramentas):
    """Mesma dualidade das demais rotas: uuid ou sha (execução corrente)."""
    r = client.get(f"/scans/{'a' * 40}/tools", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["scan_id"] == str(com_ferramentas)


def test_tools_ordenado_por_tier(client, auth_headers, com_ferramentas):
    r = client.get(f"/scans/{com_ferramentas}/tools", headers=auth_headers)
    tiers = [t["tier"] for t in r.json()["tools"]]
    assert tiers == sorted(tiers)


def test_tools_de_outro_usuario_da_404(client, com_ferramentas):
    """404 e não 403: não vazamos nem a existência do commit."""
    intruso = create_access_token(uuid4(), settings.SECRET_KEY, 15)
    r = client.get(
        f"/scans/{com_ferramentas}/tools",
        headers={"Authorization": f"Bearer {intruso}"},
    )
    assert r.status_code == 404


def test_tools_sem_token_da_401(client, com_ferramentas):
    assert client.get(f"/scans/{com_ferramentas}/tools").status_code == 401


# ───────────────── GET /scans/{id}/tools — resumo de I.A (tier 3) ─────────────
#
# O `analysis_json` do tier 3 carrega o array `findings` completo, com
# `raw_output` por finding — centenas de KB. A rota devolve um RESUMO: a lista
# de Scans a chama uma vez por card (até 12), então o blob cru seriam megabytes
# por tela. E o blob é JSON produzido por LLM, então nada nele é confiável.


ANALISE_TIER3 = {
    "attack_path": [
        {
            "step": 1,
            "phase": "credential_access",
            "technique": "T1552.003",
            "description": "Secret do Github exposto no repositorio.",
            # Strings longas legíveis por humano — a rota conta, não devolve.
            "finding_ids": [
                "trufflehog: Possível secret (não verificado): Github (README.md:184)",
                "trufflehog: Possível secret (não verificado): Github (docs/ci.md:12)",
            ],
            "caldera_validated": True,
        },
        {
            "step": 2,
            "phase": "lateral_movement",
            "technique": "T1078",
            "description": "Uso da credencial para acessar a API interna.",
            "finding_ids": ["semgrep: SSRF em app/api.py:44"],
            "caldera_validated": False,
        },
    ],
    "kill_chain_complete": True,
    "prioritized_actions": [
        {"priority": 1, "action": "Revogar o token", "rationale": "Exposto em repo publico"}
    ],
    "risk_score_adjusted": {"score": 92, "level": "critical"},
    "cti_status": "available",
    "cti_data": {
        "known_exploited": True,
        "epss_score": 0.87,
        "active_threat": True,
        "mitre_techniques": ["T1552.003", "T1078"],
        "cvss_base": 9.1,
    },
    "caldera_status": "available",
    "caldera_results": {
        "status": "reachable",
        "techniques_executed": 3,
        "techniques_successful": 2,
        "ttps_used": ["T1552.003", "T1078"],
        "caldera_validated": True,
        "validacao_parcial": False,
    },
    "degraded": False,
    # Os dois blocos pesados/irrelevantes para o resumo — nunca devem sair.
    "findings": [
        {"title": "secret", "raw_output": "x" * 5000},
        {"title": "ssrf", "raw_output": "y" * 5000},
    ],
    "validacao_evidencia": {"confirmados": 1, "detalhe": "z" * 2000},
}


@pytest.fixture
def relatorio_tier3(session_factory, seeded):
    """Fábrica: grava um relatório de tier 3 na execução corrente de 'a'*40."""

    def _gravar(analysis_json, *, degraded: bool = False):
        with session_factory() as s:
            SQLAlchemyScanReportRepository(s).save(
                ScanReport(
                    commit_sha="a" * 40, scan_job_id=seeded, tier=3,
                    report_markdown="## Relatorio Tier 3",
                    analysis_json=analysis_json,
                    degraded=degraded, comment_id=None, posted=False,
                )
            )
            s.commit()
        return seeded

    return _gravar


def test_tools_ia_resume_o_attack_path(client, auth_headers, relatorio_tier3):
    """Caminho felizmente completo: paths, risco, CTI e Caldera preenchidos."""
    scan_id = relatorio_tier3(ANALISE_TIER3)
    r = client.get(f"/scans/{scan_id}/tools", headers=auth_headers)
    assert r.status_code == 200
    ia = r.json()["ia"]

    assert ia["degraded"] is False
    assert ia["reason"] is None
    assert ia["kill_chain_complete"] is True
    assert ia["risk_score"] == 92
    assert ia["risk_level"] == "critical"

    assert len(ia["paths"]) == 2
    passo1 = ia["paths"][0]
    assert passo1["step"] == 1
    assert passo1["phase"] == "credential_access"
    assert passo1["technique"] == "T1552.003"
    assert passo1["caldera_validated"] is True
    # Só a contagem: as strings de `finding_ids` são longas e ninguém as usa.
    assert passo1["finding_count"] == 2
    assert "finding_ids" not in passo1
    assert ia["paths"][1]["finding_count"] == 1
    assert ia["paths"][1]["caldera_validated"] is False

    assert ia["cti"] == {
        "status": "available",
        "known_exploited": True,
        "epss_score": 0.87,
        "active_threat": True,
        "mitre_techniques": ["T1552.003", "T1078"],
    }
    assert ia["caldera"] == {
        "status": "reachable",
        "techniques_executed": 3,
        "techniques_successful": 2,
        "validated": True,
        "partial": False,
        "ttps": ["T1552.003", "T1078"],
    }


def test_tools_ia_nao_devolve_o_blob_de_findings(client, auth_headers, relatorio_tier3):
    """O `raw_output` dos findings não pode vazar na resposta.

    É a razão de existir do resumo: com 12 cards na tela, devolver o
    `analysis_json` cru seriam megabytes por carregamento.
    """
    scan_id = relatorio_tier3(ANALISE_TIER3)
    r = client.get(f"/scans/{scan_id}/tools", headers=auth_headers)
    corpo = r.text
    assert "raw_output" not in corpo
    assert "validacao_evidencia" not in corpo
    assert "prioritized_actions" not in corpo
    # O blob tem >12 KB só de padding; o resumo é ordens de grandeza menor.
    assert len(corpo) < 2000


def test_tools_ia_degradada(client, auth_headers, relatorio_tier3):
    """Blob real de quando o Claude falha: só `reason`/`cti_data`/`degraded`/`findings`.

    Sem `attack_path`, sem `risk_score_adjusted`, sem `caldera_results` — e nada
    disso pode virar 500.
    """
    scan_id = relatorio_tier3(
        {
            "degraded": True,
            "reason": "CircuitOpenError",
            "cti_data": {"known_exploited": False, "epss_score": 0.01,
                         "active_threat": False, "mitre_techniques": []},
            "findings": [{"title": "secret", "raw_output": "x" * 100}],
        },
        degraded=True,
    )
    r = client.get(f"/scans/{scan_id}/tools", headers=auth_headers)
    assert r.status_code == 200
    ia = r.json()["ia"]
    assert ia["degraded"] is True
    assert ia["reason"] == "CircuitOpenError"
    assert ia["paths"] == []
    assert ia["risk_score"] is None
    assert ia["risk_level"] is None
    assert ia["kill_chain_complete"] is False
    # O CTI sobreviveu à queda do Claude: é dado nosso, não do modelo.
    assert ia["cti"]["known_exploited"] is False
    assert ia["cti"]["status"] is None
    # Emulação ausente sai `None`, não um bloco zerado — "não rodou" não pode
    # parecer "rodou e falhou".
    assert ia["caldera"] is None
    # A leitura executiva não existe no blob degradado — e `None` é a resposta
    # certa: a tela mostra "não calculado", não um veredito de fachada.
    assert ia["verdict"] is None
    assert ia["effort"] is None
    assert ia["deadline"] is None
    assert ia["impact"] is None


def test_tools_ia_resume_a_leitura_executiva(client, auth_headers, relatorio_tier3):
    """Veredito, esforço e prazo, quando o Tier 3 os emitiu.

    São o que alimenta os tiles da tela de relatório. `recommendation` é um enum
    curto de propósito: a UI colore por ele em vez de parsear a `headline`.
    """
    scan_id = relatorio_tier3(
        {
            **ANALISE_TIER3,
            "executive_verdict": {
                "recommendation": "bloquear",
                "headline": "Token do Github valido exposto e alcancavel pela API interna.",
            },
            "remediation_effort": {"level": "baixo", "label": "2 arquivos, revogacao de token"},
            "recommended_deadline": {"days": 1, "label": "24 horas"},
        }
    )
    r = client.get(f"/scans/{scan_id}/tools", headers=auth_headers)
    assert r.status_code == 200
    ia = r.json()["ia"]

    assert ia["verdict"]["recommendation"] == "bloquear"
    assert ia["verdict"]["headline"].startswith("Token do Github")
    assert ia["effort"] == {"level": "baixo", "label": "2 arquivos, revogacao de token"}
    assert ia["deadline"] == {"days": 1, "label": "24 horas"}


def test_tools_ia_resume_as_cadeias_de_ataque(client, auth_headers, relatorio_tier3):
    """As cadeias agrupadas, que sao o que a tela desenha.

    O `outcome` por passo e' o ponto: `bloqueado` e' uma DEFESA que funcionou e
    nao pode virar o mesmo `false` de "nao emulado" nem de "projecao da IA".
    """
    scan_id = relatorio_tier3(
        {
            **ANALISE_TIER3,
            "attack_chains": [
                {
                    "title": "Credenciais expostas → secrets store",
                    "severity": "alto",
                    "steps": [
                        {"phase": "initial_access", "tactic": "TA0001", "technique": "T1190",
                         "asset": "/upload sem auth", "outcome": "emulado",
                         "evidence": "Payload de teste retornou 200 OK"},
                        {"phase": "exfiltration", "tactic": "TA0010", "technique": "T1567",
                         "asset": "secrets store", "outcome": "bloqueado",
                         "evidence": "Barrado por politica IAM"},
                        # Sem fase e sem tecnica: seria uma linha vazia no trilho.
                        {"asset": "ruido", "outcome": "projecao"},
                    ],
                },
                # Cadeia sem passo nenhum nao e' cadeia.
                {"title": "vazia", "severity": "baixo", "steps": []},
            ],
        }
    )
    ia = client.get(f"/scans/{scan_id}/tools", headers=auth_headers).json()["ia"]

    assert len(ia["chains"]) == 1
    cadeia = ia["chains"][0]
    assert cadeia["title"] == "Credenciais expostas → secrets store"
    assert cadeia["severity"] == "alto"
    assert len(cadeia["steps"]) == 2
    assert cadeia["steps"][0]["outcome"] == "emulado"
    assert cadeia["steps"][0]["tactic"] == "TA0001"
    assert cadeia["steps"][0]["asset"] == "/upload sem auth"
    assert cadeia["steps"][1]["outcome"] == "bloqueado"
    # `attack_path` (lista plana) segue vindo: e' o fallback dos relatorios
    # anteriores a esta versao do prompt.
    assert len(ia["paths"]) == 2


def test_tools_ia_sem_cadeias_ainda_traz_a_lista_plana(client, auth_headers, relatorio_tier3):
    """Relatorio antigo: `chains` vazio e `paths` inteiro.

    A tela cai na lista plana e monta uma cadeia sem titulo — mostrar menos, nao
    nada.
    """
    scan_id = relatorio_tier3(ANALISE_TIER3)
    ia = client.get(f"/scans/{scan_id}/tools", headers=auth_headers).json()["ia"]
    assert ia["chains"] == []
    assert len(ia["paths"]) == 2


def test_tools_ia_resume_o_impacto_ao_negocio(client, auth_headers, relatorio_tier3):
    """A traducao do risco tecnico para quem decide.

    E' o bloco que a tela de relatorio abre: uma frase sem jargao, os efeitos por
    area e a faixa de consequencias. `area`/`severity` sao enums porque a UI
    colore por eles.
    """
    scan_id = relatorio_tier3(
        {
            **ANALISE_TIER3,
            "business_impact": {
                "headline": "Credenciais versionadas dao a terceiros o mesmo acesso da equipe.",
                "areas": [
                    {"area": "dados", "severity": "critico",
                     "title": "Acesso indevido a sistemas e dados de clientes",
                     "detail": "Quem obtiver as credenciais entra com o mesmo nivel da equipe."},
                    {"area": "entrega", "severity": "medio",
                     "title": "Risco de parar o pipeline de entregas",
                     "detail": "A vulnerabilidade pode travar builds."},
                    # Item sem texto nenhum e' ruido do modelo e nao vira efeito.
                    {"area": "financeiro", "severity": "alto"},
                ],
                "if_fixed_now": {"headline": "~1 dia · 1 pessoa", "detail": "sem impacto em releases"},
                "if_deferred": {"headline": "janela de 48h", "detail": "credenciais seguem ativas"},
                "regulatory": {"headline": "LGPD · notificacao 72h", "detail": "em caso de vazamento"},
            },
        }
    )
    ia = client.get(f"/scans/{scan_id}/tools", headers=auth_headers).json()["ia"]
    impacto = ia["impact"]

    assert impacto["headline"].startswith("Credenciais versionadas")
    assert len(impacto["areas"]) == 2
    assert impacto["areas"][0]["area"] == "dados"
    assert impacto["areas"][0]["severity"] == "critico"
    assert impacto["if_fixed_now"] == {
        "headline": "~1 dia · 1 pessoa",
        "detail": "sem impacto em releases",
    }
    assert impacto["if_deferred"]["headline"] == "janela de 48h"
    assert impacto["regulatory"]["headline"] == "LGPD · notificacao 72h"


def test_tools_ia_impacto_parcial_nao_e_bloco_vazio(client, auth_headers, relatorio_tier3):
    """So' a frase, sem areas nem faixa: a tela mostra o que existe.

    O contrario tambem vale — bloco em que TUDO veio vazio sai `None`, para nao
    haver um card de "impacto ao negocio" sem impacto nenhum dentro.
    """
    so_frase = relatorio_tier3(
        {**ANALISE_TIER3, "business_impact": {"headline": "Uma frase e nada mais."}}
    )
    impacto = client.get(f"/scans/{so_frase}/tools", headers=auth_headers).json()["ia"]["impact"]
    assert impacto["headline"] == "Uma frase e nada mais."
    assert impacto["areas"] == []
    assert impacto["if_fixed_now"] is None
    assert impacto["regulatory"] is None

    vazio = relatorio_tier3(
        {**ANALISE_TIER3, "business_impact": {"headline": "", "areas": [], "regulatory": None}}
    )
    assert client.get(f"/scans/{vazio}/tools", headers=auth_headers).json()["ia"]["impact"] is None


def test_tools_ia_leitura_executiva_ausente_em_relatorio_antigo(
    client, auth_headers, relatorio_tier3
):
    """Relatório gerado antes do prompt pedir as chaves: os três saem `None`.

    É o teste de retrocompatibilidade — o blob antigo continua respondendo 200 e
    a ausência é informação, não erro.
    """
    scan_id = relatorio_tier3(ANALISE_TIER3)
    ia = client.get(f"/scans/{scan_id}/tools", headers=auth_headers).json()["ia"]
    assert ia["verdict"] is None
    assert ia["effort"] is None
    assert ia["deadline"] is None
    assert ia["impact"] is None
    # O resto do resumo segue inteiro: a ausência é só dos campos novos.
    assert ia["risk_score"] == 92


def test_tools_ia_ausente_sem_relatorio_tier3(client, auth_headers, com_ferramentas):
    """Sem relatório de tier 3, `ia` é `None` e `tools`/`expected` seguem iguais."""
    r = client.get(f"/scans/{com_ferramentas}/tools", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["ia"] is None
    assert {t["tool"] for t in body["tools"]} == {
        "trufflehog", "trivy", "prowler", "ia-tier2",
    }
    assert body["expected"]["1"] == ["trufflehog", "semgrep-changed"]


def test_tools_ia_blob_malformado_degrada_sem_500(client, auth_headers, relatorio_tier3):
    """Tipos errados vindos do LLM degradam campo a campo, nunca em erro 500."""
    scan_id = relatorio_tier3(
        {
            "attack_path": "eu deveria ser uma lista",
            "risk_score_adjusted": [92, "critical"],
            "cti_data": None,
            "kill_chain_complete": "talvez",
            "degraded": None,
            "reason": {"tipo": "objeto onde se esperava string"},
            "caldera_results": {
                "status": ["reachable"],
                "techniques_executed": "3",
                "techniques_successful": None,
                "ttps_used": "T1078",
                "caldera_validated": "true",
                "validacao_parcial": 1,
            },
        }
    )
    r = client.get(f"/scans/{scan_id}/tools", headers=auth_headers)
    assert r.status_code == 200
    ia = r.json()["ia"]
    assert ia["paths"] == []
    assert ia["risk_score"] is None and ia["risk_level"] is None
    assert ia["kill_chain_complete"] is False
    assert ia["degraded"] is False
    assert ia["reason"] is None
    assert ia["cti"] is None
    # Coerções conservadoras: string numérica vira int, `"true"` vira True,
    # lista onde se esperava string vira `None`, string onde se esperava lista
    # vira `[]`.
    assert ia["caldera"]["status"] is None
    assert ia["caldera"]["techniques_executed"] == 3
    assert ia["caldera"]["techniques_successful"] == 0
    assert ia["caldera"]["validated"] is True
    assert ia["caldera"]["partial"] is True
    assert ia["caldera"]["ttps"] == []


def test_tools_ia_passo_sem_step_usa_a_posicao(client, auth_headers, relatorio_tier3):
    """Passo sem `step` numérico ainda é um passo; a posição serve de número.

    Itens que não são objetos são descartados: não há como desenhá-los.
    """
    scan_id = relatorio_tier3(
        {
            "attack_path": [
                "isto nao e' um passo",
                {"phase": "execution", "technique": "T1059", "description": "d"},
            ]
        }
    )
    ia = client.get(f"/scans/{scan_id}/tools", headers=auth_headers).json()["ia"]
    assert len(ia["paths"]) == 1
    assert ia["paths"][0]["step"] == 2
    assert ia["paths"][0]["finding_count"] == 0
    assert ia["paths"][0]["caldera_validated"] is False
