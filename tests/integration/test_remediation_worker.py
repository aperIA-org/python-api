"""Testes do worker que gera remediações.

Duas coisas são testadas aqui e em nenhum outro lugar:

1. **Quem entra na fila de remediação.** DAST fora, sem arquivo fora, mais
   graves primeiro, teto respeitado. Errar isso não quebra nada visível — só
   gasta chamadas do Claude com finding que não tem patch possível.
2. **Qual ``finding_id`` vai para a tabela.** É FK, e o id que trafega no
   canvas não é necessariamente o do banco. Ver ``test_rescan_*``.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.application.remediation.suggest_patch_use_case import SuggestPatchResult
from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    remediation_model,
    scan_job_model,
    scan_tool_run_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.persistence.models.scan_job_model import ScanJobModel
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)
from app.presentation.workers import remediation_worker
from app.presentation.workers.remediation_worker import (
    _dedup_key,
    _selecionar,
    suggest_remediations,
)

COMMIT = "a" * 40


# ------------------------------------------------------------------ seleção


def _f(**kw) -> dict:
    base = {
        "tier": 2,
        "severity": "high",
        "file_path": "app/db.py",
        "line_number": 42,
        "title": "SQL injection",
        "source": "semgrep",
        "commit_sha": COMMIT,
    }
    base.update(kw)
    return base


def test_selecao_exclui_dast_e_findings_sem_ancora():
    escolhidos = _selecionar(
        [
            _f(title="codigo-t1", tier=1),
            _f(title="codigo-t2", tier=2),
            _f(title="dast", tier=3),
            _f(title="sem-arquivo", file_path=None),
            _f(title="sem-linha", line_number=None),
            "nao-e-dict",
        ],
        teto=10,
    )
    assert [f["title"] for f in escolhidos.itens] == ["codigo-t1", "codigo-t2"]


def test_selecao_ordena_por_severidade_e_respeita_o_teto():
    escolhidos = _selecionar(
        [
            _f(title="baixo", severity="low"),
            _f(title="critico", severity="critical"),
            _f(title="desconhecido", severity="???"),
            _f(title="alto", severity="high"),
        ],
        teto=2,
    )
    assert [f["title"] for f in escolhidos.itens] == ["critico", "alto"]


def test_dedup_key_bate_com_a_da_entidade():
    """Se as duas fórmulas divergirem, nenhum finding é encontrado no banco.

    O worker reconstrói a chave a partir de um dict; a UNIQUE do banco foi
    escrita a partir da entidade. Divergir aqui não dá erro — só faz todas as
    remediações serem puladas por "finding não persistido".
    """
    finding = Finding(
        source="semgrep",
        severity=Severity.HIGH,
        title="SQL injection",
        description="x",
        commit_sha=COMMIT,
        repo_url="https://github.com/x/y",
        file_path="app/db.py",
        line_number=42,
        tier=2,
    )
    dicionario = {
        "source": "semgrep",
        "cve_id": None,
        "title": "SQL injection",
        "file_path": "app/db.py",
        "line_number": 42,
        "commit_sha": COMMIT,
    }
    assert _dedup_key(dicionario) == finding.dedup_key()


# ------------------------------------------------------------------ worker


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
def factory(engine, monkeypatch):
    """Substitui o ``SessionLocal`` do worker pelo SQLite do teste."""
    fabrica = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    monkeypatch.setattr(remediation_worker, "SessionLocal", fabrica)
    return fabrica


@pytest.fixture
def comandos(monkeypatch):
    """Captura os ``SuggestPatchCommand`` sem chamar Claude nem GitHub."""
    capturados = []

    class FakeUseCase:
        def __init__(self, repository):
            self.repository = repository

        def execute(self, cmd):
            capturados.append(cmd)
            return SuggestPatchResult(
                remediation_id=uuid4(), posted=True, skipped=False
            )

    monkeypatch.setattr(remediation_worker, "SuggestPatchUseCase", FakeUseCase)
    return capturados


def _scan_job(session, *, commit=COMMIT):
    job_id = uuid4()
    session.add(
        ScanJobModel(
            id=job_id,
            commit_sha=commit,
            repo_url="https://github.com/x/y",
            installation_id=42,
            user_id=uuid4(),
            created_at=datetime.utcnow(),
        )
    )
    session.commit()
    return job_id


def _finding(**kw) -> Finding:
    base = dict(
        source="semgrep",
        severity=Severity.HIGH,
        title="SQL injection",
        description="x",
        commit_sha=COMMIT,
        repo_url="https://github.com/x/y",
        file_path="app/db.py",
        line_number=42,
        tier=2,
    )
    base.update(kw)
    return Finding(**base)


def _executar(analysis, pr_number=None):
    return suggest_remediations.run(
        analysis,
        repo_full_name="acme/repo",
        pr_number=pr_number,
        commit_sha=COMMIT,
        installation_id=42,
    )


def test_devolve_none_quando_upstream_ignorou(factory, comandos):
    """Gate 1 bloqueou → ``None`` entra, ``None`` sai, nada é gerado."""
    assert _executar(None) is None
    assert _executar("nao-e-dict") is None
    assert comandos == []


def test_devolve_analysis_intacta(factory, comandos):
    """O ``tier3_gate`` vem depois e decide em cima desta mesma análise."""
    with factory() as s:
        _scan_job(s)
        SQLAlchemyFindingRepository(s).bulk_save([_finding()])
        s.commit()

    analysis = {
        "findings": [_f()],
        "risk_score": 800,
        "severity": "high",
        "_post_meta": {"posted": True},
    }
    saida = _executar(analysis, pr_number=7)

    assert saida == analysis
    assert len(comandos) == 1


def test_sem_candidatos_nao_abre_sessao(factory, comandos):
    analysis = {"findings": [_f(tier=3)]}
    assert _executar(analysis) == analysis
    assert comandos == []


def test_sem_scan_job_nao_gera_nada(factory, comandos):
    """Nenhum ScanJob para o commit: loga e segue, sem estourar o pipeline."""
    with factory() as s:
        SQLAlchemyFindingRepository(s).bulk_save([_finding()])
        s.commit()

    analysis = {"findings": [_f()]}
    assert _executar(analysis) == analysis
    assert comandos == []


def test_pula_finding_que_nao_chegou_ao_banco(factory, comandos):
    """Sem linha em ``findings`` não há FK possível — pula em vez de estourar."""
    with factory() as s:
        _scan_job(s)

    assert _executar({"findings": [_f()]}) is not None
    assert comandos == []


def test_rescan_usa_o_id_da_linha_existente(factory, comandos):
    """O ponto mais fácil de errar, e o que falha só no INSERT.

    ``bulk_save`` grava com ``ON CONFLICT DO NOTHING``: no segundo scan do
    mesmo commit o insert é descartado e a linha mantém o id ANTIGO. O dict do
    canvas, porém, carrega um ``uuid4`` novo a cada execução. Passar esse id
    adiante viola a FK de ``remediations.finding_id``.
    """
    primeiro = _finding()
    with factory() as s:
        _scan_job(s)
        SQLAlchemyFindingRepository(s).bulk_save([primeiro])
        s.commit()

    # Re-scan: mesma dedup_key, id novo em memória.
    segundo = _finding()
    assert segundo.id != primeiro.id
    assert segundo.dedup_key() == primeiro.dedup_key()
    with factory() as s:
        SQLAlchemyFindingRepository(s).bulk_save([segundo])
        s.commit()

    _executar({"findings": [_f(title=segundo.title)]})

    assert len(comandos) == 1
    assert comandos[0].finding["id"] == str(primeiro.id)


def test_teto_limita_as_chamadas(factory, comandos, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "REMEDIATION_MAX_PER_SCAN", 2)

    findings = [
        _finding(title=f"finding {i}", line_number=i + 1, severity=Severity.CRITICAL)
        for i in range(5)
    ]
    with factory() as s:
        _scan_job(s)
        SQLAlchemyFindingRepository(s).bulk_save(findings)
        s.commit()

    _executar(
        {
            "findings": [
                _f(title=f.title, line_number=f.line_number, severity="critical")
                for f in findings
            ]
        }
    )
    assert len(comandos) == 2


def test_falha_de_banco_nao_derruba_o_canvas(factory, comandos, monkeypatch):
    def explode():
        raise RuntimeError("banco fora")

    monkeypatch.setattr(remediation_worker, "SessionLocal", explode)
    analysis = {"findings": [_f()]}
    assert _executar(analysis) == analysis


# ------------------------------------------------- ruído do TruffleHog
#
# Um scan real do python-api trouxe 8 "secrets", dos quais 6 eram URIs de
# exemplo em teste e documentação — inclusive uma linha de tabela markdown.
# Não existe patch para falso positivo: o modelo, obrigado a inventar um,
# devolvia a linha inalterada ou pendurava um `# noqa` nela. Cada um desses
# custava uma chamada ao Claude para produzir ruído no PR.


def _secret(file_path: str, *, verificado: bool = False) -> dict:
    return _f(
        source="trufflehog",
        title="Possível secret (não verificado): URI",
        severity="medium",
        tier=1,
        file_path=file_path,
        secret_verified=verificado,
    )


@pytest.mark.parametrize(
    "caminho",
    [
        "tests/integration/test_repository_routes.py",
        "tests/unit/domain/test_target_url.py",
        "docs/howto/conectar-github.md",
        "README.md",
        "app/spec/coisa.py",
        "src/__tests__/algo.js",
        "pkg/fixtures/dados.py",
        "examples/config.py",
        "conftest.py",
        "internal/servico_test.go",
        "web/componente.spec.ts",
        "notas.rst",
    ],
)
def test_descarta_secret_nao_verificado_em_exemplo(caminho):
    selecao = _selecionar([_secret(caminho)], teto=10)
    assert selecao.itens == []
    assert selecao.ruido == 1


@pytest.mark.parametrize(
    "caminho",
    [
        "app/config.py",
        "src/api/auth.py",
        "Dockerfile",
        "deploy/terraform/main.tf",
        # "contest" contém "test" mas não É teste — o casamento é por segmento
        # de caminho inteiro, não por substring.
        "app/contest/handler.py",
    ],
)
def test_mantem_secret_nao_verificado_em_producao(caminho):
    selecao = _selecionar([_secret(caminho)], teto=10)
    assert len(selecao.itens) == 1
    assert selecao.ruido == 0


def test_secret_VERIFICADO_em_teste_continua_valendo():
    """A condição que não pode cair.

    Credencial confirmada vaza igual estando num teste — esse caso chega a
    bloquear o Gate 1. O corte é só para o que o scanner não conseguiu
    confirmar.
    """
    selecao = _selecionar(
        [_secret("tests/integration/test_x.py", verificado=True)], teto=10
    )
    assert len(selecao.itens) == 1
    assert selecao.ruido == 0


def test_o_corte_nao_atinge_outros_scanners():
    """Semgrep num teste ainda é código com defeito — só o TruffleHog rui."""
    semgrep = _f(
        source="semgrep",
        title="python.lang.security.audit.formatted-sql-query",
        file_path="tests/integration/test_repository_routes.py",
    )
    selecao = _selecionar([semgrep], teto=10)
    assert len(selecao.itens) == 1
    assert selecao.ruido == 0


def test_o_teto_conta_depois_do_corte():
    """O ruído não pode consumir as vagas dos findings que importam.

    Se o filtro rodasse depois do corte por teto, 10 URIs de documentação
    empurrariam para fora o secret de verdade em `app/config.py`.
    """
    entrada = [_secret(f"docs/pagina{i}.md") for i in range(10)]
    entrada.append(_secret("app/config.py"))
    selecao = _selecionar(entrada, teto=3)
    assert [f["file_path"] for f in selecao.itens] == ["app/config.py"]
    assert selecao.ruido == 10


def test_deduplica_o_mesmo_finding_vindo_de_dois_tiers():
    """Observado num scan real: 3 das 10 vagas foram para repetição.

    `analysis["findings"]` junta T1 e T2, e o mesmo finding aparece nos dois.
    O candidato repetido chegava ao use case, era barrado pela idempotência
    por `finding_id` — e já tinha consumido uma vaga do teto.
    """
    t1 = _f(tier=1, title="SQL injection", file_path="app/db.py", line_number=42)
    t2 = _f(tier=2, title="SQL injection", file_path="app/db.py", line_number=42)
    outro = _f(title="Outro problema", file_path="app/api.py", line_number=7)

    selecao = _selecionar([t1, t2, outro], teto=10)

    assert len(selecao.itens) == 2
    assert selecao.duplicados == 1
    assert selecao.ruido == 0


def test_a_deduplicacao_vem_antes_do_teto():
    """Senão a repetição empurra o finding real para fora da janela.

    Mesma armadilha do filtro de ruído: cortar depois do teto faz o descarte
    acontecer tarde demais para liberar a vaga.
    """
    repetido = [
        _f(title="Repetido", file_path="app/db.py", line_number=1, tier=t)
        for t in (1, 2, 1, 2)
    ]
    real = _f(title="Unico", file_path="app/api.py", line_number=9)

    selecao = _selecionar([*repetido, real], teto=2)

    assert sorted(f["title"] for f in selecao.itens) == ["Repetido", "Unico"]
    assert selecao.duplicados == 3


def test_findings_diferentes_no_mesmo_arquivo_nao_sao_duplicata():
    """A chave inclui a linha — dois problemas no mesmo arquivo continuam dois."""
    selecao = _selecionar(
        [
            _f(title="A", file_path="app/db.py", line_number=10),
            _f(title="B", file_path="app/db.py", line_number=20),
        ],
        teto=10,
    )
    assert len(selecao.itens) == 2
    assert selecao.duplicados == 0
