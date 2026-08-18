from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import CVEId, Severity
from app.domain.scan.entities import ScanJob
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.persistence.models import (  # noqa: F401 — needed for metadata
    finding_model,
    remediation_model,
    scan_job_model,
    scan_tool_run_model,
)
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
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


def test_em_lotes_respeita_o_teto_de_parametros():
    """Nenhum statement pode passar do limite de parâmetros do dialeto.

    O Postgres corta em 65535 e derruba a query inteira. Um scan do ZAP virou
    ~8.5k findings depois que o mapeamento parou de colapsar as rotas, e o
    INSERT único estourava — marcando o Tier 3 como `failed` por causa da
    escrita, com o scan já concluído.
    """
    from app.infrastructure.repositories.sqlalchemy_finding_repository import (
        _MAX_PARAMS,
        _em_lotes,
    )

    colunas = 19
    rows = [{f"c{i}": i for i in range(colunas)} for _ in range(9000)]

    for dialect, teto in _MAX_PARAMS.items():
        lotes = list(_em_lotes(rows, dialect))
        assert sum(len(lote) for lote in lotes) == len(rows), dialect
        assert all(len(lote) * colunas <= teto for lote in lotes), dialect


def test_bulk_save_grava_volume_acima_de_um_lote(session):
    """Volume que exige vários statements continua sendo gravado por inteiro."""
    repo = SQLAlchemyFindingRepository(session)
    total = 500  # bem acima do lote do sqlite (999 // 19 = 52)
    repo.bulk_save(
        [_make_finding(file_path=f"app/rota_{i}.py") for i in range(total)]
    )
    session.commit()

    assert len(repo.get_by_commit("a" * 40)) == total


def test_bulk_save_deduplica_atraves_da_fronteira_do_lote(session):
    """Duplicata em lotes DIFERENTES não pode virar duas linhas.

    Dentro de um lote o ON CONFLICT resolve; entre lotes, quem resolve é a
    unique no banco, contra a linha que o statement anterior já gravou. Sem
    isso o fatiamento reintroduziria duplicatas que o insert único não deixava
    passar.
    """
    repo = SQLAlchemyFindingRepository(session)
    findings = [_make_finding(file_path=f"app/rota_{i}.py") for i in range(200)]
    findings.append(_make_finding(file_path="app/rota_0.py"))  # duplica o 1o lote
    repo.bulk_save(findings)
    session.commit()

    assert len(repo.get_by_commit("a" * 40)) == 200


# ------------------------------------------------- agregação por tipo
#
# `group_by_type` existe porque a listagem plana é ilegível com DAST: um scan
# grava milhares de findings que são dezenas de problemas repetidos por rota.
# Os testes abaixo fixam o contrato do read model — contagem, ordem, amostra e,
# principalmente, o escopo multi-tenant.


def _alerta_zap(rota: str, **overrides) -> Finding:
    """Uma ocorrência de alerta DAST — o formato que motivou a agregação.

    Cada rota vira um finding distinto (é isso que explode a cardinalidade),
    então o caminho é o que diferencia a `dedup_key`.
    """
    base = {
        "source": "zap",
        "severity": Severity.MEDIUM,
        "title": "Cross-Domain Misconfiguration",
        "description": "CORS permissivo",
        "tier": 3,
        "file_path": rota,
        "line_number": None,
        "asset": "https://juice.example",
    }
    base.update(overrides)
    return _make_finding(**base)


def test_group_by_type_colapsa_ocorrencias_do_mesmo_tipo(session):
    """N ocorrências do mesmo problema viram UM grupo com `ocorrencias == N`.

    É a razão de ser da função: 3.007 linhas de "Cross-Domain Misconfiguration"
    (uma por URL) precisam caber numa linha só na tela.
    """
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save([_alerta_zap(f"/rota/{i:03d}") for i in range(25)])
    session.commit()

    grupos = repo.group_by_type()

    assert len(grupos) == 1
    assert grupos[0].title == "Cross-Domain Misconfiguration"
    assert grupos[0].ocorrencias == 25


def test_group_by_type_separa_tipos_diferentes(session):
    """Tipos distintos não podem ser somados no mesmo grupo."""
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save(
        [_alerta_zap(f"/cors/{i}") for i in range(3)]
        + [_alerta_zap(f"/csp/{i}", title="CSP ausente") for i in range(2)]
        + [
            _make_finding(source="semgrep", title="SQL injection", file_path="app/db.py",
                          line_number=i)
            for i in range(4)
        ]
    )
    session.commit()

    grupos = {g.title: g for g in repo.group_by_type()}

    assert set(grupos) == {"Cross-Domain Misconfiguration", "CSP ausente", "SQL injection"}
    assert grupos["Cross-Domain Misconfiguration"].ocorrencias == 3
    assert grupos["CSP ausente"].ocorrencias == 2
    assert grupos["SQL injection"].ocorrencias == 4


def test_group_by_type_separa_por_source_severity_e_tier(session):
    """A chave do grupo não é só o título — mesmo título em scanners/tiers
    diferentes são problemas diferentes e não podem colapsar."""
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save(
        [
            _make_finding(source="semgrep", tier=1, severity=Severity.HIGH,
                          title="Hardcoded secret", file_path="a.py", line_number=1),
            _make_finding(source="trufflehog", tier=1, severity=Severity.HIGH,
                          title="Hardcoded secret", file_path="a.py", line_number=2),
            _make_finding(source="semgrep", tier=2, severity=Severity.HIGH,
                          title="Hardcoded secret", file_path="a.py", line_number=3),
            _make_finding(source="semgrep", tier=1, severity=Severity.LOW,
                          title="Hardcoded secret", file_path="a.py", line_number=4),
        ]
    )
    session.commit()

    grupos = repo.group_by_type()

    assert len(grupos) == 4
    assert all(g.ocorrencias == 1 for g in grupos)


def test_group_by_type_caminhos_conta_distintos_nao_ocorrencias(session):
    """`caminhos` é o número de `file_path` DISTINTOS, não de ocorrências.

    Duas métricas diferentes de propósito: 6 alertas em 2 arquivos é um
    problema menor do que 6 alertas em 6 arquivos. Se `caminhos` fosse só um
    apelido de `ocorrencias`, a tela mentiria sobre o alcance do problema.
    """
    repo = SQLAlchemyFindingRepository(session)
    # 6 ocorrências espalhadas em apenas 2 caminhos (linhas diferentes é o que
    # mantém as `dedup_key` distintas).
    repo.bulk_save(
        [
            _make_finding(file_path="app/db.py", line_number=n)
            for n in (10, 20, 30, 40)
        ]
        + [_make_finding(file_path="app/api.py", line_number=n) for n in (5, 7)]
    )
    session.commit()

    grupo = repo.group_by_type()[0]

    assert grupo.ocorrencias == 6
    assert grupo.caminhos == 2


def test_group_by_type_ordena_severidade_antes_de_volume(session):
    """Severidade manda; volume só desempata dentro da mesma severidade.

    É o ponto inteiro da ordenação: o grupo `info` do DAST tem ordens de
    grandeza mais ocorrências que o `critical`, e não pode encabeçar a lista.
    """
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save(
        [_alerta_zap(f"/info/{i:03d}", severity=Severity.INFO, title="Cabeçalho ausente")
         for i in range(60)]
        + [_alerta_zap("/admin", severity=Severity.CRITICAL, title="RCE")]
        + [_alerta_zap(f"/med/{i}", severity=Severity.MEDIUM, title="CORS") for i in range(5)]
    )
    session.commit()

    grupos = repo.group_by_type()

    assert [g.severity for g in grupos] == ["critical", "medium", "info"]
    # O volumoso ficou por último mesmo sendo 60x maior que o primeiro.
    assert grupos[0].ocorrencias == 1
    assert grupos[-1].ocorrencias == 60


def test_group_by_type_desempata_por_volume_dentro_da_severidade(session):
    """Mesma severidade: o mais volumoso vem primeiro."""
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save(
        [_alerta_zap(f"/a/{i}", title="Alerta A") for i in range(2)]
        + [_alerta_zap(f"/b/{i}", title="Alerta B") for i in range(9)]
        + [_alerta_zap(f"/c/{i}", title="Alerta C") for i in range(5)]
    )
    session.commit()

    grupos = repo.group_by_type()

    assert [g.title for g in grupos] == ["Alerta B", "Alerta C", "Alerta A"]


def test_group_by_type_amostra_respeita_o_limite_pedido(session):
    """A amostra é um preview da expansão do grupo, não o grupo inteiro."""
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save([_alerta_zap(f"/rota/{i:03d}") for i in range(30)])
    session.commit()

    grupo = repo.group_by_type(amostra_por_grupo=3)[0]

    assert grupo.ocorrencias == 30
    assert len(grupo.amostra) == 3
    # Ordenada por caminho: são as três primeiras rotas, não três quaisquer.
    assert grupo.amostra == ["/rota/000", "/rota/001", "/rota/002"]


def test_group_by_type_amostra_zero_ainda_traz_exemplo(session):
    """`amostra=0` desliga o preview, mas NÃO o `exemplo_finding_id`.

    O id de exemplo é o que liga o grupo ao deep link de um finding concreto na
    tela (`?finding=<id>`); sem ele o grupo vira um beco sem saída. Por isso o
    piso interno da consulta é 1 mesmo quando o cliente pede zero.
    """
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save([_alerta_zap(f"/rota/{i}") for i in range(10)])
    session.commit()

    grupo = repo.group_by_type(amostra_por_grupo=0)[0]

    assert grupo.exemplo_finding_id is not None
    assert len(grupo.amostra) <= 1  # o piso de 1, não os 10


def test_group_by_type_amostra_formata_caminho_e_linha(session):
    """`caminho:linha` quando há linha; só o caminho quando não há; e um
    marcador legível quando o finding não tem caminho nenhum (comum em
    findings de dependência/infra)."""
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save(
        [
            _make_finding(title="Com linha", file_path="app/db.py", line_number=42),
            _make_finding(title="Sem linha", file_path="Dockerfile", line_number=None),
            _make_finding(title="Sem caminho", file_path=None, line_number=None),
        ]
    )
    session.commit()

    amostras = {g.title: g.amostra for g in repo.group_by_type()}

    assert amostras["Com linha"] == ["app/db.py:42"]
    assert amostras["Sem linha"] == ["Dockerfile"]
    assert amostras["Sem caminho"] == ["(sem caminho)"]


def test_group_by_type_caminhos_ignora_findings_sem_caminho(session):
    """`count(distinct file_path)` não conta NULL — um grupo só de findings sem
    caminho tem `caminhos == 0` mas `ocorrencias > 0`."""
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save(
        [
            _make_finding(title="Dep vulnerável", file_path=None, line_number=n)
            for n in (1, 2, 3)
        ]
    )
    session.commit()

    grupo = repo.group_by_type()[0]

    assert grupo.ocorrencias == 3
    assert grupo.caminhos == 0


def test_group_by_type_exemplo_pertence_ao_grupo(session):
    """O `exemplo_finding_id` tem que ser um finding DAQUELE grupo.

    O deep link leva o usuário a um finding concreto a partir da linha
    agregada; apontar para outro tipo levaria a uma tela que não tem relação
    com o que ele clicou.
    """
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save(
        [_alerta_zap(f"/cors/{i}") for i in range(4)]
        + [_alerta_zap(f"/csp/{i}", title="CSP ausente", severity=Severity.LOW)
           for i in range(3)]
        + [
            _make_finding(source="semgrep", tier=1, severity=Severity.HIGH,
                          title="SQL injection", file_path="app/db.py", line_number=i)
            for i in range(2)
        ]
    )
    session.commit()

    for grupo in repo.group_by_type():
        exemplo = repo.get_by_id(grupo.exemplo_finding_id)
        assert exemplo is not None, grupo.title
        assert (exemplo.source, exemplo.severity.value, exemplo.tier, exemplo.title,
                exemplo.asset) == (grupo.source, grupo.severity, grupo.tier,
                                   grupo.title, grupo.asset)


def test_group_by_type_exemplo_correto_quando_grupos_so_diferem_no_cwe(session):
    """Grupos que só diferem no `cwe_id` são grupos distintos no agregado —
    então cada um precisa do seu próprio exemplo e da sua própria amostra."""
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save(
        [_alerta_zap(f"/rota/{i}", cwe_id="CWE-16", line_number=1) for i in range(4)]
        + [_alerta_zap(f"/rota/{i}", cwe_id="CWE-693", line_number=2) for i in range(4)]
    )
    session.commit()

    grupos = repo.group_by_type(amostra_por_grupo=2)

    assert len(grupos) == 2
    for grupo in grupos:
        assert len(grupo.amostra) == 2, "amostra somada de dois grupos"
        exemplo = repo.get_by_id(grupo.exemplo_finding_id)
        assert exemplo.cwe_id == grupo.cwe_id, "exemplo de outro grupo"
    assert grupos[0].exemplo_finding_id != grupos[1].exemplo_finding_id


def test_group_by_type_secret_verificado_se_ao_menos_um_for(session):
    """`algum_secret_verificado` é um OR sobre o grupo, não um AND.

    Uma única credencial confirmada como válida no meio de dezenas de
    suspeitas já muda a prioridade do grupo inteiro.
    """
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save(
        [
            _make_finding(source="trufflehog", title="AWS key", file_path="a.env",
                          line_number=1, secret_verified=False),
            _make_finding(source="trufflehog", title="AWS key", file_path="b.env",
                          line_number=2, secret_verified=True),
            _make_finding(source="trufflehog", title="AWS key", file_path="c.env",
                          line_number=3, secret_verified=False),
            _make_finding(source="trufflehog", title="Slack token", file_path="d.env",
                          line_number=4, secret_verified=False),
        ]
    )
    session.commit()

    grupos = {g.title: g for g in repo.group_by_type()}

    assert grupos["AWS key"].ocorrencias == 3
    assert grupos["AWS key"].algum_secret_verificado is True
    assert grupos["Slack token"].algum_secret_verificado is False


def test_group_by_type_intervalo_cobre_primeira_e_ultima_ocorrencia(session):
    """`primeiro_em`/`ultimo_em` são os extremos reais do grupo."""
    repo = SQLAlchemyFindingRepository(session)
    datas = [
        datetime(2024, 1, 10, 8, 0),
        datetime(2024, 3, 5, 12, 30),
        datetime(2024, 6, 29, 16, 0),
    ]
    repo.bulk_save(
        [
            _alerta_zap(f"/rota/{i}", created_at=d)
            for i, d in enumerate(datas)
        ]
        # Outro grupo, com intervalo próprio — os extremos não podem vazar.
        + [_alerta_zap("/outra", title="CSP ausente", created_at=datetime(2020, 1, 1))]
    )
    session.commit()

    grupos = {g.title: g for g in repo.group_by_type()}

    assert grupos["Cross-Domain Misconfiguration"].primeiro_em == min(datas)
    assert grupos["Cross-Domain Misconfiguration"].ultimo_em == max(datas)
    assert grupos["CSP ausente"].primeiro_em == datetime(2020, 1, 1)
    assert grupos["CSP ausente"].ultimo_em == datetime(2020, 1, 1)


def test_group_by_type_sem_findings_retorna_lista_vazia(session):
    repo = SQLAlchemyFindingRepository(session)
    assert repo.group_by_type() == []


def test_group_by_type_filtra_por_commit_sha(session):
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save(
        [_alerta_zap(f"/rota/{i}", commit_sha="a" * 40) for i in range(5)]
        + [_alerta_zap(f"/rota/{i}", commit_sha="b" * 40, title="Outro") for i in range(2)]
    )
    session.commit()

    grupos = repo.group_by_type(commit_sha="a" * 40)

    assert len(grupos) == 1
    assert grupos[0].ocorrencias == 5


def test_group_by_type_isola_por_usuario(session):
    """SEGURANÇA: o agregado de um usuário não pode incluir findings de outro.

    Findings não têm dono próprio — o escopo vem do `ScanJob` do commit. Um
    furo aqui não seria uma contagem errada: seria o usuário A vendo os
    títulos, CVEs e caminhos das vulnerabilidades do usuário B.
    """
    repo = SQLAlchemyFindingRepository(session)
    dono = uuid4()
    outro = uuid4()
    jobs = SQLAlchemyScanJobRepository(session)
    jobs.save(ScanJob(commit_sha="a" * 40, repo_url="https://github.com/acme/meu",
                      installation_id=1, user_id=dono))
    jobs.save(ScanJob(commit_sha="b" * 40, repo_url="https://github.com/rival/seu",
                      installation_id=2, user_id=outro))
    repo.bulk_save(
        [_alerta_zap(f"/meu/{i}", commit_sha="a" * 40, title="Meu problema")
         for i in range(3)]
        + [_alerta_zap(f"/seu/{i}", commit_sha="b" * 40, title="Problema do rival",
                       severity=Severity.CRITICAL) for i in range(9)]
    )
    session.commit()

    grupos = repo.group_by_type(user_id=dono)

    assert [g.title for g in grupos] == ["Meu problema"]
    assert grupos[0].ocorrencias == 3
    # E o inverso também vale — não é que o filtro simplesmente zerou tudo.
    assert [g.title for g in repo.group_by_type(user_id=outro)] == ["Problema do rival"]


def test_group_by_type_ignora_findings_sem_scan_job(session):
    """Com `user_id`, um finding órfão (sem ScanJob dono) não aparece.

    O escopo é uma allowlist derivada de `scan_jobs`, não uma denylist: o que
    não tem dono conhecido fica de fora.
    """
    repo = SQLAlchemyFindingRepository(session)
    dono = uuid4()
    SQLAlchemyScanJobRepository(session).save(
        ScanJob(commit_sha="a" * 40, repo_url="https://github.com/acme/repo",
                installation_id=1, user_id=dono)
    )
    repo.bulk_save(
        [_alerta_zap("/meu", commit_sha="a" * 40, title="Meu problema")]
        + [_alerta_zap("/orfao", commit_sha="c" * 40, title="Órfão")]
    )
    session.commit()

    assert [g.title for g in repo.group_by_type(user_id=dono)] == ["Meu problema"]
    # Sem escopo, o órfão continua visível — o filtro é que o exclui.
    assert len(repo.group_by_type()) == 2


def test_group_by_type_isola_por_repositorio(session):
    """`repository_id` recorta o agregado a um repositório monitorado."""
    repo = SQLAlchemyFindingRepository(session)
    dono = uuid4()
    repo_a, repo_b = uuid4(), uuid4()
    jobs = SQLAlchemyScanJobRepository(session)
    jobs.save(ScanJob(commit_sha="a" * 40, repo_url="https://github.com/acme/a",
                      installation_id=1, user_id=dono, repository_id=repo_a))
    jobs.save(ScanJob(commit_sha="b" * 40, repo_url="https://github.com/acme/b",
                      installation_id=1, user_id=dono, repository_id=repo_b))
    repo.bulk_save(
        [_alerta_zap(f"/a/{i}", commit_sha="a" * 40, title="No repo A") for i in range(4)]
        + [_alerta_zap("/b", commit_sha="b" * 40, title="No repo B")]
    )
    session.commit()

    grupos = repo.group_by_type(repository_id=repo_a)

    assert [g.title for g in grupos] == ["No repo A"]
    assert grupos[0].ocorrencias == 4


def test_group_by_type_respeita_o_limite_de_grupos(session):
    """O teto de grupos é uma trava de segurança e precisa cortar de verdade."""
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save([_alerta_zap(f"/rota/{i}", title=f"Alerta {i:03d}") for i in range(12)])
    session.commit()

    assert len(repo.group_by_type(limit=5)) == 5
    assert len(repo.group_by_type()) == 12


# ------------------------------------------------- filtro `title`


def test_query_por_title_e_igualdade_exata(session):
    """`title` é o drill-down de um grupo — igualdade EXATA, nunca prefixo nem
    substring.

    O grupo carrega o título literal; se o filtro fosse `LIKE`, abrir um grupo
    traria ocorrências de outros tipos e a contagem da tela não bateria com a
    lista que ela abre.
    """
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save(
        [
            _make_finding(title="SQL injection", file_path="a.py", line_number=1),
            _make_finding(title="SQL injection", file_path="b.py", line_number=2),
            _make_finding(title="SQL injection em raw query", file_path="c.py",
                          line_number=3),
            _make_finding(title="Blind SQL injection", file_path="d.py", line_number=4),
        ]
    )
    session.commit()

    exatos = repo.query(title="SQL injection")
    assert len(exatos) == 2
    assert {f.file_path for f in exatos} == {"a.py", "b.py"}

    # Nem prefixo (o título mais longo começa com o filtro) nem substring.
    assert repo.query(title="SQL") == []
    assert repo.query(title="injection") == []
    assert repo.query(title="SQL injection%") == []


def test_count_por_title_e_igualdade_exata(session):
    """`count` usa os mesmos filtros de `query` — o total da página tem que
    concordar com os itens dela."""
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save(
        [
            _make_finding(title="CSP ausente", file_path=f"/r/{i}", line_number=i)
            for i in range(3)
        ]
        + [_make_finding(title="CSP ausente ou fraca", file_path="/x", line_number=9)]
    )
    session.commit()

    assert repo.count(title="CSP ausente") == 3
    assert repo.count(title="CSP ausente ou fraca") == 1
    assert repo.count(title="CSP") == 0


def test_title_combina_com_o_escopo_do_usuario(session):
    """SEGURANÇA: o drill-down por título continua preso ao dono.

    O título vem do grupo e é previsível; sem o escopo, adivinhar um título
    daria acesso a findings de outro usuário.
    """
    repo = SQLAlchemyFindingRepository(session)
    dono, outro = uuid4(), uuid4()
    jobs = SQLAlchemyScanJobRepository(session)
    jobs.save(ScanJob(commit_sha="a" * 40, repo_url="u", installation_id=1, user_id=dono))
    jobs.save(ScanJob(commit_sha="b" * 40, repo_url="u", installation_id=1, user_id=outro))
    repo.bulk_save(
        [_make_finding(title="CSP ausente", commit_sha="a" * 40, file_path="/meu")]
        + [_make_finding(title="CSP ausente", commit_sha="b" * 40, file_path="/seu")]
    )
    session.commit()

    encontrados = repo.query(title="CSP ausente", user_id=dono)
    assert [f.file_path for f in encontrados] == ["/meu"]
    assert repo.count(title="CSP ausente", user_id=dono) == 1


def test_title_do_grupo_reabre_exatamente_as_ocorrencias_do_grupo(session):
    """Contrato entre as duas rotas: `ocorrencias` do grupo == `count` do
    drill-down por `title`. Se divergirem, a tela mostra "12 ocorrências" e
    abre uma lista com outro tamanho."""
    repo = SQLAlchemyFindingRepository(session)
    repo.bulk_save(
        [_alerta_zap(f"/rota/{i:03d}") for i in range(12)]
        + [_alerta_zap(f"/csp/{i}", title="CSP ausente") for i in range(4)]
    )
    session.commit()

    for grupo in repo.group_by_type():
        assert repo.count(title=grupo.title) == grupo.ocorrencias, grupo.title
