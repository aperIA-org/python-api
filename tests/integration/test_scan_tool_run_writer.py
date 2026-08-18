"""Testes do writer best-effort de ScanToolRun (``scan_tool_runs``).

Religa ``SCAN_PERSISTENCE_ENABLED`` (o autouse desliga por padrão) e aponta o
``SessionLocal`` do writer para um sqlite in-memory — mesmo arranjo dos demais
testes de writer.

O que estes testes protegem, no fim, é uma distinção só: "a ferramenta rodou e
não achou nada" **não** é a mesma coisa que "a ferramenta quebrou". Antes desta
tabela as duas chegavam ao banco como `[]`.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.domain.scan.entities import ScanJob
from app.domain.scan.tool_run_entities import ScanToolRun
from app.domain.scan.value_objects import TierStatus, ToolStatus
from app.infrastructure.persistence import scan_tool_run_writer
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    refresh_token_model,
    remediation_model,
    scan_job_model,
    scan_report_model,
    scan_tool_run_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.persistence.models.scan_job_model import ScanJobModel
from app.infrastructure.persistence.models.scan_tool_run_model import ScanToolRunModel
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_tool_run_repository import (
    SQLAlchemyScanToolRunRepository,
)

SHA = "a" * 40


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
    with patch.object(scan_tool_run_writer, "SessionLocal", sqlite_factory):
        yield sqlite_factory
    settings.SCAN_PERSISTENCE_ENABLED = original


def _cria_execucao(factory, commit_sha: str = SHA) -> ScanJob:
    job = ScanJob(
        commit_sha=commit_sha,
        repo_url="https://github.com/acme/r",
        installation_id=1,
        tier1_status=TierStatus.RUNNING,
        tier1_started_at=datetime(2026, 8, 1, 10, 0),
    )
    with factory() as s:
        SQLAlchemyScanJobRepository(s).save(job)
        s.commit()
    return job


def _linhas(factory) -> list[ScanToolRunModel]:
    with factory() as s:
        return list(s.execute(select(ScanToolRunModel)).scalars().all())


def test_grava_ferramenta_concluida(persistence_on):
    job = _cria_execucao(persistence_on)

    scan_tool_run_writer.record_tool_run(
        commit_sha=SHA,
        tier=2,
        tool="trivy",
        status=ToolStatus.DONE,
        findings_count=0,
        duration_ms=1234,
    )

    (linha,) = _linhas(persistence_on)
    assert linha.scan_job_id == job.id
    assert linha.tool == "trivy"
    assert linha.status == "done"
    # 0, não NULL: rodou e não achou nada.
    assert linha.findings_count == 0
    assert linha.duration_ms == 1234
    assert linha.reason is None


def test_falha_e_sucesso_vazio_sao_distinguiveis(persistence_on):
    """A razão de ser da tabela: `[]` do `run_safe` não distingue os dois."""
    _cria_execucao(persistence_on)

    scan_tool_run_writer.record_tool_run(
        commit_sha=SHA, tier=2, tool="trivy", status=ToolStatus.DONE, findings_count=0
    )
    scan_tool_run_writer.record_tool_run(
        commit_sha=SHA,
        tier=2,
        tool="semgrep-full",
        status=ToolStatus.FAILED,
        reason="TimeoutError: deu ruim",
    )

    por_tool = {l.tool: l for l in _linhas(persistence_on)}
    assert por_tool["trivy"].status == "done"
    assert por_tool["trivy"].findings_count == 0
    assert por_tool["semgrep-full"].status == "failed"
    # `findings_count` NULL na falha: não houve contagem, e 0 seria mentira.
    assert por_tool["semgrep-full"].findings_count is None
    assert "TimeoutError" in por_tool["semgrep-full"].reason


def test_upsert_por_scan_job_e_tool(persistence_on):
    """Replay do canvas reescreve a linha em vez de duplicar."""
    _cria_execucao(persistence_on)

    scan_tool_run_writer.record_tool_run(
        commit_sha=SHA, tier=1, tool="trufflehog", status=ToolStatus.RUNNING
    )
    scan_tool_run_writer.record_tool_run(
        commit_sha=SHA, tier=1, tool="trufflehog", status=ToolStatus.DONE, findings_count=3
    )

    (linha,) = _linhas(persistence_on)
    assert linha.status == "done"
    assert linha.findings_count == 3


def test_reexecucao_do_commit_nao_sobrescreve_a_anterior(persistence_on):
    """Chave é `(scan_job_id, tool)`, não `(commit_sha, tool)`.

    É o mesmo erro que `scan_reports` já corrigiu: chavear pelo sha faria a
    reexecução apagar o resultado da execução anterior, e o histórico por
    ferramenta deixaria de existir.
    """
    primeira = _cria_execucao(persistence_on)
    scan_tool_run_writer.record_tool_run(
        commit_sha=SHA, tier=1, tool="trufflehog", status=ToolStatus.FAILED, reason="x"
    )

    # Nova execução do MESMO commit — `save` do repositório de scan job faz
    # upsert por commit, então criamos a linha nova direto.
    segunda = ScanJob(
        commit_sha=SHA,
        repo_url="https://github.com/acme/r",
        installation_id=1,
        tier1_status=TierStatus.DONE,
    )
    with persistence_on() as s:
        s.add(ScanJobModel.from_entity(segunda))
        s.commit()
        SQLAlchemyScanToolRunRepository(s).save(
            ScanToolRun(
                commit_sha=SHA,
                tier=1,
                tool="trufflehog",
                status=ToolStatus.DONE,
                scan_job_id=segunda.id,
            )
        )
        s.commit()

    linhas = _linhas(persistence_on)
    assert len(linhas) == 2
    por_job = {l.scan_job_id: l.status for l in linhas}
    assert por_job[primeira.id] == "failed"
    assert por_job[segunda.id] == "done"


def test_sem_execucao_nao_grava_orfao(persistence_on):
    """Sem `ScanJob` não há onde pendurar — e uma linha órfã seria inalcançável."""
    scan_tool_run_writer.record_tool_run(
        commit_sha="f" * 40, tier=1, tool="trufflehog", status=ToolStatus.DONE
    )
    assert _linhas(persistence_on) == []


def test_flag_desligada_nao_grava(sqlite_factory):
    _cria_execucao(sqlite_factory)
    original = settings.SCAN_PERSISTENCE_ENABLED
    settings.SCAN_PERSISTENCE_ENABLED = False
    try:
        with patch.object(scan_tool_run_writer, "SessionLocal", sqlite_factory):
            scan_tool_run_writer.record_tool_run(
                commit_sha=SHA, tier=1, tool="trufflehog", status=ToolStatus.DONE
            )
    finally:
        settings.SCAN_PERSISTENCE_ENABLED = original
    assert _linhas(sqlite_factory) == []


def test_erro_de_banco_nao_propaga(persistence_on):
    """Best-effort: um banco fora do ar não pode derrubar o scan."""
    with patch.object(
        scan_tool_run_writer, "SessionLocal", side_effect=RuntimeError("banco fora")
    ):
        scan_tool_run_writer.record_tool_run(
            commit_sha=SHA, tier=1, tool="trufflehog", status=ToolStatus.DONE
        )


def test_reason_truncado_no_limite_da_coluna(persistence_on):
    _cria_execucao(persistence_on)
    scan_tool_run_writer.record_tool_run(
        commit_sha=SHA,
        tier=3,
        tool="zap",
        status=ToolStatus.FAILED,
        reason="e" * 500,
    )
    (linha,) = _linhas(persistence_on)
    assert len(linha.reason) == 200


def test_lista_ordenada_por_tier_e_nome(persistence_on):
    job = _cria_execucao(persistence_on)
    for tier, tool in ((3, "zap"), (1, "trufflehog"), (2, "trivy"), (1, "semgrep-changed")):
        scan_tool_run_writer.record_tool_run(
            commit_sha=SHA, tier=tier, tool=tool, status=ToolStatus.DONE
        )

    with persistence_on() as s:
        runs = SQLAlchemyScanToolRunRepository(s).list_by_scan_job(job.id)
    assert [r.tool for r in runs] == ["semgrep-changed", "trufflehog", "trivy", "zap"]
