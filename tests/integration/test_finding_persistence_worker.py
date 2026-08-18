"""Persistência de findings ligada aos scan workers.

Garante que o ``run_tier2_scan`` grava os findings no banco via
``persist_findings`` (best-effort). Os scanners são mockados; a
``SessionLocal`` usada pelo writer é substituída por uma factory sqlite
em memória para não exigir Postgres.

O autouse ``disable_findings_persistence`` (conftest) desliga a escrita
por padrão — aqui religamos explicitamente via o fixture ``persistence_on``.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity
from app.infrastructure.persistence import finding_writer
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    remediation_model,
    scan_job_model,
    scan_tool_run_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)
from app.presentation.workers import tier2_scan_worker


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
    """Religa a persistência e aponta o writer para o sqlite em memória."""
    original = settings.FINDINGS_PERSISTENCE_ENABLED
    settings.FINDINGS_PERSISTENCE_ENABLED = True
    with patch.object(finding_writer, "SessionLocal", sqlite_factory):
        yield sqlite_factory
    settings.FINDINGS_PERSISTENCE_ENABLED = original


def _make_finding(**overrides) -> Finding:
    base = {
        "source": "trivy",
        "severity": Severity.HIGH,
        "title": "Issue",
        "description": "x",
        "commit_sha": "a" * 40,
        "repo_url": "https://github.com/acme/repo",
        "file_path": "app/x.py",
        "line_number": 1,
        "tier": 2,
    }
    base.update(overrides)
    return Finding(**base)


@pytest.fixture
def patched_scanners():
    with patch.object(tier2_scan_worker, "TrivyScanner") as Trivy, patch.object(
        tier2_scan_worker, "_SemgrepExpandedAdapter"
    ) as SemgrepExp, patch.object(
        tier2_scan_worker, "ProwlerScanner"
    ) as Prowler:
        Trivy.return_value.run_safe.return_value = []
        SemgrepExp.return_value.run_safe.return_value = []
        Prowler.return_value.run_safe.return_value = []
        yield {"trivy": Trivy, "semgrep": SemgrepExp, "prowler": Prowler}


class TestWorkerPersistsFindings:
    def test_tier2_scan_persists_to_db(self, patched_scanners, persistence_on):
        patched_scanners["trivy"].return_value.run_safe.return_value = [
            _make_finding(file_path="lib/a.js", line_number=10, title="trivy-1"),
        ]
        patched_scanners["semgrep"].return_value.run_safe.return_value = [
            _make_finding(source="semgrep", file_path="app/b.py", line_number=20, title="semgrep-1"),
        ]

        result = tier2_scan_worker.run_tier2_scan.delay(
            repo_full_name="acme/repo",
            installation_id=42,
            changed_files=[],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
        ).get()

        # O canvas continua recebendo os dicts.
        assert len(result) == 2

        # E o banco agora tem as 2 linhas persistidas.
        with persistence_on() as db:
            rows = SQLAlchemyFindingRepository(db).get_by_commit("a" * 40)
        assert len(rows) == 2
        assert {r.source for r in rows} == {"trivy", "semgrep"}

    def test_persistence_uses_on_conflict(self, patched_scanners, persistence_on):
        """Dois scans do mesmo commit (mesma dedup_key) → 1 linha no banco."""
        finding = _make_finding(file_path="dup.py", line_number=42, title="dup")
        patched_scanners["trivy"].return_value.run_safe.return_value = [finding]

        for _ in range(2):
            tier2_scan_worker.run_tier2_scan.delay(
                repo_full_name="acme/repo",
                installation_id=42,
                changed_files=[],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            ).get()

        with persistence_on() as db:
            rows = SQLAlchemyFindingRepository(db).get_by_commit("a" * 40)
        assert len(rows) == 1

    def test_disabled_persistence_writes_nothing(self, patched_scanners, sqlite_factory):
        """Com o flag desligado (default em teste), nada é gravado."""
        patched_scanners["trivy"].return_value.run_safe.return_value = [
            _make_finding(file_path="x.py", line_number=1),
        ]
        with patch.object(finding_writer, "SessionLocal", sqlite_factory):
            tier2_scan_worker.run_tier2_scan.delay(
                repo_full_name="acme/repo",
                installation_id=42,
                changed_files=[],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            ).get()

        with sqlite_factory() as db:
            rows = SQLAlchemyFindingRepository(db).get_by_commit("a" * 40)
        assert rows == []

    def test_db_failure_falha_o_scan(self, patched_scanners):
        """Perder findings FALHA a task — não é mais engolido.

        O contrato era o oposto: erro de banco virava warning e o scan
        concluía "com sucesso". Um `cwe_id` de 93 caracteres numa coluna de 50
        derrubou o INSERT em produção e o pipeline anunciou zero findings sobre
        um repositório onde ele mesmo achou um XSS. O dashboard lê o banco, não
        o payload do canvas: silêncio ali é indistinguível de repositório limpo.
        """
        patched_scanners["trivy"].return_value.run_safe.return_value = [
            _make_finding(file_path="x.py", line_number=1),
        ]
        settings.FINDINGS_PERSISTENCE_ENABLED = True
        try:
            def _boom():
                raise RuntimeError("db down")

            with patch.object(finding_writer, "SessionLocal", _boom):
                with pytest.raises(Exception) as exc_info:
                    tier2_scan_worker.run_tier2_scan.delay(
                        repo_full_name="acme/repo",
                        installation_id=42,
                        changed_files=[],
                        commit_sha="a" * 40,
                        repo_url="https://github.com/x/y",
                    ).get()
            # A causa precisa chegar legível a quem for depurar.
            assert "db down" in str(exc_info.value) or "finding" in str(
                exc_info.value
            ).lower()
        finally:
            settings.FINDINGS_PERSISTENCE_ENABLED = False

    def test_persistencia_desligada_nao_falha(self, patched_scanners):
        """Sem persistência configurada não há perda — logo, não há falha."""
        patched_scanners["trivy"].return_value.run_safe.return_value = [
            _make_finding(file_path="x.py", line_number=1),
        ]
        settings.FINDINGS_PERSISTENCE_ENABLED = False

        def _boom():
            raise RuntimeError("db down")

        with patch.object(finding_writer, "SessionLocal", _boom):
            result = tier2_scan_worker.run_tier2_scan.delay(
                repo_full_name="acme/repo",
                installation_id=42,
                changed_files=[],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            ).get()
        assert len(result) == 1
