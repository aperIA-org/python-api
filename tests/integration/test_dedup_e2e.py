"""Testes E2E de deduplicação: domain (FindingDeduplicator) + DB (UNIQUE).

Cenários do guia (Semana 7):

1. ``FindingDeduplicator`` com 3 findings idênticos → 1 (já coberto
   em ``tests/unit/domain/finding/test_services.py``; aqui replicamos
   no contexto E2E para garantir round-trip via worker → repo).
2. 3 findings com mesma ``dedup_key`` → banco persiste apenas 1 via
   ``on_conflict_do_nothing``.
3. Findings ``trivy`` e ``semgrep`` para a **mesma CVE** ficam
   separados — ``source`` faz parte do ``dedup_key``, por design.

Bonus: re-scan completo do mesmo commit (duas chamadas de
``bulk_save``) ainda resulta em 1 linha — idempotência real.

Banco: SQLite em memória via ``aiosqlite``, criado por fixture com
``Base.metadata.create_all``. Os índices/UniqueConstraint vêm dos
models — não da migration — para isolar o teste do Alembic.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.domain.finding.entities import Finding
from app.domain.finding.services import FindingDeduplicator
from app.domain.finding.value_objects import CVEId, Severity
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    remediation_model,
    scan_job_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)


@pytest_asyncio.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture
async def session(engine):
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    async with factory() as s:
        yield s


def _make(
    *,
    source: str = "semgrep",
    severity: Severity = Severity.HIGH,
    file_path: str | None = "app/x.py",
    line_number: int | None = 1,
    commit_sha: str = "a" * 40,
    cve_id: CVEId | None = None,
    title: str = "Issue",
) -> Finding:
    return Finding(
        source=source,
        severity=severity,
        title=title,
        description="x",
        commit_sha=commit_sha,
        repo_url="https://github.com/acme/repo",
        file_path=file_path,
        line_number=line_number,
        cve_id=cve_id,
        tier=1,
    )


# -----------------------------------------------------------------------------
# Critério 1 — Deduplicador em memória
# -----------------------------------------------------------------------------


class TestDomainDeduplicator:
    def test_three_identical_findings_become_one(self):
        common = {"file_path": "x.py", "line_number": 10}
        findings = [_make(**common), _make(**common), _make(**common)]
        assert len(FindingDeduplicator().deduplicate(findings)) == 1

    def test_different_commit_keeps_separate(self):
        f1 = _make(commit_sha="a" * 40)
        f2 = _make(commit_sha="b" * 40)
        assert len(FindingDeduplicator().deduplicate([f1, f2])) == 2


# -----------------------------------------------------------------------------
# Critério 2 — UNIQUE constraint no banco
# -----------------------------------------------------------------------------


class TestDatabaseDedup:
    @pytest.mark.asyncio
    async def test_three_identical_persists_one(self, session):
        repo = SQLAlchemyFindingRepository(session)
        # 3 findings com mesma dedup_key (file_path/line/source/commit)
        common = dict(file_path="dup.py", line_number=42)
        findings = [_make(**common), _make(**common), _make(**common)]
        # Domain dedup → 1; ainda assim, simulamos o pior caso de
        # dedup pular tudo e mandar 3 ao banco — o constraint segura.
        await repo.bulk_save(findings)
        await session.commit()

        rows = await repo.get_by_commit("a" * 40)
        assert len(rows) == 1

    @pytest.mark.asyncio
    async def test_rescan_same_commit_is_idempotent(self, session):
        """T1 e depois T2 (re-scan) com mesmo finding = 1 linha."""
        repo = SQLAlchemyFindingRepository(session)
        f_t1 = _make(file_path="app/x.py", line_number=42)
        await repo.bulk_save([f_t1])
        await session.commit()

        # Re-scan no Tier 2 gerou o "mesmo" finding (nova UUID, mesma
        # dedup_key).
        f_t2 = _make(file_path="app/x.py", line_number=42)
        f_t2.id = uuid4()
        await repo.bulk_save([f_t2])
        await session.commit()

        rows = await repo.get_by_commit("a" * 40)
        assert len(rows) == 1


# -----------------------------------------------------------------------------
# Critério 3 — Cross-scanner com mesma CVE NÃO deduplica
# -----------------------------------------------------------------------------


class TestCrossScannerSeparation:
    @pytest.mark.asyncio
    async def test_trivy_and_semgrep_same_cve_kept_separate(self, session):
        repo = SQLAlchemyFindingRepository(session)
        cve = CVEId("CVE-2021-44228")
        common = dict(
            file_path="lib/log4j-core.jar",
            line_number=None,
            cve_id=cve,
        )
        trivy_f = _make(source="trivy", **common, title="trivy:log4shell")
        semgrep_f = _make(source="semgrep", **common, title="semgrep:log4shell")
        await repo.bulk_save([trivy_f, semgrep_f])
        await session.commit()

        rows = await repo.get_by_commit("a" * 40)
        assert len(rows) == 2
        sources = sorted(r.source for r in rows)
        assert sources == ["semgrep", "trivy"]

    def test_dedup_key_includes_source(self):
        """Asserção direta sobre a estrutura da dedup_key."""
        cve = CVEId("CVE-2021-44228")
        f_trivy = _make(source="trivy", cve_id=cve, file_path="x", line_number=1)
        f_semgrep = _make(source="semgrep", cve_id=cve, file_path="x", line_number=1)
        assert f_trivy.dedup_key() != f_semgrep.dedup_key()
        # Mas ambos contêm a CVE
        assert "CVE-2021-44228" in f_trivy.dedup_key()
        assert "CVE-2021-44228" in f_semgrep.dedup_key()


# -----------------------------------------------------------------------------
# Domain + DB combinados (o pipeline real)
# -----------------------------------------------------------------------------


class TestDomainPlusDbCombined:
    @pytest.mark.asyncio
    async def test_pipeline_dedupes_in_memory_then_db_seals(self, session):
        """Caminho realista: deduplicador remove 99% do volume, DB
        segura o ~1% que escapar (race entre workers paralelos)."""
        repo = SQLAlchemyFindingRepository(session)
        # Cenário: 5 findings, 3 duplicados, 2 distintos.
        dup = dict(file_path="db.py", line_number=42)
        findings = [
            _make(**dup, title="A"),
            _make(**dup, title="A"),
            _make(**dup, title="A"),
            _make(file_path="auth.py", line_number=10, title="B"),
            _make(file_path="auth.py", line_number=10, title="B"),
        ]
        deduped = FindingDeduplicator().deduplicate(findings)
        # Domain reduz 5 → 2 (mesma dedup_key)
        assert len(deduped) == 2

        await repo.bulk_save(deduped)
        await session.commit()
        # DB tem 2 linhas
        assert len(await repo.get_by_commit("a" * 40)) == 2

    @pytest.mark.asyncio
    async def test_db_catches_what_domain_misses(self, session):
        """Se por algum motivo o deduplicador não rodar (race
        condition entre workers paralelos), o banco não duplica.
        Esse teste simula passing das duplicatas direto ao banco."""
        repo = SQLAlchemyFindingRepository(session)
        dup = dict(file_path="db.py", line_number=42)
        # 3 findings idênticos vão ao banco SEM passar pelo dedup do domain.
        await repo.bulk_save([_make(**dup), _make(**dup), _make(**dup)])
        await session.commit()
        assert len(await repo.get_by_commit("a" * 40)) == 1
