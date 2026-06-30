"""Testes do SuggestPatchUseCase com foco em idempotência.

Decisão #2 Semana 11: re-scan/retry não pode duplicar comentário no PR.
A idempotência é feita consultando ``get_by_scan_job`` antes de gerar
o patch — se já existe Remediation para o ``finding_id``, o use case
retorna sem fazer nada (não chama Claude, não posta no GitHub).
"""
from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.application.remediation.suggest_patch_use_case import (
    SuggestPatchCommand,
    SuggestPatchUseCase,
)
from app.domain.remediation.entities import Remediation, RemediationStatus
from app.infrastructure.persistence.models import (  # noqa: F401
    finding_model,
    remediation_model,
    scan_job_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.persistence.models.finding_model import FindingModel
from app.infrastructure.persistence.models.scan_job_model import ScanJobModel
from app.infrastructure.repositories.sqlalchemy_remediation_repository import (
    SQLAlchemyRemediationRepository,
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


@pytest_asyncio.fixture
async def scan_job_id(session) -> UUID:
    sid = uuid4()
    session.add(
        ScanJobModel(
            id=sid,
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
            installation_id=42,
            created_at=datetime.utcnow(),
        )
    )
    await session.flush()
    return sid


@pytest_asyncio.fixture
async def finding_record(session) -> UUID:
    fid = uuid4()
    session.add(
        FindingModel(
            id=fid,
            source="semgrep",
            severity="high",
            tier=1,
            title="SQL injection",
            description="x",
            file_path="app/db.py",
            line_number=42,
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
            secret_verified=False,
            dedup_key="key1",
            created_at=datetime.utcnow(),
        )
    )
    await session.flush()
    return fid


def _finding_dict(finding_id: UUID, **overrides) -> dict:
    base = {
        "id": str(finding_id),
        "source": "semgrep",
        "severity": "high",
        "title": "SQL injection",
        "description": "f-string in query",
        "file_path": "app/db.py",
        "line_number": 42,
        "cve_id": None,
        "cwe_id": "CWE-89",
        "secret_verified": False,
        "secret_type": None,
        "commit_sha": "a" * 40,
    }
    base.update(overrides)
    return base


def _fake_claude_returning(patch_payload: dict) -> MagicMock:
    fake = MagicMock()
    fake.call_json.return_value = patch_payload
    return fake


def _fake_github_factory(comment_id: int = 7777, raise_on_post: bool = False, file_content: str = "line1\nline2\n>>>line3\nline4\nline5\n"):
    fake_client = MagicMock()
    fake_client.get_file_content.return_value = file_content
    if raise_on_post:
        fake_client.post_inline_suggestion.side_effect = RuntimeError("403")
    else:
        fake_client.post_inline_suggestion.return_value = comment_id

    def factory(installation_id: int):
        return fake_client

    factory.client = fake_client  # type: ignore[attr-defined]
    return factory


# -----------------------------------------------------------------------------
# Happy path
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_posts_and_persists(session, scan_job_id, finding_record):
    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning(
        {
            "patch_diff": "--- a/app/db.py\n+++ b/app/db.py\n@@ -1 +1 @@\n-bad\n+good",
            "explanation": "Use parametrized query.",
            "requires_secret_rotation": False,
            "rotation_instructions": None,
        }
    )
    factory = _fake_github_factory(comment_id=12345)
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = await use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(finding_record),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    await session.commit()

    assert result.posted is True
    assert result.skipped is False
    assert result.remediation_id is not None

    factory.client.post_inline_suggestion.assert_called_once()
    args = factory.client.post_inline_suggestion.call_args.kwargs
    assert args["repo_full_name"] == "acme/repo"
    assert args["pr_number"] == 7
    assert args["file_path"] == "app/db.py"
    assert args["line"] == 42

    persisted = await repo.get_by_scan_job(scan_job_id)
    assert len(persisted) == 1
    assert persisted[0].github_comment_id == 12345
    assert persisted[0].status is RemediationStatus.SUGGESTED


# -----------------------------------------------------------------------------
# Idempotência — decisão #2 Semana 11
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_skip_when_remediation_already_exists(session, scan_job_id, finding_record):
    """Pré-existe uma Remediation para o mesmo finding → use case skipa."""
    repo = SQLAlchemyRemediationRepository(session)
    existing = Remediation(
        finding_id=finding_record,
        scan_job_id=scan_job_id,
        patch_diff="pre-existing",
        explanation="from earlier scan",
    )
    await repo.save(existing)
    await session.commit()

    claude = _fake_claude_returning(
        {"patch_diff": "should-not-be-used", "explanation": "x"}
    )
    factory = _fake_github_factory()
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = await use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(finding_record),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )

    # Skipou; não chamou Claude nem postou no GitHub
    assert result.skipped is True
    assert result.posted is False
    assert result.reason == "already_remediated"
    assert result.remediation_id == existing.id
    claude.call_json.assert_not_called()
    factory.client.post_inline_suggestion.assert_not_called()


@pytest.mark.asyncio
async def test_runs_for_different_finding_in_same_scan(session, scan_job_id, finding_record):
    """Outro finding no mesmo scan_job → não há idempotência cruzada."""
    repo = SQLAlchemyRemediationRepository(session)
    # Pré-existente para um finding diferente
    other_finding = uuid4()
    session.add(
        FindingModel(
            id=other_finding,
            source="semgrep",
            severity="low",
            tier=1,
            title="other",
            commit_sha="a" * 40,
            repo_url="x",
            secret_verified=False,
            dedup_key="k2",
            created_at=datetime.utcnow(),
        )
    )
    await session.flush()
    await repo.save(
        Remediation(
            finding_id=other_finding,
            scan_job_id=scan_job_id,
            patch_diff="x",
            explanation="x",
        )
    )
    await session.commit()

    claude = _fake_claude_returning(
        {"patch_diff": "-bad\n+good", "explanation": "ok"}
    )
    factory = _fake_github_factory(comment_id=42)
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = await use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(finding_record),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    assert result.posted is True


# -----------------------------------------------------------------------------
# Caminhos de erro
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_claude_circuit_open_skips_silently(session, scan_job_id, finding_record):
    from app.infrastructure.ai.claude_client import CircuitOpenError

    repo = SQLAlchemyRemediationRepository(session)
    claude = MagicMock()
    claude.call_json.side_effect = CircuitOpenError("open")
    factory = _fake_github_factory()
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = await use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(finding_record),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    assert result.skipped is True
    assert result.reason == "CircuitOpenError"
    factory.client.post_inline_suggestion.assert_not_called()


@pytest.mark.asyncio
async def test_empty_patch_diff_skips(session, scan_job_id, finding_record):
    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning(
        {"patch_diff": "   ", "explanation": "Não tenho contexto suficiente"}
    )
    factory = _fake_github_factory()
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = await use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(finding_record),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    assert result.skipped is True
    assert result.reason == "empty_patch_diff"
    factory.client.post_inline_suggestion.assert_not_called()


@pytest.mark.asyncio
async def test_github_post_failure_skips_without_persisting(session, scan_job_id, finding_record):
    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning(
        {"patch_diff": "-bad\n+good", "explanation": "fix"}
    )
    factory = _fake_github_factory(raise_on_post=True)
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = await use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(finding_record),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    await session.commit()

    assert result.posted is False
    assert "post_failed" in (result.reason or "")
    # Não persistiu Remediation porque o post falhou
    assert await repo.get_by_scan_job(scan_job_id) == []


@pytest.mark.asyncio
async def test_secret_finding_carries_rotation_metadata(session, scan_job_id):
    """Patch para secret retornado pelo Claude preserva flags de rotação."""
    secret_finding_id = uuid4()
    session.add(
        FindingModel(
            id=secret_finding_id,
            source="trufflehog",
            severity="critical",
            tier=1,
            title="AWS verified",
            file_path="config/.env",
            line_number=12,
            commit_sha="a" * 40,
            repo_url="x",
            secret_verified=True,
            secret_type="AWS",
            dedup_key="k3",
            created_at=datetime.utcnow(),
        )
    )
    await session.flush()

    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning(
        {
            "patch_diff": "- AKIA...\n+ # removido — rotar credencial",
            "explanation": "Remoção do secret hardcoded.",
            "requires_secret_rotation": True,
            "rotation_instructions": "Rotar via AWS IAM Console; revogar a chave.",
        }
    )
    factory = _fake_github_factory(comment_id=99)
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = await use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(
                secret_finding_id,
                source="trufflehog",
                severity="critical",
                file_path="config/.env",
                line_number=12,
                secret_verified=True,
                secret_type="AWS",
            ),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    await session.commit()

    assert result.posted is True
    persisted = await repo.get_by_scan_job(scan_job_id)
    assert persisted[0].requires_secret_rotation is True
    assert "AWS IAM" in persisted[0].rotation_instructions


@pytest.mark.asyncio
async def test_missing_file_or_line_skips(session, scan_job_id, finding_record):
    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning({"patch_diff": "-x\n+y", "explanation": "fix"})
    factory = _fake_github_factory()
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = await use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(
                finding_record, file_path=None, line_number=None
            ),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    assert result.skipped is True
    assert result.reason == "missing_file_or_line"


@pytest.mark.asyncio
async def test_invalid_finding_id_skips_safely(session, scan_job_id):
    repo = SQLAlchemyRemediationRepository(session)
    claude = MagicMock()
    factory = _fake_github_factory()
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = await use_case.execute(
        SuggestPatchCommand(
            finding={"id": "not-a-uuid", "file_path": "x", "line_number": 1},
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    assert result.skipped is True
    assert result.reason == "invalid_finding_id"
    claude.call_json.assert_not_called()


@pytest.mark.asyncio
async def test_code_context_failure_does_not_block_patch(
    session, scan_job_id, finding_record
):
    """Falha ao buscar contexto de código não impede a geração do patch."""
    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning(
        {"patch_diff": "-x\n+y", "explanation": "ok"}
    )
    factory = _fake_github_factory(comment_id=1)
    factory.client.get_file_content.side_effect = RuntimeError("404")

    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )
    result = await use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(finding_record),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    assert result.posted is True
