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
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.application.remediation.suggest_patch_use_case import (
    SuggestPatchCommand,
    SuggestPatchUseCase,
)
from app.domain.remediation.entities import Remediation, RemediationStatus
from app.infrastructure.persistence.models import (  # noqa: F401
    finding_model,
    remediation_model,
    scan_job_model,
    scan_tool_run_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.persistence.models.finding_model import FindingModel
from app.infrastructure.persistence.models.scan_job_model import ScanJobModel
from app.infrastructure.repositories.sqlalchemy_remediation_repository import (
    SQLAlchemyRemediationRepository,
)


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
def session(engine):
    factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    with factory() as s:
        yield s


@pytest.fixture
def scan_job_id(session) -> UUID:
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
    session.flush()
    return sid


@pytest.fixture
def finding_record(session) -> UUID:
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
    session.flush()
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


#: Arquivo falso com 50 linhas, indentado, com o alvo na 42.
#:
#: A indentação é o ponto: o modelo perde o recuo, e é contra ESTE conteúdo
#: que `verificar` confere o eco dele. Um arquivo sem recuo não exercitaria o
#: reparo — foi assim que o bug original passou despercebido.
FAKE_FILE = "\n".join(
    [f"# preambulo {i}" for i in range(1, 41)]
    + [
        "def consulta(email):",
        '    query = f"SELECT * FROM users WHERE email = \'{email}\'"',
        "    return db.execute(query)",
    ]
    + [f"# rodape {i}" for i in range(1, 8)]
)

#: Resposta do modelo no contrato novo, batendo com FAKE_FILE linha 42.
PATCH_OK = {
    "start_line": 42,
    "end_line": 42,
    "original": ['    query = f"SELECT * FROM users WHERE email = \'{email}\'"'],
    "replacement": ["    query = select(User).where(User.email == email)"],
    "explanation": "Use parametrized query.",
    "requires_secret_rotation": False,
    "rotation_instructions": None,
}


def _fake_github_factory(comment_id: int = 7777, raise_on_post: bool = False, file_content: str = FAKE_FILE):
    fake_client = MagicMock()
    fake_client.get_file_content.return_value = file_content
    # Por padrão todo arquivo está no diff — o teste que quiser o contrário
    # sobrescreve. Sem isto o MagicMock devolveria um objeto cujo `in` é
    # sempre falso, e tudo pareceria estar fora do PR.
    fake_client.list_pr_files.return_value = {"app/db.py", "config/.env"}
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


def test_happy_path_posts_and_persists(session, scan_job_id, finding_record):
    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning(
PATCH_OK
    )
    factory = _fake_github_factory(comment_id=12345)
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(finding_record),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    session.commit()

    assert result.posted is True
    assert result.skipped is False
    assert result.remediation_id is not None

    factory.client.post_inline_suggestion.assert_called_once()
    args = factory.client.post_inline_suggestion.call_args.kwargs
    assert args["repo_full_name"] == "acme/repo"
    assert args["pr_number"] == 7
    assert args["file_path"] == "app/db.py"
    assert args["line"] == 42

    persisted = repo.get_by_scan_job(scan_job_id)
    assert len(persisted) == 1
    assert persisted[0].github_comment_id == 12345
    assert persisted[0].status is RemediationStatus.SUGGESTED


# -----------------------------------------------------------------------------
# Idempotência — decisão #2 Semana 11
# -----------------------------------------------------------------------------


def test_skip_when_remediation_already_exists(session, scan_job_id, finding_record):
    """Pré-existe uma Remediation para o mesmo finding → use case skipa."""
    repo = SQLAlchemyRemediationRepository(session)
    existing = Remediation(
        finding_id=finding_record,
        scan_job_id=scan_job_id,
        patch_diff="pre-existing",
        explanation="from earlier scan",
    )
    repo.save(existing)
    session.commit()

    claude = _fake_claude_returning(
        {**PATCH_OK, "explanation": "nao deve ser usado"}
    )
    factory = _fake_github_factory()
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = use_case.execute(
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


def test_runs_for_different_finding_in_same_scan(session, scan_job_id, finding_record):
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
    session.flush()
    repo.save(
        Remediation(
            finding_id=other_finding,
            scan_job_id=scan_job_id,
            patch_diff="x",
            explanation="x",
        )
    )
    session.commit()

    claude = _fake_claude_returning(
        {**PATCH_OK, "explanation": "ok"}
    )
    factory = _fake_github_factory(comment_id=42)
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = use_case.execute(
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


def test_claude_circuit_open_skips_silently(session, scan_job_id, finding_record):
    from app.infrastructure.ai.claude_client import CircuitOpenError

    repo = SQLAlchemyRemediationRepository(session)
    claude = MagicMock()
    claude.call_json.side_effect = CircuitOpenError("open")
    factory = _fake_github_factory()
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = use_case.execute(
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


def test_replacement_vazio_skipa(session, scan_job_id, finding_record):
    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning(
        {**PATCH_OK, "replacement": [], "explanation": "Não tenho contexto suficiente"}
    )
    factory = _fake_github_factory()
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = use_case.execute(
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
    assert result.reason == "patch_invalido"
    factory.client.post_inline_suggestion.assert_not_called()


def test_github_post_failure_skips_without_persisting(session, scan_job_id, finding_record):
    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning(
        {**PATCH_OK, "explanation": "fix"}
    )
    factory = _fake_github_factory(raise_on_post=True)
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(finding_record),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    session.commit()

    assert result.posted is False
    assert "post_failed" in (result.reason or "")
    # Não persistiu Remediation porque o post falhou
    assert repo.get_by_scan_job(scan_job_id) == []


def test_secret_finding_carries_rotation_metadata(session, scan_job_id):
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
    session.flush()

    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning(
        {
            "start_line": 12,
            "end_line": 12,
            "original": ["# preambulo 12"],
            "replacement": ["# removido — rotar credencial"],
            "explanation": "Remoção do secret hardcoded.",
            "requires_secret_rotation": True,
            "rotation_instructions": "Rotar via AWS IAM Console; revogar a chave.",
        }
    )
    factory = _fake_github_factory(comment_id=99)
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = use_case.execute(
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
    session.commit()

    assert result.posted is True
    persisted = repo.get_by_scan_job(scan_job_id)
    assert persisted[0].requires_secret_rotation is True
    assert "AWS IAM" in persisted[0].rotation_instructions


def test_missing_file_or_line_skips(session, scan_job_id, finding_record):
    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning({**PATCH_OK, "explanation": "fix"})
    factory = _fake_github_factory()
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = use_case.execute(
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


def test_invalid_finding_id_skips_safely(session, scan_job_id):
    repo = SQLAlchemyRemediationRepository(session)
    claude = MagicMock()
    factory = _fake_github_factory()
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = use_case.execute(
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


def test_sem_o_arquivo_nao_gera_patch(session, scan_job_id, finding_record):
    """Buscar o arquivo deixou de ser best-effort, e isso é deliberado.

    Antes o conteúdo servia só para enriquecer o prompt, então falhar era
    aceitável: o patch saía mesmo assim. Agora é contra esse conteúdo que o
    trecho devolvido pelo modelo é conferido — sem ele não há verificação, e
    sem verificação não se posta. Nem o Claude chega a ser chamado.
    """
    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning({**PATCH_OK, "explanation": "ok"})
    factory = _fake_github_factory(comment_id=1)
    factory.client.get_file_content.side_effect = RuntimeError("404")

    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )
    result = use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(finding_record),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    assert result.posted is False
    assert result.skipped is True
    assert result.reason == "sem_conteudo_do_arquivo"
    claude.call_json.assert_not_called()
    factory.client.post_inline_suggestion.assert_not_called()
    assert repo.get_by_scan_job(scan_job_id) == []


# -----------------------------------------------------------------------------
# Scan manual: sem PR onde comentar
# -----------------------------------------------------------------------------


def test_sem_pr_persiste_sem_postar(session, scan_job_id, finding_record):
    """`pr_number=None` é o scan de branch — o caminho do dashboard.

    Sem PR não há inline suggestion, mas o patch continua valendo: ele é o que
    a tela de Remediações mostra. Se este caso voltasse a pular a persistência,
    todo scan disparado pelo dashboard produziria zero remediações — e a tela
    ficaria vazia sem nenhum erro para explicar por quê.
    """
    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning(
PATCH_OK
    )
    factory = _fake_github_factory()
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )

    result = use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(finding_record),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=None,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    session.commit()

    assert result.skipped is False
    assert result.posted is False
    assert result.remediation_id is not None
    factory.client.post_inline_suggestion.assert_not_called()

    persistidas = repo.get_by_scan_job(scan_job_id)
    assert len(persistidas) == 1
    assert persistidas[0].github_comment_id is None
    # O diff é montado a partir do arquivo real, não copiado do modelo.
    diff = persistidas[0].patch_diff
    assert diff.startswith("--- a/app/db.py\n+++ b/app/db.py\n@@ -42,1 +42,1 @@")
    assert '-    query = f"SELECT * FROM users WHERE email = \'{email}\'"' in diff
    assert "+    query = select(User).where(User.email == email)" in diff


def test_sem_pr_continua_idempotente(session, scan_job_id, finding_record):
    """Re-scan manual do mesmo commit não gera uma segunda remediação."""
    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning(
        {**PATCH_OK, "explanation": "x"}
    )
    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=_fake_github_factory()
    )
    comando = SuggestPatchCommand(
        finding=_finding_dict(finding_record),
        scan_job_id=scan_job_id,
        repo_full_name="acme/repo",
        pr_number=None,
        commit_sha="a" * 40,
        installation_id=42,
    )

    use_case.execute(comando)
    session.commit()
    segunda = use_case.execute(comando)
    session.commit()

    assert segunda.skipped is True
    assert segunda.reason == "already_remediated"
    assert len(repo.get_by_scan_job(scan_job_id)) == 1
    assert claude.call_json.call_count == 1


# -----------------------------------------------------------------------------
# Arquivo fora do diff do PR
# -----------------------------------------------------------------------------


def test_fora_do_diff_persiste_sem_postar(session, scan_job_id, finding_record):
    """Regressão do PR #20: 5 de 8 tentativas levaram 422.

    Um PR de um arquivo só; o Tier 2 acha problema no repositório inteiro. O
    GitHub recusa comentário inline ancorado fora do diff, então cada um
    daqueles findings custava uma chamada ao Claude para receber uma recusa
    garantida — e a remediação era descartada junto com a falha do post, em
    vez de ir para o dashboard.
    """
    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning({**PATCH_OK, "explanation": "ok"})
    factory = _fake_github_factory()
    factory.client.list_pr_files.return_value = {"outro/arquivo.py"}

    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )
    result = use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(finding_record),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    session.commit()

    assert result.skipped is False
    assert result.posted is False
    factory.client.post_inline_suggestion.assert_not_called()

    # O que importa: a remediação SOBREVIVE e chega ao dashboard.
    persistidas = repo.get_by_scan_job(scan_job_id)
    assert len(persistidas) == 1
    assert persistidas[0].github_comment_id is None


def test_falha_ao_listar_o_diff_nao_impede_o_post(session, scan_job_id, finding_record):
    """Na dúvida, tenta postar: um 422 custa menos que um comentário a menos."""
    repo = SQLAlchemyRemediationRepository(session)
    claude = _fake_claude_returning({**PATCH_OK, "explanation": "ok"})
    factory = _fake_github_factory(comment_id=555)
    factory.client.list_pr_files.side_effect = RuntimeError("500")

    use_case = SuggestPatchUseCase(
        repository=repo, claude=claude, github_client_factory=factory
    )
    result = use_case.execute(
        SuggestPatchCommand(
            finding=_finding_dict(finding_record),
            scan_job_id=scan_job_id,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
    )
    session.commit()

    assert result.posted is True
    factory.client.post_inline_suggestion.assert_called_once()
