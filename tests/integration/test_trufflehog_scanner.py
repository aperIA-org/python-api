import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.trufflehog_scanner import TruffleHogScanner


FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "trufflehog_verified.jsonl"
)


def _fake_completed_process(stdout: str, returncode: int = 0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.returncode = returncode
    return proc


@pytest.fixture
def fixture_jsonl() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def test_reporta_verificados_e_nao_verificados(fixture_jsonl):
    """Não-verificados deixaram de ser descartados: viram severidade menor.

    Antes o filtro existia em dobro (``--only-verified`` na CLI + um segundo
    ``if item["Verified"]`` no parsing), e um segredo que o TruffleHog não
    conseguisse validar sumia sem rastro.
    """
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(fixture_jsonl),
    ):
        findings = TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha="abc",
            head_sha="def",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

    # Fixture tem 3 entradas: 2 com Verified=true, 1 com Verified=false
    assert len(findings) == 3
    verificados = [f for f in findings if f.secret_verified]
    nao_verificados = [f for f in findings if not f.secret_verified]
    assert len(verificados) == 2
    assert len(nao_verificados) == 1

    # A verificação vira severidade, não censura.
    assert all(f.severity is Severity.CRITICAL for f in verificados)
    assert nao_verificados[0].severity is Severity.MEDIUM
    assert nao_verificados[0].title.startswith("Possível secret (não verificado)")


def test_nao_verificado_nao_bloqueia_nem_escala(fixture_jsonl):
    """MEDIUM é deliberado: não escala p/ Tier 3 nem bloqueia o PR.

    O Gate 1 bloqueia apenas em ``secret_verified=True`` e o Gate 2 escala
    apenas em ``high``/``critical`` — um achado não verificado fica visível sem
    travar merge por suspeita nem inflar a análise profunda.
    """
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(fixture_jsonl),
    ):
        findings = TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha="abc",
            head_sha="def",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

    nao_verificado = next(f for f in findings if not f.secret_verified)
    assert nao_verificado.severity.value not in ("high", "critical")
    assert nao_verificado.is_critical_secret() is False


def test_finding_metadata(fixture_jsonl):
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(fixture_jsonl),
    ):
        findings = TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha="abc",
            head_sha="def",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

    aws = next(f for f in findings if f.secret_type == "AWS")
    assert aws.severity is Severity.CRITICAL
    assert aws.source == "trufflehog"
    assert aws.tier == 1
    assert aws.file_path == "config/secrets.env"
    assert aws.line_number == 12
    assert aws.commit_sha == "a" * 40
    assert aws.title == "Secret verificado: AWS"
    assert aws.is_critical_secret() is True


def test_handles_invalid_json_line_silently():
    bad_stdout = (
        '{"Verified":true,"DetectorName":"AWS","SourceMetadata":{"Data":{"Git":{}}}}\n'
        "this is not json\n"
        '{"Verified":true,"DetectorName":"GitHub","SourceMetadata":{"Data":{"Git":{}}}}\n'
    )
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(bad_stdout),
    ):
        findings = TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha="x",
            head_sha="y",
            commit_sha="b" * 40,
            repo_url="https://github.com/x/y",
        )
    assert len(findings) == 2


def test_empty_stdout_returns_empty():
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(""),
    ):
        findings = TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha="x",
            head_sha="y",
            commit_sha="c" * 40,
            repo_url="https://github.com/x/y",
        )
    assert findings == []


def test_modo_git_quando_ha_base_distinta(fixture_jsonl):
    """PR: base != head, existe intervalo de commits para percorrer."""
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(fixture_jsonl),
    ) as run_mock:
        TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha="aaa",
            head_sha="bbb",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

    args = run_mock.call_args[0][0]
    assert args[0] == "trufflehog"
    assert args[1] == "git"
    assert "file:///tmp/repo" in args
    assert "--since-commit" in args and "aaa" in args
    assert "--branch" in args and "bbb" in args
    assert "--json" in args
    assert "--no-update" in args
    # O filtro da CLI saiu: quem decide agora é a severidade.
    assert "--only-verified" not in args
    # Sem shell=True
    assert run_mock.call_args[1].get("shell") in (None, False)
    # Timeout configurado
    assert run_mock.call_args[1]["timeout"] == TruffleHogScanner.TIMEOUT


@pytest.mark.parametrize("base", ["", "bbb"])
def test_modo_filesystem_sem_base_real(fixture_jsonl, base):
    """Branch: sem base (ou base == head) o modo git varreria ZERO commits.

    O checkout do pipeline é raso (``--depth 1``), então só o modo filesystem
    enxerga os arquivos do commit materializado.
    """
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(fixture_jsonl),
    ) as run_mock:
        TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha=base,
            head_sha="bbb",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

    args = run_mock.call_args[0][0]
    assert args[1] == "filesystem"
    assert "/tmp/repo" in args
    assert "--since-commit" not in args
    assert "--branch" not in args


def test_filesystem_exclui_git(fixture_jsonl):
    """`.git` fora do escopo no modo filesystem.

    O working tree do checkout inclui `.git`, entao todo segredo era reportado
    duas vezes: no arquivo real e no blob correspondente em `.git/objects/`.
    Num alvo de teste, 16 findings eram 4 valores distintos — ruido que ainda
    inflava os prompts dos Tiers 2 e 3.
    """
    # O conteudo tem de ser lido DURANTE a chamada: o arquivo e temporario e
    # some no fim do scan (ver `test_arquivo_de_exclusoes_e_removido_apos_o_scan`).
    conteudo = {}

    def _ler_exclusoes(args, **kwargs):
        caminho = args[args.index("--exclude-paths") + 1]
        with open(caminho, encoding="utf-8") as fh:
            conteudo["texto"] = fh.read()
        return _fake_completed_process(fixture_jsonl)

    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        side_effect=_ler_exclusoes,
    ) as run_mock:
        TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha="",
            head_sha="bbb",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

    assert "--exclude-paths" in run_mock.call_args[0][0]
    # O `-x` do TruffleHog recebe um ARQUIVO com um regex por linha, nao o
    # padrao direto — passar o regex aqui falharia em silencio.
    assert r"(^|/)\.git/" in conteudo["texto"]


def test_modo_git_nao_exclui_nada(fixture_jsonl):
    """O modo `git` percorre commits, nao o diretorio: nao ha `.git` a excluir.

    E excluir ali seria pior que inutil — o padrao poderia casar caminhos
    legitimos do historico.
    """
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(fixture_jsonl),
    ) as run_mock:
        TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha="aaa",
            head_sha="bbb",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

    assert "--exclude-paths" not in run_mock.call_args[0][0]


def test_arquivo_de_exclusoes_e_removido_apos_o_scan(fixture_jsonl):
    """Quem cria remove — mesmo padrao do checkout."""
    capturado = {}

    def _capturar(args, **kwargs):
        capturado["caminho"] = args[args.index("--exclude-paths") + 1]
        return _fake_completed_process(fixture_jsonl)

    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        side_effect=_capturar,
    ):
        TruffleHogScanner().scan(
            repo_path="/tmp/repo",
            base_sha="",
            head_sha="bbb",
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

    assert not os.path.exists(capturado["caminho"])


def test_run_safe_returns_empty_on_subprocess_timeout():
    import subprocess as sp

    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        side_effect=sp.TimeoutExpired(cmd="trufflehog", timeout=120),
    ):
        findings = TruffleHogScanner().run_safe(
            repo_path="/tmp/repo",
            base_sha="x",
            head_sha="y",
            commit_sha="d" * 40,
            repo_url="https://github.com/x/y",
        )
    assert findings == []


def test_caminho_vira_relativo_ao_repositorio():
    """Modo filesystem reporta caminho ABSOLUTO do checkout temporário.

    `/tmp/aperia-checkout-q9kwt74e/lib/insecurity.ts` vaza detalhe de execução
    para dentro do finding, e o prefixo muda a cada scan — o mesmo arquivo
    geraria caminhos diferentes, atrapalhando qualquer agrupamento e impedindo
    montar link para o GitHub.
    """
    saida = (
        '{"DetectorName":"PrivateKey","Verified":false,'
        '"SourceMetadata":{"Data":{"Filesystem":{'
        '"file":"/tmp/aperia-checkout-q9kwt74e/lib/insecurity.ts","line":42}}}}\n'
    )
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(saida),
    ):
        findings = TruffleHogScanner().scan(
            repo_path="/tmp/aperia-checkout-q9kwt74e",
            base_sha="",
            head_sha="h" * 40,
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

    assert findings[0].file_path == "lib/insecurity.ts"
    assert findings[0].line_number == 42


def test_caminho_fora_da_arvore_e_preservado():
    """Fora do checkout, devolve como veio em vez de inventar relativo."""
    saida = (
        '{"DetectorName":"AWS","Verified":false,'
        '"SourceMetadata":{"Data":{"Filesystem":{"file":"/etc/passwd"}}}}\n'
    )
    with patch(
        "app.infrastructure.scanners.trufflehog_scanner.subprocess.run",
        return_value=_fake_completed_process(saida),
    ):
        findings = TruffleHogScanner().scan(
            repo_path="/tmp/aperia-checkout-x",
            base_sha="",
            head_sha="h" * 40,
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

    assert findings[0].file_path == "/etc/passwd"
