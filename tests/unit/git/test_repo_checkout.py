"""Testes do checkout efêmero do repositório.

Nada aqui toca a rede: ``get_installation_token`` e ``subprocess.run`` são
mockados no namespace do módulo — mesmo padrão dos testes de scanner.

O foco é o que dá para quebrar sem perceber: a sequência de comandos, a
limpeza do diretório em **todos** os caminhos e o vazamento do token (argv,
mensagem de exceção, log).
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

import pytest
from structlog.testing import capture_logs

from app.core.exceptions import RepoCheckoutError
from app.infrastructure.git import repo_checkout
from app.infrastructure.git.repo_checkout import (
    checkout_repo,
    listar_arquivos_alterados,
)

TOKEN = "ghs_tokenSuperSecreto1234567890"
COMMIT = "a" * 40
BASE = "b" * 40


class GitFalso:
    """Substitui ``subprocess.run`` e grava cada chamada.

    ``falhas`` mapeia uma marca presente nos argumentos (ex.: o SHA do base)
    para o resultado que aquela chamada deve produzir.
    """

    def __init__(self, falhas: dict[str, object] | None = None) -> None:
        self.chamadas: list[dict] = []
        self.falhas = falhas or {}

    def __call__(self, args, **kwargs):
        self.chamadas.append({"args": list(args), "env": kwargs.get("env")})
        for marca, resultado in self.falhas.items():
            if marca in args:
                if isinstance(resultado, Exception):
                    raise resultado
                return resultado
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    @property
    def comandos(self) -> list[list[str]]:
        return [c["args"] for c in self.chamadas]

    def argv_concatenado(self) -> str:
        return " ".join(" ".join(c) for c in self.comandos)


def _falha(stderr: str, rc: int = 128) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], rc, stdout="", stderr=stderr)


@pytest.fixture
def token_mockado():
    with patch.object(
        repo_checkout, "get_installation_token", return_value=TOKEN
    ) as m:
        yield m


class TestCaminhoFeliz:
    def test_sequencia_de_comandos(self, token_mockado):
        git = GitFalso()
        with patch.object(repo_checkout.subprocess, "run", git):
            with checkout_repo(
                repo_full_name="acme/repo",
                commit_sha=COMMIT,
                installation_id=42,
            ) as caminho:
                assert os.path.isdir(caminho)

        etapas = [c[1] if c[1] != "-C" else c[3] for c in git.comandos]
        assert etapas == ["init", "remote", "fetch", "checkout"]
        # Fetch é do commit exato e raso.
        fetch = git.comandos[2]
        assert fetch[-4:] == ["--depth", "1", "origin", COMMIT]
        assert git.comandos[3][-1] == "FETCH_HEAD"
        token_mockado.assert_called_once_with(42)

    def test_remote_nao_carrega_credencial(self, token_mockado):
        git = GitFalso()
        with patch.object(repo_checkout.subprocess, "run", git):
            with checkout_repo(
                repo_full_name="acme/repo", commit_sha=COMMIT, installation_id=42
            ):
                pass

        remote = git.comandos[1]
        assert remote[-1] == "https://github.com/acme/repo.git"
        assert "x-access-token" not in " ".join(remote)

    def test_token_vai_por_env_e_nunca_por_argv(self, token_mockado):
        git = GitFalso()
        with patch.object(repo_checkout.subprocess, "run", git):
            with checkout_repo(
                repo_full_name="acme/repo", commit_sha=COMMIT, installation_id=42
            ):
                pass

        assert TOKEN not in git.argv_concatenado()
        env_fetch = git.chamadas[2]["env"]
        assert env_fetch["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraHeader"
        assert env_fetch["GIT_CONFIG_VALUE_0"].startswith("Authorization: Basic ")
        assert env_fetch["GIT_TERMINAL_PROMPT"] == "0"
        # O token cru também não aparece no header — vai em base64.
        assert TOKEN not in env_fetch["GIT_CONFIG_VALUE_0"]

    def test_todas_as_chamadas_tem_timeout(self, token_mockado):
        with patch.object(repo_checkout.subprocess, "run") as run_mock:
            run_mock.return_value = subprocess.CompletedProcess([], 0, "", "")
            with checkout_repo(
                repo_full_name="acme/repo", commit_sha=COMMIT, installation_id=42
            ):
                pass

        assert run_mock.call_count == 4
        assert all(c.kwargs.get("timeout") for c in run_mock.call_args_list)
        assert all(c.kwargs.get("shell") is None for c in run_mock.call_args_list)


class TestBaseSha:
    def test_base_diferente_do_commit_e_buscado(self, token_mockado):
        git = GitFalso()
        with patch.object(repo_checkout.subprocess, "run", git):
            with checkout_repo(
                repo_full_name="acme/repo",
                commit_sha=COMMIT,
                installation_id=42,
                base_sha=BASE,
            ):
                pass

        assert len(git.comandos) == 5
        assert git.comandos[-1][-1] == BASE

    def test_base_igual_ao_commit_nao_gera_fetch_extra(self, token_mockado):
        git = GitFalso()
        with patch.object(repo_checkout.subprocess, "run", git):
            with checkout_repo(
                repo_full_name="acme/repo",
                commit_sha=COMMIT,
                installation_id=42,
                base_sha=COMMIT,
            ):
                pass

        assert len(git.comandos) == 4

    def test_falha_no_base_nao_derruba_o_checkout(self, token_mockado):
        """Force-push no branch base apaga o objeto — o scan continua válido."""
        git = GitFalso(falhas={BASE: _falha("fatal: not our ref")})
        with patch.object(repo_checkout.subprocess, "run", git):
            with checkout_repo(
                repo_full_name="acme/repo",
                commit_sha=COMMIT,
                installation_id=42,
                base_sha=BASE,
            ) as caminho:
                assert os.path.isdir(caminho)


class TestLimpeza:
    def test_diretorio_removido_no_sucesso(self, token_mockado):
        git = GitFalso()
        with patch.object(repo_checkout.subprocess, "run", git):
            with checkout_repo(
                repo_full_name="acme/repo", commit_sha=COMMIT, installation_id=42
            ) as caminho:
                visto = caminho
        assert not os.path.exists(visto)

    def test_diretorio_removido_quando_o_corpo_levanta(self, token_mockado):
        git = GitFalso()
        visto = None
        with patch.object(repo_checkout.subprocess, "run", git):
            with pytest.raises(RuntimeError):
                with checkout_repo(
                    repo_full_name="acme/repo", commit_sha=COMMIT, installation_id=42
                ) as caminho:
                    visto = caminho
                    raise RuntimeError("scanner explodiu")
        assert visto is not None
        assert not os.path.exists(visto)

    def test_diretorio_removido_quando_o_fetch_falha(self, token_mockado):
        git = GitFalso(falhas={COMMIT: _falha("fatal: remote error")})
        with patch.object(repo_checkout.subprocess, "run", git):
            with pytest.raises(RepoCheckoutError):
                with checkout_repo(
                    repo_full_name="acme/repo", commit_sha=COMMIT, installation_id=42
                ):
                    pass

        # O diretório criado é sempre o argumento do ``git init``.
        criado = git.comandos[0][-1]
        assert not os.path.exists(criado)


class TestRedacaoDoToken:
    def test_token_redigido_na_mensagem_de_erro(self, token_mockado):
        """git costuma ecoar a URL autenticada em stderr — o erro não pode."""
        stderr = (
            f"fatal: unable to access 'https://x-access-token:{TOKEN}@github.com/"
            "acme/repo.git/': 403"
        )
        git = GitFalso(falhas={COMMIT: _falha(stderr)})
        with patch.object(repo_checkout.subprocess, "run", git):
            with pytest.raises(RepoCheckoutError) as exc:
                with checkout_repo(
                    repo_full_name="acme/repo", commit_sha=COMMIT, installation_id=42
                ):
                    pass

        mensagem = str(exc.value)
        assert TOKEN not in mensagem
        assert "***" in mensagem

    def test_token_redigido_no_log(self, token_mockado):
        stderr = f"fatal: could not read Username for 'https://{TOKEN}@github.com'"
        git = GitFalso(falhas={BASE: _falha(stderr)})
        with patch.object(repo_checkout.subprocess, "run", git):
            with capture_logs() as logs:
                with checkout_repo(
                    repo_full_name="acme/repo",
                    commit_sha=COMMIT,
                    installation_id=42,
                    base_sha=BASE,
                ):
                    pass

        texto = str(logs)
        assert TOKEN not in texto
        assert "***" in texto

    def test_forma_base64_do_token_tambem_e_redigida(self, token_mockado):
        import base64

        codificado = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
        git = GitFalso(falhas={COMMIT: _falha(f"header enviado: Basic {codificado}")})
        with patch.object(repo_checkout.subprocess, "run", git):
            with pytest.raises(RepoCheckoutError) as exc:
                with checkout_repo(
                    repo_full_name="acme/repo", commit_sha=COMMIT, installation_id=42
                ):
                    pass

        assert codificado not in str(exc.value)


class TestFalhasDeRede:
    def test_timeout_vira_repo_checkout_error(self, token_mockado):
        git = GitFalso(
            falhas={COMMIT: subprocess.TimeoutExpired(cmd="git fetch", timeout=300)}
        )
        with patch.object(repo_checkout.subprocess, "run", git):
            with pytest.raises(RepoCheckoutError) as exc:
                with checkout_repo(
                    repo_full_name="acme/repo", commit_sha=COMMIT, installation_id=42
                ):
                    pass

        assert "timeout" in str(exc.value).lower()
        assert not os.path.exists(git.comandos[0][-1])

    def test_timeout_nao_propaga_a_excecao_original(self, token_mockado):
        """``TimeoutExpired`` carrega ``cmd``/``output`` — não pode subir junto."""
        git = GitFalso(
            falhas={COMMIT: subprocess.TimeoutExpired(cmd="git fetch", timeout=300)}
        )
        with patch.object(repo_checkout.subprocess, "run", git):
            with pytest.raises(RepoCheckoutError) as exc:
                with checkout_repo(
                    repo_full_name="acme/repo", commit_sha=COMMIT, installation_id=42
                ):
                    pass

        assert exc.value.__cause__ is None

    def test_git_ausente_vira_repo_checkout_error(self, token_mockado):
        with patch.object(
            repo_checkout.subprocess, "run", side_effect=FileNotFoundError("git")
        ):
            with pytest.raises(RepoCheckoutError):
                with checkout_repo(
                    repo_full_name="acme/repo", commit_sha=COMMIT, installation_id=42
                ):
                    pass

    def test_falha_ao_obter_token(self):
        with patch.object(
            repo_checkout,
            "get_installation_token",
            side_effect=RuntimeError("401 Bad credentials"),
        ):
            with pytest.raises(RepoCheckoutError) as exc:
                with checkout_repo(
                    repo_full_name="acme/repo", commit_sha=COMMIT, installation_id=42
                ):
                    pass

        assert "instalacao 42" in str(exc.value)


class TestValidacaoDeEntrada:
    @pytest.mark.parametrize(
        "full_name",
        [
            "",
            "semBarra",
            "acme/repo; rm -rf /",
            "../etc/passwd",
            "-upload-pack=touch/x",
            "acme/../repo",
        ],
    )
    def test_full_name_invalido_e_recusado(self, full_name):
        with patch.object(repo_checkout, "get_installation_token") as token:
            with pytest.raises(RepoCheckoutError):
                with checkout_repo(
                    repo_full_name=full_name, commit_sha=COMMIT, installation_id=42
                ):
                    pass
        # Recusa antes de gastar um token de instalação.
        token.assert_not_called()

    @pytest.mark.parametrize(
        "sha", ["", "zzz", "--upload-pack=x", "a" * 41, "HEAD", "abc"]
    )
    def test_commit_sha_invalido_e_recusado(self, sha):
        with patch.object(repo_checkout, "get_installation_token") as token:
            with pytest.raises(RepoCheckoutError):
                with checkout_repo(
                    repo_full_name="acme/repo", commit_sha=sha, installation_id=42
                ):
                    pass
        token.assert_not_called()

    def test_base_sha_invalido_e_recusado(self):
        with patch.object(repo_checkout, "get_installation_token") as token:
            with pytest.raises(RepoCheckoutError):
                with checkout_repo(
                    repo_full_name="acme/repo",
                    commit_sha=COMMIT,
                    installation_id=42,
                    base_sha="--upload-pack=x",
                ):
                    pass
        token.assert_not_called()


class TestListarArquivosAlterados:
    def test_retorna_arquivos_do_diff(self):
        saida = "app/db.py\nlib/x.ts\n"
        with patch.object(
            repo_checkout.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, stdout=saida, stderr=""),
        ) as run_mock:
            arquivos = listar_arquivos_alterados(
                "/tmp/x", base_sha=BASE, head_sha=COMMIT
            )

        assert arquivos == ["app/db.py", "lib/x.ts"]
        cmd = run_mock.call_args.args[0]
        assert "--diff-filter=d" in cmd
        assert cmd[-2:] == [BASE, COMMIT]

    def test_descarta_caminhos_perigosos(self):
        saida = "ok.py\n../fora.py\n/etc/passwd\n"
        with patch.object(
            repo_checkout.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, stdout=saida, stderr=""),
        ):
            assert listar_arquivos_alterados(
                "/tmp/x", base_sha=BASE, head_sha=COMMIT
            ) == ["ok.py"]

    def test_base_igual_ao_head_nem_chama_o_git(self):
        with patch.object(repo_checkout.subprocess, "run") as run_mock:
            assert (
                listar_arquivos_alterados("/tmp/x", base_sha=COMMIT, head_sha=COMMIT)
                == []
            )
        run_mock.assert_not_called()

    def test_erro_do_git_devolve_lista_vazia(self):
        with patch.object(
            repo_checkout.subprocess,
            "run",
            return_value=_falha("fatal: bad object"),
        ):
            assert (
                listar_arquivos_alterados("/tmp/x", base_sha=BASE, head_sha=COMMIT)
                == []
            )

    def test_excecao_devolve_lista_vazia(self):
        with patch.object(
            repo_checkout.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="git diff", timeout=30),
        ):
            assert (
                listar_arquivos_alterados("/tmp/x", base_sha=BASE, head_sha=COMMIT)
                == []
            )
