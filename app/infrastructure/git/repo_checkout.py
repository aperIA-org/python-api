"""Checkout efêmero do repositório para os scanners que leem arquivos.

Por que **um checkout por tarefa** e não um clone compartilhado
-------------------------------------------------------------
``repo_path`` é consumido pelo Tier 1 (Semgrep + TruffleHog) e pelo Tier 2
(Trivy), que rodam em **containers diferentes** — cada serviço de worker em
``docker-compose.base.yml`` monta só o ``.env``, não há filesystem comum. Um
clone feito no container do Tier 1 simplesmente não existe no do Tier 2.

Um volume compartilhado resolveria o acesso, mas criaria a pergunta "quem
apaga e quando": o pipeline é assíncrono, tem gates que o interrompem no meio
(Gate 1 bloqueia, Gate 2 não escala) e tasks que podem ser reexecutadas
(``acks_late=True``), então nenhum ponto do canvas sabe que ninguém mais vai
precisar daquela árvore. Com checkout por tarefa a resposta é trivial: **quem
clonou apaga, no ``finally``** — inclusive quando a task morre por exceção.

O preço é materializar o mesmo commit mais de uma vez por pipeline. Como é
sempre um fetch **raso do commit exato** (``--depth 1``), o custo é da ordem do
tamanho da árvore, não do histórico — barato perto de manter estado
compartilhado e vivo entre containers.

Por que fetch por SHA e não ``git clone --depth 1``
--------------------------------------------------
``clone --depth 1`` só alcança a ponta de um branch. O pipeline escaneia um
**commit específico** (o HEAD do PR, que pode já não ser a ponta de nada
quando o worker roda). ``git init`` + ``fetch --depth 1 origin <sha>`` busca
exatamente aquele objeto — o github.com aceita fetch por SHA arbitrário.

Segurança do token
------------------
O token de instalação é um segredo de vida curta com acesso de leitura ao
repositório. Ele **não** entra:

- na **URL do remote** (``https://x-access-token:<token>@github.com/...``):
  ficaria gravado em texto puro no ``.git/config`` dentro do diretório
  temporário e vazaria em qualquer log ou dump que ecoasse o remote;
- na **linha de comando** (``git -c http.extraHeader=...``): argv é legível
  por qualquer processo da máquina em ``/proc/<pid>/cmdline``.

A credencial viaja por **variável de ambiente** (``GIT_CONFIG_COUNT`` /
``GIT_CONFIG_KEY_0`` / ``GIT_CONFIG_VALUE_0``, suportado a partir do git 2.31 —
a imagem é bookworm, git 2.39). O git aplica essas chaves como se fossem
``-c``, sem persistir nada no diretório e sem aparecer em argv;
``/proc/<pid>/environ`` só é legível pelo dono do processo. É a opção **menos
ruim**, não uma opção perfeita: não existe forma de autenticar sem que o
segredo esteja em algum canal do processo filho. O header é escopado em
``http.https://github.com/.extraHeader`` para não ser enviado a outro host em
caso de redirect.

Como o git pode ecoar o comando/URL em stderr, tudo que sai daqui (log ou
mensagem de exceção) passa por ``_redigir`` antes: token e sua forma base64
viram ``***``.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager

import structlog

from app.config import settings
from app.core.exceptions import RepoCheckoutError
from app.infrastructure.git.github_auth import get_installation_token

logger = structlog.get_logger()

# ``full_name`` e ``commit_sha`` vêm de payload externo (webhook do GitHub).
# Mesmo passando lista de argumentos (nunca ``shell=True``), um valor começando
# com "-" viraria flag do git e um "../" escaparia do diretório temporário.
_RE_FULL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
_RE_SHA = re.compile(r"^[0-9a-fA-F]{7,40}$")

# Operações que só mexem em disco local — nunca deveriam demorar.
_TIMEOUT_LOCAL = 30


def _validar_sha(valor: str, *, campo: str) -> None:
    if not valor or not _RE_SHA.match(valor):
        raise RepoCheckoutError(f"{campo} invalido: esperado hex de 7 a 40 caracteres.")


def _validar_full_name(valor: str) -> None:
    if not valor or ".." in valor or not _RE_FULL_NAME.match(valor):
        raise RepoCheckoutError(
            "repo_full_name invalido: esperado 'owner/repo' sem caracteres especiais."
        )


def _redigir(texto: str, segredos: Sequence[str]) -> str:
    """Troca cada segredo por ``***``. Aplicado antes de logar ou propagar."""
    limpo = texto or ""
    for segredo in segredos:
        if segredo:
            limpo = limpo.replace(segredo, "***")
    return limpo


def _credencial(token: str) -> tuple[str, tuple[str, ...]]:
    """Header ``Authorization`` e as formas do segredo que precisam ser redigidas.

    O token viaja em base64 dentro do header, então **as duas** representações
    (crua e codificada) entram na lista de redação.
    """
    codificado = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return f"Authorization: Basic {codificado}", (token, codificado)


def _env_autenticado(header: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraHeader",
            "GIT_CONFIG_VALUE_0": header,
            # Sem isso, token inválido faz o git pedir usuário/senha no
            # terminal e pendurar o worker até o timeout.
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return env


def _git(
    etapa: str,
    args: Sequence[str],
    *,
    segredos: Sequence[str],
    timeout: int,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Roda ``git`` com timeout obrigatório e stderr redigido em caso de erro.

    ``etapa`` nomeia o passo do checkout na mensagem de erro — a linha de
    comando não serve para isso, porque ela é justamente o que não pode ser
    ecoada sem passar pela redação.
    """
    try:
        proc = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # ``from None``: a TimeoutExpired original carrega ``cmd`` e a saída
        # parcial do processo — nada disso pode subir junto com a exceção.
        raise RepoCheckoutError(
            f"checkout ({etapa}) excedeu o timeout de {timeout}s."
        ) from None
    except OSError as exc:  # git ausente na imagem, permissão, etc.
        raise RepoCheckoutError(
            f"checkout ({etapa}) nao pode executar o git: "
            f"{_redigir(str(exc), segredos)}"
        ) from None

    if proc.returncode != 0:
        raise RepoCheckoutError(
            f"checkout ({etapa}) falhou (rc={proc.returncode}): "
            f"{_redigir(proc.stderr.strip(), segredos)}"
        )
    return proc


def _obter_token(installation_id: int) -> str:
    try:
        return get_installation_token(installation_id)
    except Exception as exc:  # noqa: BLE001 — httpx, JWT, arquivo de chave...
        raise RepoCheckoutError(
            f"nao foi possivel obter o token da instalacao {installation_id}: {exc}"
        ) from None


@contextmanager
def checkout_repo(
    *,
    repo_full_name: str,
    commit_sha: str,
    installation_id: int,
    base_sha: str | None = None,
) -> Iterator[str]:
    """Materializa ``commit_sha`` em um diretório temporário e entrega o caminho.

    Sequência: ``git init`` → ``remote add origin`` (URL **sem** credencial) →
    ``fetch --depth 1 origin <commit_sha>`` (autenticado por env) →
    ``checkout FETCH_HEAD``.

    ``base_sha``, quando informado e diferente do commit, é buscado num segundo
    fetch raso **best-effort**: ele não é necessário para escanear a árvore, só
    para calcular o diff do PR (``listar_arquivos_alterados``) e para o
    ``--since-commit`` do TruffleHog. Se o objeto sumiu (force-push no base) o
    checkout continua válido — quem depende do diff trata a ausência.

    O diretório é removido **sempre**, inclusive quando o corpo do ``with``
    levanta exceção. Levanta ``RepoCheckoutError`` em qualquer falha, com o
    token já redigido.
    """
    _validar_full_name(repo_full_name)
    _validar_sha(commit_sha, campo="commit_sha")
    if base_sha:
        _validar_sha(base_sha, campo="base_sha")

    header, segredos = _credencial(_obter_token(installation_id))
    env = _env_autenticado(header)
    timeout_rede = settings.REPO_CHECKOUT_TIMEOUT

    destino = tempfile.mkdtemp(prefix="aperia-checkout-")
    try:
        _git(
            "init",
            ["init", "--quiet", destino],
            segredos=segredos,
            timeout=_TIMEOUT_LOCAL,
        )
        _git(
            "remote",
            [
                "-C",
                destino,
                "remote",
                "add",
                "origin",
                f"https://github.com/{repo_full_name}.git",
            ],
            segredos=segredos,
            timeout=_TIMEOUT_LOCAL,
        )
        _git(
            "fetch",
            ["-C", destino, "fetch", "--quiet", "--depth", "1", "origin", commit_sha],
            segredos=segredos,
            timeout=timeout_rede,
            env=env,
        )
        # Checkout ANTES do fetch do base: o segundo fetch reescreve FETCH_HEAD.
        _git(
            "checkout",
            ["-C", destino, "checkout", "--quiet", "FETCH_HEAD"],
            segredos=segredos,
            timeout=_TIMEOUT_LOCAL,
        )
        if base_sha and base_sha != commit_sha:
            try:
                _git(
                    "fetch-base",
                    [
                        "-C",
                        destino,
                        "fetch",
                        "--quiet",
                        "--depth",
                        "1",
                        "origin",
                        base_sha,
                    ],
                    segredos=segredos,
                    timeout=timeout_rede,
                    env=env,
                )
            except RepoCheckoutError as exc:
                logger.warning(
                    "repo_checkout_base_indisponivel",
                    repo=repo_full_name,
                    commit_sha=commit_sha,
                    base_sha=base_sha,
                    error=_redigir(str(exc), segredos),
                )

        logger.info(
            "repo_checkout_pronto",
            repo=repo_full_name,
            commit_sha=commit_sha,
            path=destino,
        )
        yield destino
    finally:
        shutil.rmtree(destino, ignore_errors=True)
        logger.info(
            "repo_checkout_removido", repo=repo_full_name, commit_sha=commit_sha
        )


def listar_arquivos_alterados(
    repo_path: str, *, base_sha: str, head_sha: str
) -> list[str]:
    """Arquivos tocados entre ``base_sha`` e ``head_sha`` (o diff do PR).

    Funciona sobre o checkout raso porque ``git diff`` compara **árvores**: não
    precisa da ancestralidade entre os dois commits, só dos dois objetos —
    exatamente o que os dois fetches ``--depth 1`` trazem.

    ``--diff-filter=d`` descarta os arquivos deletados: eles não existem na
    árvore em disco e fariam o Semgrep abortar em "path not found".

    **Best-effort**: qualquer falha (base ausente por force-push, git
    indisponível, timeout) devolve ``[]``. O caller trata lista vazia como
    "varre a árvore inteira" — errar para o lado de escanear demais, nunca de
    menos.
    """
    if not base_sha or not head_sha or base_sha == head_sha:
        return []
    try:
        proc = subprocess.run(
            [
                "git",
                "-C",
                repo_path,
                "diff",
                "--name-only",
                "--diff-filter=d",
                base_sha,
                head_sha,
            ],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_LOCAL,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001 — best-effort, nunca derruba o scan
        logger.warning("repo_diff_indisponivel", error=str(exc), path=repo_path)
        return []

    if proc.returncode != 0:
        logger.warning(
            "repo_diff_indisponivel",
            base_sha=base_sha,
            head_sha=head_sha,
            error=proc.stderr.strip()[:300],
        )
        return []

    arquivos: list[str] = []
    for linha in proc.stdout.splitlines():
        caminho = linha.strip()
        # Mesma proteção do ``diff_utils``: nada de escapar do checkout.
        if not caminho or ".." in caminho or caminho.startswith("/"):
            continue
        arquivos.append(caminho)
    return arquivos
