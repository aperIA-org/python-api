import json
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

import structlog

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.base_scanner import BaseScanner

logger = structlog.get_logger()


def _caminho_no_repo(caminho: str | None, repo_path: str) -> str | None:
    """Converte caminho absoluto do checkout em caminho relativo ao repositório.

    O modo ``filesystem`` do TruffleHog reporta o caminho **absoluto** do
    diretório temporário — ``/tmp/aperia-checkout-q9kwt74e/lib/insecurity.ts``.
    Isso vaza um detalhe de execução para dentro do finding e torna o caminho
    inútil: o diretório é apagado no fim do scan, o prefixo muda a cada
    execução, e o mesmo arquivo gera caminhos diferentes a cada scan — o que
    também atrapalharia qualquer agrupamento por arquivo.

    O que interessa é o caminho **dentro do repositório** (``lib/insecurity.ts``),
    que é o que o Semgrep já devolve (ele roda com ``cwd=repo_path``) e o que
    permite montar link para o GitHub.
    """
    if not caminho:
        return None
    try:
        return str(Path(caminho).resolve().relative_to(Path(repo_path).resolve()))
    except ValueError:
        # Fora da árvore do checkout: devolve como veio em vez de inventar.
        return caminho


# Regexes de caminho que o modo `filesystem` não deve varrer.
#
# `.git` é o caso que importa. O modo `filesystem` varre o working tree, e o
# working tree do checkout inclui o diretório `.git` — então todo segredo era
# reportado DUAS vezes: uma no arquivo real (`app/config.py`) e outra no blob
# correspondente (`.git/objects/16/87f7c3…`). Num alvo de teste, 16 findings
# eram 4 valores distintos.
#
# Não é só ruído de contagem. Os findings duplicados entram no prompt do Tier 2
# e no do Tier 3, inflando entrada e saída de uma análise que já é limitada por
# `max_tokens` — e o caminho `.git/objects/…` não diz a ninguém onde corrigir o
# problema, porque não é um arquivo que alguém edita.
#
# O modo `git` não precisa disso: ele já percorre commits, não o diretório.
_EXCLUIR_DO_FILESYSTEM = (
    r"(^|/)\.git/",
)


@contextmanager
def _arquivo_de_exclusoes(padroes: tuple[str, ...]):
    """Materializa os regexes num arquivo temporário, que é o que o `-x` aceita.

    O TruffleHog não recebe padrão por argumento: `--exclude-paths` quer um
    caminho para arquivo com um regex por linha. O arquivo é apagado no `finally`
    — mesmo padrão do checkout, quem cria remove.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="trufflehog-exclude-", delete=True
    ) as fh:
        fh.write("\n".join(padroes) + "\n")
        fh.flush()
        yield fh.name


class TruffleHogScanner(BaseScanner):
    """Busca secrets no repositório materializado pelo checkout.

    **Modo de varredura.** O checkout do pipeline é raso (``--depth 1``): existe
    UM commit na árvore. O modo ``git`` do TruffleHog percorre *histórico*, então
    sobre um checkout raso ele tem, no melhor caso, um único commit para olhar —
    e no scan manual de branch, onde ``base_sha == head_sha``, o intervalo
    ``--since-commit`` é **vazio** e ele não examina commit nenhum. O resultado
    era ``0 findings`` sem ter procurado.

    Por isso o modo é escolhido pelo que existe para examinar:

    - **branch** (sem base distinta) → ``filesystem`` sobre o working tree. É o
      único modo que enxerga os arquivos do commit materializado.
    - **pull request** (base distinta do head) → ``git`` com ``--since-commit``,
      que é onde percorrer histórico faz sentido: varre os commits do PR.

    **Secrets não verificados são reportados.** Antes o filtro existia em dobro —
    ``--only-verified`` na CLI e um segundo ``if item["Verified"]`` no parsing —
    e um segredo que o TruffleHog não conseguisse validar contra o provedor
    sumia sem deixar rastro. Isso esconde credencial revogada, de ambiente de
    teste, ou de provedor para o qual não existe verificador.

    A verificação vira **severidade**, não censura: verificado é ``CRITICAL``,
    não verificado é ``MEDIUM``. `MEDIUM` é deliberado — não escala para o Tier 3
    (que exige ``high``/``critical``) e não bloqueia o PR (o Gate 1 bloqueia
    apenas em ``secret_verified=True``), então o achado fica visível sem inflar
    a análise profunda nem travar merge por suspeita.
    """

    TIMEOUT = 120

    def scan(
        self,
        repo_path: str,
        base_sha: str,
        head_sha: str,
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        # Base ausente ou igual ao head = não há intervalo de commits a varrer.
        tem_base_real = bool(base_sha) and base_sha != head_sha

        if tem_base_real:
            modo = "git"
            args = [
                "git",
                f"file://{repo_path}",
                "--since-commit",
                base_sha,
                "--branch",
                head_sha,
            ]
            result = subprocess.run(
                ["trufflehog", *args, "--json", "--no-update"],
                capture_output=True,
                text=True,
                timeout=self.TIMEOUT,
            )
        else:
            modo = "filesystem"
            args = ["filesystem", repo_path]
            # Só o modo `filesystem` precisa excluir `.git` — ver
            # `_EXCLUIR_DO_FILESYSTEM`.
            with _arquivo_de_exclusoes(_EXCLUIR_DO_FILESYSTEM) as exclusoes:
                result = subprocess.run(
                    [
                        "trufflehog",
                        *args,
                        "--exclude-paths",
                        exclusoes,
                        "--json",
                        "--no-update",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.TIMEOUT,
                )

        findings: list[Finding] = []
        verificados = 0
        for line in result.stdout.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Linhas de progresso/erro do TruffleHog também são JSON; só entram
            # os achados, que sempre trazem o detector.
            if not item.get("DetectorName"):
                continue
            verificado = bool(item.get("Verified"))
            if verificado:
                verificados += 1
            findings.append(
                self._to_finding(item, commit_sha, repo_url, verificado, repo_path)
            )

        # Sem o modo no log é impossível distinguir "não achei" de "não procurei".
        logger.info(
            "trufflehog_scan_done",
            commit_sha=commit_sha,
            modo=modo,
            findings_count=len(findings),
            verificados=verificados,
            nao_verificados=len(findings) - verificados,
        )
        return findings

    def _to_finding(
        self,
        item: dict,
        commit_sha: str,
        repo_url: str,
        verificado: bool,
        repo_path: str,
    ) -> Finding:
        git_meta = item.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
        fs_meta = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        detector = item.get("DetectorName", "unknown")
        rotulo = "Secret verificado" if verificado else "Possível secret (não verificado)"

        return Finding(
            source="trufflehog",
            severity=Severity.CRITICAL if verificado else Severity.MEDIUM,
            title=f"{rotulo}: {detector}",
            description=item.get("Raw", ""),
            commit_sha=commit_sha,
            repo_url=repo_url,
            # No modo filesystem os metadados vêm em `Filesystem`, não em `Git`.
            file_path=_caminho_no_repo(
                git_meta.get("file") or fs_meta.get("file"), repo_path
            ),
            line_number=git_meta.get("line") or fs_meta.get("line"),
            secret_verified=verificado,
            secret_type=detector,
            raw_output=item,
            tier=1,
        )
