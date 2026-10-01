"""Ensaio de remediação: gera o patch de um finding e mostra o que iria ao PR.

Existe porque o caminho da code suggestion só se exercita de verdade com um
PR aberto, e abrir PR para testar formatação é caro e sujo. Aqui o pipeline
roda inteiro — Claude, arquivo real do GitHub, verificação — e para antes de
postar. O que é impresso é literalmente o que seria enviado.

Foi escrito depois de descobrir que o formato estava errado desde sempre: o
modelo devolvia diff unificado, o diff ia cru para um bloco ```suggestion, e
"Apply suggestion" escreveria `@@`/`-`/`+` dentro do arquivo. Nada disso
aparecia em lugar nenhum — nem log, nem erro.

Uso (dentro do container `api`):

    python scripts/ensaiar_remediacao.py <commit_sha> [quantos]
"""
from __future__ import annotations

import sys

from app.application.remediation.suggest_patch_use_case import _anotar, _linhas
from app.domain.remediation.patch_suggestion import PatchInvalido, verificar
from app.infrastructure.ai import prompts
from app.infrastructure.ai.claude_client import ClaudeClient, ClaudeClientError
from app.infrastructure.ai.models import FORMATTING
from app.infrastructure.database.sqlalchemy import SessionLocal
from app.infrastructure.git.github_client import GitHubClient
from app.infrastructure.persistence.models.finding_model import FindingModel
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.presentation.workers.remediation_worker import _selecionar

VERDE, VERMELHO, AMARELO, CINZA, FIM = (
    "\033[32m",
    "\033[31m",
    "\033[33m",
    "\033[90m",
    "\033[0m",
)


def main(commit_sha: str, quantos: int) -> int:
    with SessionLocal() as db:
        job = SQLAlchemyScanJobRepository(db).get_by_commit(commit_sha)
        if job is None:
            print(f"{VERMELHO}sem scan_job para {commit_sha}{FIM}")
            return 1

        linhas = (
            db.query(FindingModel)
            .filter(FindingModel.commit_sha == commit_sha)
            .all()
        )
        candidatos, descartados = _selecionar(
            [
                {
                    "id": str(f.id),
                    "source": f.source,
                    "severity": f.severity,
                    "tier": f.tier,
                    "title": f.title,
                    "description": f.description,
                    "cve_id": f.cve_id,
                    "cwe_id": f.cwe_id,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "secret_verified": f.secret_verified,
                    "secret_type": f.secret_type,
                    "commit_sha": f.commit_sha,
                }
                for f in linhas
            ],
            teto=quantos,
        )

    print(f"{CINZA}descartados por ruído (secret não verificado em teste/doc): "
          f"{descartados}{FIM}")
    if not candidatos:
        print(f"{AMARELO}nenhum finding de tier 1/2 com arquivo e linha{FIM}")
        return 0

    github = GitHubClient(installation_id=job.installation_id)
    claude = ClaudeClient()
    placar = {"ok": 0, "reindentado": 0, "recusado": 0, "erro": 0}

    for i, finding in enumerate(candidatos, 1):
        titulo = str(finding["title"])[:60]
        print(f"\n{'─' * 78}\n[{i}/{len(candidatos)}] {titulo}")
        print(f"{CINZA}{finding['file_path']}:{finding['line_number']}{FIM}")

        try:
            conteudo = github.get_file_content(
                repo_full_name=job.repo_full_name,
                path=str(finding["file_path"]),
                ref=commit_sha,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"{VERMELHO}  arquivo não veio: {exc}{FIM}")
            placar["erro"] += 1
            continue

        do_arquivo = conteudo.splitlines()
        try:
            dados = claude.call_json(
                system=prompts.remediation.SYSTEM,
                user=prompts.remediation.build(
                    finding, _anotar(do_arquivo, int(finding["line_number"]))
                ),
                model=FORMATTING,
                commit_sha=commit_sha,
            )
        except ClaudeClientError as exc:
            # Mesmo desfecho do pipeline: pula este finding e segue. Um ensaio
            # que morre no primeiro tropeço não serve para medir taxa de acerto.
            print(f"{VERMELHO}  Claude falhou: {str(exc)[:110]}{FIM}")
            placar["erro"] += 1
            continue

        try:
            sub = verificar(
                start_line=int(dados.get("start_line") or 0),
                end_line=int(dados.get("end_line") or 0),
                original=_linhas(dados.get("original")),
                replacement=_linhas(dados.get("replacement")),
                linhas_do_arquivo=do_arquivo,
            )
        except (PatchInvalido, TypeError, ValueError) as exc:
            print(f"{VERMELHO}  RECUSADO: {exc}{FIM}")
            print(f"{CINZA}  explicação do modelo: {str(dados.get('explanation'))[:90]}{FIM}")
            placar["recusado"] += 1
            continue

        marca = f"{AMARELO}REINDENTADO{FIM}" if sub.reindentado else f"{VERDE}EXATO{FIM}"
        placar["reindentado" if sub.reindentado else "ok"] += 1
        print(f"  {marca}  linhas {sub.start_line}-{sub.end_line}")
        print(f"\n  {CINZA}--- o que iria no bloco ```suggestion ---{FIM}")
        for linha in sub.suggestion_body().split("\n"):
            print(f"  {VERDE}|{FIM}{linha}")
        print(f"  {CINZA}--- fim (repare no recuo) ---{FIM}")

    print(f"\n{'═' * 78}\n{placar}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 3))
