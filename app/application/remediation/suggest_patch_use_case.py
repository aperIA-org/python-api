"""Use case: gera patch via Claude e posta como inline suggestion.

Princípios invioláveis:

1. **Remediação sempre humana**: este use case NUNCA aplica o patch.
   Apenas posta como GitHub code suggestion para o desenvolvedor
   aprovar via "Apply suggestion".
2. **Sem PR, sem comentário — mas com remediação**: um scan manual
   (de branch) não tem PR onde postar. O patch continua sendo gerado e
   persistido, com ``github_comment_id=None``; só o post é pulado. É a
   mesma regra que ``reporting_worker.post_tier2_report`` aplica ao
   relatório, e sem ela o caminho do dashboard não geraria nada.
3. **``finding["id"]`` já vem resolvido contra o banco**: quem chama é
   responsável por passar o id da LINHA persistida, não o ``uuid4`` que a
   dataclass gerou em memória. ``finding_id`` é FK para ``findings.id``, e
   num re-scan o ``ON CONFLICT DO NOTHING`` descarta o insert — o id do
   canvas simplesmente não existe na tabela. Ver
   ``remediation_worker._id_persistido``.
4. **Idempotência por finding**: antes de gerar patch e postar,
   consulta ``RemediationRepository.get_by_scan_job`` e verifica se
   já existe uma Remediation com o mesmo ``finding_id``. Se sim,
   retorna a existente sem fazer nada — re-scans não duplicam
   comentários no PR.
5. **Fault isolation do Claude**: ``CircuitOpenError`` /
   ``GuardBlockedError`` levam ao skip silencioso da remediação
   daquele finding (modo degradado). O caller decide se reporta a
   ausência.

O use case orquestra:
    code_context = GitHubClient.get_file_content(repo, path, ref)
    patch = ClaudeClient.call_json(remediation prompt)
    comment_id = GitHubClient.post_inline_suggestion(...)
    Remediation persisted with github_comment_id
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

import structlog

from app.domain.remediation.entities import Remediation, RemediationStatus
from app.domain.remediation.patch_suggestion import (
    PatchInvalido,
    verificar,
)
from app.domain.remediation.repositories import RemediationRepository
from app.infrastructure.ai import prompts
from app.infrastructure.ai.claude_client import (
    CircuitOpenError,
    ClaudeClient,
    ClaudeClientError,
    GuardBlockedError,
)
from app.infrastructure.ai.models import FORMATTING
from app.infrastructure.git.github_client import GitHubClient

logger = structlog.get_logger()


# Quantas linhas ao redor da linha afetada incluir como contexto.
# 20 acima + 20 abaixo é o suficiente para que o modelo entenda
# a função/bloco sem inflar o prompt além do razoável.
_CODE_CONTEXT_RADIUS = 20


@dataclass
class SuggestPatchCommand:
    finding: dict[str, Any]  # dict serializado de Finding
    scan_job_id: UUID
    repo_full_name: str
    pr_number: int | None
    commit_sha: str
    installation_id: int


@dataclass
class SuggestPatchResult:
    remediation_id: UUID | None
    posted: bool
    skipped: bool
    reason: str | None = None


class SuggestPatchUseCase:
    def __init__(
        self,
        repository: RemediationRepository,
        claude: ClaudeClient | None = None,
        github_client_factory=None,
    ) -> None:
        self.repository = repository
        self.claude = claude or ClaudeClient()
        # Factory permite injetar um GitHubClient mockado nos testes
        # sem precisar dar um installation_id real.
        self._github_factory = github_client_factory or GitHubClient

    def execute(self, cmd: SuggestPatchCommand) -> SuggestPatchResult:
        finding_id_raw = cmd.finding.get("id")
        if not finding_id_raw:
            return SuggestPatchResult(
                remediation_id=None,
                posted=False,
                skipped=True,
                reason="no_finding_id",
            )
        try:
            finding_id = UUID(str(finding_id_raw))
        except (ValueError, TypeError):
            return SuggestPatchResult(
                remediation_id=None,
                posted=False,
                skipped=True,
                reason="invalid_finding_id",
            )

        # ---- Idempotência: já existe Remediation para este finding/scan? ----
        existing = self.repository.get_by_scan_job(cmd.scan_job_id)
        for r in existing:
            if r.finding_id == finding_id:
                logger.info(
                    "suggest_patch_idempotent_skip",
                    finding_id=str(finding_id),
                    scan_job_id=str(cmd.scan_job_id),
                    existing_id=str(r.id),
                )
                return SuggestPatchResult(
                    remediation_id=r.id,
                    posted=False,
                    skipped=True,
                    reason="already_remediated",
                )

        github = self._github_factory(installation_id=cmd.installation_id)

        # ---- Arquivo + contexto anotado ----
        # As linhas CRUAS são o que permite conferir o que o modelo devolver.
        # Sem elas não há verificação possível, e sem verificação não se posta.
        file_path = cmd.finding.get("file_path")
        line_number = cmd.finding.get("line_number")
        if not file_path or not line_number:
            return SuggestPatchResult(
                remediation_id=None,
                posted=False,
                skipped=True,
                reason="missing_file_or_line",
            )

        linhas_do_arquivo = self._fetch_file_lines(
            github=github,
            repo_full_name=cmd.repo_full_name,
            file_path=file_path,
            commit_sha=cmd.commit_sha,
        )
        if linhas_do_arquivo is None:
            return SuggestPatchResult(
                remediation_id=None,
                posted=False,
                skipped=True,
                reason="sem_conteudo_do_arquivo",
            )
        code_context = _anotar(linhas_do_arquivo, int(line_number))

        # ---- Patch via Claude ----
        user_prompt = prompts.remediation.build(cmd.finding, code_context)
        try:
            patch_data = self.claude.call_json(
                system=prompts.remediation.SYSTEM,
                user=user_prompt,
                model=FORMATTING,
                commit_sha=cmd.commit_sha,
            )
        except (CircuitOpenError, GuardBlockedError, ClaudeClientError) as exc:
            logger.warning(
                "suggest_patch_claude_failed",
                finding_id=str(finding_id),
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return SuggestPatchResult(
                remediation_id=None,
                posted=False,
                skipped=True,
                reason=type(exc).__name__,
            )

        explanation = (patch_data.get("explanation") or "").strip()

        # ---- Verifica o trecho contra o arquivo ----
        # O modelo erra a indentação com frequência e às vezes erra a âncora.
        # O que passa daqui é substituição conferida linha a linha; o que não
        # passa não vira patch nenhum, em vez de virar um patch que quebra o
        # arquivo de quem clicar em "Apply suggestion".
        try:
            substituicao = verificar(
                start_line=int(patch_data.get("start_line") or 0),
                end_line=int(patch_data.get("end_line") or 0),
                original=_linhas(patch_data.get("original")),
                replacement=_linhas(patch_data.get("replacement")),
                linhas_do_arquivo=linhas_do_arquivo,
                file_path=file_path,
            )
        except (PatchInvalido, TypeError, ValueError) as exc:
            logger.info(
                "suggest_patch_recusado",
                finding_id=str(finding_id),
                motivo=str(exc)[:120],
                explanation=explanation[:80],
            )
            return SuggestPatchResult(
                remediation_id=None,
                posted=False,
                skipped=True,
                reason="patch_invalido",
            )

        if substituicao.reindentado:
            # Vale log: se isto parar de aparecer, o modelo melhorou; se for
            # a regra, o prompt é que não está pegando.
            logger.info(
                "suggest_patch_reindentado",
                finding_id=str(finding_id),
                file_path=file_path,
            )

        # O diff é gerado por nós, a partir do arquivo real — é só exibição,
        # para o card do dashboard. O que vai ao GitHub são as linhas cruas.
        patch_diff = substituicao.unified_diff(file_path)

        # ---- Posta inline suggestion ----
        comment_id: int | None = None
        # Arquivo fora do diff do PR: o GitHub recusaria com 422. A remediação
        # vale mesmo assim — vai para o dashboard, como no scan manual. Antes
        # ela era descartada junto com a falha do post, e o trabalho do Claude
        # ia embora com ela.
        fora_do_diff = cmd.pr_number is not None and not self._no_diff(
            github, cmd.repo_full_name, cmd.pr_number, file_path
        )
        if cmd.pr_number is None or fora_do_diff:
            # Scan manual (de branch): não há PR onde comentar. A remediação
            # é persistida mesmo assim — o dashboard é a superfície que resta,
            # e sem isso o caminho manual não produziria patch nenhum.
            logger.info(
                "suggest_patch_fora_do_diff" if fora_do_diff else "suggest_patch_sem_pr",
                finding_id=str(finding_id),
                file_path=file_path,
                commit_sha=cmd.commit_sha,
            )
        else:
            try:
                comment_id = github.post_inline_suggestion(
                    repo_full_name=cmd.repo_full_name,
                    pr_number=cmd.pr_number,
                    commit_sha=cmd.commit_sha,
                    file_path=file_path,
                    start_line=substituicao.start_line,
                    line=substituicao.end_line,
                    suggestion_body=substituicao.suggestion_body(),
                    explanation=explanation,
                )
            except Exception as exc:  # noqa: BLE001
                # Não persiste: sem linha, o próximo scan do mesmo commit
                # tenta postar de novo. Gravar aqui faria a idempotência por
                # finding engolir a retentativa e o PR ficaria sem a sugestão.
                logger.warning(
                    "suggest_patch_post_failed",
                    finding_id=str(finding_id),
                    error=str(exc),
                )
                return SuggestPatchResult(
                    remediation_id=None,
                    posted=False,
                    skipped=True,
                    reason=f"post_failed:{type(exc).__name__}",
                )

        # ---- Persiste Remediation ----
        remediation = Remediation(
            finding_id=finding_id,
            scan_job_id=cmd.scan_job_id,
            patch_diff=patch_diff,
            explanation=explanation,
            status=RemediationStatus.SUGGESTED,
            requires_secret_rotation=bool(
                patch_data.get("requires_secret_rotation", False)
            ),
            rotation_instructions=patch_data.get("rotation_instructions"),
            github_comment_id=comment_id,
        )
        self.repository.save(remediation)
        logger.info(
            "suggest_patch_posted",
            finding_id=str(finding_id),
            remediation_id=str(remediation.id),
            comment_id=comment_id,
        )
        return SuggestPatchResult(
            remediation_id=remediation.id,
            posted=comment_id is not None,
            skipped=False,
        )

    @staticmethod
    def _no_diff(
        github: GitHubClient, repo_full_name: str, pr_number: int, file_path: str
    ) -> bool:
        """O arquivo está entre os tocados pelo PR?

        Na dúvida (a chamada falhou), responde que sim: tentar postar e levar
        422 é melhor do que deixar de comentar um arquivo que estava no diff.
        """
        try:
            return file_path in github.list_pr_files(repo_full_name, pr_number)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "pr_files_fetch_failed", pr_number=pr_number, error=str(exc)
            )
            return True

    def _fetch_file_lines(
        self,
        github: GitHubClient,
        repo_full_name: str,
        file_path: str,
        commit_sha: str,
    ) -> list[str] | None:
        """O arquivo inteiro, em linhas. ``None`` quando não deu para buscar.

        Deixou de ser best-effort. Antes o contexto era só para enriquecer o
        prompt, e seguir sem ele custava qualidade; agora é também o que
        confere o que o modelo devolveu. Sem o arquivo não há verificação, e
        sem verificação não se posta.
        """
        try:
            content = github.get_file_content(
                repo_full_name=repo_full_name,
                path=file_path,
                ref=commit_sha,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "code_context_fetch_failed",
                file_path=file_path,
                error=str(exc),
            )
            return None
        linhas = content.splitlines()
        return linhas or None


def _linhas(valor: object) -> list[str]:
    """Normaliza ``original``/``replacement`` do JSON do modelo.

    O schema pede lista de strings, e é o que costuma vir — mas o modelo às
    vezes manda o bloco inteiro numa string só. Aceitar as duas formas aqui é
    mais barato do que recusar um patch bom por causa do invólucro.
    """
    if valor is None:
        return []
    if isinstance(valor, str):
        return valor.split("\n")
    if isinstance(valor, list):
        return [str(item) for item in valor]
    raise TypeError(f"esperava lista de linhas, veio {type(valor).__name__}")


def _anotar(linhas: list[str], line_number: int) -> str:
    """Trecho ao redor da linha afetada, numerado, com ``>>>`` no alvo.

    O SYSTEM do prompt descreve este formato e avisa que tudo depois de
    ``NNNN: `` é conteúdo literal — inclusive os espaços de indentação. As duas
    coisas precisam continuar combinando: foi a indentação atravessando esse
    prefixo que o modelo vinha perdendo.
    """
    if not linhas:
        return ""
    inicio = max(0, line_number - 1 - _CODE_CONTEXT_RADIUS)
    fim = min(len(linhas), line_number + _CODE_CONTEXT_RADIUS)
    trecho = linhas[inicio:fim]
    alvo = (line_number - 1) - inicio
    return "\n".join(
        f"{'>>> ' if i == alvo else '    '}{inicio + i + 1:4d}: {linha}"
        for i, linha in enumerate(trecho)
    )
