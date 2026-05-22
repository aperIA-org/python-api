"""Use case: gera patch via Claude e posta como inline suggestion.

Princípios invioláveis:

1. **Remediação sempre humana**: este use case NUNCA aplica o patch.
   Apenas posta como GitHub code suggestion para o desenvolvedor
   aprovar via "Apply suggestion".
2. **Idempotência por finding**: antes de gerar patch e postar,
   consulta ``RemediationRepository.get_by_scan_job`` e verifica se
   já existe uma Remediation com o mesmo ``finding_id``. Se sim,
   retorna a existente sem fazer nada — re-scans não duplicam
   comentários no PR.
3. **Fault isolation do Claude**: ``CircuitOpenError`` /
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
    pr_number: int
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

    async def execute(self, cmd: SuggestPatchCommand) -> SuggestPatchResult:
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
        existing = await self.repository.get_by_scan_job(cmd.scan_job_id)
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

        # ---- Code context (best effort) ----
        code_context = self._fetch_code_context(
            github=github,
            repo_full_name=cmd.repo_full_name,
            file_path=cmd.finding.get("file_path"),
            line_number=cmd.finding.get("line_number"),
            commit_sha=cmd.commit_sha,
        )

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

        patch_diff = (patch_data.get("patch_diff") or "").strip()
        explanation = (patch_data.get("explanation") or "").strip()
        if not patch_diff:
            logger.info(
                "suggest_patch_empty_diff",
                finding_id=str(finding_id),
                explanation=explanation[:80],
            )
            return SuggestPatchResult(
                remediation_id=None,
                posted=False,
                skipped=True,
                reason="empty_patch_diff",
            )

        # ---- Posta inline suggestion ----
        file_path = cmd.finding.get("file_path")
        line_number = cmd.finding.get("line_number")
        if not file_path or not line_number:
            return SuggestPatchResult(
                remediation_id=None,
                posted=False,
                skipped=True,
                reason="missing_file_or_line",
            )

        try:
            comment_id = github.post_inline_suggestion(
                repo_full_name=cmd.repo_full_name,
                pr_number=cmd.pr_number,
                commit_sha=cmd.commit_sha,
                file_path=file_path,
                line=int(line_number),
                patch_diff=patch_diff,
                explanation=explanation,
            )
        except Exception as exc:  # noqa: BLE001
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
        await self.repository.save(remediation)
        logger.info(
            "suggest_patch_posted",
            finding_id=str(finding_id),
            remediation_id=str(remediation.id),
            comment_id=comment_id,
        )
        return SuggestPatchResult(
            remediation_id=remediation.id,
            posted=True,
            skipped=False,
        )

    def _fetch_code_context(
        self,
        github: GitHubClient,
        repo_full_name: str,
        file_path: str | None,
        line_number: int | None,
        commit_sha: str,
    ) -> str | None:
        if not file_path or not line_number:
            return None
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
        lines = content.splitlines()
        if not lines:
            return None
        # GitHub line_number é 1-based
        start = max(0, line_number - 1 - _CODE_CONTEXT_RADIUS)
        end = min(len(lines), line_number + _CODE_CONTEXT_RADIUS)
        snippet = lines[start:end]
        # Anota a linha exata para o modelo
        anchor_index = (line_number - 1) - start
        annotated: list[str] = []
        for i, line in enumerate(snippet):
            marker = ">>> " if i == anchor_index else "    "
            annotated.append(f"{marker}{start + i + 1:4d}: {line}")
        return "\n".join(annotated)
