from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.domain.remediation.entities import RemediationComContexto


class RemediationStatusSchema(str, Enum):
    """Espelha o enum `RemediationStatus` do dominio na camada de apresentacao."""

    SUGGESTED = "suggested"
    APPROVED = "approved"
    REJECTED = "rejected"
    MERGED = "merged"


class RemediationResponse(BaseModel):
    """Uma remediacao com o contexto que a tela mostra ao redor dela.

    Os campos `finding_*` e os do scan nao estao na tabela `remediations`:
    saem do mesmo join que prova a posse. Vao juntos porque o card do
    dashboard precisa deles, e a alternativa seria a tela varrer o conjunto
    inteiro de findings do usuario para resolver algumas dezenas de patches.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    finding_id: UUID
    scan_job_id: UUID
    status: RemediationStatusSchema
    explanation: str
    patch_diff: str
    requires_secret_rotation: bool
    rotation_instructions: str | None
    github_comment_id: int | None
    approved_by: str | None
    approved_at: datetime | None
    created_at: datetime

    # ---- contexto (join com findings e scan_jobs) ----
    finding_title: str | None
    finding_severity: str | None
    finding_file_path: str | None
    finding_repo_url: str | None
    repo_full_name: str | None
    pr_number: int | None
    commit_sha: str | None

    @classmethod
    def from_contexto(cls, ctx: RemediationComContexto) -> "RemediationResponse":
        r = ctx.remediation
        return cls(
            id=r.id,
            finding_id=r.finding_id,
            scan_job_id=r.scan_job_id,
            status=r.status.value,
            explanation=r.explanation,
            patch_diff=r.patch_diff,
            requires_secret_rotation=r.requires_secret_rotation,
            rotation_instructions=r.rotation_instructions,
            github_comment_id=r.github_comment_id,
            approved_by=r.approved_by,
            approved_at=r.approved_at,
            created_at=r.created_at,
            finding_title=ctx.finding_title,
            finding_severity=ctx.finding_severity,
            finding_file_path=ctx.finding_file_path,
            finding_repo_url=ctx.finding_repo_url,
            repo_full_name=ctx.repo_full_name,
            pr_number=ctx.pr_number,
            commit_sha=ctx.commit_sha,
        )


class RemediationPage(BaseModel):
    """Pagina de resultados para listagem de remediacoes."""

    items: list[RemediationResponse]
    total: int
    limit: int
    offset: int
