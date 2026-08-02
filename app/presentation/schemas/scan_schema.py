"""
Schemas Pydantic (leitura) para status de scans (`ScanJob`).

Separados das entidades de dominio conforme Clean Architecture: aqui vivem
apenas os DTOs expostos pela API, com os metodos `from_entity` responsaveis
por converter enums de dominio (`TierStatus`, `ScanTier`) em valores
primitivos (`str`/`int`) prontos para serializacao JSON.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class FindingsSummary(BaseModel):
    """Agregado de findings de um scan: por severidade, por tier e total."""

    by_severity: dict[str, int]
    by_tier: dict[str, int]
    total: int


class ScanJobResponse(BaseModel):
    """Representacao completa do status de um `ScanJob`, com resumo de findings."""

    # Identidade da EXECUÇÃO. O mesmo commit pode ter várias (rescan da mesma
    # branch), então `commit_sha` deixou de identificar um scan sozinho.
    id: UUID
    commit_sha: str
    repo_url: str
    repo_full_name: str | None
    pr_number: int | None
    tier1_status: str | None
    tier1_started_at: datetime | None
    tier1_completed_at: datetime | None
    tier2_status: str | None
    tier2_started_at: datetime | None
    tier2_completed_at: datetime | None
    tier3_status: str | None
    tier3_started_at: datetime | None
    tier3_completed_at: datetime | None
    blocked_at_tier: int | None
    final_risk_score: int | None
    final_risk_level: str | None
    created_at: datetime
    findings_summary: FindingsSummary

    @classmethod
    def from_entity(cls, job, summary: FindingsSummary) -> "ScanJobResponse":
        """Constroi o response a partir da entidade `ScanJob`, convertendo enums em valores."""
        return cls(
            id=job.id,
            commit_sha=job.commit_sha,
            repo_url=job.repo_url,
            repo_full_name=job.repo_full_name,
            pr_number=job.pr_number,
            tier1_status=job.tier1_status.value if job.tier1_status else None,
            tier1_started_at=job.tier1_started_at,
            tier1_completed_at=job.tier1_completed_at,
            tier2_status=job.tier2_status.value if job.tier2_status else None,
            tier2_started_at=job.tier2_started_at,
            tier2_completed_at=job.tier2_completed_at,
            tier3_status=job.tier3_status.value if job.tier3_status else None,
            tier3_started_at=job.tier3_started_at,
            tier3_completed_at=job.tier3_completed_at,
            blocked_at_tier=job.blocked_at_tier.value if job.blocked_at_tier else None,
            final_risk_score=job.final_risk_score,
            final_risk_level=job.final_risk_level,
            created_at=job.created_at,
            findings_summary=summary,
        )


class ScanJobSummary(BaseModel):
    """Versao enxuta de `ScanJobResponse` (sem resumo de findings), usada em listagens."""

    # Identidade da EXECUÇÃO. O mesmo commit pode ter várias (rescan da mesma
    # branch), então `commit_sha` deixou de identificar um scan sozinho.
    id: UUID
    commit_sha: str
    repo_url: str
    repo_full_name: str | None
    pr_number: int | None
    tier1_status: str | None
    tier1_started_at: datetime | None
    tier1_completed_at: datetime | None
    tier2_status: str | None
    tier2_started_at: datetime | None
    tier2_completed_at: datetime | None
    tier3_status: str | None
    tier3_started_at: datetime | None
    tier3_completed_at: datetime | None
    blocked_at_tier: int | None
    final_risk_score: int | None
    final_risk_level: str | None
    created_at: datetime

    @classmethod
    def from_entity(cls, job) -> "ScanJobSummary":
        """Constroi o resumo a partir da entidade `ScanJob`, convertendo enums em valores."""
        return cls(
            id=job.id,
            commit_sha=job.commit_sha,
            repo_url=job.repo_url,
            repo_full_name=job.repo_full_name,
            pr_number=job.pr_number,
            tier1_status=job.tier1_status.value if job.tier1_status else None,
            tier1_started_at=job.tier1_started_at,
            tier1_completed_at=job.tier1_completed_at,
            tier2_status=job.tier2_status.value if job.tier2_status else None,
            tier2_started_at=job.tier2_started_at,
            tier2_completed_at=job.tier2_completed_at,
            tier3_status=job.tier3_status.value if job.tier3_status else None,
            tier3_started_at=job.tier3_started_at,
            tier3_completed_at=job.tier3_completed_at,
            blocked_at_tier=job.blocked_at_tier.value if job.blocked_at_tier else None,
            final_risk_score=job.final_risk_score,
            final_risk_level=job.final_risk_level,
            created_at=job.created_at,
        )


class ScanJobPage(BaseModel):
    """Pagina de resultados da listagem de scans recentes."""

    items: list[ScanJobSummary]
    total: int
    limit: int
    offset: int


class ScanReportResponse(BaseModel):
    """Representacao de um `ScanReport` (relatorio markdown de um tier).

    Carrega `scan_id`/`commit_sha` porque a listagem por repositorio mistura
    execucoes: sem eles, dois relatorios de tier 2 do mesmo commit sao
    indistinguiveis.
    """

    scan_id: UUID
    commit_sha: str
    tier: int
    report_markdown: str
    analysis_json: dict
    degraded: bool
    comment_id: int | None
    posted: bool
    created_at: datetime

    @classmethod
    def from_entity(cls, report) -> "ScanReportResponse":
        """Constroi o response a partir da entidade `ScanReport`."""
        return cls(
            scan_id=report.scan_job_id,
            commit_sha=report.commit_sha,
            tier=report.tier,
            report_markdown=report.report_markdown,
            analysis_json=report.analysis_json,
            degraded=report.degraded,
            comment_id=report.comment_id,
            posted=report.posted,
            created_at=report.created_at,
        )


class ScanReportsResponse(BaseModel):
    """Lista de relatorios (um por tier) de UMA execucao."""

    scan_id: UUID
    commit_sha: str
    reports: list[ScanReportResponse]


class ManualScanResponse(BaseModel):
    """Aceite de um scan manual (`POST /repositories/{id}/scan`).

    No espirito da resposta do webhook (`{"status": "queued", "commit_sha": ...}`),
    acrescentando o `branch` cujo HEAD foi resolvido.
    """

    status: str
    commit_sha: str
    branch: str
