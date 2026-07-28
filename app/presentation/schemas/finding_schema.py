from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class FindingSeverity(str, Enum):
    """Espelha o enum `Severity` do dominio para uso na camada de apresentacao."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingResponse(BaseModel):
    """Representacao publica de um finding para listagem (sem `raw_output`)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source: str
    severity: FindingSeverity
    tier: int
    title: str
    description: str
    cve_id: str | None
    cwe_id: str | None
    file_path: str | None
    line_number: int | None
    asset: str | None
    asset_criticality: str | None
    secret_verified: bool
    secret_type: str | None
    commit_sha: str
    repo_url: str
    created_at: datetime

    @classmethod
    def from_entity(cls, finding) -> "FindingResponse":
        """Constroi a resposta a partir de uma entidade `Finding` do dominio."""
        return cls(
            id=finding.id,
            source=finding.source,
            severity=finding.severity.value,
            tier=finding.tier,
            title=finding.title,
            description=finding.description,
            cve_id=str(finding.cve_id) if finding.cve_id else None,
            cwe_id=finding.cwe_id,
            file_path=finding.file_path,
            line_number=finding.line_number,
            asset=finding.asset,
            asset_criticality=finding.asset_criticality,
            secret_verified=finding.secret_verified,
            secret_type=finding.secret_type,
            commit_sha=finding.commit_sha,
            repo_url=finding.repo_url,
            created_at=finding.created_at,
        )


class FindingDetail(FindingResponse):
    """Representacao detalhada de um finding, incluindo `raw_output` do scanner."""

    raw_output: dict

    @classmethod
    def from_entity(cls, finding) -> "FindingDetail":
        """Constroi o detalhe a partir de uma entidade `Finding` do dominio."""
        return cls(
            id=finding.id,
            source=finding.source,
            severity=finding.severity.value,
            tier=finding.tier,
            title=finding.title,
            description=finding.description,
            cve_id=str(finding.cve_id) if finding.cve_id else None,
            cwe_id=finding.cwe_id,
            file_path=finding.file_path,
            line_number=finding.line_number,
            asset=finding.asset,
            asset_criticality=finding.asset_criticality,
            secret_verified=finding.secret_verified,
            secret_type=finding.secret_type,
            commit_sha=finding.commit_sha,
            repo_url=finding.repo_url,
            created_at=finding.created_at,
            raw_output=finding.raw_output,
        )


class FindingPage(BaseModel):
    """Pagina de resultados para listagem de findings."""

    items: list[FindingResponse]
    total: int
    limit: int
    offset: int
