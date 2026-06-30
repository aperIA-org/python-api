from dataclasses import dataclass, field
from uuid import UUID, uuid4
from datetime import datetime

from app.domain.finding.value_objects import Severity, CVEId


@dataclass
class Finding:
    source: str
    severity: Severity
    title: str
    description: str
    commit_sha: str
    repo_url: str
    id: UUID = field(default_factory=uuid4)
    cve_id: CVEId | None = None
    cwe_id: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    asset: str | None = None
    asset_criticality: str | None = None
    secret_verified: bool = False
    secret_type: str | None = None
    raw_output: dict = field(default_factory=dict)
    tier: int = 1
    created_at: datetime = field(default_factory=datetime.utcnow)

    def dedup_key(self) -> str:
        return (
            f"{self.source}:{self.cve_id or self.title}:"
            f"{self.file_path}:{self.line_number}:{self.commit_sha}"
        )

    def is_critical_secret(self) -> bool:
        return self.secret_verified and self.severity == Severity.CRITICAL
