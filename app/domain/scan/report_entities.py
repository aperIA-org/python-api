from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4


@dataclass
class ScanReport:
    """Relatório markdown gerado pelo pipeline para um commit/tier específico."""

    commit_sha: str
    tier: int
    report_markdown: str
    id: UUID = field(default_factory=uuid4)
    scan_job_id: UUID | None = None
    analysis_json: dict = field(default_factory=dict)
    degraded: bool = False
    comment_id: int | None = None
    posted: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)
