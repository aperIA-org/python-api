from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4


@dataclass
class ScanReport:
    """Relatório markdown gerado pelo pipeline para um tier de uma EXECUÇÃO.

    ``scan_job_id`` é obrigatório de propósito: a coluna é NOT NULL desde que o
    relatório passou a pertencer à execução, e um default ``None`` deixava o
    erro aparecer só no flush, longe de quem esqueceu de preencher.
    """

    commit_sha: str
    tier: int
    report_markdown: str
    scan_job_id: UUID
    id: UUID = field(default_factory=uuid4)
    analysis_json: dict = field(default_factory=dict)
    degraded: bool = False
    comment_id: int | None = None
    posted: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)
