from dataclasses import dataclass, field
from uuid import UUID, uuid4
from datetime import datetime

from app.domain.scan.value_objects import ScanTier, TierStatus


@dataclass
class ScanJob:
    commit_sha: str
    repo_url: str
    installation_id: int
    id: UUID = field(default_factory=uuid4)
    pr_number: int | None = None
    repo_full_name: str | None = None
    tier1_status: TierStatus | None = None
    tier1_started_at: datetime | None = None
    tier1_completed_at: datetime | None = None
    tier2_status: TierStatus | None = None
    tier2_started_at: datetime | None = None
    tier2_completed_at: datetime | None = None
    tier3_status: TierStatus | None = None
    tier3_started_at: datetime | None = None
    tier3_completed_at: datetime | None = None
    blocked_at_tier: ScanTier | None = None
    final_risk_score: int | None = None
    final_risk_level: str | None = None
    # Multi-tenant: dono do scan (desnormalizado para filtro rápido) e
    # repositório conectado que o originou. Nullable p/ scans legados.
    user_id: UUID | None = None
    repository_id: UUID | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)
