from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID


@dataclass
class DomainEvent:
    occurred_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class VerifiedSecretDetected(DomainEvent):
    finding_id: UUID | None = None
    commit_sha: str = ""
    secret_type: str = ""
    repo_url: str = ""


@dataclass
class AttackPathCreated(DomainEvent):
    chain_id: UUID | None = None
    risk_score: int = 0
    risk_level: str = ""
    commit_sha: str = ""
