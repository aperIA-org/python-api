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
    pr_number: int | None = None


@dataclass
class AttackPathCreated(DomainEvent):
    attack_path_id: UUID | None = None
    risk_score: int = 0
    risk_level: str = ""
    commit_sha: str = ""
    repo_url: str = ""


@dataclass
class ScanCompleted(DomainEvent):
    scan_job_id: UUID | None = None
    commit_sha: str = ""
    repo_url: str = ""
    findings_count: int = 0
    risk_score: int = 0


@dataclass
class RemediationPosted(DomainEvent):
    remediation_id: UUID | None = None
    scan_job_id: UUID | None = None
    pr_number: int = 0
    patches_count: int = 0
    repo_url: str = ""
