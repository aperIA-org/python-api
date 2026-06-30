from dataclasses import dataclass, field
from uuid import UUID, uuid4
from datetime import datetime
from enum import Enum


class RemediationStatus(str, Enum):
    SUGGESTED = "suggested"
    APPROVED = "approved"
    REJECTED = "rejected"
    MERGED = "merged"


@dataclass
class Remediation:
    finding_id: UUID
    scan_job_id: UUID
    patch_diff: str
    explanation: str
    id: UUID = field(default_factory=uuid4)
    status: RemediationStatus = RemediationStatus.SUGGESTED
    requires_secret_rotation: bool = False
    rotation_instructions: str | None = None
    github_comment_id: int | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)
