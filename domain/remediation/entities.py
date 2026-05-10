from dataclasses import dataclass, field
from uuid import UUID, uuid4
from datetime import datetime

from domain.remediation.value_objects import PatchContent, RemediationDecision


class RemediationStatus:
    PENDING = "pending"
    SUGGESTION_POSTED = "suggestion_posted"
    APPROVED = "approved"
    REJECTED = "rejected"
    MERGED = "merged"


@dataclass
class PatchDiff:
    """Diff gerado pelo Claude para um finding específico."""
    finding_id: UUID
    patch_content: PatchContent
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Remediation:
    """
    Remediação para um ScanJob.
    REGRA INVIOLÁVEL: patches só são entregues como code suggestions — nunca auto-applied.
    """
    scan_job_id: UUID
    commit_sha: str
    repo_url: str
    pr_number: int
    id: UUID = field(default_factory=uuid4)
    patches: list[PatchDiff] = field(default_factory=list)
    status: str = RemediationStatus.PENDING
    github_suggestion_ids: list[int] = field(default_factory=list)
    decision: RemediationDecision = RemediationDecision.PENDING
    decision_by: str | None = None
    decision_at: datetime | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    def mark_suggestion_posted(self, suggestion_ids: list[int]) -> None:
        self.status = RemediationStatus.SUGGESTION_POSTED
        self.github_suggestion_ids = suggestion_ids

    def approve(self, reviewer: str) -> None:
        self.decision = RemediationDecision.APPROVED
        self.decision_by = reviewer
        self.decision_at = datetime.utcnow()
        self.status = RemediationStatus.APPROVED

    def reject(self, reviewer: str) -> None:
        self.decision = RemediationDecision.REJECTED
        self.decision_by = reviewer
        self.decision_at = datetime.utcnow()
        self.status = RemediationStatus.REJECTED
