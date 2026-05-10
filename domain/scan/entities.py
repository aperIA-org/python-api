from dataclasses import dataclass, field
from uuid import UUID, uuid4
from datetime import datetime
from enum import Enum


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanJob:
    commit_sha: str
    repo_url: str
    id: UUID = field(default_factory=uuid4)
    pr_number: int | None = None
    installation_id: int | None = None
    status: ScanStatus = ScanStatus.PENDING
    error_message: str | None = None
    findings_count: int | None = None
    risk_score: int | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None

    def start(self) -> None:
        if self.status != ScanStatus.PENDING:
            raise ValueError(f"Não é possível iniciar scan com status {self.status}")
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.utcnow()

    def complete(self, findings_count: int, risk_score: int) -> None:
        self.status = ScanStatus.COMPLETED
        self.findings_count = findings_count
        self.risk_score = risk_score
        self.completed_at = datetime.utcnow()

    def fail(self, error: str) -> None:
        self.status = ScanStatus.FAILED
        self.error_message = error
        self.completed_at = datetime.utcnow()

    def cancel(self) -> None:
        self.status = ScanStatus.CANCELLED
        self.completed_at = datetime.utcnow()


@dataclass
class ScanResult:
    scan_job_id: UUID
    tool: str
    raw_output: dict
    findings_count: int = 0
    duration_seconds: float = 0.0
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=datetime.utcnow)
