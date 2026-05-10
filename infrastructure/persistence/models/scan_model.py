from sqlalchemy import Column, String, Integer, DateTime
from sqlalchemy.dialects.postgresql import UUID as PGUUID

from infrastructure.persistence.models.base import Base
from domain.scan.entities import ScanJob, ScanStatus


class ScanJobModel(Base):
    __tablename__ = "scan_jobs"

    id               = Column(PGUUID(as_uuid=True), primary_key=True)
    commit_sha       = Column(String(40), nullable=False, index=True)
    repo_url         = Column(String, nullable=False)
    pr_number        = Column(Integer)
    installation_id  = Column(Integer)
    status           = Column(String(20), nullable=False, index=True)
    error_message    = Column(String)
    findings_count   = Column(Integer)
    risk_score       = Column(Integer)
    created_at       = Column(DateTime, nullable=False)
    started_at       = Column(DateTime)
    completed_at     = Column(DateTime)

    @classmethod
    def from_entity(cls, s: ScanJob) -> "ScanJobModel":
        return cls(
            id=s.id,
            commit_sha=s.commit_sha,
            repo_url=s.repo_url,
            pr_number=s.pr_number,
            installation_id=s.installation_id,
            status=s.status.value,
            error_message=s.error_message,
            findings_count=s.findings_count,
            risk_score=s.risk_score,
            created_at=s.created_at,
            started_at=s.started_at,
            completed_at=s.completed_at,
        )

    def to_entity(self) -> ScanJob:
        return ScanJob(
            id=self.id,
            commit_sha=self.commit_sha,
            repo_url=self.repo_url,
            pr_number=self.pr_number,
            installation_id=self.installation_id,
            status=ScanStatus(self.status),
            error_message=self.error_message,
            findings_count=self.findings_count,
            risk_score=self.risk_score,
            created_at=self.created_at,
            started_at=self.started_at,
            completed_at=self.completed_at,
        )
