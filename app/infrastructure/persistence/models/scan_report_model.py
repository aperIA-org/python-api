from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB

from app.domain.scan.report_entities import ScanReport
from app.infrastructure.persistence.models.base import Base


class ScanReportModel(Base):
    __tablename__ = "scan_reports"

    __table_args__ = (
        UniqueConstraint("commit_sha", "tier", name="scan_reports_commit_tier_key"),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True)
    scan_job_id = Column(Uuid(as_uuid=True))
    commit_sha = Column(String(40), nullable=False)
    tier = Column(SmallInteger, nullable=False)
    report_markdown = Column(Text)
    analysis_json = Column(JSONB().with_variant(JSON(), "sqlite"))
    degraded = Column(Boolean, default=False, nullable=False)
    comment_id = Column(BigInteger)
    posted = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, nullable=False)

    @classmethod
    def from_entity(cls, r: ScanReport) -> "ScanReportModel":
        return cls(
            id=r.id,
            scan_job_id=r.scan_job_id,
            commit_sha=r.commit_sha,
            tier=r.tier,
            report_markdown=r.report_markdown,
            analysis_json=r.analysis_json,
            degraded=r.degraded,
            comment_id=r.comment_id,
            posted=r.posted,
            created_at=r.created_at,
        )

    def to_entity(self) -> ScanReport:
        return ScanReport(
            id=self.id,
            scan_job_id=self.scan_job_id,
            commit_sha=self.commit_sha,
            tier=self.tier,
            report_markdown=self.report_markdown,
            analysis_json=self.analysis_json or {},
            degraded=self.degraded,
            comment_id=self.comment_id,
            posted=self.posted,
            created_at=self.created_at,
        )
