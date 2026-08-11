from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
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
    """Um relatório pertence a uma EXECUÇÃO, não a um commit.

    A chave era ``(commit_sha, tier)``, então rescanear a mesma branch fazia o
    upsert sobrescrever o markdown anterior — o relatório antigo desaparecia.
    Agora a chave é ``(scan_job_id, tier)``: cada execução guarda o seu.

    ``commit_sha`` continua na tabela como atalho de leitura/diagnóstico, mas
    não identifica mais nada sozinho.
    """

    __tablename__ = "scan_reports"

    __table_args__ = (
        UniqueConstraint("scan_job_id", "tier", name="scan_reports_job_tier_key"),
        Index("idx_scan_reports_commit_sha", "commit_sha"),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True)
    scan_job_id = Column(
        Uuid(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
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
