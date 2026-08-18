from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    UniqueConstraint,
    Uuid,
)

from app.domain.scan.tool_run_entities import ScanToolRun
from app.domain.scan.value_objects import ToolStatus
from app.infrastructure.persistence.models.base import Base


class ScanToolRunModel(Base):
    """Uma linha por ferramenta por EXECUÇÃO.

    A chave é ``(scan_job_id, tool)`` — nunca ``commit_sha`` —, pelo mesmo
    motivo de ``scan_reports``: rescanear a mesma branch empilha uma execução
    nova, e chavear pelo sha faria o upsert apagar o resultado anterior.

    ``status`` é gravado como texto (o ``value`` do ``ToolStatus``) e não como
    ENUM do Postgres: acrescentar um valor a um ENUM exige migration com
    ``ALTER TYPE``, e este conjunto ainda deve crescer conforme o pipeline ganha
    etapas. O mesmo já vale para ``scan_jobs.tier*_status``.
    """

    __tablename__ = "scan_tool_runs"

    __table_args__ = (
        UniqueConstraint("scan_job_id", "tool", name="scan_tool_runs_job_tool_key"),
        Index("idx_scan_tool_runs_commit_sha", "commit_sha"),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True)
    scan_job_id = Column(
        Uuid(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    commit_sha = Column(String(40), nullable=False)
    tier = Column(SmallInteger, nullable=False)
    tool = Column(String(40), nullable=False)
    status = Column(String(16), nullable=False)
    reason = Column(String(200))
    # NULL onde a ferramenta não produz finding (I.A, threat intel, Caldera) —
    # diferente de 0, que é "rodou e não achou nada".
    findings_count = Column(Integer)
    duration_ms = Column(Integer)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False)

    @classmethod
    def from_entity(cls, r: ScanToolRun) -> "ScanToolRunModel":
        return cls(
            id=r.id,
            scan_job_id=r.scan_job_id,
            commit_sha=r.commit_sha,
            tier=r.tier,
            tool=r.tool,
            status=r.status.value,
            reason=r.reason,
            findings_count=r.findings_count,
            duration_ms=r.duration_ms,
            started_at=r.started_at,
            completed_at=r.completed_at,
            created_at=r.created_at,
        )

    def to_entity(self) -> ScanToolRun:
        return ScanToolRun(
            id=self.id,
            scan_job_id=self.scan_job_id,
            commit_sha=self.commit_sha,
            tier=self.tier,
            tool=self.tool,
            status=ToolStatus(self.status),
            reason=self.reason,
            findings_count=self.findings_count,
            duration_ms=self.duration_ms,
            started_at=self.started_at,
            completed_at=self.completed_at,
            created_at=self.created_at,
        )
