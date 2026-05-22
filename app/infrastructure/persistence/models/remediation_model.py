from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    String,
    Text,
    Uuid,
)

from app.domain.remediation.entities import Remediation, RemediationStatus
from app.infrastructure.persistence.models.base import Base


class RemediationModel(Base):
    __tablename__ = "remediations"

    id = Column(Uuid(as_uuid=True), primary_key=True)
    finding_id = Column(
        Uuid(as_uuid=True), ForeignKey("findings.id"), nullable=False
    )
    scan_job_id = Column(
        Uuid(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False
    )
    patch_diff = Column(Text, nullable=False)
    explanation = Column(Text)
    requires_secret_rotation = Column(Boolean, default=False, nullable=False)
    rotation_instructions = Column(Text)
    github_comment_id = Column(BigInteger)
    status = Column(String(20), nullable=False)
    approved_by = Column(String(100))
    approved_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False)

    @classmethod
    def from_entity(cls, r: Remediation) -> "RemediationModel":
        return cls(
            id=r.id,
            finding_id=r.finding_id,
            scan_job_id=r.scan_job_id,
            patch_diff=r.patch_diff,
            explanation=r.explanation,
            requires_secret_rotation=r.requires_secret_rotation,
            rotation_instructions=r.rotation_instructions,
            github_comment_id=r.github_comment_id,
            status=r.status.value,
            approved_by=r.approved_by,
            approved_at=r.approved_at,
            created_at=r.created_at,
        )

    def to_entity(self) -> Remediation:
        return Remediation(
            id=self.id,
            finding_id=self.finding_id,
            scan_job_id=self.scan_job_id,
            patch_diff=self.patch_diff,
            explanation=self.explanation or "",
            requires_secret_rotation=self.requires_secret_rotation,
            rotation_instructions=self.rotation_instructions,
            github_comment_id=self.github_comment_id,
            status=RemediationStatus(self.status),
            approved_by=self.approved_by,
            approved_at=self.approved_at,
            created_at=self.created_at,
        )
