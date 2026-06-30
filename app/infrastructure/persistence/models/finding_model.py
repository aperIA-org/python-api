from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import CVEId, Severity
from app.infrastructure.persistence.models.base import Base


class FindingModel(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("dedup_key", name="findings_dedup_key"),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True)
    source = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    tier = Column(SmallInteger, nullable=False)
    title = Column(Text, nullable=False)
    description = Column(Text)
    cve_id = Column(String(50))
    cwe_id = Column(String(50))
    file_path = Column(Text)
    line_number = Column(Integer)
    asset = Column(Text)
    asset_criticality = Column(String(20))
    secret_verified = Column(Boolean, default=False, nullable=False)
    secret_type = Column(String(100))
    raw_output = Column(JSONB().with_variant(JSON(), "sqlite"))
    commit_sha = Column(String(40), nullable=False)
    repo_url = Column(Text, nullable=False)
    # Coluna que materializa Finding.dedup_key() para uma UNIQUE constraint
    # confiável em qualquer dialeto. UniqueConstraint multi-coluna não funciona
    # quando algum componente (ex: cve_id) é NULL — NULL != NULL em SQL.
    dedup_key = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False)

    @classmethod
    def from_entity(cls, f: Finding) -> "FindingModel":
        return cls(
            id=f.id,
            source=f.source,
            severity=f.severity.value,
            tier=f.tier,
            title=f.title,
            description=f.description,
            cve_id=str(f.cve_id) if f.cve_id else None,
            cwe_id=f.cwe_id,
            file_path=f.file_path,
            line_number=f.line_number,
            asset=f.asset,
            asset_criticality=f.asset_criticality,
            secret_verified=f.secret_verified,
            secret_type=f.secret_type,
            raw_output=f.raw_output,
            commit_sha=f.commit_sha,
            repo_url=f.repo_url,
            dedup_key=f.dedup_key(),
            created_at=f.created_at,
        )

    def to_entity(self) -> Finding:
        return Finding(
            id=self.id,
            source=self.source,
            severity=Severity(self.severity),
            title=self.title,
            description=self.description or "",
            cve_id=CVEId(self.cve_id) if self.cve_id else None,
            cwe_id=self.cwe_id,
            file_path=self.file_path,
            line_number=self.line_number,
            asset=self.asset,
            asset_criticality=self.asset_criticality,
            secret_verified=self.secret_verified,
            secret_type=self.secret_type,
            raw_output=self.raw_output or {},
            tier=self.tier,
            commit_sha=self.commit_sha,
            repo_url=self.repo_url,
            created_at=self.created_at,
        )
