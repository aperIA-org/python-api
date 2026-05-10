from sqlalchemy import Column, String, Boolean, Integer, DateTime, JSON, ARRAY
from sqlalchemy.dialects.postgresql import UUID as PGUUID

from infrastructure.persistence.models.base import Base
from domain.finding.entities import Finding
from domain.finding.value_objects import Severity, CVEId, CWEId


class FindingModel(Base):
    __tablename__ = "findings"

    id              = Column(PGUUID(as_uuid=True), primary_key=True)
    source          = Column(String(50), nullable=False, index=True)
    severity        = Column(String(20), nullable=False, index=True)
    title           = Column(String, nullable=False)
    description     = Column(String)
    cve_id          = Column(String(50), index=True)
    cwe_id          = Column(String(50))
    file_path       = Column(String)
    line_number     = Column(Integer)
    asset           = Column(String)
    asset_criticality = Column(String(20))
    secret_verified = Column(Boolean, default=False, nullable=False, index=True)
    secret_type     = Column(String(100))
    raw_output      = Column(JSON)
    ttp_ids         = Column(ARRAY(String), default=list)
    commit_sha      = Column(String(40), nullable=False, index=True)
    repo_url        = Column(String, nullable=False, index=True)
    created_at      = Column(DateTime, nullable=False)

    @classmethod
    def from_entity(cls, f: Finding) -> "FindingModel":
        return cls(
            id=f.id,
            source=f.source,
            severity=f.severity.value,
            title=f.title,
            description=f.description,
            cve_id=str(f.cve_id) if f.cve_id else None,
            cwe_id=str(f.cwe_id) if f.cwe_id else None,
            file_path=f.file_path,
            line_number=f.line_number,
            asset=f.asset,
            asset_criticality=f.asset_criticality,
            secret_verified=f.secret_verified,
            secret_type=f.secret_type,
            raw_output=f.raw_output,
            ttp_ids=f.ttp_ids,
            commit_sha=f.commit_sha,
            repo_url=f.repo_url,
            created_at=f.created_at,
        )

    def to_entity(self) -> Finding:
        cve = None
        if self.cve_id:
            try:
                cve = CVEId(self.cve_id)
            except ValueError:
                cve = None

        cwe = None
        if self.cwe_id:
            try:
                cwe = CWEId(self.cwe_id)
            except ValueError:
                cwe = None

        return Finding(
            id=self.id,
            source=self.source,
            severity=Severity(self.severity),
            title=self.title,
            description=self.description or "",
            commit_sha=self.commit_sha,
            repo_url=self.repo_url,
            cve_id=cve,
            cwe_id=cwe,
            file_path=self.file_path,
            line_number=self.line_number,
            asset=self.asset,
            asset_criticality=self.asset_criticality,
            secret_verified=self.secret_verified or False,
            secret_type=self.secret_type,
            raw_output=self.raw_output or {},
            ttp_ids=self.ttp_ids or [],
            created_at=self.created_at,
        )
