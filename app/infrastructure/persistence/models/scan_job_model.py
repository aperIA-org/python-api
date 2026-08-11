from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    Uuid,
    text,
)

from app.domain.scan.entities import ScanJob
from app.domain.scan.value_objects import ScanTier, TierStatus
from app.infrastructure.persistence.models.base import Base


# Versão SQL de ``STATUS_EM_ANDAMENTO`` (app/domain/scan/entities.py). As duas
# precisam andar juntas: é este predicado que define o que é uma execução "viva"
# para o índice unique parcial abaixo.
EM_ANDAMENTO_SQL = (
    "tier1_status IN ('queued', 'running')"
    " OR tier2_status IN ('queued', 'running')"
    " OR tier3_status IN ('queued', 'running')"
)


class ScanJobModel(Base):
    """Uma linha = uma EXECUÇÃO de scan, não um commit.

    Havia um ``UNIQUE(commit_sha)`` aqui, criado para tornar o disparo
    idempotente (dois webhooks do mesmo push não podem gerar dois pipelines).
    O efeito colateral era que rescanear a mesma branch reaproveitava a linha e
    destruía o resultado anterior — não existia histórico.

    A idempotência agora é expressa pelo que ela de fato significa: **no máximo
    uma execução em andamento por commit**. Execuções encerradas não conflitam,
    e é isso que permite empilhar o histórico.
    """

    __tablename__ = "scan_jobs"

    __table_args__ = (
        Index(
            "uq_scan_jobs_commit_em_andamento",
            "commit_sha",
            unique=True,
            postgresql_where=text(EM_ANDAMENTO_SQL),
            sqlite_where=text(EM_ANDAMENTO_SQL),
        ),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True)
    commit_sha = Column(String(40), nullable=False)
    repo_url = Column(Text, nullable=False)
    pr_number = Column(Integer)
    repo_full_name = Column(Text)
    installation_id = Column(BigInteger, nullable=False)
    tier1_status = Column(String(20))
    tier1_started_at = Column(DateTime)
    tier1_completed_at = Column(DateTime)
    tier2_status = Column(String(20))
    tier2_started_at = Column(DateTime)
    tier2_completed_at = Column(DateTime)
    tier3_status = Column(String(20))
    tier3_started_at = Column(DateTime)
    tier3_completed_at = Column(DateTime)
    blocked_at_tier = Column(SmallInteger)
    final_risk_score = Column(Integer)
    final_risk_level = Column(String(20))
    # Multi-tenant: dono e repositório conectado (nullable p/ scans legados).
    user_id = Column(Uuid(as_uuid=True))
    repository_id = Column(Uuid(as_uuid=True))
    created_at = Column(DateTime, nullable=False)

    @classmethod
    def from_entity(cls, job: ScanJob) -> "ScanJobModel":
        return cls(
            id=job.id,
            commit_sha=job.commit_sha,
            repo_url=job.repo_url,
            pr_number=job.pr_number,
            repo_full_name=job.repo_full_name,
            installation_id=job.installation_id,
            tier1_status=job.tier1_status.value if job.tier1_status else None,
            tier1_started_at=job.tier1_started_at,
            tier1_completed_at=job.tier1_completed_at,
            tier2_status=job.tier2_status.value if job.tier2_status else None,
            tier2_started_at=job.tier2_started_at,
            tier2_completed_at=job.tier2_completed_at,
            tier3_status=job.tier3_status.value if job.tier3_status else None,
            tier3_started_at=job.tier3_started_at,
            tier3_completed_at=job.tier3_completed_at,
            blocked_at_tier=job.blocked_at_tier.value if job.blocked_at_tier else None,
            final_risk_score=job.final_risk_score,
            final_risk_level=job.final_risk_level,
            user_id=job.user_id,
            repository_id=job.repository_id,
            created_at=job.created_at,
        )

    def to_entity(self) -> ScanJob:
        return ScanJob(
            id=self.id,
            commit_sha=self.commit_sha,
            repo_url=self.repo_url,
            pr_number=self.pr_number,
            repo_full_name=self.repo_full_name,
            installation_id=self.installation_id,
            tier1_status=TierStatus(self.tier1_status) if self.tier1_status else None,
            tier1_started_at=self.tier1_started_at,
            tier1_completed_at=self.tier1_completed_at,
            tier2_status=TierStatus(self.tier2_status) if self.tier2_status else None,
            tier2_started_at=self.tier2_started_at,
            tier2_completed_at=self.tier2_completed_at,
            tier3_status=TierStatus(self.tier3_status) if self.tier3_status else None,
            tier3_started_at=self.tier3_started_at,
            tier3_completed_at=self.tier3_completed_at,
            blocked_at_tier=ScanTier(self.blocked_at_tier)
            if self.blocked_at_tier
            else None,
            final_risk_score=self.final_risk_score,
            final_risk_level=self.final_risk_level,
            user_id=self.user_id,
            repository_id=self.repository_id,
            created_at=self.created_at,
        )
