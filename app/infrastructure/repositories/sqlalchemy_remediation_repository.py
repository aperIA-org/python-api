"""Implementação SQLAlchemy do RemediationRepository.

Síncrono, como todo o acesso a dados desta aplicação: os workers Celery e as
rotas FastAPI operam sobre ``Session``, e o engine async foi removido. Este
arquivo era o último resquício de ``AsyncSession`` no ``app/``.

Por que não há ``bulk_save`` aqui: remediações são geradas uma a
uma pela Claude — não há cenário de inserção em massa. Cada
``save`` adiciona e faz flush; commit fica a cargo do orquestrador.

Não há como mudar o status de uma remediação, e isso é deliberado. Havia um
``update_status``, usado pelo ``PATCH /remediations/{id}/status`` do
dashboard; os dois saíram quando a aprovação voltou a ser exclusiva do
GitHub. Uma remediação nasce ``suggested`` e assim permanece — quem decide é
o "Apply suggestion", e o pipeline não fica sabendo.

**Posse vem do join, não da tabela.** ``remediations`` não tem ``user_id``:
quem é dono de uma remediação é o dono do ``scan_job`` que a gerou. Por isso
``query``/``count`` sempre juntam ``scan_jobs`` e filtram por
``scan_jobs.user_id`` — é a mesma regra que ``finding_routes`` aplica aos
findings. O join com ``findings`` vem junto e de graça, e é o que dá contexto
ao card do dashboard sem uma segunda rodada de consultas.
"""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.domain.remediation.entities import (
    Remediation,
    RemediationComContexto,
    RemediationStatus,
)
from app.domain.remediation.repositories import RemediationRepository
from app.infrastructure.persistence.models.finding_model import FindingModel
from app.infrastructure.persistence.models.remediation_model import (
    RemediationModel,
)
from app.infrastructure.persistence.models.scan_job_model import ScanJobModel


class SQLAlchemyRemediationRepository(RemediationRepository):
    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, remediation: Remediation) -> None:
        self.db.add(RemediationModel.from_entity(remediation))
        self.db.flush()

    def get_by_scan_job(self, scan_job_id: UUID) -> list[Remediation]:
        result = self.db.execute(
            select(RemediationModel).where(
                RemediationModel.scan_job_id == scan_job_id
            )
        )
        return [m.to_entity() for m in result.scalars().all()]

    def get_by_id(self, remediation_id: UUID) -> Remediation | None:
        model = self.db.get(RemediationModel, remediation_id)
        return model.to_entity() if model else None

    def query(
        self,
        *,
        user_id: UUID,
        remediation_id: UUID | None = None,
        scan_job_id: UUID | None = None,
        status: RemediationStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[RemediationComContexto]:
        stmt = (
            select(
                RemediationModel,
                FindingModel.title,
                FindingModel.severity,
                FindingModel.file_path,
                FindingModel.repo_url,
                ScanJobModel.repo_full_name,
                ScanJobModel.pr_number,
                ScanJobModel.commit_sha,
            )
            # O join com findings é LEFT: o finding é FK NOT NULL, mas um
            # outer join garante que a remediação continue aparecendo mesmo se
            # a linha de origem sumir por manutenção de dados. Perder o
            # contexto é aceitável; sumir com o patch, não.
            .outerjoin(FindingModel, FindingModel.id == RemediationModel.finding_id)
            .join(ScanJobModel, ScanJobModel.id == RemediationModel.scan_job_id)
            .where(ScanJobModel.user_id == user_id)
            .order_by(RemediationModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        # Buscar UMA remediacao passa por aqui de proposito: o filtro por id
        # herda o join com scan_jobs, entao a posse ja esta provada e o
        # chamador nao precisa refazer a checagem.
        if remediation_id is not None:
            stmt = stmt.where(RemediationModel.id == remediation_id)
        if scan_job_id is not None:
            stmt = stmt.where(RemediationModel.scan_job_id == scan_job_id)
        if status is not None:
            stmt = stmt.where(RemediationModel.status == status.value)

        return [
            RemediationComContexto(
                remediation=linha[0].to_entity(),
                finding_title=linha[1],
                finding_severity=linha[2],
                finding_file_path=linha[3],
                finding_repo_url=linha[4],
                repo_full_name=linha[5],
                pr_number=linha[6],
                commit_sha=linha[7],
            )
            for linha in self.db.execute(stmt).all()
        ]

    def count(
        self,
        *,
        user_id: UUID,
        scan_job_id: UUID | None = None,
        status: RemediationStatus | None = None,
    ) -> int:
        stmt = (
            select(func.count())
            .select_from(RemediationModel)
            .join(ScanJobModel, ScanJobModel.id == RemediationModel.scan_job_id)
            .where(ScanJobModel.user_id == user_id)
        )
        if scan_job_id is not None:
            stmt = stmt.where(RemediationModel.scan_job_id == scan_job_id)
        if status is not None:
            stmt = stmt.where(RemediationModel.status == status.value)
        return int(self.db.execute(stmt).scalar() or 0)
