from dataclasses import dataclass, field
from uuid import UUID, uuid4
from datetime import datetime
from enum import Enum


class RemediationStatus(str, Enum):
    SUGGESTED = "suggested"
    APPROVED = "approved"
    REJECTED = "rejected"
    MERGED = "merged"


@dataclass
class Remediation:
    finding_id: UUID
    scan_job_id: UUID
    patch_diff: str
    explanation: str
    id: UUID = field(default_factory=uuid4)
    status: RemediationStatus = RemediationStatus.SUGGESTED
    requires_secret_rotation: bool = False
    rotation_instructions: str | None = None
    github_comment_id: int | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass(frozen=True)
class RemediationComContexto:
    """Uma remediação mais o que a tela mostra ao redor dela.

    A ``Remediation`` sozinha é um patch sem origem: o card do dashboard
    precisa do título e da severidade do finding, e do PR onde a sugestão foi
    postada. Esses campos moram em ``findings`` e ``scan_jobs``, e a consulta já
    passa pelas duas tabelas de qualquer jeito — o join com ``scan_jobs`` é o
    que prova a posse, já que ``remediations`` não tem ``user_id``.

    Trazer tudo de uma vez evita a alternativa: a tela buscar o conjunto inteiro
    de findings do usuário só para resolver algumas dezenas de remediações.
    """

    remediation: Remediation
    finding_title: str | None
    finding_severity: str | None
    finding_file_path: str | None
    finding_repo_url: str | None
    repo_full_name: str | None
    pr_number: int | None
    commit_sha: str | None
