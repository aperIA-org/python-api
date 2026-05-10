from dataclasses import dataclass, field
from uuid import UUID, uuid4
from datetime import datetime

from domain.finding.value_objects import Severity, CVEId, CWEId


VALID_SOURCES = frozenset({
    "trufflehog", "semgrep", "trivy", "zap", "openvas", "wazuh", "prowler"
})


@dataclass
class Finding:
    source: str
    severity: Severity
    title: str
    description: str
    commit_sha: str
    repo_url: str
    id: UUID = field(default_factory=uuid4)
    cve_id: CVEId | None = None
    cwe_id: CWEId | None = None
    file_path: str | None = None
    line_number: int | None = None
    asset: str | None = None
    asset_criticality: str | None = None
    secret_verified: bool = False
    secret_type: str | None = None
    raw_output: dict = field(default_factory=dict)
    ttp_ids: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def __post_init__(self) -> None:
        if self.source not in VALID_SOURCES:
            raise ValueError(f"Fonte desconhecida: {self.source}")
        if not self.commit_sha or len(self.commit_sha) != 40:
            raise ValueError(f"commit_sha inválido: {self.commit_sha}")

    def is_critical_secret(self) -> bool:
        return self.secret_verified and self.severity == Severity.CRITICAL

    def dedup_key(self) -> str:
        return f"{self.source}:{self.cve_id or self.title}:{self.file_path}:{self.line_number}"


@dataclass
class EventChain:
    """Cadeia de eventos que constrói um attack path."""
    id: UUID = field(default_factory=uuid4)
    commit_sha: str = ""
    repo_url: str = ""
    steps: list[dict] = field(default_factory=list)
    narrative: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AttackPath:
    """Path de ataque derivado de um conjunto de findings correlacionados."""
    id: UUID = field(default_factory=uuid4)
    commit_sha: str = ""
    repo_url: str = ""
    finding_ids: list[UUID] = field(default_factory=list)
    ttp_ids: list[str] = field(default_factory=list)
    event_chain: EventChain | None = None
    risk_score: int = 0
    risk_level: str = "low"
    description: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class RiskScore:
    value: int
    cvss_component: float = 0.0
    cti_component: float = 0.0
    caldera_component: float = 0.0
    business_component: float = 0.0

    def __post_init__(self) -> None:
        if not 0 <= self.value <= 100:
            raise ValueError(f"Risk score fora do range [0, 100]: {self.value}")

    @property
    def level(self) -> str:
        if self.value >= 90:
            return "critical"
        if self.value >= 70:
            return "high"
        if self.value >= 40:
            return "medium"
        return "low"
