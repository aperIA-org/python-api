from enum import Enum
from dataclasses import dataclass, field
import re


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.INFO


@dataclass(frozen=True)
class CVEId:
    value: str

    def __post_init__(self) -> None:
        if not re.match(r"CVE-\d{4}-\d+", self.value):
            raise ValueError(f"CVE ID inválido: {self.value}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class CommitSha:
    value: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{40}", self.value):
            raise ValueError(f"Commit SHA inválido: {self.value}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class BusinessImpact:
    description: str
    estimated_cost_brl: float | None = None
    compliance_violations: list[str] = field(default_factory=list)
