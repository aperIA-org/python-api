from dataclasses import dataclass
from enum import Enum


class AssetCriticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ThreatLevel(str, Enum):
    ACTIVE = "active"
    POTENTIAL = "potential"
    HISTORICAL = "historical"
    NONE = "none"


@dataclass(frozen=True)
class BusinessContext:
    asset_name: str
    asset_criticality: AssetCriticality
    team_owner: str
    compliance_scope: tuple[str, ...]
    internet_facing: bool = False
    contains_pii: bool = False
    contains_financial_data: bool = False
