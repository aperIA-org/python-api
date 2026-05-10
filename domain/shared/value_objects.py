from dataclasses import dataclass, field
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
    """
    Contexto de negócio inferido automaticamente do repositório.
    Alimenta o componente Business do RiskScorer e os prompts do Claude.
    """
    asset_name: str
    asset_criticality: AssetCriticality
    team_owner: str
    compliance_scope: tuple[str, ...]

    # Dados sensíveis presentes
    internet_facing: bool = False
    contains_pii: bool = False
    contains_financial_data: bool = False
    contains_health_data: bool = False

    # Tipo e domínio inferidos
    app_type: str = "unknown"
    domain: str = "unknown"
    estimated_users: str = "unknown"

    # Estimativa de impacto financeiro em caso de breach (BRL)
    breach_cost_brl_min: int = 0
    breach_cost_brl_max: int = 0

    # Ativos críticos identificados no código
    key_assets: tuple[str, ...] = ()

    # Confiança da inferência (0.0–1.0): >0.7 = Claude, <0.5 = heurístico puro
    inference_confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "asset_name": self.asset_name,
            "asset_criticality": self.asset_criticality.value,
            "compliance_scope": list(self.compliance_scope),
            "internet_facing": self.internet_facing,
            "contains_pii": self.contains_pii,
            "contains_financial_data": self.contains_financial_data,
            "contains_health_data": self.contains_health_data,
            "app_type": self.app_type,
            "domain": self.domain,
            "estimated_users": self.estimated_users,
            "breach_cost_brl_min": self.breach_cost_brl_min,
            "breach_cost_brl_max": self.breach_cost_brl_max,
            "key_assets": list(self.key_assets),
            "inference_confidence": self.inference_confidence,
        }
