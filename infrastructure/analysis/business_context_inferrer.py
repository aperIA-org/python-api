"""
BusinessContextInferrer: analisa automaticamente um repositório clonado e infere
o contexto de negócio sem nenhuma configuração manual da empresa.

Fluxo:
  1. extract_repo_signals() — leitura de arquivos, zero execução de código
  2. Claude (call_json) — síntese dos sinais em BusinessContext estruturado
  3. Fallback heurístico — se Claude indisponível ou falhar

O resultado alimenta o _business_component do RiskScorer e os prompts
do HeuristicEngine com contexto de impacto real.
"""
import structlog

from domain.shared.value_objects import AssetCriticality, BusinessContext
from infrastructure.ai.claude_client import ClaudeClient
from infrastructure.ai.prompts import business_context as bc_prompt
from infrastructure.analysis._repo_signals import (
    classify_signals,
    extract_repo_signals,
)

logger = structlog.get_logger()

# Fallback de custo por nível de criticidade (BRL)
_BREACH_COST = {
    AssetCriticality.CRITICAL: (500_000, 5_000_000),
    AssetCriticality.HIGH:     (100_000, 1_000_000),
    AssetCriticality.MEDIUM:   ( 15_000,   200_000),
    AssetCriticality.LOW:      (  5_000,    50_000),
}


class BusinessContextInferrer:
    """
    Infere BusinessContext de um repositório clonado.
    Usa Claude para síntese — fallback para heurística pura se indisponível.
    """

    def __init__(self, claude: ClaudeClient | None = None) -> None:
        self._claude = claude or ClaudeClient()

    def infer(self, repo_path: str, commit_sha: str, repo_name: str = "") -> BusinessContext:
        """
        Extrai sinais e chama Claude para inferência.
        Nunca levanta exceção — fallback para heurístico em caso de falha.
        """
        log = logger.bind(commit_sha=commit_sha, repo_name=repo_name)
        log.info("business_context_inference_start")

        signals = extract_repo_signals(repo_path)

        try:
            raw = self._claude.call_json(
                system=bc_prompt.SYSTEM,
                user_prompt=bc_prompt.build(signals),
                commit_sha=commit_sha,
            )
            ctx = _from_claude_response(raw, repo_name)
            log.info(
                "business_context_inferred_by_claude",
                domain=ctx.domain,
                criticality=ctx.asset_criticality.value,
                confidence=ctx.inference_confidence,
            )
            return ctx
        except Exception as exc:
            log.warning("business_context_claude_failed_fallback", error=str(exc))
            ctx = _heuristic_context(signals, repo_name)
            log.info(
                "business_context_inferred_by_heuristic",
                domain=ctx.domain,
                criticality=ctx.asset_criticality.value,
            )
            return ctx

    def infer_without_llm(self, repo_path: str, repo_name: str = "") -> BusinessContext:
        """Versão sem LLM — usa apenas heurísticas. Útil para testes e ambientes sem API key."""
        signals = extract_repo_signals(repo_path)
        return _heuristic_context(signals, repo_name)


# ── Conversão do response Claude → BusinessContext ─────────────────────────


def _from_claude_response(raw: dict, repo_name: str) -> BusinessContext:
    criticality = _parse_criticality(raw.get("asset_criticality", "medium"))
    cost_min, cost_max = (
        int(raw.get("breach_cost_brl_min", _BREACH_COST[criticality][0])),
        int(raw.get("breach_cost_brl_max", _BREACH_COST[criticality][1])),
    )
    return BusinessContext(
        asset_name=repo_name or "unknown",
        asset_criticality=criticality,
        team_owner="",
        compliance_scope=tuple(dict.fromkeys(raw.get("compliance_scope", []))),
        internet_facing=bool(raw.get("internet_facing", False)),
        contains_pii=bool(raw.get("contains_pii", False)),
        contains_financial_data=bool(raw.get("contains_financial_data", False)),
        contains_health_data=bool(raw.get("contains_health_data", False)),
        app_type=str(raw.get("app_type", "unknown")),
        domain=str(raw.get("domain", "unknown")),
        estimated_users=str(raw.get("estimated_users", "unknown")),
        breach_cost_brl_min=cost_min,
        breach_cost_brl_max=cost_max,
        key_assets=tuple(raw.get("key_assets", [])),
        inference_confidence=float(raw.get("confidence", 0.75)),
    )


# ── Fallback heurístico (sem LLM) ─────────────────────────────────────────


def _heuristic_context(signals: dict, repo_name: str) -> BusinessContext:
    flags = classify_signals(signals)

    criticality = _heuristic_criticality(flags)
    compliance = _heuristic_compliance(flags)
    app_type = _heuristic_app_type(signals)
    domain = _heuristic_domain(flags, signals)
    key_assets = _heuristic_key_assets(flags)
    cost_min, cost_max = _BREACH_COST[criticality]

    return BusinessContext(
        asset_name=repo_name or "unknown",
        asset_criticality=criticality,
        team_owner="",
        compliance_scope=tuple(dict.fromkeys(compliance)),
        internet_facing=flags["is_internet_facing"],
        contains_pii=flags["is_pii"],
        contains_financial_data=flags["is_financial"],
        contains_health_data=flags["is_health"],
        app_type=app_type,
        domain=domain,
        estimated_users="unknown",
        breach_cost_brl_min=cost_min,
        breach_cost_brl_max=cost_max,
        key_assets=tuple(key_assets),
        inference_confidence=0.40,
    )


def _heuristic_criticality(flags: dict) -> AssetCriticality:
    if flags["is_financial"] or flags["is_health"]:
        return AssetCriticality.CRITICAL
    if flags["is_pii"] and flags["is_internet_facing"]:
        return AssetCriticality.HIGH
    if flags["is_pii"] or flags["is_internet_facing"]:
        return AssetCriticality.MEDIUM
    return AssetCriticality.LOW


def _heuristic_compliance(flags: dict) -> list[str]:
    compliance = []
    if flags["is_financial"]:
        compliance.append("PCI-DSS")
    if flags["is_pii"]:
        compliance.append("LGPD")
    if flags["is_health"]:
        compliance.append("HIPAA")
    if flags["is_internet_facing"] and flags["is_pii"]:
        compliance.append("GDPR")
    return compliance


def _heuristic_app_type(signals: dict) -> str:
    frameworks = signals.get("frameworks", [])
    if "data_pipeline" in frameworks:
        return "data_pipeline"
    if "frontend" in frameworks:
        return "frontend"
    if any(f in frameworks for f in ("web_api", "web_fullstack")):
        return "web_api"
    return "unknown"


def _heuristic_domain(flags: dict, signals: dict) -> str:
    if flags["is_health"]:
        return "healthcare"
    if flags["is_financial"]:
        return "fintech"
    routes = flags.get("routes", set())
    models = flags.get("models", set())
    if {"order", "product", "cart", "inventory"} & models:
        return "ecommerce"
    if {"checkout", "/order", "/product"} & routes:
        return "ecommerce"
    dirs = set(signals.get("dir_structure", []))
    if {"api", "services", "microservices"} & dirs:
        return "saas"
    return "other"


def _heuristic_key_assets(flags: dict) -> list[str]:
    assets = []
    if "user" in flags.get("models", set()) or "customer" in flags.get("models", set()):
        assets.append("banco de dados de usuários (PII)")
    if flags["is_financial"]:
        assets.append("serviço de processamento de pagamentos")
    if "/auth" in flags.get("routes", set()) or "/login" in flags.get("routes", set()):
        assets.append("serviço de autenticação")
    if flags["is_health"]:
        assets.append("registros médicos de pacientes")
    return assets


def _parse_criticality(value: str) -> AssetCriticality:
    try:
        return AssetCriticality(value.lower())
    except ValueError:
        return AssetCriticality.MEDIUM
