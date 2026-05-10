import structlog

from domain.shared.value_objects import BusinessContext
from infrastructure.analysis.business_context_inferrer import BusinessContextInferrer

logger = structlog.get_logger()


class InferBusinessContextUseCase:
    """
    Infere o contexto de negócio de um repositório clonado sem configuração manual.
    Produz um BusinessContext que alimenta o RiskScorer e os prompts do Claude.
    """

    def __init__(self, inferrer: BusinessContextInferrer | None = None) -> None:
        self._inferrer = inferrer or BusinessContextInferrer()

    def execute(
        self,
        repo_path: str,
        commit_sha: str,
        repo_full_name: str = "",
    ) -> BusinessContext:
        log = logger.bind(commit_sha=commit_sha, repo=repo_full_name)
        log.info("business_context_inference_requested")

        ctx = self._inferrer.infer(
            repo_path=repo_path,
            commit_sha=commit_sha,
            repo_name=repo_full_name,
        )

        log.info(
            "business_context_ready",
            domain=ctx.domain,
            criticality=ctx.asset_criticality.value,
            pii=ctx.contains_pii,
            financial=ctx.contains_financial_data,
            health=ctx.contains_health_data,
            compliance=list(ctx.compliance_scope),
            confidence=ctx.inference_confidence,
        )
        return ctx
