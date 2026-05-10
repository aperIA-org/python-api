import structlog

from domain.finding.entities import Finding

logger = structlog.get_logger()


class GeneratePatchUseCase:
    """
    Invoca HeuristicEngine para análise completa via Claude.
    Retorna dict com chain, attack_paths, remediations, pr_report, risk_score.
    """

    def __init__(self, engine=None) -> None:
        if engine is None:
            from infrastructure.ai.heuristic_engine import HeuristicEngine
            engine = HeuristicEngine()
        self._engine = engine

    def execute(
        self,
        findings: list[Finding],
        cti_data: dict,
        caldera_results: dict,
        repo_context: dict,
    ) -> dict:
        commit_sha = repo_context.get("commit", "")
        log = logger.bind(commit_sha=commit_sha, findings_count=len(findings))
        log.info("heuristic_analysis_started")

        result = self._engine.run(findings, cti_data, caldera_results, repo_context)

        log.info(
            "heuristic_analysis_done",
            remediations_count=len(result.get("remediations", [])),
            paths_count=len(result.get("attack_paths", {}).get("paths", [])),
        )
        return result
