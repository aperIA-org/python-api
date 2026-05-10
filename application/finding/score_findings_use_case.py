import structlog

from domain.finding.entities import Finding, RiskScore
from domain.finding.services import RiskScorer

logger = structlog.get_logger()


class ScoreFindingsUseCase:
    def __init__(self, scorer: RiskScorer) -> None:
        self.scorer = scorer

    async def execute(
        self,
        findings: list[Finding],
        cti_data: dict,
        caldera_results: dict,
        commit_sha: str,
    ) -> RiskScore:
        score = self.scorer.calculate(findings, cti_data, caldera_results)
        logger.bind(commit_sha=commit_sha).info(
            "risk_score_calculated",
            score=score.value,
            level=score.level,
        )
        return score
