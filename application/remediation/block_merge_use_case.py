import structlog

from domain.finding.entities import RiskScore
from infrastructure.git.github_client import GitHubClient

logger = structlog.get_logger()


class BlockMergeUseCase:
    """Bloqueia merge do PR via commit status failure baseado no risk score."""

    def __init__(self, github: GitHubClient) -> None:
        self.github = github

    def execute(
        self,
        repo_full_name: str,
        commit_sha: str,
        risk_score: RiskScore,
    ) -> None:
        reason = (
            f"Risk {risk_score.level.upper()} ({risk_score.value}/100) — "
            "patch review required before merge"
        )
        self.github.block_merge(repo_full_name, commit_sha, reason)
        logger.bind(
            repo_full_name=repo_full_name,
            commit_sha=commit_sha,
        ).info("merge_blocked_by_risk_score", level=risk_score.level, score=risk_score.value)
