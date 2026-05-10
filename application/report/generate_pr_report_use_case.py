import structlog

from domain.finding.entities import RiskScore
from infrastructure.git.github_client import GitHubClient

logger = structlog.get_logger()

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


class GeneratePRReportUseCase:
    """
    Posta o relatório aperIA como PR review no GitHub.
    Decide o event (REQUEST_CHANGES / COMMENT / APPROVE) pelo risk level.
    O relatório é gerado pelo HeuristicEngine (Claude) e já está em Markdown.
    """

    def __init__(self, github: GitHubClient) -> None:
        self.github = github

    def execute(
        self,
        analysis: dict,
        risk_score: RiskScore,
        repo_full_name: str,
        pr_number: int,
        commit_sha: str,
    ) -> None:
        log = logger.bind(
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            commit_sha=commit_sha,
            risk_level=risk_score.level,
        )

        report = analysis.get("pr_report", "")
        if not report:
            log.warning("pr_report_empty_skipping")
            return

        # Se Claude não incluiu o header padrão aperIA, adiciona
        if "aperIA" not in report[:80]:
            report = _build_header(risk_score) + "\n\n" + report

        event = _review_event(risk_score)
        log.info("posting_pr_review", event=event)

        self.github.create_pr_review(
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            body=report,
            event=event,
        )
        log.info("pr_review_posted", event=event)


def _review_event(risk_score: RiskScore) -> str:
    if risk_score.level in ("critical", "high"):
        return "REQUEST_CHANGES"
    if risk_score.level == "medium":
        return "COMMENT"
    return "APPROVE"


def _build_header(risk_score: RiskScore) -> str:
    emoji = _SEVERITY_EMOJI.get(risk_score.level, "⚪")
    return (
        f"## {emoji} aperIA Security Analysis — "
        f"Risk Score: {risk_score.value}/100 {risk_score.level.upper()}"
    )
