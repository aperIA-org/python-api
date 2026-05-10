import structlog

from domain.finding.entities import Finding, AttackPath

logger = structlog.get_logger()


class GeneratePRReportUseCase:
    """Gera relatório de segurança para postagem no PR."""

    def __init__(self, github_client) -> None:
        self.github = github_client

    async def execute(
        self,
        findings: list[Finding],
        attack_path: AttackPath | None,
        risk_score: int,
        repo_url: str,
        pr_number: int,
        commit_sha: str,
    ) -> None:
        logger.bind(
            commit_sha=commit_sha,
            pr_number=pr_number,
            findings_count=len(findings),
            risk_score=risk_score,
        ).info("pr_report_generation_started")
        # DEBT: implementar na Fase 3 com github_client real
