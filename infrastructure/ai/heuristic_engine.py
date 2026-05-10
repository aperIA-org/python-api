import structlog

from domain.finding.entities import Finding
from infrastructure.ai.claude_client import ClaudeClient
from infrastructure.ai.prompts import chain_of_events, attack_path, remediation, pr_report

logger = structlog.get_logger()


class HeuristicEngine:
    """
    Orquestra os 4 prompts do Claude em sequência:
    chain_of_events → attack_path → remediation → pr_report.
    Cada etapa alimenta a próxima com contexto acumulado.
    """

    def __init__(self) -> None:
        self.claude = ClaudeClient()

    def run(
        self,
        findings: list[Finding],
        cti_data: dict,
        caldera_results: dict,
        repo_context: dict,
    ) -> dict:
        commit_sha = repo_context.get("commit", "")
        log = logger.bind(commit_sha=commit_sha, findings_count=len(findings))
        log.info("heuristic_engine_start")

        chain = self.claude.call_json(
            system=chain_of_events.SYSTEM,
            user_prompt=chain_of_events.build(findings, cti_data, repo_context),
            commit_sha=commit_sha,
        )

        paths = self.claude.call_json(
            system=attack_path.SYSTEM,
            user_prompt=attack_path.build(chain, caldera_results, repo_context),
            commit_sha=commit_sha,
        )

        remediations = self.claude.call_json(
            system=remediation.SYSTEM,
            user_prompt=remediation.build(findings, paths, repo_context),
            commit_sha=commit_sha,
        )

        report = self.claude.call(
            system=pr_report.SYSTEM,
            user_prompt=pr_report.build(chain, paths, remediations, repo_context),
            commit_sha=commit_sha,
            max_tokens=8192,
        )

        log.info("heuristic_engine_done")

        return {
            "chain": chain,
            "attack_paths": paths,
            "remediations": remediations.get("remediations", []),
            "pr_report": report,
            "risk_score": chain.get("risk_score", {}),
        }
