import structlog

from domain.finding.entities import Finding, AttackPath, EventChain
from domain.finding.repositories import AttackPathRepository
from domain.finding.services import AttackPathBuilder

logger = structlog.get_logger()


class BuildAttackPathUseCase:
    def __init__(self, repo: AttackPathRepository, builder: AttackPathBuilder) -> None:
        self.repo = repo
        self.builder = builder

    async def execute(
        self,
        findings: list[Finding],
        cti_data: dict,
        risk_score: int,
        risk_level: str,
        commit_sha: str,
        repo_url: str,
    ) -> AttackPath:
        narrative = self.builder.build_narrative(findings, cti_data)
        ttp_ids = list(cti_data.get("techniques", []))

        chain = EventChain(
            commit_sha=commit_sha,
            repo_url=repo_url,
            narrative=narrative,
        )
        attack_path = AttackPath(
            commit_sha=commit_sha,
            repo_url=repo_url,
            finding_ids=[f.id for f in findings],
            ttp_ids=ttp_ids,
            event_chain=chain,
            risk_score=risk_score,
            risk_level=risk_level,
            description=narrative,
        )
        await self.repo.save(attack_path)
        logger.bind(commit_sha=commit_sha).info(
            "attack_path_built", attack_path_id=str(attack_path.id)
        )
        return attack_path
