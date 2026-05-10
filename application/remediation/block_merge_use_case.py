import structlog

logger = structlog.get_logger()


class BlockMergeUseCase:
    """Bloqueia merge do PR até aprovação humana da code suggestion."""

    def __init__(self, github_client) -> None:
        self.github = github_client

    async def execute(
        self,
        repo_url: str,
        pr_number: int,
        commit_sha: str,
        reason: str,
    ) -> None:
        logger.bind(
            repo_url=repo_url,
            pr_number=pr_number,
            commit_sha=commit_sha,
        ).info("merge_block_requested", reason=reason)
        # DEBT: implementar na Fase 3 com github_client real
