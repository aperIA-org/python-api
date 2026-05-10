import structlog

logger = structlog.get_logger()

# DEBT: implementar GitLab support (MR suggestions, webhooks) na Fase futura


class GitLabClient:
    """Placeholder — GitLab support não implementado nesta fase."""

    async def create_merge_request_comment(self, *args, **kwargs) -> None:
        raise NotImplementedError("GitLab support not yet implemented")
