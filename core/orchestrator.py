import structlog

logger = structlog.get_logger()


def run_pipeline(
    commit_sha: str,
    repo_url: str,
    pr_number: int | None = None,
    installation_id: int | None = None,
) -> None:
    # DEBT: implementar pipeline completo nas fases seguintes
    log = logger.bind(commit_sha=commit_sha, repo_url=repo_url, pr_number=pr_number)
    log.info("pipeline_started")
    raise NotImplementedError("Pipeline será implementado na Fase 1")
