import structlog

from core.celery_app import celery_app
from core.orchestrator import run_pipeline

logger = structlog.get_logger()


@celery_app.task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    name="presentation.workers.scan_worker.run_scan",
)
def run_scan(
    self,
    commit_sha: str,
    repo_url: str,
    pr_number: int | None = None,
    installation_id: int | None = None,
) -> None:
    log = logger.bind(
        commit_sha=commit_sha,
        repo_url=repo_url,
        task_id=self.request.id,
    )
    try:
        log.info("scan_task_started")
        self.update_state(state="PROGRESS", meta={"step": "starting"})
        run_pipeline(commit_sha, repo_url, pr_number, installation_id)
        log.info("scan_task_completed")
    except Exception as exc:
        log.error("scan_task_failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc)
