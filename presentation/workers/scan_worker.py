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
    base_sha: str | None = None,
    repo_full_name: str | None = None,
) -> None:
    log = logger.bind(
        commit_sha=commit_sha,
        repo_url=repo_url,
        task_id=self.request.id,
    )
    try:
        log.info("scan_task_started")
        self.update_state(state="PROGRESS", meta={"step": "cloning"})

        findings = run_pipeline(
            commit_sha=commit_sha,
            repo_url=repo_url,
            pr_number=pr_number,
            installation_id=installation_id,
            base_sha=base_sha,
            repo_full_name=repo_full_name,
        )

        log.info("scan_task_completed", findings_count=len(findings))

    except Exception as exc:
        log.error("scan_task_failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc)
