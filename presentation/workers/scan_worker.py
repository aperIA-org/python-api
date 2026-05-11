import structlog

from core.celery_app import celery_app
from core.orchestrator import run_pipeline
from domain.scan.entities import ScanJob
from infrastructure.persistence.db_utils import (
    bulk_save_findings,
    save_scan_job,
    update_scan_job,
)

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

    scan_job = ScanJob(
        commit_sha=commit_sha,
        repo_url=repo_url,
        pr_number=pr_number,
        installation_id=installation_id,
    )
    save_scan_job(scan_job)
    log.info("scan_job_created", scan_job_id=str(scan_job.id))

    scan_job.start()
    update_scan_job(scan_job)
    self.update_state(state="PROGRESS", meta={"step": "scanning", "scan_job_id": str(scan_job.id)})

    try:
        log.info("scan_task_started")
        result = run_pipeline(
            commit_sha=commit_sha,
            repo_url=repo_url,
            pr_number=pr_number,
            installation_id=installation_id,
            base_sha=base_sha,
            repo_full_name=repo_full_name,
        )

        scan_job.complete(
            findings_count=len(result.findings),
            risk_score=result.risk_score.value,
        )
        update_scan_job(scan_job)

        if result.findings:
            bulk_save_findings(result.findings)

        log.info(
            "scan_task_completed",
            findings_count=len(result.findings),
            risk_score=result.risk_score.value,
            scan_job_id=str(scan_job.id),
        )

    except Exception as exc:
        scan_job.fail(str(exc)[:500])
        update_scan_job(scan_job)
        log.error("scan_task_failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc)
