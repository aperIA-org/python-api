import structlog

from core.celery_app import celery_app

logger = structlog.get_logger()


@celery_app.task(
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    name="presentation.workers.remediation_worker.run_remediation",
)
def run_remediation(self, scan_job_id: str) -> None:
    log = logger.bind(scan_job_id=scan_job_id, task_id=self.request.id)
    try:
        log.info("remediation_task_started")
        self.update_state(state="PROGRESS", meta={"step": "remediation"})
        # DEBT: implementar na Fase 3
        log.info("remediation_task_completed")
    except Exception as exc:
        log.error("remediation_task_failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc)
