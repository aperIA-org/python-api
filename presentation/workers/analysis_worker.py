import structlog

from core.celery_app import celery_app

logger = structlog.get_logger()


@celery_app.task(
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    name="presentation.workers.analysis_worker.run_analysis",
)
def run_analysis(self, scan_job_id: str) -> None:
    log = logger.bind(scan_job_id=scan_job_id, task_id=self.request.id)
    try:
        log.info("analysis_task_started")
        self.update_state(state="PROGRESS", meta={"step": "analysis"})
        # DEBT: implementar na Fase 2
        log.info("analysis_task_completed")
    except Exception as exc:
        log.error("analysis_task_failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc)
