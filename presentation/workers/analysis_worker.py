"""
Worker de re-análise: CTI enrichment + risk scoring para um scan já existente.
Útil quando novos dados de ameaças chegam após o scan original.
"""
import structlog

from core.celery_app import celery_app
from domain.finding.services import RiskScorer
from application.finding.enrich_findings_use_case import EnrichFindingsUseCase
from infrastructure.persistence.db_utils import (
    load_findings_by_commit,
    load_scan_job,
    update_scan_job,
)

logger = structlog.get_logger()

_risk_scorer = RiskScorer()


@celery_app.task(
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    name="presentation.workers.analysis_worker.run_analysis",
)
def run_analysis(self, scan_job_id: str) -> None:
    log = logger.bind(scan_job_id=scan_job_id, task_id=self.request.id)

    scan_job = load_scan_job(scan_job_id)
    if not scan_job:
        log.error("analysis_scan_job_not_found")
        return

    log = log.bind(commit_sha=scan_job.commit_sha)
    log.info("analysis_task_started")
    self.update_state(state="PROGRESS", meta={"step": "cti_enrichment"})

    try:
        findings = load_findings_by_commit(scan_job.commit_sha)
        if not findings:
            log.warning("analysis_no_findings")
            return

        cti_data = EnrichFindingsUseCase().execute(findings, scan_job.commit_sha)

        risk_score = _risk_scorer.calculate(
            findings=findings,
            cti_data=cti_data,
            caldera_results={
                "techniques_executed": 0,
                "techniques_successful": 0,
                "success_rate": 0.0,
                "ttps_used": [],
                "caldera_validated": False,
            },
            business_ctx=None,
        )

        scan_job.risk_score = risk_score.value
        update_scan_job(scan_job)

        log.info(
            "analysis_task_completed",
            risk_score=risk_score.value,
            findings_count=len(findings),
            active_campaigns=cti_data.get("active_campaigns", 0),
        )

    except Exception as exc:
        log.error("analysis_task_failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc)
