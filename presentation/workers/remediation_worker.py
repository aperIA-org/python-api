"""
Worker de re-remediação: regenera patches e PR report para um scan existente.
Útil quando o report inicial falhou ou quando se quer forçar nova análise.
"""
import structlog

from core.celery_app import celery_app
from core.config import settings
from application.remediation.generate_patch_use_case import GeneratePatchUseCase
from application.remediation.suggest_patch_use_case import SuggestPatchUseCase
from application.report.generate_pr_report_use_case import GeneratePRReportUseCase
from domain.finding.services import RiskScorer
from infrastructure.git.github_client import GitHubClient, get_installation_token
from infrastructure.persistence.db_utils import (
    load_findings_by_commit,
    load_scan_job,
)

logger = structlog.get_logger()

_risk_scorer = RiskScorer()


def _build_github_client(installation_id: int | None) -> GitHubClient | None:
    try:
        token = get_installation_token(installation_id) if installation_id else settings.GITHUB_TOKEN
        return GitHubClient(token=token)
    except Exception as exc:
        logger.warning("remediation_github_client_failed", error=str(exc))
        return None


@celery_app.task(
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    name="presentation.workers.remediation_worker.run_remediation",
)
def run_remediation(self, scan_job_id: str) -> None:
    log = logger.bind(scan_job_id=scan_job_id, task_id=self.request.id)

    scan_job = load_scan_job(scan_job_id)
    if not scan_job:
        log.error("remediation_scan_job_not_found")
        return

    if not scan_job.pr_number:
        log.info("remediation_skipped_no_pr")
        return

    log = log.bind(commit_sha=scan_job.commit_sha, pr_number=scan_job.pr_number)
    log.info("remediation_task_started")
    self.update_state(state="PROGRESS", meta={"step": "generating_patches"})

    try:
        findings = load_findings_by_commit(scan_job.commit_sha)
        if not findings:
            log.warning("remediation_no_findings")
            return

        github = _build_github_client(scan_job.installation_id)
        if not github:
            log.error("remediation_no_github_client")
            return

        repo_context = {
            "commit": scan_job.commit_sha,
            "repo": scan_job.repo_url,
            "pr_number": scan_job.pr_number,
        }

        risk_score = _risk_scorer.calculate(
            findings=findings,
            cti_data={"per_cve": {}, "active_campaigns": 0, "techniques": []},
            caldera_results={
                "techniques_executed": 0,
                "techniques_successful": 0,
                "success_rate": 0.0,
                "ttps_used": [],
                "caldera_validated": False,
            },
            business_ctx=None,
        )

        analysis = GeneratePatchUseCase().execute(
            findings=findings,
            cti_data={"per_cve": {}, "active_campaigns": 0, "techniques": []},
            caldera_results={},
            repo_context=repo_context,
        )

        repo_full_name = scan_job.repo_url.split("github.com/")[-1].rstrip(".git")
        posted = SuggestPatchUseCase(github).execute(
            remediations=analysis.get("remediations", []),
            findings=findings,
            repo_full_name=repo_full_name,
            commit_sha=scan_job.commit_sha,
            pr_number=scan_job.pr_number,
        )

        GeneratePRReportUseCase(github).execute(
            analysis=analysis,
            risk_score=risk_score,
            repo_full_name=repo_full_name,
            pr_number=scan_job.pr_number,
            commit_sha=scan_job.commit_sha,
        )

        log.info("remediation_task_completed", suggestions_posted=posted)

    except Exception as exc:
        log.error("remediation_task_failed", error=str(exc), exc_info=True)
        raise self.retry(exc=exc)
