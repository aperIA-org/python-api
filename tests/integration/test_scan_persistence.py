"""
Testes de integração para persistência do scan pipeline.
Testa o ciclo completo do ScanJob e a persistência de findings via db_utils.
Usa AsyncMock para simular a camada de banco sem PostgreSQL real.
"""
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from domain.finding.entities import Finding
from domain.finding.value_objects import Severity
from domain.scan.entities import ScanJob, ScanStatus


# ── Fixtures ──────────────────────────────────────────────────────────────


def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        source="semgrep",
        severity=Severity.HIGH,
        title="SQL Injection",
        description="Unsanitized input in query",
        commit_sha="a" * 40,
        repo_url="https://github.com/org/repo",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _make_scan_job(**kwargs) -> ScanJob:
    defaults = dict(
        commit_sha="a" * 40,
        repo_url="https://github.com/org/repo",
    )
    defaults.update(kwargs)
    return ScanJob(**defaults)


# ── ScanJob lifecycle ──────────────────────────────────────────────────────


class TestScanJobLifecycle:
    def test_start_transitions_to_running(self):
        job = _make_scan_job()
        assert job.status == ScanStatus.PENDING
        job.start()
        assert job.status == ScanStatus.RUNNING
        assert job.started_at is not None

    def test_complete_sets_counts(self):
        job = _make_scan_job()
        job.start()
        job.complete(findings_count=5, risk_score=72)
        assert job.status == ScanStatus.COMPLETED
        assert job.findings_count == 5
        assert job.risk_score == 72
        assert job.completed_at is not None

    def test_fail_records_error(self):
        job = _make_scan_job()
        job.start()
        job.fail("scanner timeout")
        assert job.status == ScanStatus.FAILED
        assert job.error_message == "scanner timeout"
        assert job.completed_at is not None

    def test_start_raises_if_not_pending(self):
        job = _make_scan_job()
        job.start()
        with pytest.raises(ValueError):
            job.start()

    def test_cancel_sets_cancelled(self):
        job = _make_scan_job()
        job.cancel()
        assert job.status == ScanStatus.CANCELLED


# ── db_utils sync wrappers ─────────────────────────────────────────────────


class TestDbUtils:
    @patch("infrastructure.persistence.db_utils.AsyncSessionLocal")
    def test_save_scan_job_calls_repo_save(self, mock_session_local):
        from infrastructure.persistence.db_utils import save_scan_job

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session_local.return_value = mock_session

        mock_repo = AsyncMock()
        mock_repo.save = AsyncMock()

        with patch(
            "infrastructure.persistence.db_utils.SQLAlchemyScanRepository",
            return_value=mock_repo,
        ):
            job = _make_scan_job()
            save_scan_job(job)
            mock_repo.save.assert_called_once_with(job)
            mock_session.commit.assert_called_once()

    @patch("infrastructure.persistence.db_utils.AsyncSessionLocal")
    def test_bulk_save_findings_calls_repo(self, mock_session_local):
        from infrastructure.persistence.db_utils import bulk_save_findings

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session_local.return_value = mock_session

        mock_repo = AsyncMock()
        mock_repo.bulk_save = AsyncMock()

        with patch(
            "infrastructure.persistence.db_utils.SQLAlchemyFindingRepository",
            return_value=mock_repo,
        ):
            findings = [_make_finding(), _make_finding(title="XSS")]
            bulk_save_findings(findings)
            mock_repo.bulk_save.assert_called_once_with(findings)
            mock_session.commit.assert_called_once()

    @patch("infrastructure.persistence.db_utils.AsyncSessionLocal")
    def test_load_scan_job_returns_entity(self, mock_session_local):
        from infrastructure.persistence.db_utils import load_scan_job

        job = _make_scan_job()
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session_local.return_value = mock_session

        mock_repo = AsyncMock()
        mock_repo.get_by_id = AsyncMock(return_value=job)

        with patch(
            "infrastructure.persistence.db_utils.SQLAlchemyScanRepository",
            return_value=mock_repo,
        ):
            result = load_scan_job(str(job.id))
            assert result is job
            mock_repo.get_by_id.assert_called_once_with(job.id)

    @patch("infrastructure.persistence.db_utils.AsyncSessionLocal")
    def test_load_findings_returns_list(self, mock_session_local):
        from infrastructure.persistence.db_utils import load_findings_by_commit

        findings = [_make_finding(), _make_finding(title="SQLI")]
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session_local.return_value = mock_session

        mock_repo = AsyncMock()
        mock_repo.get_by_commit = AsyncMock(return_value=findings)

        with patch(
            "infrastructure.persistence.db_utils.SQLAlchemyFindingRepository",
            return_value=mock_repo,
        ):
            result = load_findings_by_commit("a" * 40)
            assert result == findings


# ── scan_worker task logic ─────────────────────────────────────────────────


class TestScanWorkerPersistence:
    def _make_pipeline_result(self, findings=None):
        from core.orchestrator import PipelineResult
        from domain.finding.entities import RiskScore

        findings = findings or [_make_finding()]
        risk = RiskScore(
            value=65,
            level="medium",
            components={"cvss": 20.0, "cti": 15.0, "caldera": 20.0, "business": 10.0},
            verified_secret=False,
        )
        return PipelineResult(findings=findings, risk_score=risk)

    @patch("presentation.workers.scan_worker.bulk_save_findings")
    @patch("presentation.workers.scan_worker.update_scan_job")
    @patch("presentation.workers.scan_worker.save_scan_job")
    @patch("presentation.workers.scan_worker.run_pipeline")
    def test_successful_scan_persists_job_and_findings(
        self, mock_pipeline, mock_save, mock_update, mock_bulk
    ):
        from presentation.workers.scan_worker import run_scan

        mock_pipeline.return_value = self._make_pipeline_result()
        task = MagicMock()
        task.request.id = "celery-task-id"

        run_scan.__wrapped__(
            task,
            commit_sha="a" * 40,
            repo_url="https://github.com/org/repo",
        )

        mock_save.assert_called_once()
        assert mock_update.call_count == 2  # start + complete
        mock_bulk.assert_called_once()

        saved_job: ScanJob = mock_save.call_args[0][0]
        assert saved_job.status == ScanStatus.COMPLETED
        assert saved_job.findings_count == 1
        assert saved_job.risk_score == 65

    @patch("presentation.workers.scan_worker.bulk_save_findings")
    @patch("presentation.workers.scan_worker.update_scan_job")
    @patch("presentation.workers.scan_worker.save_scan_job")
    @patch("presentation.workers.scan_worker.run_pipeline")
    def test_failed_scan_marks_job_failed(
        self, mock_pipeline, mock_save, mock_update, mock_bulk
    ):
        from presentation.workers.scan_worker import run_scan

        mock_pipeline.side_effect = RuntimeError("scanner crashed")
        task = MagicMock()
        task.request.id = "celery-task-id"
        task.retry.side_effect = RuntimeError("retry")

        with pytest.raises(RuntimeError, match="retry"):
            run_scan.__wrapped__(
                task,
                commit_sha="a" * 40,
                repo_url="https://github.com/org/repo",
            )

        mock_save.assert_called_once()
        mock_bulk.assert_not_called()

        failed_job: ScanJob = mock_save.call_args[0][0]
        assert failed_job.status == ScanStatus.FAILED
        assert "scanner crashed" in (failed_job.error_message or "")
