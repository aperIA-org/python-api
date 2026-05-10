from unittest.mock import MagicMock

import pytest

from application.report.generate_pr_report_use_case import GeneratePRReportUseCase
from domain.finding.entities import RiskScore

_SHA = "b" * 40


def _risk(value: int) -> RiskScore:
    return RiskScore(value=value)


class TestGeneratePRReportUseCase:
    def test_request_changes_for_critical_risk(self):
        github = MagicMock()
        analysis = {"pr_report": "## aperIA\n\nCritical finding found."}

        GeneratePRReportUseCase(github).execute(
            analysis=analysis,
            risk_score=_risk(95),
            repo_full_name="org/repo",
            pr_number=5,
            commit_sha=_SHA,
        )

        github.create_pr_review.assert_called_once()
        _, kwargs = github.create_pr_review.call_args
        assert kwargs["event"] == "REQUEST_CHANGES"

    def test_request_changes_for_high_risk(self):
        github = MagicMock()
        analysis = {"pr_report": "## aperIA\n\nHigh finding found."}

        GeneratePRReportUseCase(github).execute(
            analysis=analysis,
            risk_score=_risk(75),
            repo_full_name="org/repo",
            pr_number=5,
            commit_sha=_SHA,
        )

        _, kwargs = github.create_pr_review.call_args
        assert kwargs["event"] == "REQUEST_CHANGES"

    def test_comment_for_medium_risk(self):
        github = MagicMock()
        analysis = {"pr_report": "## aperIA\n\nMedium finding."}

        GeneratePRReportUseCase(github).execute(
            analysis=analysis,
            risk_score=_risk(45),
            repo_full_name="org/repo",
            pr_number=5,
            commit_sha=_SHA,
        )

        _, kwargs = github.create_pr_review.call_args
        assert kwargs["event"] == "COMMENT"

    def test_approve_for_low_risk(self):
        github = MagicMock()
        analysis = {"pr_report": "## aperIA\n\nAll clear."}

        GeneratePRReportUseCase(github).execute(
            analysis=analysis,
            risk_score=_risk(15),
            repo_full_name="org/repo",
            pr_number=5,
            commit_sha=_SHA,
        )

        _, kwargs = github.create_pr_review.call_args
        assert kwargs["event"] == "APPROVE"

    def test_prepends_header_when_missing(self):
        github = MagicMock()
        analysis = {"pr_report": "Some report without aperIA header."}

        GeneratePRReportUseCase(github).execute(
            analysis=analysis,
            risk_score=_risk(90),
            repo_full_name="org/repo",
            pr_number=1,
            commit_sha=_SHA,
        )

        _, kwargs = github.create_pr_review.call_args
        assert "aperIA Security Analysis" in kwargs["body"]
        assert "90/100" in kwargs["body"]

    def test_skips_when_report_empty(self):
        github = MagicMock()
        analysis = {"pr_report": ""}

        GeneratePRReportUseCase(github).execute(
            analysis=analysis,
            risk_score=_risk(80),
            repo_full_name="org/repo",
            pr_number=1,
            commit_sha=_SHA,
        )

        github.create_pr_review.assert_not_called()

    def test_passes_correct_repo_and_pr(self):
        github = MagicMock()
        analysis = {"pr_report": "## aperIA\n\nReport."}

        GeneratePRReportUseCase(github).execute(
            analysis=analysis,
            risk_score=_risk(80),
            repo_full_name="myorg/myrepo",
            pr_number=42,
            commit_sha=_SHA,
        )

        _, kwargs = github.create_pr_review.call_args
        assert kwargs["repo_full_name"] == "myorg/myrepo"
        assert kwargs["pr_number"] == 42
