from unittest.mock import MagicMock

from application.remediation.block_merge_use_case import BlockMergeUseCase
from domain.finding.entities import RiskScore

_SHA = "c" * 40


class TestBlockMergeUseCase:
    def test_calls_block_merge_with_reason(self):
        github = MagicMock()
        risk = RiskScore(value=85)

        BlockMergeUseCase(github).execute(
            repo_full_name="org/repo",
            commit_sha=_SHA,
            risk_score=risk,
        )

        github.block_merge.assert_called_once()
        args = github.block_merge.call_args
        assert args[0][0] == "org/repo"
        assert args[0][1] == _SHA
        reason = args[0][2]
        assert "HIGH" in reason
        assert "85" in reason

    def test_reason_contains_critical_for_score_95(self):
        github = MagicMock()
        risk = RiskScore(value=95)

        BlockMergeUseCase(github).execute(
            repo_full_name="org/repo",
            commit_sha=_SHA,
            risk_score=risk,
        )

        reason = github.block_merge.call_args[0][2]
        assert "CRITICAL" in reason

    def test_reason_contains_low_for_score_20(self):
        github = MagicMock()
        risk = RiskScore(value=20)

        BlockMergeUseCase(github).execute(
            repo_full_name="org/repo",
            commit_sha=_SHA,
            risk_score=risk,
        )

        reason = github.block_merge.call_args[0][2]
        assert "LOW" in reason
