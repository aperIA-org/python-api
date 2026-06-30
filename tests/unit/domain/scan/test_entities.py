import pytest

from app.domain.scan.entities import ScanJob
from app.domain.scan.value_objects import ScanTier, TierStatus


class TestScanJobInvariants:
    def test_installation_id_is_required(self):
        with pytest.raises(TypeError):
            ScanJob(  # type: ignore[call-arg]
                commit_sha="a" * 40,
                repo_url="https://github.com/acme/repo",
            )

    def test_minimum_construction(self):
        job = ScanJob(
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
            installation_id=12345,
        )
        assert job.installation_id == 12345
        assert job.blocked_at_tier is None
        assert job.tier1_status is None

    def test_blocked_at_tier_one_means_gate_1_blocked(self):
        job = ScanJob(
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
            installation_id=1,
            blocked_at_tier=ScanTier.ONE,
        )
        assert job.blocked_at_tier is ScanTier.ONE

    def test_separate_status_per_tier(self):
        job = ScanJob(
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
            installation_id=1,
            tier1_status=TierStatus.DONE,
            tier2_status=TierStatus.RUNNING,
        )
        assert job.tier1_status is TierStatus.DONE
        assert job.tier2_status is TierStatus.RUNNING
        assert job.tier3_status is None
