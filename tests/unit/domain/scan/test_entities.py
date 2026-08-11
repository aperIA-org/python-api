from datetime import datetime, timedelta

import pytest

from app.domain.scan.entities import ScanJob
from app.domain.scan.value_objects import ScanTier, TierStatus

AGORA = datetime(2026, 8, 1, 12, 0, 0)


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


class TestTierConcluido:
    """``tier_concluido`` é o que protege um resultado real de virar 'skipped'."""

    def test_status_do_tier_le_o_campo_certo(self):
        job = ScanJob(
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
            installation_id=1,
            tier1_status=TierStatus.DONE,
            tier2_status=TierStatus.RUNNING,
        )
        assert job.status_do_tier(ScanTier.ONE) is TierStatus.DONE
        assert job.status_do_tier(ScanTier.TWO) is TierStatus.RUNNING
        assert job.status_do_tier(ScanTier.THREE) is None

    @pytest.mark.parametrize(
        "status,esperado",
        [
            (TierStatus.DONE, True),
            (TierStatus.FAILED, True),
            (TierStatus.RUNNING, False),
            (TierStatus.QUEUED, False),
            (TierStatus.SKIPPED, False),
            (None, False),
        ],
    )
    def test_apenas_done_e_failed_sao_desfecho_real(self, status, esperado):
        job = ScanJob(
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
            installation_id=1,
            tier3_status=status,
        )
        assert job.tier_concluido(ScanTier.THREE) is esperado


def _job(**overrides) -> ScanJob:
    base = {
        "commit_sha": "a" * 40,
        "repo_url": "https://github.com/acme/repo",
        "installation_id": 1,
        "created_at": AGORA,
    }
    base.update(overrides)
    return ScanJob(**base)


class TestScanJobTravado:
    """Regra de job travado (stale) — base da recuperação de jobs órfãos."""

    def test_ultimo_progresso_cai_no_created_at_sem_timestamps_de_tier(self):
        # Cenário do incidente: a linha nasce com tier1 "running" e nada mais
        # é escrito porque a fila do broker se perdeu.
        job = _job(tier1_status=TierStatus.RUNNING)
        assert job.ultimo_progresso_em == AGORA

    def test_ultimo_progresso_e_o_timestamp_mais_recente(self):
        job = _job(
            tier1_status=TierStatus.DONE,
            tier1_started_at=AGORA + timedelta(minutes=1),
            tier1_completed_at=AGORA + timedelta(minutes=3),
            tier2_status=TierStatus.RUNNING,
            tier2_started_at=AGORA + timedelta(minutes=4),
        )
        assert job.ultimo_progresso_em == AGORA + timedelta(minutes=4)

    def test_job_recem_criado_nao_esta_travado(self):
        job = _job(tier1_status=TierStatus.RUNNING)
        assert job.em_andamento() is True
        assert (
            job.esta_travado(agora=AGORA + timedelta(minutes=5), limiar_minutos=30)
            is False
        )

    def test_job_sem_progresso_alem_do_limiar_esta_travado(self):
        job = _job(tier1_status=TierStatus.RUNNING)
        assert (
            job.esta_travado(agora=AGORA + timedelta(minutes=31), limiar_minutos=30)
            is True
        )

    def test_progresso_recente_em_outro_tier_afasta_o_travamento(self):
        job = _job(
            tier1_status=TierStatus.DONE,
            tier1_completed_at=AGORA + timedelta(hours=2),
            tier2_status=TierStatus.RUNNING,
            tier2_started_at=AGORA + timedelta(hours=2),
        )
        assert (
            job.esta_travado(agora=AGORA + timedelta(hours=2, minutes=5), limiar_minutos=30)
            is False
        )

    def test_job_concluido_nunca_esta_travado(self):
        job = _job(tier1_status=TierStatus.DONE, tier2_status=TierStatus.SKIPPED)
        assert job.em_andamento() is False
        assert (
            job.esta_travado(agora=AGORA + timedelta(days=30), limiar_minutos=30)
            is False
        )
