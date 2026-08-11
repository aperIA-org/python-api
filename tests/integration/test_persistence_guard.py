"""O guard de persistência encerra o ScanJob antes de propagar a falha.

Espelha `test_worker_checkout.py`: uma task que falha interrompe o canvas, e
sem esta marcação o `ScanJob` ficaria `running` até a varredura de jobs
travados — bloqueando novos disparos daquele commit com 409 nesse intervalo.
"""
from unittest.mock import patch

import pytest

from app.core.exceptions import FindingPersistenceError
from app.presentation.workers import persistence_guard

COMMIT = "f" * 40


def test_propaga_a_falha_e_encerra_os_tiers():
    with patch.object(
        persistence_guard,
        "persist_findings",
        side_effect=FindingPersistenceError("coluna estourou"),
    ), patch.object(persistence_guard.scan_job_writer, "fail_pending_tiers") as fail:
        with pytest.raises(FindingPersistenceError):
            persistence_guard.persistir_ou_falhar([], commit_sha=COMMIT, tier=1)

    fail.assert_called_once()
    assert fail.call_args[0][0] == COMMIT
    # O motivo precisa identificar o tier — é o que se lê no banco depois.
    assert "persistencia_tier1" in fail.call_args[1]["motivo"]


def test_sucesso_nao_toca_no_scan_job():
    with patch.object(
        persistence_guard, "persist_findings", return_value=3
    ), patch.object(persistence_guard.scan_job_writer, "fail_pending_tiers") as fail:
        assert persistence_guard.persistir_ou_falhar([], commit_sha=COMMIT, tier=2) == 3

    fail.assert_not_called()


@pytest.mark.parametrize("tier", [1, 2, 3])
def test_motivo_identifica_cada_tier(tier):
    with patch.object(
        persistence_guard,
        "persist_findings",
        side_effect=FindingPersistenceError("db down"),
    ), patch.object(persistence_guard.scan_job_writer, "fail_pending_tiers") as fail:
        with pytest.raises(FindingPersistenceError):
            persistence_guard.persistir_ou_falhar([], commit_sha=COMMIT, tier=tier)

    assert f"persistencia_tier{tier}" in fail.call_args[1]["motivo"]
