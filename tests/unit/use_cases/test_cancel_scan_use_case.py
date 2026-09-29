"""Cancelar uma execução: revogar ANTES de escrever, e recusar o que não dá."""
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from app.application.exceptions import ScanNotCancellableError
from app.application.use_cases import cancel_scan_use_case as modulo
from app.application.use_cases.cancel_scan_use_case import CancelScanUseCase


def make_job(*, em_andamento=True, task_id="task-1"):
    job = MagicMock()
    job.id = uuid4()
    job.commit_sha = "abc123"
    job.celery_task_id = task_id
    job.em_andamento.return_value = em_andamento
    return job


@pytest.fixture
def revoke(monkeypatch):
    """Substitui a revogação real; guarda a ordem das chamadas."""
    chamadas = []
    monkeypatch.setattr(
        CancelScanUseCase,
        "_revogar",
        lambda self, task_id, commit_sha: chamadas.append(("revogar", task_id)),
    )
    return chamadas


def test_revoga_antes_de_escrever_no_banco(revoke):
    """Se o banco fosse primeiro, as tarefas vivas reescreveriam o status."""
    repo = MagicMock()
    repo.cancel_pending_tiers.side_effect = lambda job_id: (
        revoke.append(("banco", job_id)) or 2
    )

    CancelScanUseCase(repo).execute(make_job())

    assert [nome for nome, _ in revoke] == ["revogar", "banco"]


def test_devolve_quantos_tiers_fechou(revoke):
    repo = MagicMock()
    repo.cancel_pending_tiers.return_value = 2
    assert CancelScanUseCase(repo).execute(make_job()) == 2


def test_execucao_ja_encerrada_e_recusada(revoke):
    repo = MagicMock()
    with pytest.raises(ScanNotCancellableError, match="já terminou"):
        CancelScanUseCase(repo).execute(make_job(em_andamento=False))
    repo.cancel_pending_tiers.assert_not_called()
    assert revoke == []


def test_sem_task_id_recusa_em_vez_de_mexer_so_no_banco(revoke):
    """Fechar só no banco deixaria as tarefas vivas para sobrescrever depois."""
    repo = MagicMock()
    with pytest.raises(ScanNotCancellableError, match="antes do cancelamento"):
        CancelScanUseCase(repo).execute(make_job(task_id=None))
    repo.cancel_pending_tiers.assert_not_called()
    assert revoke == []


def test_corrida_no_update_vira_409(revoke):
    """Terminou entre a checagem e o UPDATE: não dá para alegar cancelamento."""
    repo = MagicMock()
    repo.cancel_pending_tiers.return_value = 0
    with pytest.raises(ScanNotCancellableError, match="já terminou"):
        CancelScanUseCase(repo).execute(make_job())


def test_falha_ao_revogar_nao_e_engolida(monkeypatch):
    """Sem revogação o cancelamento seria mentira — o erro tem de subir."""
    def explode(self, task_id, commit_sha):
        raise RuntimeError("broker fora do ar")

    monkeypatch.setattr(CancelScanUseCase, "_revogar", explode)
    repo = MagicMock()

    with pytest.raises(RuntimeError, match="broker"):
        CancelScanUseCase(repo).execute(make_job())
    repo.cancel_pending_tiers.assert_not_called()


def test_encerra_as_tarefas_fargate_depois_de_revogar(monkeypatch, revoke):
    """A emulação roda fora do worker: revogar a fila não a alcança."""
    monkeypatch.setattr(
        modulo,
        "parar_tarefas_do_scan",
        lambda commit_sha: revoke.append(("fargate", commit_sha)),
    )
    repo = MagicMock()
    repo.cancel_pending_tiers.side_effect = lambda job_id: (
        revoke.append(("banco", job_id)) or 1
    )

    CancelScanUseCase(repo).execute(make_job())

    # Ordem: revogar a fila, derrubar o que já está de pé, só então escrever.
    assert [nome for nome, _ in revoke] == ["revogar", "fargate", "banco"]
