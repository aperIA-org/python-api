"""Interrompe uma execução em andamento.

Duas metades, e a ordem entre elas é o ponto: **revogar antes de escrever**. Se
o banco fosse atualizado primeiro, as tarefas ainda enfileiradas continuariam
rodando e reescreveriam o status logo depois — o usuário veria o scan "voltar a
andar" sozinho, que é pior do que não ter botão.

O que este caso de uso NÃO faz, de propósito:

- **Não apaga os findings já gravados.** O que as etapas concluídas
  encontraram continua valendo: o código foi analisado de verdade. Cancelar
  interrompe o que falta, não invalida o que passou.
"""
from __future__ import annotations

from uuid import UUID

import structlog

from app.application.exceptions import ScanNotCancellableError
from app.domain.scan.entities import ScanJob
from app.infrastructure.scanners.fargate_tasks import parar_tarefas_do_scan

logger = structlog.get_logger()


class CancelScanUseCase:
    def __init__(self, scan_repo, tool_run_repo=None) -> None:
        self._scan_repo = scan_repo
        self._tool_run_repo = tool_run_repo

    def execute(self, job: ScanJob) -> int:
        """Revoga o canvas e fecha os tiers pendentes. Devolve quantos fechou."""
        if not job.em_andamento():
            raise ScanNotCancellableError("Esta execução já terminou.")

        if not job.celery_task_id:
            # Execução anterior à coluna, ou dispatch cujo id não foi gravado.
            # Fechar só no banco deixaria as tarefas vivas para sobrescrever.
            raise ScanNotCancellableError(
                "Esta execução não pode ser cancelada: ela foi disparada antes "
                "do cancelamento existir."
            )

        self._revogar(job.celery_task_id, job.commit_sha)

        # Depois de revogar e antes de escrever: as tarefas do Tier 3 vivem
        # fora do worker, então revogar a fila não as alcança. Sem isto, a
        # emulação seguiria rodando até o teto de uma hora do próprio
        # container — e quem cancelou não tem por que pagar essa espera.
        parar_tarefas_do_scan(job.commit_sha)

        # As ferramentas em voo precisam fechar junto: a faixa do tier diria
        # "cancelado" e, ao expandi-la, a ferramenta dentro continuaria "em
        # execução".
        if self._tool_run_repo is not None:
            self._tool_run_repo.cancel_pending(job.id)

        tiers = self._scan_repo.cancel_pending_tiers(job.id)
        if tiers == 0:
            # Corrida: terminou entre a checagem e o UPDATE.
            raise ScanNotCancellableError("Esta execução já terminou.")

        logger.info(
            "scan_cancelado",
            scan_id=str(job.id),
            commit_sha=job.commit_sha,
            task_id=job.celery_task_id,
        )
        return tiers

    def _revogar(self, task_id: str, commit_sha: str) -> None:
        """Revoga a raiz do canvas, alcançando o que ainda não começou.

        ``terminate=True`` mata a etapa que já está executando; sem isso, um
        teste dinâmico de seis minutos seguiria até o fim depois de o usuário
        pedir para parar. O processo filho morre e o Celery cria outro — o
        ``--max-tasks-per-child`` do worker já o faz rotineiramente.

        Falha aqui **não** é engolida: sem revogação, cancelar seria mentira.
        """
        from app.core.celery_app import celery_app

        celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
        logger.info("scan_canvas_revogado", task_id=task_id, commit_sha=commit_sha)
