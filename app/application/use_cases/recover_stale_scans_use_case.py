"""Recuperação de ``ScanJob`` travados (stale).

O problema que este caso de uso resolve é de **durabilidade assimétrica**: o
Postgres tem volume, o Redis (broker do Celery) não precisa ter — e mesmo com
AOF ligado há janelas (worker morto no meio da task, fila purgada) em que a
tarefa some. Quando isso acontece, a linha de ``scan_jobs`` fica órfã: diz
``running`` para sempre porque não existe mais ninguém para concluí-la.

Além de poluir ``GET /scans``, um job órfão **bloqueia** o commit: o disparo
manual responde 409 enquanto algum tier estiver ``queued``/``running``. Sem
recuperação, aquele commit vira permanentemente não-escaneável.

A regra de "sem progresso" mora no domínio (``ScanJob.esta_travado``); aqui só
orquestramos: listar o que está em voo, filtrar o que está travado e encerrar
os tiers pendentes como ``failed``.
"""

from __future__ import annotations

from datetime import datetime

import structlog

from app.config import settings
from app.domain.scan.repositories import ScanJobRepository

logger = structlog.get_logger()


class RecoverStaleScanJobsUseCase:
    """Marca como ``failed`` os scan jobs em andamento que pararam de progredir.

    Usado na varredura de boot da API (``app/main.py``). Não existe celery beat
    na stack, então o boot é o único momento periódico garantido — e é
    exatamente o momento certo: se a API está subindo, a stack foi reiniciada e
    tudo que estava em voo no broker anterior já se perdeu.
    """

    def __init__(
        self,
        scan_jobs: ScanJobRepository,
        *,
        stale_after_minutes: int | None = None,
        now: datetime | None = None,
    ) -> None:
        self.scan_jobs = scan_jobs
        # Lido em runtime (e não como default de argumento) para que testes
        # possam sobrescrever ``settings`` via monkeypatch.
        self.stale_after_minutes = (
            stale_after_minutes
            if stale_after_minutes is not None
            else settings.SCAN_STALE_AFTER_MINUTES
        )
        self._now = now

    def execute(self) -> list[str]:
        """Libera os jobs travados e devolve os ``commit_sha`` afetados."""
        agora = self._now or datetime.utcnow()
        liberados: list[str] = []

        for job in self.scan_jobs.list_in_progress():
            if not job.esta_travado(
                agora=agora, limiar_minutos=self.stale_after_minutes
            ):
                continue
            self.scan_jobs.fail_pending_tiers(job.commit_sha)
            liberados.append(job.commit_sha)
            logger.warning(
                "scan_job_stale_liberado",
                commit_sha=job.commit_sha,
                repo=job.repo_full_name,
                ultimo_progresso_em=job.ultimo_progresso_em.isoformat(),
                limiar_minutos=self.stale_after_minutes,
            )

        logger.info(
            "scan_jobs_stale_varredura",
            liberados=len(liberados),
            limiar_minutos=self.stale_after_minutes,
        )
        return liberados
