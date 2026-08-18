from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.scan.tool_run_entities import ScanToolRun


class ScanToolRunRepository(ABC):
    """Interface síncrona de persistência de ``ScanToolRun``."""

    @abstractmethod
    def save(self, run: ScanToolRun) -> None:
        """Persiste (upsert) a execução de uma ferramenta.

        A chave é ``(scan_job_id, tool)``: dentro de uma execução, uma
        ferramenta tem uma linha só, e um replay do canvas (``acks_late``)
        sobrescreve em vez de duplicar. Reexecutar o commit cria outra execução,
        com outro ``scan_job_id``, e portanto outro conjunto de linhas — é assim
        que o histórico por ferramenta existe.
        """

    @abstractmethod
    def list_by_scan_job(self, scan_job_id: UUID) -> list[ScanToolRun]:
        """Ferramentas de uma execução, ordenadas por tier e depois por nome."""
