from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.scan.report_entities import ScanReport


class ScanReportRepository(ABC):
    """Interface síncrona de persistência de ``ScanReport``."""

    @abstractmethod
    def save(self, report: ScanReport) -> None:
        """Persiste o relatório de um tier de UMA execução.

        O upsert é por ``(scan_job_id, tier)``: ele cobre replay do canvas
        dentro da mesma execução. Uma reexecução do commit tem outro
        ``scan_job_id`` e grava uma linha nova — é assim que o histórico existe.
        """

    @abstractmethod
    def get_by_scan_job(self, scan_job_id: UUID) -> list[ScanReport]:
        """Lista os relatórios de uma execução, ordenados por tier."""

    @abstractmethod
    def get_by_scan_job_and_tier(self, scan_job_id: UUID, tier: int) -> ScanReport | None:
        """Busca o relatório de uma execução para um tier específico."""

    @abstractmethod
    def list_by_repository(self, repository_id: UUID) -> list[ScanReport]:
        """Lista os relatórios de todos os commits de um repositório, ordenados por tier."""
