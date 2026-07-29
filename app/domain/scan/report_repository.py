from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.scan.report_entities import ScanReport


class ScanReportRepository(ABC):
    """Interface síncrona de persistência de ``ScanReport``."""

    @abstractmethod
    def save(self, report: ScanReport) -> None:
        """Persiste (ou substitui, via upsert) o relatório de um tier/commit."""

    @abstractmethod
    def get_by_commit(self, commit_sha: str) -> list[ScanReport]:
        """Lista todos os relatórios de um commit, ordenados por tier."""

    @abstractmethod
    def get_by_commit_and_tier(self, commit_sha: str, tier: int) -> ScanReport | None:
        """Busca o relatório de um commit para um tier específico."""

    @abstractmethod
    def list_by_repository(self, repository_id: UUID) -> list[ScanReport]:
        """Lista os relatórios de todos os commits de um repositório, ordenados por tier."""
