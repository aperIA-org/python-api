from abc import ABC, abstractmethod

from app.domain.finding.entities import Finding


class FindingRepository(ABC):
    @abstractmethod
    def save(self, finding: Finding) -> None: ...

    @abstractmethod
    def bulk_save(self, findings: list[Finding]) -> None: ...

    @abstractmethod
    def get_by_commit(self, commit_sha: str) -> list[Finding]: ...

    @abstractmethod
    def get_verified_secrets(self, commit_sha: str) -> list[Finding]: ...

    @abstractmethod
    def find_duplicate(self, dedup_key: str) -> Finding | None: ...
