from abc import ABC, abstractmethod

from app.domain.finding.entities import Finding


class FindingRepository(ABC):
    @abstractmethod
    async def save(self, finding: Finding) -> None: ...

    @abstractmethod
    async def bulk_save(self, findings: list[Finding]) -> None: ...

    @abstractmethod
    async def get_by_commit(self, commit_sha: str) -> list[Finding]: ...

    @abstractmethod
    async def get_verified_secrets(self, commit_sha: str) -> list[Finding]: ...

    @abstractmethod
    async def find_duplicate(self, dedup_key: str) -> Finding | None: ...
