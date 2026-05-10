from abc import ABC, abstractmethod
from uuid import UUID

from domain.finding.entities import Finding, AttackPath


class FindingRepository(ABC):
    @abstractmethod
    async def save(self, finding: Finding) -> None: ...

    @abstractmethod
    async def bulk_save(self, findings: list[Finding]) -> None: ...

    @abstractmethod
    async def get_by_id(self, finding_id: UUID) -> Finding | None: ...

    @abstractmethod
    async def get_by_commit(self, commit_sha: str) -> list[Finding]: ...

    @abstractmethod
    async def get_verified_secrets(self, commit_sha: str) -> list[Finding]: ...

    @abstractmethod
    async def find_duplicate(self, dedup_key: str, commit_sha: str) -> Finding | None: ...


class AttackPathRepository(ABC):
    @abstractmethod
    async def save(self, attack_path: AttackPath) -> None: ...

    @abstractmethod
    async def get_by_commit(self, commit_sha: str) -> list[AttackPath]: ...

    @abstractmethod
    async def get_by_id(self, attack_path_id: UUID) -> AttackPath | None: ...
