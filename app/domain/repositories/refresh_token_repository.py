from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional
from uuid import UUID


class RefreshTokenRepository(ABC):
    """Interface do repositorio de refresh tokens. Implementada na camada de infraestrutura."""

    @abstractmethod
    async def save(
        self,
        user_id: UUID,
        token_hash: str,
        family_id: UUID,
        expires_at: datetime,
    ) -> None:
        """Persiste um novo refresh token."""
        ...

    @abstractmethod
    async def find_by_hash(self, token_hash: str) -> Optional[object]:
        """
        Busca um refresh token pelo seu hash SHA-256.
        Retorna o model ou None se nao encontrado.
        """
        ...

    @abstractmethod
    async def revoke_family(self, family_id: UUID) -> None:
        """Revoga todos os tokens de uma mesma familia (resposta a reuso suspeito)."""
        ...

    @abstractmethod
    async def revoke_by_hash(self, token_hash: str) -> None:
        """Revoga um token especifico pelo hash."""
        ...
