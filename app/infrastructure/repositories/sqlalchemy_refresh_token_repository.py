from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.domain.repositories.refresh_token_repository import RefreshTokenRepository
from app.infrastructure.persistence.models.refresh_token_model import RefreshTokenModel


class SQLAlchemyRefreshTokenRepository(RefreshTokenRepository):
    def __init__(self, session: Session) -> None:
        self._session = session

    async def save(
        self,
        user_id: UUID,
        token_hash: str,
        family_id: UUID,
        expires_at: datetime,
    ) -> None:
        token = RefreshTokenModel(
            user_id=user_id,
            token_hash=token_hash,
            family_id=family_id,
            expires_at=expires_at,
        )
        self._session.add(token)
        self._session.flush()

    async def find_by_hash(self, token_hash: str) -> Optional[RefreshTokenModel]:
        result = self._session.execute(
            select(RefreshTokenModel).where(RefreshTokenModel.token_hash == token_hash)
        )
        return result.scalar_one_or_none()

    async def revoke_family(self, family_id: UUID) -> None:
        self._session.execute(
            update(RefreshTokenModel)
            .where(RefreshTokenModel.family_id == family_id)
            .values(revoked=True)
        )

    async def revoke_by_hash(self, token_hash: str) -> None:
        self._session.execute(
            update(RefreshTokenModel)
            .where(RefreshTokenModel.token_hash == token_hash)
            .values(revoked=True)
        )
