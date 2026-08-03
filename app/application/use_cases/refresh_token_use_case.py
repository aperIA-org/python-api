import hashlib
import logging
from datetime import datetime, timedelta, timezone

from app.application.exceptions import (
    TokenExpiredError,
    TokenReusedError,
    TokenRevokedError,
)
from app.config import settings
from app.domain.entities.auth_tokens import AuthTokens
from app.domain.repositories.refresh_token_repository import RefreshTokenRepository
from app.infrastructure.security.jwt_handler import create_access_token
from app.infrastructure.security.token_service import generate_opaque_token

logger = logging.getLogger(__name__)


class RefreshTokenUseCase:
    """
    Executa a rotacao de refresh tokens.

    Fluxo:
    1. Busca o token pelo hash SHA-256
    2. Se nao existir -> token invalido (erro generico)
    3. Se existir mas estiver revogado:
       - revogado ha <= REFRESH_ROTATION_GRACE_SECONDS (por rotacao recente) ->
         REPLAY CONCORRENTE BENIGNO: emite um novo par na mesma familia, sem
         invalidar nada. E o caso do cliente com varias requisicoes em voo quando
         o access expira (polling de um scan); sem isso, so uma rotaciona e as
         demais levam 401 -> logout.
       - revogado ha mais tempo -> reuso de fato -> revoga a familia inteira.
    4. Se expirado -> erro de expiracao
    5. Caso normal: revoga o token atual e emite um novo par (rotacao)

    O family_id e mantido na rotacao para que um reuso futuro
    ainda invalide todos os tokens da cadeia.
    """

    def __init__(
        self,
        token_repo: RefreshTokenRepository,
    ) -> None:
        self._token_repo = token_repo

    async def execute(self, raw_refresh_token: str) -> AuthTokens:
        token_hash = hashlib.sha256(raw_refresh_token.encode()).hexdigest()
        record = await self._token_repo.find_by_hash(token_hash)

        if record is None:
            raise TokenRevokedError("Refresh token nao encontrado.")

        now = datetime.now(timezone.utc)

        if record.revoked:
            if self._dentro_da_graca(record, now):
                # Replay concorrente benigno: outra requisicao ja rotacionou
                # este token ha instantes. Emite um par novo na mesma familia
                # sem revogar nada — as requisicoes concorrentes todas seguem
                # com sessao valida.
                logger.info(
                    "refresh_token_replay_concorrente",
                    extra={
                        "family_id": str(record.family_id),
                        "user_id": str(record.user_id),
                    },
                )
                return await self._emitir_par(record.user_id, record.family_id, now)

            # Fora da janela: reuso de fato -> invalida toda a familia.
            logger.warning(
                "refresh_token_reuse_detected",
                extra={"family_id": str(record.family_id), "user_id": str(record.user_id)},
            )
            await self._token_repo.revoke_family(record.family_id)
            raise TokenReusedError("Reuso de refresh token detectado.")

        expires_at = record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < now:
            raise TokenExpiredError("Refresh token expirado.")

        # Rotacao normal: revoga o token atual e emite um novo par.
        await self._token_repo.revoke_by_hash(token_hash)
        return await self._emitir_par(record.user_id, record.family_id, now)

    def _dentro_da_graca(self, record, now: datetime) -> bool:
        """Se o token foi revogado ha pouco por ROTACAO (replay benigno).

        ``revoked_at`` NULL (revogado antes da coluna existir, ou por um caminho
        que nao carimba) conta como "ha muito tempo" — conservador: na duvida,
        trata como reuso.
        """
        revoked_at = getattr(record, "revoked_at", None)
        if revoked_at is None:
            return False
        if revoked_at.tzinfo is None:
            revoked_at = revoked_at.replace(tzinfo=timezone.utc)
        return (now - revoked_at) <= timedelta(
            seconds=settings.REFRESH_ROTATION_GRACE_SECONDS
        )

    async def _emitir_par(self, user_id, family_id, now: datetime) -> AuthTokens:
        """Emite um novo access + refresh, persistindo o refresh na familia."""
        new_access = create_access_token(
            user_id=user_id,
            secret=settings.SECRET_KEY,
            expire_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        )
        raw_new_refresh, new_hash = generate_opaque_token()
        new_expires = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        await self._token_repo.save(
            user_id=user_id,
            token_hash=new_hash,
            family_id=family_id,
            expires_at=new_expires,
        )
        return AuthTokens(access_token=new_access, refresh_token=raw_new_refresh)
