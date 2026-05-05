import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.application.exceptions import InvalidCredentialsError
from app.config import settings
from app.domain.entities.auth_tokens import AuthTokens
from app.domain.repositories.refresh_token_repository import RefreshTokenRepository
from app.domain.repositories.user_repository import UserRepository
from app.domain.services.password_service import PasswordVerifier
from app.infrastructure.security.jwt_handler import create_access_token
from app.infrastructure.security.token_service import generate_opaque_token

logger = logging.getLogger(__name__)

# Hash falso com formato Argon2id valido.
# Usado quando o usuario nao existe para garantir tempo de resposta constante
# e evitar enumeracao de usuarios por timing attack.
_DUMMY_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4"
    "$c29tZXNhbHRzb21lc2FsdA"
    "$RdescudvJCsgt3ub+b+dWRWJTQnIE8U4fIHB8vB8sLs"
)


@dataclass(frozen=True)
class LoginCommand:
    """
    Objeto de comando para o caso de uso de login.
    Encapsula os dados de entrada e deixa explicito o que e obrigatorio.
    """

    email: str
    password: str


class LoginUseCase:
    """
    Orquestra a autenticacao de um usuario.

    Responsabilidades:
    - Verificar credenciais (email + senha Argon2)
    - Gerar access token JWT
    - Gerar e persistir refresh token opaco
    - Garantir tempo de resposta constante (anti-timing attack)

    NAO e responsavel por:
    - Rate limiting (responsabilidade da camada de apresentacao/middleware)
    - Logging de IP (responsabilidade do router)
    """

    def __init__(
        self,
        user_repo: UserRepository,
        token_repo: RefreshTokenRepository,
        password_verifier: PasswordVerifier,
    ) -> None:
        self._user_repo = user_repo
        self._token_repo = token_repo
        self._password_verifier = password_verifier

    async def execute(self, command: LoginCommand) -> AuthTokens:
        # Normaliza email antes da busca
        email = command.email.lower().strip()

        user = await self._user_repo.find_by_email(email)

        # Usa hash falso quando usuario nao existe para equalizar o tempo
        # de resposta entre "usuario nao encontrado" e "senha errada".
        stored_hash = user.password if user else _DUMMY_HASH
        password_ok = self._password_verifier.verify(stored_hash, command.password)

        if not user or not password_ok:
            raise InvalidCredentialsError("Credenciais invalidas.")

        access_token = create_access_token(
            user_id=user.id,
            secret=settings.SECRET_KEY,
            expire_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        )

        raw_refresh, token_hash = generate_opaque_token()
        family_id = uuid.uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )

        await self._token_repo.save(
            user_id=user.id,
            token_hash=token_hash,
            family_id=family_id,
            expires_at=expires_at,
        )

        return AuthTokens(access_token=access_token, refresh_token=raw_refresh)
