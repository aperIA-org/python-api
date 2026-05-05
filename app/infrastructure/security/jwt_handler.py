from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt

from app.application.exceptions import InvalidCredentialsError, TokenExpiredError

_ALGORITHM = "HS256"
_ISSUER = "python-api"
_AUDIENCE = "python-api-clients"


def create_access_token(user_id: UUID, secret: str, expire_minutes: int) -> str:
    """
    Gera um JWT assinado com HS256.
    Inclui: sub (user_id), exp, iat, iss, aud.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "exp": now + timedelta(minutes=expire_minutes),
        "iat": now,
        "iss": _ISSUER,
        "aud": _AUDIENCE,
    }
    return jwt.encode(payload, secret, algorithm=_ALGORITHM)


def decode_access_token(token: str, secret: str) -> dict:
    """
    Decodifica e valida um JWT.
    Mapeia excecoes do PyJWT para excecoes do dominio da aplicacao.
    Nunca deixa vazar jwt.InvalidTokenError para a camada de apresentacao.
    """
    try:
        return jwt.decode(
            token,
            secret,
            algorithms=[_ALGORITHM],
            audience=_AUDIENCE,
            issuer=_ISSUER,
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpiredError("Token expirado.") from exc
    except jwt.InvalidTokenError as exc:
        raise InvalidCredentialsError("Token invalido.") from exc
