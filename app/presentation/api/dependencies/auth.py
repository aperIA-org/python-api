"""
Dependency FastAPI para autenticacao via Bearer JWT.

Reutilizavel em qualquer rota que exija usuario autenticado: basta declarar
`user_id: UUID = Depends(get_current_user)` na assinatura da rota. Reusa a
infra de auth ja existente (`decode_access_token`) e apenas traduz as
excecoes de dominio em uma resposta HTTP 401 padronizada.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.application.exceptions import InvalidCredentialsError, TokenExpiredError
from app.config import settings
from app.infrastructure.security.jwt_handler import decode_access_token

# auto_error=False: com auto_error=True o FastAPI devolveria 403 quando o
# header Authorization estiver ausente. Aqui queremos controlar a resposta
# nos mesmos (sempre 401), entao tratamos o caso `credentials is None` a mao.
_bearer = HTTPBearer(auto_error=False)

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Credenciais invalidas ou token expirado.",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> UUID:
    """
    Extrai e valida o usuario autenticado a partir do JWT Bearer.

    Protege rotas de leitura exigindo um `Authorization: Bearer <token>`
    valido. Decodifica o token via `decode_access_token` (infra existente),
    mapeia falhas de token (expirado ou invalido) e ausencia/malformacao da
    claim `sub` para HTTP 401, e retorna o `UUID` do usuario autenticado.
    """
    if credentials is None:
        raise _UNAUTHORIZED

    try:
        payload = decode_access_token(credentials.credentials, settings.SECRET_KEY)
    except (TokenExpiredError, InvalidCredentialsError) as exc:
        raise _UNAUTHORIZED from exc

    sub = payload.get("sub")
    if sub is None:
        raise _UNAUTHORIZED

    try:
        return UUID(sub)
    except ValueError as exc:
        raise _UNAUTHORIZED from exc
