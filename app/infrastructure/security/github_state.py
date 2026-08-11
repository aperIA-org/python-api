"""Assinatura do parâmetro ``state`` do fluxo de conexão GitHub.

O ``state`` liga o redirect de instalação do App ao usuário logado. É um JWT
curto (HS256, ~10 min) assinado com ``SECRET_KEY``, com ``purpose`` fixo para
não ser confundido com um access token. Isso impede CSRF/"account linking":
o callback só vincula a instalação ao usuário provado pelo ``state``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt

_ALGORITHM = "HS256"
_PURPOSE = "github_connect"


def create_connect_state(user_id: UUID, secret: str, expire_minutes: int = 10) -> str:
    """Gera o ``state`` assinado que amarra o redirect ao ``user_id``."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "purpose": _PURPOSE,
        "iat": now,
        "exp": now + timedelta(minutes=expire_minutes),
    }
    return jwt.encode(payload, secret, algorithm=_ALGORITHM)


def decode_connect_state(state: str, secret: str) -> UUID:
    """Valida o ``state`` e devolve o ``user_id``. Levanta ``ValueError`` se
    inválido, expirado ou com ``purpose`` incorreto.
    """
    try:
        payload = jwt.decode(state, secret, algorithms=[_ALGORITHM])
    except jwt.InvalidTokenError as exc:
        raise ValueError("state invalido ou expirado") from exc
    if payload.get("purpose") != _PURPOSE:
        raise ValueError("state com purpose invalido")
    sub = payload.get("sub")
    if not sub:
        raise ValueError("state sem sub")
    try:
        return UUID(sub)
    except (ValueError, TypeError) as exc:
        raise ValueError("state com sub invalido") from exc
