from dataclasses import dataclass


@dataclass(frozen=True)
class AuthTokens:
    """Representa o par de tokens retornado apos autenticacao bem-sucedida."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
