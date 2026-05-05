import re

from pydantic import BaseModel, field_validator


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        """Normaliza o email para lowercase com strip antes de qualquer validacao."""
        if isinstance(v, str):
            return v.lower().strip()
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not re.fullmatch(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", v):
            raise ValueError("E-mail invalido")
        return v


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
