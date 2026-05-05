import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values

ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
_ENV_VALUES = dotenv_values(ENV_PATH)


def _get_env(key: str, default: str) -> str:
    return str(os.getenv(key) or _ENV_VALUES.get(key) or default)


def _get_int(key: str, default: int) -> int:
    raw_value = _get_env(key, str(default))
    try:
        return int(raw_value)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7


settings = Settings(
    SECRET_KEY=_get_env(
        "SECRET_KEY",
        "change-this-secret-key-with-at-least-32-characters",
    ),
    ACCESS_TOKEN_EXPIRE_MINUTES=_get_int("ACCESS_TOKEN_EXPIRE_MINUTES", 15),
    REFRESH_TOKEN_EXPIRE_DAYS=_get_int("REFRESH_TOKEN_EXPIRE_DAYS", 7),
)
