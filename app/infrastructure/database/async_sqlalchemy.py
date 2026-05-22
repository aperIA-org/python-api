import os
from collections.abc import AsyncGenerator
from pathlib import Path
from urllib.parse import quote_plus

from dotenv import dotenv_values
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

ENV_PATH = Path(__file__).resolve().parents[3] / ".env"
_env_values = dotenv_values(ENV_PATH)


def _get_env(key: str, default: str | None = None) -> str | None:
    return os.getenv(key) or _env_values.get(key) or default


def _to_async_scheme(url: str) -> str:
    if url.startswith("postgresql+psycopg://"):
        return url.replace("postgresql+psycopg://", "postgresql+asyncpg://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("sqlite://"):
        return url.replace("sqlite://", "sqlite+aiosqlite://", 1)
    return url


def _build_async_database_url() -> str:
    direct = _get_env("ASYNC_DATABASE_URL") or _get_env("DATABASE_URL")
    if direct:
        return _to_async_scheme(direct)

    user = quote_plus(_get_env("DB_USER", "postgres") or "postgres")
    password = quote_plus(_get_env("DB_PASSWORD", "postgres") or "postgres")
    host = _get_env("DB_HOST", "db") or "db"
    port = _get_env("DB_PORT", "5432") or "5432"
    name = _get_env("DB_NAME", "postgres") or "postgres"
    return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{name}"


ASYNC_DATABASE_URL = _build_async_database_url()
_url = make_url(ASYNC_DATABASE_URL)
_connect_args = {}
if _url.drivername.startswith("sqlite"):
    _connect_args["check_same_thread"] = False

async_engine: AsyncEngine = create_async_engine(
    ASYNC_DATABASE_URL,
    connect_args=_connect_args,
    future=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
