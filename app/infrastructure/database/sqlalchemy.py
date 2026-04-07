from collections.abc import Generator
import os
from pathlib import Path
import socket
from urllib.parse import quote_plus

from dotenv import dotenv_values
from sqlalchemy.engine import make_url
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

ENV_PATH = Path(__file__).resolve().parents[3] / ".env"
env_values = dotenv_values(ENV_PATH)


def _get_env(key: str, default: str | None = None) -> str | None:
    return os.getenv(key) or env_values.get(key) or default


def _normalize_scheme(url: str) -> str:
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def _to_bool(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _append_ipv4_hostaddr(url: str) -> str:
    if not _to_bool(_get_env("DB_FORCE_IPV4")):
        return url

    parsed_url = make_url(url)
    if not parsed_url.host:
        return url

    try:
        ipv4_result = socket.getaddrinfo(parsed_url.host, parsed_url.port, family=socket.AF_INET)
    except OSError:
        return url

    if not ipv4_result:
        return url

    hostaddr = ipv4_result[0][4][0]
    return parsed_url.update_query_dict({"hostaddr": hostaddr}).render_as_string(hide_password=False)


def _build_database_url() -> str:
    direct_url = _get_env("DATABASE_URL")
    if direct_url:
        return _append_ipv4_hostaddr(_normalize_scheme(direct_url))

    user = quote_plus(_get_env("DB_USER", "postgres") or "postgres")
    password = quote_plus(_get_env("DB_PASSWORD", "postgres") or "postgres")
    host = _get_env("DB_HOST", "db") or "db"
    port = _get_env("DB_PORT", "5432") or "5432"
    name = _get_env("DB_NAME", "postgres") or "postgres"
    built_url = f"postgresql+psycopg://{user}:{password}@{host}:{port}/{name}"
    return _append_ipv4_hostaddr(built_url)


DATABASE_URL = _build_database_url()

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
