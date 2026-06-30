import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool

from alembic import context

# Ensure the app package is importable when running alembic from project root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.infrastructure.persistence.models.base import Base  # noqa: E402

# Import every model that should be picked up by autogenerate.
from app.infrastructure.persistence.models import (  # noqa: E402, F401
    finding_model,
    remediation_model,
    scan_job_model,
    user_model,
    refresh_token_model,
)

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _resolve_database_url() -> str:
    env_url = (
        os.getenv("ALEMBIC_DATABASE_URL")
        or os.getenv("DATABASE_URL")
        or config.get_main_option("sqlalchemy.url")
        or ""
    )
    if env_url.startswith("postgresql+asyncpg://"):
        env_url = env_url.replace("postgresql+asyncpg://", "postgresql+psycopg://", 1)
    elif env_url.startswith("postgresql://"):
        env_url = env_url.replace("postgresql://", "postgresql+psycopg://", 1)
    elif env_url.startswith("sqlite+aiosqlite://"):
        env_url = env_url.replace("sqlite+aiosqlite://", "sqlite://", 1)
    return env_url


config.set_main_option("sqlalchemy.url", _resolve_database_url())

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=url.startswith("sqlite"),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
