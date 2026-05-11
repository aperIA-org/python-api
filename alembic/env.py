import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy.ext.asyncio import create_async_engine
from alembic import context

# Garante que o pacote aperia está no path quando alembic é executado
sys.path.insert(0, str(Path(__file__).parent.parent))

from infrastructure.persistence.models.base import Base  # noqa: E402
from infrastructure.persistence.models.finding_model import FindingModel  # noqa: E402, F401
from infrastructure.persistence.models.scan_model import ScanJobModel  # noqa: E402, F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _get_url() -> str:
    # Prioridade: DATABASE_URL do ambiente > alembic.ini
    url = os.environ.get("DATABASE_URL") or config.get_main_option("sqlalchemy.url", "")
    # Alembic com asyncpg requer o prefixo postgresql+asyncpg
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=_get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def _run_async_migrations() -> None:
    engine = create_async_engine(_get_url())
    async with engine.begin() as conn:
        await conn.run_sync(_do_run_migrations)
    await engine.dispose()


def run_migrations_online() -> None:
    asyncio.run(_run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
