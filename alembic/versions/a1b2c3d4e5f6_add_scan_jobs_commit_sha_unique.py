"""add_scan_jobs_commit_sha_unique

Adiciona UNIQUE constraint em ``scan_jobs.commit_sha`` para viabilizar o
upsert idempotente (ON CONFLICT DO NOTHING) no repositório síncrono.

Revision ID: a1b2c3d4e5f6
Revises: b64896ca3325
Create Date: 2026-07-23 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'b64896ca3325'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_unique_constraint("scan_jobs_commit_sha_key", "scan_jobs", ["commit_sha"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint("scan_jobs_commit_sha_key", "scan_jobs", type_="unique")
