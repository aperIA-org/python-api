"""add_scan_reports_table

Cria a tabela ``scan_reports`` — relatório markdown por tier gerado pelo
pipeline, com UNIQUE(commit_sha, tier) para viabilizar o upsert idempotente
(ON CONFLICT DO UPDATE) no repositório síncrono.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-07-23 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "scan_reports",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("scan_job_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("commit_sha", sa.String(length=40), nullable=False),
        sa.Column("tier", sa.SmallInteger(), nullable=False),
        sa.Column("report_markdown", sa.Text(), nullable=True),
        sa.Column("analysis_json", postgresql.JSONB(), nullable=True),
        sa.Column("degraded", sa.Boolean(), nullable=False),
        sa.Column("comment_id", sa.BigInteger(), nullable=True),
        sa.Column("posted", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("commit_sha", "tier", name="scan_reports_commit_tier_key"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("scan_reports")
