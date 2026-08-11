"""add_github_multitenant_tables

Cria as tabelas de multi-tenant do GitHub — ``github_accounts`` (vínculo
usuário↔instalação do App) e ``repositories`` (repositório conectado,
pertence a um usuário) — e adiciona ``user_id``/``repository_id`` em
``scan_jobs`` para isolar os scans por dono.

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-07-28 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, Sequence[str], None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "github_accounts",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("installation_id", sa.BigInteger(), nullable=False),
        sa.Column("github_login", sa.String(length=255), nullable=True),
        sa.Column("account_type", sa.String(length=20), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("installation_id", name="github_accounts_installation_key"),
    )
    op.create_table(
        "repositories",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("github_account_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("installation_id", sa.BigInteger(), nullable=False),
        sa.Column("github_repo_id", sa.BigInteger(), nullable=False),
        sa.Column("full_name", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("default_branch", sa.String(length=255), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "github_repo_id", name="repositories_user_repo_key"),
    )
    op.add_column("scan_jobs", sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=True))
    op.add_column(
        "scan_jobs", sa.Column("repository_id", sa.Uuid(as_uuid=True), nullable=True)
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scan_jobs", "repository_id")
    op.drop_column("scan_jobs", "user_id")
    op.drop_table("repositories")
    op.drop_table("github_accounts")
