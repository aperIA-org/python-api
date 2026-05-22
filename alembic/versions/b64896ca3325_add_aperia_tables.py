"""add_aperia_tables

Revision ID: b64896ca3325
Revises:
Create Date: 2026-05-22 09:28:29.312066

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'b64896ca3325'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'findings',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('tier', sa.SmallInteger(), nullable=False),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('cve_id', sa.String(length=50), nullable=True),
        sa.Column('cwe_id', sa.String(length=50), nullable=True),
        sa.Column('file_path', sa.Text(), nullable=True),
        sa.Column('line_number', sa.Integer(), nullable=True),
        sa.Column('asset', sa.Text(), nullable=True),
        sa.Column('asset_criticality', sa.String(length=20), nullable=True),
        sa.Column('secret_verified', sa.Boolean(), nullable=False),
        sa.Column('secret_type', sa.String(length=100), nullable=True),
        sa.Column(
            'raw_output',
            postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), 'sqlite'),
            nullable=True,
        ),
        sa.Column('commit_sha', sa.String(length=40), nullable=False),
        sa.Column('repo_url', sa.Text(), nullable=False),
        # Materializa Finding.dedup_key() — UNIQUE multi-coluna não é confiável
        # quando algum componente (ex: cve_id) é NULL (NULL != NULL em SQL).
        sa.Column('dedup_key', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('dedup_key', name='findings_dedup_key'),
    )
    op.create_index('idx_findings_commit_sha', 'findings', ['commit_sha'])
    op.create_index('idx_findings_severity', 'findings', ['severity'])
    # Índice parcial — query do Gate 1 só precisa varrer ~1% dos findings.
    # Em Postgres usa `secret_verified = TRUE`; em SQLite usa `secret_verified = 1`.
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.create_index(
            'idx_findings_verified_secrets',
            'findings',
            ['commit_sha'],
            sqlite_where=sa.text('secret_verified = 1'),
        )
    else:
        op.create_index(
            'idx_findings_verified_secrets',
            'findings',
            ['commit_sha'],
            postgresql_where=sa.text('secret_verified = TRUE'),
        )

    op.create_table(
        'scan_jobs',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('commit_sha', sa.String(length=40), nullable=False),
        sa.Column('repo_url', sa.Text(), nullable=False),
        sa.Column('pr_number', sa.Integer(), nullable=True),
        sa.Column('repo_full_name', sa.Text(), nullable=True),
        sa.Column('installation_id', sa.BigInteger(), nullable=False),
        sa.Column('tier1_status', sa.String(length=20), nullable=True),
        sa.Column('tier1_started_at', sa.DateTime(), nullable=True),
        sa.Column('tier1_completed_at', sa.DateTime(), nullable=True),
        sa.Column('tier2_status', sa.String(length=20), nullable=True),
        sa.Column('tier2_started_at', sa.DateTime(), nullable=True),
        sa.Column('tier2_completed_at', sa.DateTime(), nullable=True),
        sa.Column('tier3_status', sa.String(length=20), nullable=True),
        sa.Column('tier3_started_at', sa.DateTime(), nullable=True),
        sa.Column('tier3_completed_at', sa.DateTime(), nullable=True),
        sa.Column('blocked_at_tier', sa.SmallInteger(), nullable=True),
        sa.Column('final_risk_score', sa.Integer(), nullable=True),
        sa.Column('final_risk_level', sa.String(length=20), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_scan_jobs_commit_sha', 'scan_jobs', ['commit_sha'])

    op.create_table(
        'users',
        sa.Column(
            'id', sa.UUID(),
            server_default=sa.text('(gen_random_uuid())'), nullable=False,
        ),
        sa.Column('username', sa.String(length=255), nullable=False),
        sa.Column('password', sa.Text(), nullable=False),
        sa.Column('email', sa.String(length=500), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
    )
    op.create_table(
        'refresh_tokens',
        sa.Column(
            'id', sa.UUID(),
            server_default=sa.text('(gen_random_uuid())'), nullable=False,
        ),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('token_hash', sa.Text(), nullable=False),
        sa.Column(
            'family_id', sa.UUID(),
            server_default=sa.text('(gen_random_uuid())'), nullable=False,
        ),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked', sa.Boolean(), nullable=False),
        sa.Column(
            'created_at', sa.DateTime(timezone=True),
            server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False,
        ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash'),
    )
    op.create_table(
        'remediations',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('finding_id', sa.Uuid(), nullable=False),
        sa.Column('scan_job_id', sa.Uuid(), nullable=False),
        sa.Column('patch_diff', sa.Text(), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=True),
        sa.Column('requires_secret_rotation', sa.Boolean(), nullable=False),
        sa.Column('rotation_instructions', sa.Text(), nullable=True),
        sa.Column('github_comment_id', sa.BigInteger(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('approved_by', sa.String(length=100), nullable=True),
        sa.Column('approved_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id']),
        sa.ForeignKeyConstraint(['scan_job_id'], ['scan_jobs.id']),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('remediations')
    op.drop_table('refresh_tokens')
    op.drop_table('users')
    op.drop_index('idx_scan_jobs_commit_sha', table_name='scan_jobs')
    op.drop_table('scan_jobs')
    op.drop_index('idx_findings_verified_secrets', table_name='findings')
    op.drop_index('idx_findings_severity', table_name='findings')
    op.drop_index('idx_findings_commit_sha', table_name='findings')
    op.drop_table('findings')
