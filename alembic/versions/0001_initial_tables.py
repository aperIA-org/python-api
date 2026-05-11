"""initial tables — scan_jobs e findings

Revision ID: 0001
Revises:
Create Date: 2026-05-10
"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("commit_sha", sa.String(40), nullable=False),
        sa.Column("repo_url", sa.String(), nullable=False),
        sa.Column("pr_number", sa.Integer(), nullable=True),
        sa.Column("installation_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("error_message", sa.String(), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_scan_jobs_commit_sha", "scan_jobs", ["commit_sha"])
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("cve_id", sa.String(50), nullable=True),
        sa.Column("cwe_id", sa.String(50), nullable=True),
        sa.Column("file_path", sa.String(), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("asset", sa.String(), nullable=True),
        sa.Column("asset_criticality", sa.String(20), nullable=True),
        sa.Column("secret_verified", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("secret_type", sa.String(100), nullable=True),
        sa.Column("raw_output", postgresql.JSON(), nullable=True),
        sa.Column("ttp_ids", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("commit_sha", sa.String(40), nullable=False),
        sa.Column("repo_url", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_findings_commit_sha", "findings", ["commit_sha"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_source", "findings", ["source"])
    op.create_index("ix_findings_secret_verified", "findings", ["secret_verified"])
    op.create_index("ix_findings_cve_id", "findings", ["cve_id"])


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("scan_jobs")
