"""scan_tool_runs

Cria ``scan_tool_runs`` — o desfecho de CADA ferramenta do pipeline dentro de
uma execução (TruffleHog, Semgrep changed/full, Trivy, Prowler, ZAP, threat
intel, Caldera e os dois passos de I.A).

Por que a tabela existe: ``scan_jobs`` só guarda ``tier{1,2,3}_status``, e
``BaseScanner.run_safe`` engole a exceção e devolve ``[]`` — então "o Trivy
rodou e não achou nada" e "o Trivy quebrou" chegavam ao banco como exatamente a
mesma coisa. Os motivos de pulo que o pipeline já decide (``no_iac_files`` do
Prowler, ``no_target_url`` do ZAP) também só existiam na linha do structlog.

A chave é ``(scan_job_id, tool)``, não ``commit_sha``: rescanear a mesma branch
empilha uma execução nova, e chavear pelo sha faria o upsert apagar o resultado
da execução anterior — o mesmo erro que ``scan_reports`` já corrigiu.

Nada é backfillado. Execuções anteriores a esta migration simplesmente não têm
linhas, e a API responde com a lista vazia; o front continua caindo para o
status do tier nesse caso.

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-08-17 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7b8c9d0e1f2'
down_revision: Union[str, Sequence[str], None] = 'f6a7b8c9d0e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "scan_tool_runs",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("scan_job_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("commit_sha", sa.String(length=40), nullable=False),
        sa.Column("tier", sa.SmallInteger(), nullable=False),
        sa.Column("tool", sa.String(length=40), nullable=False),
        # Texto, não ENUM: o conjunto de status ainda deve crescer conforme o
        # pipeline ganha etapas, e ampliar um ENUM do Postgres exige ALTER TYPE
        # em migration. Mesmo tratamento de `scan_jobs.tier*_status`.
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.String(length=200), nullable=True),
        # NULL = a ferramenta não produz finding (I.A, threat intel, Caldera).
        # Diferente de 0, que é "rodou e não achou nada".
        sa.Column("findings_count", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_job_id", "tool", name="scan_tool_runs_job_tool_key"),
    )
    op.create_index("idx_scan_tool_runs_commit_sha", "scan_tool_runs", ["commit_sha"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("idx_scan_tool_runs_commit_sha", table_name="scan_tool_runs")
    op.drop_table("scan_tool_runs")
