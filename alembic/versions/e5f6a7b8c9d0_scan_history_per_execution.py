"""scan_history_per_execution

Uma linha de ``scan_jobs`` passa a ser uma EXECUÇÃO, não um commit.

Antes: ``UNIQUE(scan_jobs.commit_sha)`` e ``UNIQUE(scan_reports.commit_sha,
tier)``. Rescanear a mesma branch sem commit novo reaproveitava a linha
(``restart_execution``) e o upsert do relatório sobrescrevia o markdown
anterior — o histórico simplesmente não existia.

O UNIQUE em ``commit_sha`` não era decoração: ele viabilizava o upsert
idempotente (dois webhooks para o mesmo push não podem gerar dois pipelines).
Essa garantia continua, mas passa a ser expressa pelo que ela realmente
significa — **no máximo uma execução EM ANDAMENTO por commit**. Execuções
encerradas não conflitam mais, e é exatamente isso que libera o histórico.

``scan_reports`` passa a pertencer à execução (``scan_job_id``), não ao commit.
O ``commit_sha`` continua na tabela como atalho de leitura/diagnóstico.

``findings`` NÃO muda: eles continuam escopados pelo commit. Reexecutar o mesmo
commit analisa o mesmo código, então o conjunto de findings é uma propriedade do
commit; o que varia entre execuções (status dos tiers, risco final, markdown) é
o que passa a ser historiado aqui.

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-08-02 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "e5f6a7b8c9d0"
down_revision: Union[str, Sequence[str], None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Um tier "vivo" é o que ainda pode progredir. Precisa bater com
# ``STATUS_EM_ANDAMENTO`` em app/domain/scan/entities.py — o índice parcial
# abaixo é a versão SQL da mesma regra.
_EM_ANDAMENTO = """(
    tier1_status IN ('queued', 'running')
    OR tier2_status IN ('queued', 'running')
    OR tier3_status IN ('queued', 'running')
)"""

_UQ_EM_ANDAMENTO = "uq_scan_jobs_commit_em_andamento"


def upgrade() -> None:
    """Upgrade schema."""
    # ── scan_jobs: várias execuções por commit, uma viva por vez ────────────
    op.drop_constraint("scan_jobs_commit_sha_key", "scan_jobs", type_="unique")
    op.execute(
        f"CREATE UNIQUE INDEX {_UQ_EM_ANDAMENTO} "
        f"ON scan_jobs (commit_sha) WHERE {_EM_ANDAMENTO}"
    )
    # A listagem ordena por COALESCE(tier1_started_at, created_at) desc; sem
    # este índice ela vira sort em cima de scan sequencial conforme o histórico
    # cresce (antes não crescia: era uma linha por commit).
    op.execute(
        "CREATE INDEX idx_scan_jobs_executado_em ON scan_jobs "
        "(COALESCE(tier1_started_at, created_at) DESC)"
    )

    # ── scan_reports: o relatório é da execução ─────────────────────────────
    # Backfill antes de exigir NOT NULL. Relatórios órfãos (commit sem job) não
    # são alcançáveis por nenhuma rota — a API sempre chega neles a partir de um
    # ScanJob —, então não há como preservá-los sob a nova chave.
    op.execute(
        """
        UPDATE scan_reports r
           SET scan_job_id = j.id
          FROM scan_jobs j
         WHERE r.scan_job_id IS NULL
           AND j.commit_sha = r.commit_sha
        """
    )
    op.execute("DELETE FROM scan_reports WHERE scan_job_id IS NULL")

    op.drop_constraint("scan_reports_commit_tier_key", "scan_reports", type_="unique")
    op.alter_column("scan_reports", "scan_job_id", nullable=False)
    op.create_foreign_key(
        "scan_reports_scan_job_id_fkey",
        "scan_reports",
        "scan_jobs",
        ["scan_job_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_unique_constraint(
        "scan_reports_job_tier_key", "scan_reports", ["scan_job_id", "tier"]
    )
    # O detalhe do relatório e o histórico buscam por commit; o índice cobre
    # ambos sem depender do UNIQUE que acabou de sair.
    op.create_index("idx_scan_reports_commit_sha", "scan_reports", ["commit_sha"])


def downgrade() -> None:
    """Downgrade schema.

    A volta é lossy por natureza: o esquema antigo comporta um relatório por
    (commit, tier) e um job por commit. As execuções extras são descartadas,
    mantendo a mais recente de cada commit.
    """
    op.drop_index("idx_scan_reports_commit_sha", table_name="scan_reports")
    op.drop_constraint("scan_reports_job_tier_key", "scan_reports", type_="unique")
    op.drop_constraint(
        "scan_reports_scan_job_id_fkey", "scan_reports", type_="foreignkey"
    )
    op.alter_column("scan_reports", "scan_job_id", nullable=True)

    # Descarta o histórico, preservando a execução mais recente de cada commit.
    op.execute(
        """
        DELETE FROM scan_jobs j
         WHERE EXISTS (
               SELECT 1 FROM scan_jobs mais_novo
                WHERE mais_novo.commit_sha = j.commit_sha
                  AND (
                      COALESCE(mais_novo.tier1_started_at, mais_novo.created_at),
                      mais_novo.id
                  ) > (
                      COALESCE(j.tier1_started_at, j.created_at),
                      j.id
                  )
         )
        """
    )
    op.create_unique_constraint(
        "scan_reports_commit_tier_key", "scan_reports", ["commit_sha", "tier"]
    )

    op.execute(f"DROP INDEX IF EXISTS {_UQ_EM_ANDAMENTO}")
    op.execute("DROP INDEX IF EXISTS idx_scan_jobs_executado_em")
    op.create_unique_constraint(
        "scan_jobs_commit_sha_key", "scan_jobs", ["commit_sha"]
    )
