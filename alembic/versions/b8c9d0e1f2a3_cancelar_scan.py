"""Guarda a raiz do canvas Celery, para poder cancelar uma execucao.

Ate aqui nao havia como interromper um scan: o pipeline era disparado e o id
que o Celery devolve era descartado. Sem ele, "cancelar" so' conseguiria mexer
no banco — as tarefas que ja' estavam na fila continuariam rodando e
sobrescreveriam o estado logo depois, e o usuario veria o scan "voltar a
andar" sozinho.

A coluna guarda o id da RAIZ do canvas. Revogar a raiz com `terminate=True`
alcanca a cadeia inteira, inclusive o que ainda nao comecou.

Nada e' preenchido retroativamente: execucao anterior a esta migration fica com
`NULL` e nao pode ser cancelada — a rota responde 409 dizendo isso, em vez de
fingir que cancelou.

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-09-28

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b8c9d0e1f2a3"
down_revision: Union[str, Sequence[str], None] = "a7b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # 155: o teto do id de task do Celery (uuid + prefixo de fila).
    op.add_column("scan_jobs", sa.Column("celery_task_id", sa.String(length=155), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scan_jobs", "celery_task_id")
