"""refresh_token_revoked_at

Adiciona ``refresh_tokens.revoked_at`` para a janela de graca de rotacao.

Sem ela, refreshes concorrentes do mesmo token (varias requisicoes em voo quando
o access de 15min expira, tipico durante o polling de um scan) faziam so um
rotacionar e os outros levarem 401 -> o middleware do front zerava os cookies e
deslogava o usuario. Com o ``revoked_at``, um token revogado ha poucos segundos
(por rotacao) e reconhecido como replay benigno; um revogado ha muito tempo
continua sendo reuso e invalida a familia.

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-08-02 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "f6a7b8c9d0e1"
down_revision: Union[str, Sequence[str], None] = "e5f6a7b8c9d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "refresh_tokens",
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("refresh_tokens", "revoked_at")
