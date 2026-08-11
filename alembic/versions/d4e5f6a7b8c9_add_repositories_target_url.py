"""add_repositories_target_url

Adiciona ``repositories.target_url`` — a URL onde aquele repositório está
publicado (staging/preview). É a origem que faltava para o DAST: o Tier 3 já
chamava ``ZAPScanner.run_safe(target_url=...)``, mas ``dispatch_pipeline``
passava ``None`` fixo porque não havia onde guardar o endereço da aplicação.

**Por que ``target_url`` e não ``app_url``/``deploy_url``:** este é exatamente
o nome que o valor já tem em todo o resto do caminho —
``dispatch_pipeline(target_url=)`` → ``build_pipeline_canvas(target_url=)`` →
``_prepare_tier3_payload(target_url=)`` → ``run_tier3_scan(target_url=)`` →
``ZAPScanner.scan(target_url=)``. Escolher outro nome criaria uma tradução
numa das pontas e um segundo vocabulário para a mesma coisa. O prefixo
"target" também diz *o que a URL é* neste domínio: o alvo do scan — o que a
distingue de ``repositories.url``, que é o endereço do repositório no GitHub.

**Nullable:** a maioria dos repositórios não tem deploy conhecido. Ausência é
o estado normal, não pendência de preenchimento — o Tier 3 pula o ZAP com
``reason="no_target_url"``, que é o comportamento de hoje para todos.

Sem valor default e sem backfill: nenhuma linha existente tem uma URL de
aplicação que possamos inferir, e inventar uma faria o pipeline atacar um
alvo que ninguém autorizou.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-08-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, Sequence[str], None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("repositories", sa.Column("target_url", sa.Text(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("repositories", "target_url")
