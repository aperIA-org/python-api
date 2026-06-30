"""Prompt de PR report (Tier 2).

Recebe a análise estruturada (output do chain_of_events) e gera
markdown amigável para o desenvolvedor. Roda em Haiku — é formatação,
não reasoning novo.

Blindagem: o SYSTEM instrui o modelo a refletir EXATAMENTE os
campos da análise, sem inferir conclusões adicionais.
"""
from __future__ import annotations

import json

SYSTEM = """Você é um redator técnico que transforma análises estruturadas de segurança em relatórios markdown claros para desenvolvedores.

REGRAS:
1. Reflita EXATAMENTE os campos fornecidos. NÃO infira conclusões adicionais nem invente dados.
2. Se "cti_status" == "unavailable", NÃO mencione campanhas ou atores.
3. Se "caldera_status" == "unavailable", NÃO afirme exploração bem-sucedida.
4. Tom: direto, acionável, em português brasileiro.
5. Tamanho: máximo 25 linhas de markdown.

Formato:
## 🛡️ aperIA — Análise de Segurança (Tier 2)

**Risk Score:** <score>/100 (<level>)

**Resumo do ataque:**
<attack_narrative resumido em 2-4 linhas>

**Cadeia de eventos:**
1. [<TTP ou —>] <descrição>
2. ...

**Impacto de negócio:**
<business_impact.description>

**Status de inteligência:**
- CTI: <available|unavailable>
- Caldera: <available|unavailable>"""


def build(analysis: dict, context: dict | None = None) -> str:
    """Constrói o user prompt a partir da análise estruturada.

    ``analysis`` deve seguir o schema retornado por
    ``chain_of_events.SYSTEM``. ``context`` aceita ``{"commit",
    "pr_number", "repo"}`` opcionalmente.
    """
    ctx = context or {}
    header = (
        f"Repositório: {ctx.get('repo', 'N/A')}\n"
        f"PR: #{ctx.get('pr_number', '—')}\n"
        f"Commit: {ctx.get('commit', 'N/A')}\n\n"
    )
    return header + "Análise estruturada (JSON):\n" + json.dumps(
        analysis, indent=2, ensure_ascii=False
    )
