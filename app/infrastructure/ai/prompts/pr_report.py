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


# Teto de findings embutidos no prompt.
#
# O relatório do Tier 3 estourou a janela de contexto: **357.218 tokens contra
# 200.000** de limite. A causa foi o ZAP passar a funcionar — 369 alertas, cada
# um com seu `raw_output` (o JSON bruto do scanner) serializado inteiro. O
# gargalo existia desde sempre; estava escondido atrás de outro defeito, porque
# o ZAP sempre devolvia zero.
#
# 40 é o que cabe num relatório que alguém lê, e a ordenação por severidade
# garante que sejam os 40 que importam. Mandar 369 não faria o modelo raciocinar
# melhor — faria a chamada falhar, que é o pior dos resultados.
_MAX_FINDINGS_NO_PROMPT = 40

# `raw_output` é o payload bruto do scanner: o maior contribuinte de tokens e o
# menos útil para o modelo, que já recebe título, severidade, arquivo e CWE.
_CAMPOS_DESCARTADOS = ("raw_output",)

# Descrição de alerta do ZAP costuma ter parágrafos de recomendação genérica.
_MAX_DESCRICAO = 400

_RANK_SEVERIDADE = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _enxugar_findings(analysis: dict) -> dict:
    """Corta o volume de findings mantendo os mais severos, e diz o que cortou.

    Devolve a análise com `findings` limitado e um `findings_resumo` explicando
    quantos ficaram de fora e em quais severidades — para o modelo não concluir
    que viu tudo, e para o relatório poder dizer isso a quem lê.
    """
    findings = analysis.get("findings") or []
    if not isinstance(findings, list) or not findings:
        return analysis

    ordenados = sorted(
        findings,
        key=lambda f: _RANK_SEVERIDADE.get(
            str((f or {}).get("severity", "")).lower(), 0
        ),
        reverse=True,
    )
    incluidos = ordenados[:_MAX_FINDINGS_NO_PROMPT]

    enxutos = []
    for f in incluidos:
        if not isinstance(f, dict):
            continue
        copia = {k: v for k, v in f.items() if k not in _CAMPOS_DESCARTADOS}
        descricao = copia.get("description")
        if isinstance(descricao, str) and len(descricao) > _MAX_DESCRICAO:
            copia["description"] = descricao[:_MAX_DESCRICAO] + "… (truncado)"
        enxutos.append(copia)

    resultado = {**analysis, "findings": enxutos}

    omitidos = len(findings) - len(incluidos)
    if omitidos > 0:
        por_severidade: dict[str, int] = {}
        for f in ordenados[_MAX_FINDINGS_NO_PROMPT:]:
            sev = str((f or {}).get("severity", "desconhecida")).lower()
            por_severidade[sev] = por_severidade.get(sev, 0) + 1
        resultado["findings_resumo"] = {
            "total": len(findings),
            "incluidos_no_prompt": len(incluidos),
            "omitidos": omitidos,
            "omitidos_por_severidade": por_severidade,
            "criterio": "os mais severos primeiro",
        }
    return resultado


def build(analysis: dict, context: dict | None = None) -> str:
    """Constrói o user prompt a partir da análise estruturada.

    ``analysis`` deve seguir o schema retornado por
    ``chain_of_events.SYSTEM``. ``context`` aceita ``{"commit",
    "pr_number", "repo"}`` opcionalmente.

    Os findings são enxugados antes de serializar — ver ``_enxugar_findings``.
    """
    ctx = context or {}
    header = (
        f"Repositório: {ctx.get('repo', 'N/A')}\n"
        f"PR: #{ctx.get('pr_number', '—')}\n"
        f"Commit: {ctx.get('commit', 'N/A')}\n\n"
    )
    return header + "Análise estruturada (JSON):\n" + json.dumps(
        _enxugar_findings(analysis), indent=2, ensure_ascii=False
    )
