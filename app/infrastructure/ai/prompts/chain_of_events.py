"""Prompt de chain-of-events (Tier 2).

**CTI e Caldera não entram aqui, por desenho.** Os dois rodam no Tier 3 — o
enriquecimento do OpenCTI e a emulação do Caldera acontecem depois desta
análise, não antes. O prompt já carregou blocos "Dados CTI"/"Dados Caldera" e
campos `cti_status`/`caldera_status` no schema de saída, mas o único chamador em
produção (`_bridge_t1_findings_into_analyze`) nunca passou esses dados: os
blocos diziam sempre "sem dados disponíveis" e o relatório do Tier 2 fechava com
um rodapé fixo de `unavailable`/`unavailable`. Era ruído que ocupava contexto e
sugeria ao leitor que algo tinha falhado, quando nada tinha sido tentado.

Blindagem contra alucinação que segue valendo:

1. O SYSTEM manda refletir apenas o que está no prompt — nada de CVE, TTP, IOC
   ou nome de campanha inventado.
2. ``risk_score`` ausente faz fallback explícito em vez de Claude adivinhar — o
   caller (`RiskScorer`) é a fonte de verdade.

O `findings` é injetado como lista resumida; o conteúdo bruto vai
para o LLM Guard antes de chegar aqui.
"""
from __future__ import annotations

from app.infrastructure.ai.prompts._findings_limit import limitar

SYSTEM = """Você é um analista de segurança ofensiva sênior atuando em modo red team.

Sua tarefa: correlacionar findings de segurança e construir uma cadeia de eventos de ataque possíveis. Mapeie cada passo para uma técnica MITRE ATT&CK quando aplicável (formato TXXXX).

REGRAS INVIOLÁVEIS:
1. Use APENAS dados fornecidos no prompt do usuário. NÃO invente CVEs, TTPs, IOCs, valores de risco, ou nomes de campanhas.
2. NÃO mencione campanhas ativas, atores ou grupos de ameaça, e NÃO afirme que uma exploração teve sucesso: esta análise não recebe inteligência externa nem resultado de emulação.
3. Quando não houver findings suficientes para uma cadeia plausível, retorne event_chain vazio e attack_narrative explicando o motivo.
4. Responda em PORTUGUÊS BRASILEIRO no campo attack_narrative.
5. Em "technique" e "technique_parent" escreva SOMENTE o identificador (ex.: "T1059.007", "T1059") — sem nome da técnica, sem parênteses, sem texto em volta. O campo é consumido por máquina: qualquer texto extra faz a emulação não encontrar a técnica.

Formato de saída — JSON estritamente neste schema, sem markdown fences:
{
  "event_chain": [
    {
      "step": <int>,
      "technique": "<TXXXX ou TXXXX.YYY, o ID MITRE MAIS ESPECIFICO que a evidencia sustenta, ou null>",
      "technique_parent": "<TXXXX, a tecnica-pai de technique; igual a technique quando ela ja for pai; null se technique for null>",
      "description": "<string curta>",
      "finding_ids": ["<uuid|título>", ...]
    }
  ],
  "risk_score": {
    "score": <int 0-100>,
    "level": "critical" | "high" | "medium" | "low" | "info"
  },
  "business_impact": {
    "description": "<string>",
    "estimated_cost_brl": <float ou null>
  },
  "attack_narrative": "<string>"
}"""


def _format_findings(findings: list[dict]) -> str:
    if not findings:
        return "(nenhum finding fornecido)"
    lines: list[str] = []
    for f in findings:
        severity = str(f.get("severity", "?")).upper()
        source = f.get("source", "?")
        title = f.get("title", "?")
        file_path = f.get("file_path", "N/A")
        line_number = f.get("line_number", "?")
        lines.append(
            f"- [{severity}] {source}: {title} "
            f"(arquivo: {file_path}:{line_number})"
        )
    return "\n".join(lines)


def build(findings: list[dict], context: dict | None = None) -> str:
    """Constrói o user prompt para chain-of-events.

    O argumento ``context`` aceita ``{"commit": <sha>}`` opcionalmente.

    Os findings passam por ``_findings_limit.limitar`` — ver o módulo para o
    porquê. A contagem exibida é a **total**, não a da amostra: dizer
    "Findings (60)" quando o commit tem 102 seria esconder o corte do próprio
    modelo que precisa saber dele.
    """
    ctx = context or {}
    commit = ctx.get("commit", "N/A")
    incluidos, nota = limitar(findings)
    cabecalho = f"Commit: {commit}\n\n"
    if nota:
        cabecalho += f"{nota}\n\n"
    return (
        f"{cabecalho}"
        f"Findings ({len(findings)}):\n{_format_findings(incluidos)}\n"
    )
