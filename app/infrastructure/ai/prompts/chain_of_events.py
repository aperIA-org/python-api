"""Prompt de chain-of-events (Tier 2).

Blindagem contra alucinação:

1. O SYSTEM instrui explicitamente o modelo a NÃO inventar dados de
   CTI ou Caldera quando ausentes — deve usar ``"cti_status":
   "unavailable"`` e ``"caldera_status": "unavailable"`` no JSON de
   resposta.
2. ``build()`` injeta sentinelas claros (``"sem dados CTI
   disponíveis nesta análise"``, ``"sem dados de emulação Caldera
   disponíveis"``) em vez de string vazia / "None" — strings vazias
   foram mostradas em testes como gatilho para o modelo "preencher"
   com plausibilidade.
3. ``risk_score`` ausente faz fallback explícito em vez de Claude
   adivinhar — o caller (`RiskScorer`) é a fonte de verdade.

O `findings` é injetado como lista resumida; o conteúdo bruto vai
para o LLM Guard antes de chegar aqui.
"""
from __future__ import annotations

SYSTEM = """Você é um analista de segurança ofensiva sênior atuando em modo red team.

Sua tarefa: correlacionar findings de segurança e construir uma cadeia de eventos de ataque possíveis. Mapeie cada passo para uma técnica MITRE ATT&CK quando aplicável (formato TXXXX).

REGRAS INVIOLÁVEIS:
1. Use APENAS dados fornecidos no prompt do usuário. NÃO invente CVEs, TTPs, IOCs, valores de risco, ou nomes de campanhas.
2. Se o bloco "Dados CTI" disser "sem dados CTI disponíveis", retorne "cti_status": "unavailable" no JSON e NÃO mencione campanhas ativas, atores ou grupos.
3. Se o bloco "Dados Caldera" disser "sem dados de emulação Caldera disponíveis", retorne "caldera_status": "unavailable" e NÃO afirme se a exploração teve sucesso.
4. Quando não houver findings suficientes para uma cadeia plausível, retorne event_chain vazio e attack_narrative explicando o motivo.
5. Responda em PORTUGUÊS BRASILEIRO no campo attack_narrative.
6. Em "technique" e "technique_parent" escreva SOMENTE o identificador (ex.: "T1059.007", "T1059") — sem nome da técnica, sem parênteses, sem texto em volta. O campo é consumido por máquina: qualquer texto extra faz a emulação não encontrar a técnica.

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
  "attack_narrative": "<string>",
  "cti_status": "available" | "unavailable",
  "caldera_status": "available" | "unavailable"
}"""


_NO_CTI = "sem dados CTI disponíveis nesta análise"
_NO_CALDERA = "sem dados de emulação Caldera disponíveis"


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


def _format_cti(cti_data: dict | None) -> str:
    if not cti_data:
        return _NO_CTI
    # Renderiza apenas chaves esperadas — evita propagar payload
    # arbitrário do OpenCTI até o prompt.
    parts: list[str] = []
    if "active_campaigns" in cti_data:
        parts.append(f"campanhas ativas: {bool(cti_data['active_campaigns'])}")
    if "ttps" in cti_data:
        ttps = cti_data["ttps"]
        if isinstance(ttps, list) and ttps:
            parts.append("TTPs observadas: " + ", ".join(map(str, ttps)))
    if not parts:
        return _NO_CTI
    return "; ".join(parts)


def _format_caldera(caldera_results: dict | None) -> str:
    if not caldera_results:
        return _NO_CALDERA
    parts: list[str] = []
    if "success_rate" in caldera_results:
        parts.append(f"taxa de sucesso: {caldera_results['success_rate']:.0%}")
    if "techniques_executed" in caldera_results:
        execs = caldera_results["techniques_executed"]
        if isinstance(execs, list) and execs:
            parts.append("técnicas executadas: " + ", ".join(map(str, execs)))
    if not parts:
        return _NO_CALDERA
    return "; ".join(parts)


def build(
    findings: list[dict],
    cti_data: dict | None,
    caldera_results: dict | None,
    context: dict | None = None,
) -> str:
    """Constrói o user prompt para chain-of-events.

    O argumento ``context`` aceita ``{"commit": <sha>}`` opcionalmente.
    """
    ctx = context or {}
    commit = ctx.get("commit", "N/A")
    return (
        f"Commit: {commit}\n\n"
        f"Findings ({len(findings)}):\n{_format_findings(findings)}\n\n"
        f"Dados CTI: {_format_cti(cti_data)}\n\n"
        f"Dados Caldera: {_format_caldera(caldera_results)}\n"
    )
