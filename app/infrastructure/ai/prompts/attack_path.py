"""Prompt de attack path (Tier 3) — Sonnet.

Recebe findings + CTI enriquecido + resultado da emulação Caldera e
constrói o caminho de ataque completo com TTPs MITRE como
estrutura central.

Blindagem (mesmo padrão da Semana 6):

- SYSTEM proíbe inventar dados; se CTI ou Caldera estiverem ausentes
  no user prompt, o modelo deve retornar ``"cti_status":
  "unavailable"`` / ``"caldera_status": "unavailable"`` no JSON e
  NÃO mencionar atores, campanhas ou exploração comprovada.
- ``build()`` injeta sentinelas explícitos para dicts vazios em vez
  de strings vazias / "None" — strings vazias têm histórico de
  serem gatilho de alucinação.
- O LLM Guard é aplicado pelo ``ClaudeClient.call_json()`` antes de
  chamar a API (decisão #3 da Semana 10) — payloads crafted em
  campos de findings/Caldera/CTI são bloqueados upstream.
"""
from __future__ import annotations


SYSTEM = """Você é um red team operator sênior. Sua tarefa: a partir dos findings, dados de threat intelligence (CTI) e resultados da emulação Caldera, construa o caminho de ataque mais provável e impactante.

Mapeie cada passo para uma técnica MITRE ATT&CK (formato TXXXX). Use os TTPs do CTI e da emulação Caldera como insumo principal — não invente técnicas que não aparecem nos dados fornecidos.

REGRAS INVIOLÁVEIS:
1. Use APENAS dados fornecidos. NÃO invente CVEs, TTPs, IOCs, atores, valores de risco.
2. Se "Dados CTI" disser "sem dados CTI disponíveis", retorne "cti_status": "unavailable" e NÃO mencione campanhas, grupos ou atores.
3. Se "Dados Caldera" disser "sem dados de emulação Caldera disponíveis", retorne "caldera_status": "unavailable" e NÃO afirme que a exploração foi validada.
4. Quando não houver findings suficientes para construir attack path plausível, retorne attack_path vazio e prioritized_actions explicando o motivo.
5. "caldera_validated" é EXCLUSIVO da emulação Caldera. O bloco "Validação por evidência" é um eixo SEPARADO (segredo verificado, active scan, observação direta) e NÃO alimenta esse campo — mas NÃO afirme que um finding marcado ali como CONFIRMADO é não validado: ele foi confirmado contra o alvo por outra via.
6. Responda em PORTUGUÊS BRASILEIRO nos campos textuais.

Formato de saída — JSON ESTRITAMENTE neste schema, sem markdown fences:
{
  "attack_path": [
    {
      "step": <int>,
      "phase": "initial_access" | "execution" | "persistence" | "privilege_escalation" | "defense_evasion" | "credential_access" | "discovery" | "lateral_movement" | "collection" | "exfiltration" | "impact",
      "technique": "<TXXXX>",
      "description": "<string curta em PT-BR>",
      "finding_ids": ["<uuid|título>", ...],
      "caldera_validated": <bool>
    }
  ],
  "kill_chain_complete": <bool>,
  "prioritized_actions": [
    {"priority": <int 1-N>, "action": "<string PT-BR>", "rationale": "<string PT-BR>"}
  ],
  "risk_score_adjusted": {"score": <int 0-100>, "level": "critical" | "high" | "medium" | "low" | "info"},
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
        cve = f.get("cve_id", "—")
        lines.append(
            f"- [{severity}] {source}: {title} "
            f"(CVE: {cve}, arquivo: {file_path}:{line_number})"
        )
    return "\n".join(lines)


def _format_cti(cti_data: dict | None) -> str:
    if not cti_data:
        return _NO_CTI
    parts: list[str] = []
    if "active_threat" in cti_data:
        parts.append(f"ameaça ativa: {bool(cti_data['active_threat'])}")
    if "mitre_techniques" in cti_data:
        ttps = cti_data["mitre_techniques"]
        if isinstance(ttps, list) and ttps:
            parts.append("TTPs do CTI: " + ", ".join(map(str, ttps)))
    if "cvss_base" in cti_data and cti_data["cvss_base"] is not None:
        parts.append(f"CVSS base: {cti_data['cvss_base']}")
    if not parts:
        return _NO_CTI
    return "; ".join(parts)


def _format_caldera(caldera_results: dict | None) -> str:
    if not caldera_results:
        return _NO_CALDERA
    status = caldera_results.get("status")
    if status == "failed":
        return _NO_CALDERA
    parts: list[str] = []
    if "success_rate" in caldera_results:
        try:
            parts.append(
                f"taxa de sucesso: {float(caldera_results['success_rate']):.0%}"
            )
        except (TypeError, ValueError):
            pass
    if "ttps_used" in caldera_results:
        ttps = caldera_results["ttps_used"]
        if isinstance(ttps, list) and any(ttps):
            valid = [str(t) for t in ttps if t]
            parts.append("TTPs executadas: " + ", ".join(valid))
    if "caldera_validated" in caldera_results:
        parts.append(
            f"validado por emulação: {bool(caldera_results['caldera_validated'])}"
        )
    if not parts:
        return _NO_CALDERA
    return "; ".join(parts)


def _format_validacao(validacao: dict | None) -> str:
    """Validacao por evidencia (deterministica), para o modelo nao declarar
    "nao validado" sobre o que a cadeia de ferramentas ja confirmou."""
    if not validacao or not validacao.get("grupos"):
        return "sem sinal de validacao por evidencia"
    partes: list[str] = []
    for g in validacao["grupos"]:
        selo = "CONFIRMADO" if g.get("confirmado") else "nao confirmado"
        exemplos = ", ".join(g.get("exemplos") or [])
        partes.append(
            f"{g.get('rotulo')} [{selo}] — {g.get('total')} finding(s)"
            + (f" (ex.: {exemplos})" if exemplos else "")
        )
    return "; ".join(partes)


def build(
    findings: list[dict],
    cti_data: dict | None,
    caldera_results: dict | None,
    context: dict | None = None,
    validacao: dict | None = None,
) -> str:
    ctx = context or {}
    commit = ctx.get("commit", "N/A")
    return (
        f"Commit: {commit}\n\n"
        f"Findings ({len(findings)}):\n{_format_findings(findings)}\n\n"
        f"Dados CTI: {_format_cti(cti_data)}\n\n"
        f"Dados Caldera: {_format_caldera(caldera_results)}\n\n"
        f"Validacao por evidencia: {_format_validacao(validacao)}\n"
    )
