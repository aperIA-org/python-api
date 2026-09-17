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

from app.infrastructure.ai.prompts._findings_limit import limitar


SYSTEM = """Você é um red team operator sênior. Sua tarefa: a partir dos findings, dados de threat intelligence (CTI) e resultados da emulação Caldera, construa o caminho de ataque mais provável e impactante.

Mapeie cada passo para uma técnica MITRE ATT&CK (formato TXXXX). Use os TTPs do CTI e da emulação Caldera como insumo principal — não invente técnicas que não aparecem nos dados fornecidos.

REGRAS INVIOLÁVEIS:
1. Use APENAS dados fornecidos. NÃO invente CVEs, TTPs, IOCs, atores, valores de risco.
2. Se "Dados CTI" disser "sem dados CTI disponíveis", retorne "cti_status": "unavailable" e NÃO mencione campanhas, grupos ou atores.
3. Se "Dados Caldera" disser "sem dados de emulação Caldera disponíveis", retorne "caldera_status": "unavailable" e NÃO afirme que a exploração foi validada.
4. Quando não houver findings suficientes para construir attack path plausível, retorne attack_path vazio e prioritized_actions explicando o motivo.
5. "caldera_validated" é EXCLUSIVO da emulação Caldera. O bloco "Validação por evidência" é um eixo SEPARADO (segredo verificado, active scan, observação direta) e NÃO alimenta esse campo — mas NÃO afirme que um finding marcado ali como CONFIRMADO é não validado: ele foi confirmado contra o alvo por outra via.
6. Responda em PORTUGUÊS BRASILEIRO nos campos textuais.
7. "attack_chains" agrupa os passos em CADEIAS: cada cadeia é um caminho de ponta a ponta, com título "origem → destino" e os passos em ordem. Uma cadeia por rota de ataque distinta; não quebre a mesma rota em duas nem junte rotas que não se encontram.
8. "outcome" de cada passo é FATO, não expectativa, e as quatro opções significam coisas diferentes: "emulado" = o Caldera executou o movimento e ele funcionou; "bloqueado" = o Caldera executou e um controle conteve o movimento (isso é uma DEFESA que funcionou, e tem de aparecer como tal); "nao_emulado" = o Caldera não teve como tentar (sem alvo, sem agente); "projecao" = ninguém executou, a cadeia é inferência sua a partir dos findings. Se "Dados Caldera" disser que não há emulação, NENHUM passo pode ser "emulado" nem "bloqueado" — todos são "projecao" ou "nao_emulado".
9. "business_impact" é a TRADUÇÃO do risco técnico para quem decide: o que estes findings significam para a operação, para os dados e para os compromissos da empresa. Proibido jargão — sem CVE, sem TTP, sem nome de ferramenta, sem "CVSS". Diga o que acontece e para quem. Cada item de "areas" é um efeito de negócio distinto; não repita o mesmo efeito com outras palavras, e não invente área que os findings não sustentem (2 a 4 itens costuma ser o certo). "regulatory" só quando os dados envolvidos de fato implicarem obrigação (dado pessoal, cartão, saúde); caso contrário, null.
10. "executive_verdict", "remediation_effort" e "recommended_deadline" saem do que está NOS DADOS (severidade dos findings, KEV/EPSS, validação do Caldera, quantos arquivos e componentes são tocados) — nunca de suposição sobre o time, a empresa ou o processo de release. "days" é um número de dias corridos a partir de agora, não uma data. Se os findings não sustentarem um veredito, use "recommendation": "monitorar" e diga isso na "headline".

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
  "attack_chains": [
    {
      "title": "<string curta PT-BR no formato 'origem → destino'>",
      "severity": "critico" | "alto" | "medio" | "baixo",
      "steps": [
        {
          "phase": "<uma das fases listadas em attack_path.phase>",
          "tactic": "<TAXXXX, a tatica MITRE da fase>",
          "technique": "<TXXXX>",
          "asset": "<string CURTA: onde o passo acontece, ex.: '/upload sem auth', 'container como root'>",
          "outcome": "emulado" | "bloqueado" | "nao_emulado" | "projecao",
          "evidence": "<UMA frase PT-BR: o que foi observado, ou por que nao foi>"
        }
      ]
    }
  ],
  "kill_chain_complete": <bool>,
  "prioritized_actions": [
    {"priority": <int 1-N>, "action": "<string PT-BR>", "rationale": "<string PT-BR>"}
  ],
  "risk_score_adjusted": {"score": <int 0-100>, "level": "critical" | "high" | "medium" | "low" | "info"},
  "executive_verdict": {
    "recommendation": "bloquear" | "corrigir" | "monitorar",
    "headline": "<uma frase PT-BR: o que decidir e por que, sem jargao>"
  },
  "remediation_effort": {
    "level": "baixo" | "medio" | "alto",
    "label": "<string curta PT-BR, ex.: '3 arquivos, mudanca localizada'>"
  },
  "recommended_deadline": {
    "days": <int>,
    "label": "<string curta PT-BR, ex.: '7 dias'>"
  },
  "business_impact": {
    "headline": "<UMA frase PT-BR, sem jargao tecnico: o que isso significa para a empresa>",
    "areas": [
      {
        "area": "dados" | "propriedade_intelectual" | "entrega" | "financeiro" | "reputacao" | "regulatorio" | "operacao",
        "severity": "critico" | "alto" | "medio" | "baixo",
        "title": "<string curta PT-BR, o efeito de negocio>",
        "detail": "<1 a 2 frases PT-BR explicando o efeito, sem jargao>"
      }
    ],
    "if_fixed_now": {"headline": "<ex.: '~1 dia · 1 pessoa'>", "detail": "<ex.: 'sem impacto em releases'>"},
    "if_deferred": {"headline": "<ex.: 'janela de 48h'>", "detail": "<ex.: 'credenciais seguem ativas'>"},
    "regulatory": {"headline": "<ex.: 'LGPD · notificacao 72h'>", "detail": "<ex.: 'em caso de vazamento'>"} | null
  },
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
    # Ver `_findings_limit`: sem teto, um commit grande truncava a resposta e o
    # Tier 3 inteiro caía em modo degradado.
    incluidos, nota = limitar(findings)
    cabecalho = f"Commit: {commit}\n\n"
    if nota:
        cabecalho += f"{nota}\n\n"
    return (
        f"{cabecalho}"
        f"Findings ({len(findings)}):\n{_format_findings(incluidos)}\n\n"
        f"Dados CTI: {_format_cti(cti_data)}\n\n"
        f"Dados Caldera: {_format_caldera(caldera_results)}\n\n"
        f"Validacao por evidencia: {_format_validacao(validacao)}\n"
    )
