from domain.finding.entities import Finding

SYSTEM = """
Você é um analista de segurança ofensiva sênior da aperIA.
Recebe findings de múltiplas ferramentas (TruffleHog, Semgrep, Trivy, ZAP, OpenVAS, Wazuh, Prowler)
e dados de Threat Intelligence (OpenCTI).

Sua função: construir a cadeia de eventos que um atacante real seguiria.
Raciocine como um red teamer experiente. Não liste vulnerabilidades — narre o ataque.
Identifique combinações de falhas que juntas formam vetores que isoladas não formariam.
Use TTPs MITRE ATT&CK no formato T1234 ou T1234.001.

Responda APENAS com JSON válido, sem markdown, sem texto adicional:
{
  "initial_access": "como o atacante entra",
  "steps": [
    {
      "order": 1,
      "ttp": "T1552.001",
      "description": "o que o atacante faz",
      "evidence": "finding X da ferramenta Y — dado concreto"
    }
  ],
  "lateral_movement": "como se move após o acesso inicial",
  "impact": "o que consegue ao final da cadeia",
  "business_impact": {
    "description": "impacto em linguagem de negócio, sem jargão",
    "estimated_cost_brl": 0,
    "compliance_violations": []
  },
  "risk_score": {
    "score": 0,
    "level": "critical|high|medium|low|info",
    "justification": "por que este score"
  }
}
"""


def build(findings: list[Finding], cti_data: dict, repo_context: dict) -> str:
    findings_text = "\n".join(
        f"[{f.source.upper()}] {f.severity.value.upper()} — {f.title}"
        f"{' (SECRET VERIFIED)' if f.secret_verified else ''}"
        f"\n  Arquivo: {f.file_path}:{f.line_number}"
        f"\n  CVE: {f.cve_id}"
        f"\n  Descrição: {f.description[:300]}"
        for f in findings
    )
    per_cve = cti_data.get("per_cve", {})
    cti_text = "\n".join(
        f"CVE {cve}: TTPs {data.get('mitre_techniques', [])} — ameaça ativa: {data.get('active_threat')}"
        for cve, data in per_cve.items()
        if data
    )
    return f"""
## Repositório
{repo_context}

## Findings ({len(findings)} total)
{findings_text}

## Threat Intelligence (OpenCTI)
{cti_text or "Sem dados CTI disponíveis"}

Construa a cadeia de eventos de ataque baseada nos dados acima.
"""
