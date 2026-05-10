from domain.finding.entities import Finding

SYSTEM = """
Você é um engenheiro de segurança da aperIA gerando patches de correção.

REGRA INVIOLÁVEL: O patch será entregue como GitHub code suggestion.
O desenvolvedor SEMPRE revisa e aprova antes de qualquer merge.
Você nunca executa código — apenas sugere.

Para cada finding, gere:
1. Explicação clara do problema (para o desenvolvedor entender, sem jargão excessivo)
2. Patch em formato diff unificado (pronto para code suggestion no GitHub)
3. Se requer rotação de credencial (para secrets)

Padrões de patch:
- Secrets hardcoded → substituir por variável de ambiente (os.environ.get)
- SQL injection → parameterização (nunca f-string em query)
- XSS → escape de output (html.escape ou framework nativo)
- Dependência vulnerável → atualizar para versão sem CVE no requirements.txt
- IaC misconfiguration → corrigir a config com o valor seguro

Responda APENAS com JSON válido:
{
  "remediations": [
    {
      "finding_id": "uuid",
      "finding_title": "título do finding",
      "explanation": "explicação para o desenvolvedor",
      "patch_diff": "diff unificado pronto para suggestion",
      "requires_secret_rotation": false,
      "rotation_instructions": ""
    }
  ]
}
"""


def build(findings: list[Finding], paths: dict, repo_context: dict) -> str:
    actionable = [f for f in findings if f.file_path and f.line_number]
    findings_text = "\n".join(
        f"ID: {f.id}\n[{f.source}] {f.severity.value} — {f.title}\n"
        f"Arquivo: {f.file_path}:{f.line_number}\nDescrição: {f.description[:400]}"
        for f in actionable
    )
    primary = paths.get("primary_path", "")
    first_path = (paths.get("paths") or [{}])[0]
    return f"""
## Attack Path Principal
{primary} — {first_path.get("title", "")}

## Findings para Remediar
{findings_text}

## Contexto
{repo_context}

Gere os patches de correção para cada finding.
"""
