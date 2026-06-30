"""Prompt de remediação (Tier 3) — Haiku.

Recebe um finding específico + contexto de código e gera um diff
de patch + explicação. **NUNCA aplica nada** — apenas devolve o
diff para ser entregue como GitHub code suggestion.

Decisão #4 da Semana 10: o SYSTEM proíbe explicitamente
qualquer ação além de gerar o diff. Texto literal preservado.
"""
from __future__ import annotations

import json


SYSTEM = """Você é um engenheiro de segurança que produz correções de código em formato de diff unificado.

Gere apenas o diff do patch. Não execute, não aplique, não faça commit. A aplicação é responsabilidade exclusiva do desenvolvedor via code suggestion.

REGRAS INVIOLÁVEIS:
1. Saída sempre como JSON ESTRITO no schema abaixo — sem markdown fences ao redor.
2. patch_diff deve ser um diff unificado (formato `--- a/...` / `+++ b/...`) que aplique limpo na versão fornecida do arquivo. Se você não tiver certeza do contexto exato, retorne patch_diff vazio "" e explique em explanation.
3. Quando o finding for um secret (TruffleHog), patch_diff deve REMOVER o secret e requires_secret_rotation deve ser true. rotation_instructions deve indicar onde rotar (ex: AWS IAM, GitHub Settings).
4. Quando o finding for uma vulnerabilidade de código (Semgrep/Trivy), patch_diff deve corrigir a causa raiz, não apenas suprimir o alerta. NUNCA gere `# nosec`, `# pragma: no cover` ou comentários que silenciem o scanner.
5. NÃO sugira mudanças fora do escopo do finding. NÃO refatore além do necessário.
6. Explanation em PORTUGUÊS BRASILEIRO, curta (1-3 linhas), focada no porquê da correção.

Formato JSON estrito:
{
  "patch_diff": "<string com diff unificado, pode ser \\"\\" se não houver contexto suficiente>",
  "explanation": "<string PT-BR curta>",
  "requires_secret_rotation": <bool>,
  "rotation_instructions": "<string ou null>"
}"""


def build(finding: dict, code_context: str | None = None) -> str:
    """Constrói o user prompt para uma remediação específica.

    ``finding`` é o dict serializado de ``Finding``. ``code_context``
    é o trecho do arquivo ao redor da linha afetada (caller decide o
    tamanho — recomendado ±20 linhas).
    """
    context_block = (
        f"\n\nContexto do código (trecho ao redor da linha afetada):\n"
        f"```\n{code_context}\n```"
        if code_context
        else "\n\nContexto do código: (não fornecido)"
    )
    summary = json.dumps(
        {
            "source": finding.get("source"),
            "severity": finding.get("severity"),
            "title": finding.get("title"),
            "description": finding.get("description"),
            "cve_id": finding.get("cve_id"),
            "cwe_id": finding.get("cwe_id"),
            "file_path": finding.get("file_path"),
            "line_number": finding.get("line_number"),
            "secret_verified": finding.get("secret_verified", False),
            "secret_type": finding.get("secret_type"),
        },
        ensure_ascii=False,
        indent=2,
    )
    return f"Finding a corrigir:\n{summary}{context_block}"
