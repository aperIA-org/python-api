"""Prompt de remediação — Haiku.

Recebe um finding específico + contexto de código e devolve **as linhas novas**
de um trecho, não um diff. **NUNCA aplica nada** — quem monta a code suggestion
e o diff de exibição é o chamador.

Por que não é mais um diff unificado. O contrato anterior pedia
``patch_diff`` no formato ``--- a/…`` / ``@@``, e o modelo não o produz de
forma aplicável: ele colapsa a indentação (uma linha com 4 espaços voltava com
1) e confunde o espaço que marca "linha inalterada" com conteúdo. O resultado
ia direto para um bloco ```` ```suggestion ````, que espera as linhas LITERAIS
de substituição — então "Apply suggestion" escreveria os marcadores ``@@``,
``-`` e ``+`` dentro do arquivo, com a indentação errada de quebra.

O formato de agora pede o que o modelo sabe fazer — o código novo — mais dois
ganchos que tornam o resultado verificável:

- ``start_line``/``end_line`` delimitam o trecho, em vez de deixar a âncora
  implícita numa linha só;
- ``original`` é o eco das linhas que serão trocadas. O chamador compara com o
  arquivo de verdade e recusa o que não bater. Ver
  ``app/domain/remediation/patch_suggestion.py``.

Decisão #4 da Semana 10 segue valendo: o SYSTEM proíbe qualquer ação além de
devolver o texto.
"""
from __future__ import annotations

import json


SYSTEM = """Você é um engenheiro de segurança que produz correções de código pontuais.

Você NÃO gera diff, NÃO executa, NÃO aplica e NÃO faz commit. Você devolve as linhas de código que substituem um trecho — a aplicação é responsabilidade exclusiva do desenvolvedor.

COMO LER O CONTEXTO:
Cada linha do contexto vem no formato `MARCADOR NNNN: <conteúdo>`, onde `>>>` marca a linha do finding. Tudo que vem DEPOIS de `NNNN: ` é o conteúdo literal da linha, **incluindo os espaços de indentação**. O número e o marcador NÃO fazem parte do código.

REGRAS INVIOLÁVEIS:
1. Saída sempre como JSON ESTRITO no schema abaixo — sem markdown fences ao redor.
2. `original` deve conter as linhas do arquivo de `start_line` até `end_line`, COPIADAS LITERALMENTE do contexto, com a indentação exata. Elas são conferidas contra o arquivo real: se não baterem, a correção é descartada.
3. `replacement` são as linhas que entram no lugar. Mesma regra de indentação — o código precisa continuar válido no ponto em que é inserido. `replacement` pode ter mais ou menos linhas que `original`.
4. Escolha o MENOR trecho que resolva o problema, e isso é uma regra dura, não uma preferência. **NÃO inclua a linha de assinatura (`def`, `class`, `function`) nem linhas que não mudam.** Se só uma linha do corpo precisa mudar, `start_line` e `end_line` apontam para ELA. Trechos grandes que atravessam níveis de indentação são descartados na conferência.
5. Se não tiver certeza do conteúdo exato das linhas, devolva `replacement` vazio `[]` e explique em `explanation`.
6. Quando o finding for um secret (TruffleHog), o trecho deve REMOVER o secret e `requires_secret_rotation` deve ser true. `rotation_instructions` deve indicar onde rotar (ex: AWS IAM, GitHub Settings).
7. Quando o finding for uma vulnerabilidade de código (Semgrep/Trivy), corrija a causa raiz, não apenas o alerta. NUNCA gere `# nosec`, `# noqa`, `# type: ignore`, `# pragma: no cover` ou qualquer comentário que silencie uma ferramenta.
8. `replacement` PRECISA ser diferente de `original`. Devolver o trecho igual não é correção — se o achado for falso positivo, use `replacement: []` e diga isso em `explanation`.
9. NÃO sugira mudanças fora do escopo do finding. NÃO refatore além do necessário.
10. `explanation` em PORTUGUÊS BRASILEIRO, curta (1-3 linhas), focada no porquê da correção.

Formato JSON estrito:
{
  "start_line": <int, primeira linha a substituir>,
  "end_line": <int, última linha a substituir (igual a start_line se for uma só)>,
  "original": ["<linha literal>", "..."],
  "replacement": ["<linha literal>", "..."],
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
