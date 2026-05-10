"""Prompt Claude para síntese de contexto de negócio a partir de sinais do repositório."""

SYSTEM = """
Você é um especialista em segurança de aplicações e contexto de negócio.
Recebe sinais extraídos automaticamente de um repositório de código e deve inferir
o contexto de negócio para calibrar o impacto real de vulnerabilidades de segurança.

Raciocine a partir dos sinais concretos: dependências, nomes de entidades, rotas, variáveis de
ambiente e estrutura de diretórios. Não invente informações que não estejam nos sinais.

Responda APENAS com JSON válido, sem markdown, sem texto adicional:
{
  "app_type": "web_api|mobile_backend|cli|data_pipeline|microservice|frontend|fullstack|other",
  "domain": "fintech|healthcare|ecommerce|saas|social|logistics|devtools|government|education|other",
  "asset_criticality": "critical|high|medium|low",
  "contains_pii": true,
  "contains_financial_data": false,
  "contains_health_data": false,
  "internet_facing": true,
  "compliance_scope": ["LGPD", "PCI-DSS"],
  "estimated_users": "small_team|startup|smb|enterprise",
  "breach_cost_brl_min": 50000,
  "breach_cost_brl_max": 500000,
  "key_assets": ["serviço de autenticação", "banco de dados de usuários"],
  "confidence": 0.85,
  "reasoning": "breve explicação dos sinais mais determinantes"
}

Referências para estimativa de custo (BRL):
- LGPD: multa até 2% do faturamento anual, máx R$ 50M por infração
- PCI-DSS: fines + perda de credenciamento + custo de investigação forense
- Healthcare: notificação de pacientes + regulatory + reputacional
- Custo mínimo de resposta a incidente: R$ 15.000 (pequena empresa)
- Custo médio enterprise: R$ 2.5M (fonte: IBM Cost of a Data Breach 2024)
"""


def build(signals: dict) -> str:
    deps = signals.get("dependencies", {})
    all_deps: list[str] = []
    for lang, pkgs in deps.items():
        all_deps.extend(f"{lang}: {pkg}" for pkg in pkgs[:25])

    code = signals.get("code_patterns", {})
    dirs = signals.get("dir_structure", [])
    env_vars = signals.get("env_vars", [])
    readme = signals.get("readme_excerpt", "")
    frameworks = signals.get("frameworks", [])
    cloud = signals.get("cloud_providers", [])
    ci = signals.get("ci_cd", [])
    has_migrations = signals.get("has_migrations", False)

    return f"""
## Sinais Extraídos do Repositório

### Estrutura de Diretórios (top-level)
{dirs}

### Frameworks Detectados
{frameworks or "Nenhum detectado"}

### Cloud Providers
{cloud or "Nenhum detectado"}

### CI/CD
{ci or "Nenhum detectado"}

### Dependências (até 40 por linguagem)
{all_deps[:60] or "Nenhuma"}

### Variáveis de Ambiente (.env.example — nomes, sem valores)
{env_vars[:40] or "Arquivo não encontrado"}

### Padrões de Código Detectados
- Entidades/Modelos: {code.get("model_names", [])}
- Rotas sensíveis: {code.get("route_patterns", [])}
- Campos de dados sensíveis: {code.get("sensitive_fields", [])}

### Migrações de Banco de Dados
{"Encontradas" if has_migrations else "Não encontradas"}

### README (primeiros 1200 chars)
{readme[:1200] or "Não encontrado"}

Com base nesses sinais, infira o contexto de negócio e o impacto de um eventual breach.
"""
