# aperIA — ASPM com Heurística Ofensiva via I.A

aperIA é um **ASPM** (Application Security Posture Management) open-source que captura pushes/PRs do GitHub, executa uma esteira de 7+ ferramentas OSS em 3 tiers e usa Claude como motor central para raciocinar como um atacante: correlaciona findings, constrói attack paths e entrega patches como **GitHub code suggestions** para aprovação humana.

> **Premissa inviolável de remediação:** aperIA nunca aplica código autonomamente. Todo patch é entregue como GitHub code suggestion. Merge fica bloqueado até aprovação explícita do desenvolvedor.

---

## ⚠️ Segurança operacional (LEIA ANTES DE SUBIR)

Esta seção é **obrigatória** — projeto de segurança não pode depender de tribal knowledge.

### Variáveis de ambiente obrigatórias

Defina em `.env` na raiz do projeto: 

```dotenv
# ---- GitHub App (obrigatório para webhooks) ----
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY_PATH=/run/secrets/github_app_key.pem
GITHUB_WEBHOOK_SECRET=<32+ chars aleatório>

# ---- Anthropic (obrigatório para análise Claude) ----
ANTHROPIC_API_KEY=sk-ant-<sua chave>
CLAUDE_MODEL_REASONING=claude-sonnet-4-6
CLAUDE_MODEL_FORMATTING=claude-haiku-4-5-20251001
CLAUDE_PROMPT_CACHE_ENABLED=true

# ---- Caldera (obrigatório se for usar Tier 3 emulation) ----
CALDERA_URL=http://caldera:8888
CALDERA_API_KEY=<API key gerada no boot do Caldera>
CALDERA_SANDBOX_MODE=true        # ← OBRIGATÓRIO true em produção
CALDERA_POLL_INTERVAL=10
CALDERA_AGENT_GROUP=red

# ---- OpenCTI (Tier 3 — enriquecimento CTI) ----
OPENCTI_URL=http://opencti:8081
OPENCTI_TOKEN=<token gerado no provisioning>

# ---- ZAP (Tier 3 — DAST) ----
ZAP_BASE_URL=http://zap:8090
ZAP_API_KEY=<api key gerada no boot do ZAP>

# ---- Celery / Redis ----
REDIS_URL=redis://redis:6379/0
# Não defina CELERY_TASK_ALWAYS_EAGER=true em produção — só nos testes.

# ---- AI Security ----
LLM_GUARD_ENABLED=true
```

### `CALDERA_SANDBOX_MODE=true` é INVIOLÁVEL

`CalderaClient.__init__` valida `settings.CALDERA_SANDBOX_MODE` e levanta `SandboxViolationError` se for `false` — o serviço não sobe. Caldera executa técnicas MITRE ATT&CK **reais**; o único mecanismo que impede que movimento lateral em testes escape para sistemas em produção é o isolamento de rede.

### Rede isolada do Caldera (`internal: true`)

O `docker-compose.scanners.yml` declara a rede `aperia_caldera_sandbox` com `internal: true`. **Não remover essa flag** — significa que:

- Containers nessa rede **não têm rota de saída** para internet ou outras redes Docker.
- Agentes simulados (Sandcat, Manx) só conseguem se comunicar com o servidor Caldera dentro da rede.
- Validação no host: `docker network inspect aperia_caldera_sandbox | grep Internal` deve retornar `"Internal": true`.

### LLM Guard antes de toda chamada Claude

`ClaudeClient.call()` e `call_json()` invocam `LLMGuardClient.check(user_prompt)` antes de enviar para a Anthropic API. Findings vêm de repositórios arbitrários — um atacante pode plantar payloads tipo `Ignore all previous instructions` em comentários de código. O guard heurístico bloqueia 15 padrões comuns de prompt injection. Mantenha `LLM_GUARD_ENABLED=true`.

### Tier 1 nunca chama Claude

`run_trufflehog` + `run_semgrep_changed` + `gate1_check` executam **zero chamadas LLM**. Um PR com chave AWS verificada é bloqueado em ≤ 3 minutos sem custo de token. Não introduza dependência de Claude em workers da fila `tier1`.

### Logs nunca expõem secrets

Todos os scanners usam `structlog` com campos estruturados. Em particular, `TruffleHogScanner` armazena o secret no `raw_output` da entidade `Finding` apenas para diagnóstico interno — esse campo **não vai para o PR comment**.

---

## Arquitetura

```
PR/Push → Webhook
  → Tier 1 (≤ 3 min): TruffleHog + Semgrep changed
      └── Gate 1: secret verificado → bloqueia PR + interrompe pipeline
  → Tier 2 (≤ 10 min): Trivy + Semgrep expanded + Prowler (condicional IaC)
      └── Claude Sonnet (chain_of_events) → relatório no PR
      └── Gate 2: severidade < high → encerra aqui
  → Tier 3 (30-60 min): ZAP + OpenCTI + Caldera
      └── Claude Sonnet (attack_path) + Haiku (PR report)
      └── Code suggestions inline para cada finding remediável
```

### Stack

| Camada | Tecnologia |
|---|---|
| API | FastAPI + Pydantic v2 + pydantic-settings |
| Filas | Celery 5.6 + Redis 7 (por tier) |
| Banco | PostgreSQL 15 + asyncpg + Alembic |
| LLM reasoning | Claude Sonnet 4.6 |
| LLM formatação | Claude Haiku 4.5 |
| Threat Intel | OpenCTI (GraphQL via `gql[requests]`) |
| Emulação | MITRE Caldera 5.x (httpx, sandbox isolado) |
| Secrets | TruffleHog CLI (`--only-verified`) |
| SAST | Semgrep CLI (security-audit / auto) |
| SCA + IaC + Containers | Trivy CLI |
| DAST | OWASP ZAP REST API (active scan) |
| CSPM | Prowler CLI (apenas se PR tem arquivos IaC) |
| Git | GitHub App (JWT + installation_token) |
| Observabilidade | Prometheus + Grafana + structlog |

---

## Instalação local (Docker)

### Subir a stack base

```bash
# Necessário para Tier 1 e Tier 2 funcionar
docker compose -f docker-compose.base.yml up -d
```

Sobe: api + 5 workers Celery (um por fila) + Redis + Postgres.

### Adicionar scanners pesados (Tier 3)

```bash
docker compose -f docker-compose.base.yml -f docker-compose.scanners.yml up -d
```

Adiciona: ZAP + OpenCTI + Caldera. **Caldera entra em rede isolada `internal:true`** — ver seção "Segurança operacional".

### Adicionar observabilidade

```bash
docker compose -f docker-compose.base.yml -f docker-compose.observability.yml up -d
```

Adiciona: Prometheus (porta 9090) + Grafana (porta 3000, login `admin`/`changeme`).

### Validar configuração sem subir

```bash
docker compose -f docker-compose.base.yml config
docker compose -f docker-compose.base.yml -f docker-compose.scanners.yml config
docker compose -f docker-compose.base.yml -f docker-compose.observability.yml config
```

### Aplicar migrations

```bash
docker compose exec api alembic upgrade head
```

---

## Demo end-to-end

### Pré-requisitos

1. GitHub App criada e instalada em um repositório de teste (use [WebGoat](https://github.com/WebGoat/WebGoat) ou similar — repo vulnerável conhecido)
2. Webhook do App apontando para `https://<seu-ngrok>.ngrok.io/webhook/github`
3. `.env` preenchido com os secrets do App

### Fluxo da demo

1. Crie um PR no repo de teste introduzindo uma chave AWS fake (formato válido, não ativa)
2. Em ≤ 3 minutos: status check `failure` + comentário de bloqueio no PR (Gate 1)
3. Crie outro PR com uma vulnerabilidade SQL injection (`f-string` em query)
4. Em ≤ 10 minutos: comentário Tier 2 com chain of events + risk score
5. Se severidade ≥ high: em ~30-60 minutos chega o relatório Tier 3 com attack path + code suggestions inline

### Self-scan do aperIA

O "hello world" do projeto é o **self-scan**: rodar a aperIA contra o próprio repositório.

```bash
# Em outra branch, abre um PR contra main do aperIA
git checkout -b self-scan-test
echo "ghp_thisIsAFakeGitHubTokenForDemo1234567890" >> demo_secret.txt
git add demo_secret.txt && git commit -m "demo: secret fake"
git push origin self-scan-test
gh pr create --title "self-scan: secret" --body "demo"
```

O webhook detecta o PR, dispara o canvas Celery, e o Gate 1 bloqueia o PR. Fecha o ciclo: o sistema analisa o código que o criou.

---

## Desenvolvimento

### Rodar testes

```bash
pip install -r requirements.txt
pytest tests/ --cov-fail-under=70
```

A suíte:
- `tests/unit/` — domínio + AI prompts + circuit breaker (sem I/O)
- `tests/integration/` — scanners mockados via respx/requests-mock, repositórios em SQLite memória, workers Celery em modo eager
- `tests/e2e/test_full_pipeline.py` — canvas completo mockando todas as dependências externas

### Dashboards Grafana

Após subir `docker-compose.observability.yml`, acesse <http://localhost:3000>. Dashboards provisionados:

- **aperia-overview**: custo Claude (USD/dia), latência por tier, findings count por severity
- **aperia-cost-breakdown**: tokens por modelo (input fresh / cache_read / cache_write / output), hit-rate do prompt cache, custo por PR

Métricas expostas em `GET /metrics` (Prometheus format):

- `claude_tokens_total{model, type}` — tokens por modelo e bucket
- `claude_cost_usd_total{model}` — custo acumulado em USD
- `claude_requests_total{model, outcome}` — sucesso / circuit_open / blocked_by_guard / error

### Estrutura de pastas

```
app/
├── application/           # use cases (sem lógica de negócio)
│   └── remediation/
├── core/                  # config, exceptions, celery_app, orchestrator
├── domain/                # entidades, value objects, repos ABC (zero deps externas)
│   ├── finding/
│   ├── scan/
│   ├── remediation/
│   └── shared/
├── infrastructure/        # implementações concretas
│   ├── ai/                # ClaudeClient, LLM Guard, prompts, circuit breaker
│   ├── database/          # SQLAlchemy sync + async
│   ├── git/               # GitHubClient + auth JWT
│   ├── intelligence/      # OpenCTIClient, CalderaClient
│   ├── persistence/       # models SQLAlchemy
│   ├── repositories/      # implementações concretas dos repos
│   └── scanners/          # TruffleHog, Semgrep, Trivy, Prowler, ZAP
└── presentation/
    ├── api/routes/        # FastAPI routers (webhook, auth, health)
    └── workers/           # Celery tasks (tier1/2/3, analysis, reporting)
```

### Regras invioláveis (CLAUDE.md)

1. Remediação sempre humana — patches como code suggestion, merge bloqueado até aprovação
2. LLM Guard antes de toda chamada Claude
3. Caldera em sandbox isolado — `CALDERA_SANDBOX_MODE=true` validado no boot
4. Tier 1 sem Claude
5. Falha de scanner isolada — scanner down → skip + log, pipeline continua
6. Falha do Claude não derruba pipeline — circuit breaker retorna findings brutos sem narrativa
7. DDD: `app/domain/` sem imports externos, sem exceção
8. Nunca PAT estático — GitHub App via `installation_id` → `installation_token`

---

## Rotas

| Método | Caminho | O que faz |
|---|---|---|
| `GET` | `/health` | Healthcheck |
| `POST` | `/webhook/github` | Recebe webhook GitHub (HMAC obrigatório) |
| `POST` | `/users` | Cria usuário (auth pré-existente) |
| `GET` | `/users/{user_id}` | Consulta usuário por UUID |
| `POST` | `/auth/login` | Login + emissão de tokens JWT |
| `POST` | `/auth/refresh` | Refresh token rotation |
| `POST` | `/auth/logout` | Revoga refresh token (204 sempre) |
| `GET` | `/findings` | Lista findings persistidos (filtros + paginação; **JWT**) |
| `GET` | `/findings/{finding_id}` | Detalhe de um finding, com `raw_output` (**JWT**) |
| `GET` | `/scans` | Lista scans recentes / progresso do pipeline (**JWT**) |
| `GET` | `/scans/{commit_sha}` | Status por tier de um scan + resumo de findings (**JWT**) |
| `GET` | `/scans/{commit_sha}/report` | Relatórios de todos os tiers do commit (**JWT**) |
| `GET` | `/scans/{commit_sha}/tiers/{tier}/report` | Relatório markdown de um tier específico (**JWT**) |
| `GET` | `/metrics` | Prometheus metrics (latência, custo Claude, findings) — **ainda não exposto** |

### Documentação da API (OpenAPI / Swagger)

A app FastAPI gera a documentação a partir do próprio código (rotas + schemas
Pydantic). Com a stack no ar:

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **JSON cru:** http://localhost:8000/openapi.json

Há também um snapshot versionado em [`openapi.yaml`](openapi.yaml) (OpenAPI 3.1).
Ele é **gerado** — não edite à mão. Após alterar rotas ou schemas, regenere com:

```bash
.venv/bin/python scripts/export_openapi.py
```

---

## Licença

Veja [LICENSE](LICENSE). Stack 100% open source — exceto a Claude API (Anthropic).
