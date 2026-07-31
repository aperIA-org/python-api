# Referência

Este documento é material de **referência** (fatos: rotas, variáveis, modelos, serviços, plumbing do Claude). Descreve o sistema como ele é, sem instruções passo a passo. Para uso prático, veja os how-tos em [`howto/`](howto/) (ex.: [`howto/subir-a-stack.md`](howto/subir-a-stack.md)); para entender o "porquê" do pipeline, veja [`explicacao-pipeline.md`](explicacao-pipeline.md).

Fontes: `openapi.yaml`, `.env.example`, `app/config.py`, `app/domain/{finding,scan,github}/entities.py`, `app/infrastructure/persistence/models/`, `GUIA_EXECUCAO.md`.

## 1. Rotas da API

27 rotas HTTP registradas em `app/main.py`, agrupadas em 8 tags. `Auth` indica exigência de `Authorization: Bearer <access_token>` (JWT); rotas sem essa exigência estão marcadas "—". O webhook usa um esquema de autenticação próprio (HMAC), não JWT.

| Método | Caminho | Descrição | Auth |
|---|---|---|---|
| `GET` | `/health` | Healthcheck — `{"status":"ok"}`; não verifica dependências externas. | — |
| `POST` | `/users` | Cria usuário (senha com hash Argon2, e-mail único). Retorna só o `id`. | — |
| `GET` | `/users/{user_id}` | Consulta dados públicos de um usuário por UUID. | — |
| `POST` | `/auth/login` | Autentica e retorna `access_token` (15 min) + `refresh_token` (7 dias). | — |
| `POST` | `/auth/refresh` | Troca um `refresh_token` válido por novo par (rotação); reuso detectado invalida a família. | — |
| `POST` | `/auth/logout` | Invalida o `refresh_token` fornecido. Sempre `204` (evita oracle). | — |
| `GET` | `/findings` | Lista findings do usuário logado (filtros `commit_sha`/`severity`/`tier`/`source`/`secret_verified` + paginação). Omite `raw_output`. | JWT |
| `GET` | `/findings/{finding_id}` | Detalhe de um finding, incluindo `raw_output`. 404 se não pertencer ao usuário. | JWT |
| `GET` | `/scans` | Lista scans do usuário logado, paginados (mais recentes primeiro). | JWT |
| `GET` | `/scans/{commit_sha}` | Status de um scan por `commit_sha`, com `findings_summary`. | JWT |
| `GET` | `/scans/{commit_sha}/report` | Relatórios (um por tier) de um commit. Lista vazia se o pipeline ainda não gerou nenhum. | JWT |
| `GET` | `/scans/{commit_sha}/tiers/{tier}/report` | Relatório de um tier específico (1-3) de um commit. | JWT |
| `GET` | `/github/connect` | Gera `install_url` do GitHub App com `state` assinado (10 min). Retorna 503 se `GITHUB_APP_SLUG` vazio. | JWT |
| `GET` | `/github/callback` | Recebe o redirect pós-instalação (`installation_id` + `state` + `setup_action`); vincula a instalação ao usuário via `state` assinado (não via header). Upsert de `GithubAccount`. Com `GITHUB_CONNECT_REDIRECT_URL` configurada responde `302` (inclusive em erro de `state`, com `github=erro&motivo=state`); sem ela, JSON no sucesso e `400` no erro. | — |
| `GET` | `/github/repos` | Lista, ao vivo, os repositórios visíveis pelas instalações do usuário; marca `active` nos já ativados. Traz também `private`, `language` e `pushed_at`, lidos do próprio payload da instalação. | JWT |
| `GET` | `/github/accounts` | Lista as contas GitHub (instalações) conectadas pelo usuário. | JWT |
| `DELETE` | `/github/accounts/{account_id}` | Desconecta uma conta GitHub **e remove, na mesma transação, os `repositories` vinculados a ela**. Findings, scans e relatórios são preservados. 404 se não pertencer ao usuário. | JWT |
| `GET` | `/repositories` | Lista repositórios ativados para análise pelo usuário. | JWT |
| `POST` | `/repositories` | Ativa um repositório, vinculado a uma `github_account_id` do usuário. **Upsert** por `(user_id, github_repo_id)`: reativar devolve o `id` da linha já existente, não um novo. 404 se a conta não pertencer ao usuário. | JWT |
| `GET` | `/repositories/{repository_id}` | Detalhe de um repositório. 404 se não pertencer ao usuário. | JWT |
| `PATCH` | `/repositories/{repository_id}` | Ativa/desativa um repositório (`active`). 404 se não pertencer ao usuário. | JWT |
| `DELETE` | `/repositories/{repository_id}` | Remove o vínculo do repositório. 404 se não pertencer ao usuário. | JWT |
| `POST` | `/repositories/{repository_id}/scan` | Dispara um scan manual no HEAD do `default_branch` — mesmo pipeline do webhook, com `pr_number=None`. `202` com `{"status","commit_sha","branch"}`; `409` se desativado ou se já há scan em andamento no commit; `502` se o GitHub não resolver o HEAD; `503` sem credenciais do App. | JWT |
| `GET` | `/repositories/{repository_id}/scans` | Lista scans (`ScanJob`) do repositório, paginados. | JWT |
| `GET` | `/repositories/{repository_id}/findings` | Lista findings do repositório (todos os commits), com filtros. | JWT |
| `GET` | `/repositories/{repository_id}/reports` | Lista relatórios (por commit/tier) do repositório. | JWT |
| `POST` | `/webhook/github` | Recebe eventos GitHub; dispara o pipeline em `pull_request` `opened`/`synchronize`. | HMAC (`X-Hub-Signature-256`, segredo `GITHUB_WEBHOOK_SECRET`) — não é JWT |

> Documentação interativa em runtime: `/docs` (Swagger) e `/redoc`. `openapi.yaml` é gerado a partir do código via `scripts/export_openapi.py`.

## 2. Variáveis de ambiente

Fonte: `app/config.py` (singleton `settings`, pydantic `BaseSettings`, `case_sensitive=True`, `extra="ignore"`, lê `.env`) e `.env.example`.

| Variável | Default | Necessária para |
|---|---|---|
| `SECRET_KEY` | `change-this-secret-key-with-at-least-32-characters` | Assinatura dos JWT (access token e `state` do GitHub connect) — trocar em produção. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Duração do access token. |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Duração do refresh token. |
| `GITHUB_APP_ID` | `""` | Autenticação do GitHub App (JWT do App). Junto com `GITHUB_PRIVATE_KEY_PATH`, é o par exigido pelo `POST /repositories/{id}/scan` — vazio → rota responde 503. |
| `GITHUB_PRIVATE_KEY_PATH` | `""` | Caminho do `.pem` da chave privada do App. Ver `GITHUB_APP_ID`. |
| `GITHUB_WEBHOOK_SECRET` | `""` | HMAC do `POST /webhook/github` (vazio = assina com chave vazia). |
| `GITHUB_APP_SLUG` | `""` | Monta `install_url` em `GET /github/connect`; vazio → rota responde 503. |
| `GITHUB_CONNECT_REDIRECT_URL` | `""` | Tela do front-end que recebe o retorno da instalação (ex.: `http://localhost:3000/dash/repositorios?github=conectado`). No sucesso o `GET /github/callback` redireciona (`302`) para a URL exatamente como configurada; num `state` inválido/expirado redireciona para a mesma URL com `github=erro&motivo=state` (substitui `github=conectado`, preserva os demais parâmetros). Vazio → callback responde JSON no sucesso e `400` no erro, sem `302`. |
| `ANTHROPIC_API_KEY` | `""` | Chamadas ao Claude nos tiers 2/3; sem ela a análise roda em modo degradado. |
| `CLAUDE_MODEL_REASONING` | `claude-sonnet-4-6` | Modelo usado em `tier2_analyze`/`tier3_deep_analysis` (raciocínio). |
| `CLAUDE_MODEL_FORMATTING` | `claude-haiku-4-5-20251001` | Modelo usado nos workers de `reporting` (markdown). |
| `CLAUDE_PROMPT_CACHE_ENABLED` | `True` | Ativa `cache_control: ephemeral` no bloco `system` dos prompts. |
| `ZAP_BASE_URL` | `http://zap:8090` | Endpoint do OWASP ZAP (Tier 3 DAST). |
| `ZAP_API_KEY` | `""` | Autenticação no ZAP. |
| `OPENCTI_URL` | `http://opencti:8081` | Endpoint do OpenCTI (Tier 3 threat intel). |
| `OPENCTI_TOKEN` | `""` | Autenticação no OpenCTI. |
| `CALDERA_URL` | `http://caldera:8888` | Endpoint do MITRE Caldera (Tier 3 emulação adversária). |
| `CALDERA_API_KEY` | `""` | Autenticação no Caldera. |
| `CALDERA_SANDBOX_MODE` | `True` | **Inviolável** — `false` levanta `SandboxViolationError` no `__init__` do `CalderaClient`. |
| `CALDERA_POLL_INTERVAL` | `10` | Intervalo (s) de polling de status da emulação; testes injetam `0` via construtor. |
| `CALDERA_AGENT_GROUP` | `"red"` | Grupo de agentes usado na emulação Caldera. |
| `LLM_GUARD_ENABLED` | `True` | Bloqueio de padrões de prompt injection antes de chamar a API do Claude. |
| `FINDINGS_PERSISTENCE_ENABLED` | `True` | Escrita best-effort de `Finding` na tabela `findings` pelos scan workers; testes desligam. |
| `SCAN_PERSISTENCE_ENABLED` | `True` | Escrita best-effort do ciclo de vida do `ScanJob` (criação + updates de status por tier); testes desligam. |
| `REDIS_URL` | `redis://redis:6379/0` | Broker e result backend do Celery (hostname do container, não `localhost`). |
| `CELERY_BROKER_URL` | `""` | Override do broker; vazio deriva de `REDIS_URL`. |
| `CELERY_RESULT_BACKEND` | `""` | Override do result backend; vazio deriva de `REDIS_URL`. |
| `CELERY_TASK_ALWAYS_EAGER` | `False` | Execução síncrona (só testes — nunca produção). |
| `CELERY_TASK_EAGER_PROPAGATES` | `False` | Propaga exceções em modo eager (só testes). |

> **Nota — `DATABASE_URL`/`DB_*`:** essas variáveis **não** fazem parte de `Settings` (`app/config.py`). São lidas diretamente do `os.environ` em `app/infrastructure/database/sqlalchemy.py`: `DATABASE_URL` (se definida) tem precedência total sobre as partes separadas `DB_HOST`/`DB_PORT`/`DB_NAME`/`DB_USER`/`DB_PASSWORD` (defaults `db`/`5432`/`postgres`/`postgres`/`postgres`) e `DB_FORCE_IPV4` (`false`, força IPv4 quando `true`). `_normalize_scheme` converte automaticamente `postgresql+asyncpg://` → `postgresql+psycopg://`. O `docker-compose.base.yml` injeta `DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/aperia`, que sobrescreve qualquer `DB_HOST` apontando para um banco externo.

## 3. Modelos de dados

### `Finding` (`app/domain/finding/entities.py`) — tabela `findings`

| Campo | Tipo | Observação |
|---|---|---|
| `id` | `UUID` | `default_factory=uuid4`. |
| `source` | `str` | Ferramenta de origem (`trufflehog`, `semgrep`, `trivy`, `prowler`, `zap`). |
| `severity` | `Severity` | Enum `critical`/`high`/`medium`/`low`/`info`. |
| `title` | `str` | Título/regra do finding. |
| `description` | `str` | Mensagem detalhada (nunca logar valor de secret cru). |
| `commit_sha` | `str` | SHA do commit analisado. |
| `repo_url` | `str` | URL do repositório. |
| `cve_id` | `CVEId \| None` | Value object; liga o finding ao enriquecimento OpenCTI no Tier 3. |
| `cwe_id` | `str \| None` | Classificação CWE. |
| `file_path` | `str \| None` | Caminho do arquivo. |
| `line_number` | `int \| None` | Linha do arquivo. |
| `asset` | `str \| None` | Recurso afetado (ex.: ARN, `ResourceId`). |
| `asset_criticality` | `str \| None` | Criticidade do ativo. |
| `secret_verified` | `bool` | Default `False`; só o TruffleHog seta `True` — único gatilho do Gate 1. |
| `secret_type` | `str \| None` | Ex.: `"AWS"`. |
| `raw_output` | `dict` | JSON nativo do scanner (`default_factory=dict`). |
| `tier` | `int` | `1`/`2`/`3`; default `1`. |
| `created_at` | `datetime` | `default_factory=datetime.utcnow`. |

`dedup_key()` = `f"{source}:{cve_id or title}:{file_path}:{line_number}:{commit_sha}"`. Método adicional: `is_critical_secret()` = `secret_verified and severity == CRITICAL`.

**UNIQUE:** `findings_dedup_key` em `dedup_key` (coluna materializada pelo `FindingModel`) — garante idempotência via `ON CONFLICT (dedup_key) DO NOTHING`. Mesmo CVE de scanners diferentes gera 2 linhas (o `source` é parte da chave).

### `ScanJob` (`app/domain/scan/entities.py`) — tabela `scan_jobs`

| Campo | Tipo | Observação |
|---|---|---|
| `id` | `UUID` | `default_factory=uuid4`. |
| `commit_sha` | `str` | Chave de busca do scan. |
| `repo_url` | `str` | URL do repositório. |
| `installation_id` | `int` | Instalação do GitHub App que originou o evento. |
| `pr_number` | `int \| None` | Número do PR. `None` em scan manual (`POST /repositories/{id}/scan`) — o pipeline é o mesmo, mas os workers de reporting não comentam em PR nenhum (o status check no commit continua sendo criado). |
| `repo_full_name` | `str \| None` | `org/repo`. |
| `tier1_status` / `tier2_status` / `tier3_status` | `TierStatus \| None` | Status por tier. |
| `tier1_started_at` / `tier1_completed_at` (idem tier2/tier3) | `datetime \| None` | Timestamps de início/fim por tier. |
| `blocked_at_tier` | `ScanTier \| None` | Tier em que um gate interrompeu o pipeline. |
| `final_risk_score` | `int \| None` | Score final (produzido pelo Claude). |
| `final_risk_level` | `str \| None` | Nível textual do score final. |
| `user_id` | `UUID \| None` | Dono do scan (desnormalizado p/ filtro rápido); nullable p/ scans legados. |
| `repository_id` | `UUID \| None` | `Repository` que originou o scan; nullable p/ scans legados. |
| `created_at` | `datetime` | `default_factory=datetime.utcnow`. |

**UNIQUE:** `scan_jobs_commit_sha_key` em `commit_sha`.

> Tabela relacionada `scan_reports` (não é entidade de domínio própria, é o relatório markdown por tier/commit): **UNIQUE** `scan_reports_commit_tier_key` em `(commit_sha, tier)`.

### `Repository` (`app/domain/github/entities.py`) — tabela `repositories`

| Campo | Tipo | Observação |
|---|---|---|
| `id` | `UUID` | `default_factory=uuid4`. |
| `user_id` | `UUID` | Dono do repositório conectado. |
| `github_account_id` | `UUID` | `GithubAccount` (instalação) à qual pertence. |
| `installation_id` | `int` | Instalação do GitHub App. |
| `github_repo_id` | `int` | ID do repositório no GitHub. |
| `full_name` | `str` | `org/repo`. |
| `url` | `str` | URL do repositório. |
| `default_branch` | `str` | Default `"main"`. |
| `active` | `bool` | Default `True`; controla se o repo está sob análise. |
| `created_at` | `datetime` | `default_factory=datetime.utcnow`. |

**UNIQUE:** `repositories_user_repo_key` em `(user_id, github_repo_id)` — é a chave do upsert de `POST /repositories`. O `save()` usa `RETURNING`, então a rota devolve a linha realmente persistida (com o `id` original em caso de conflito), e não o `uuid4()` gerado em memória.

Não há `ForeignKey` para `github_accounts`: quando uma conta é desconectada (`DELETE /github/accounts/{id}`), a limpeza dos repositórios dela é explícita, feita na mesma transação.

### `GithubAccount` (`app/domain/github/entities.py`) — tabela `github_accounts`

| Campo | Tipo | Observação |
|---|---|---|
| `id` | `UUID` | `default_factory=uuid4`. |
| `user_id` | `UUID` | Usuário aperIA vinculado. |
| `installation_id` | `int` | ID da instalação do GitHub App. |
| `github_login` | `str` | Login da conta/organização no GitHub. |
| `account_type` | `str` | `"User"` ou `"Organization"`. |
| `created_at` | `datetime` | `default_factory=datetime.utcnow`. |

**UNIQUE:** `github_accounts_installation_key` em `installation_id`.

## 4. Serviços / containers

`docker-compose.base.yml` — stack obrigatória, 8 containers:

| Serviço | Container | Porta | Papel |
|---|---|---|---|
| `api` | `aperia-api` | `8000` | FastAPI (webhook, health, auth). |
| `worker_tier1` | `python-api-worker_tier1-1` | — | Celery fila `tier1`, concurrency 4. |
| `worker_tier2` | `python-api-worker_tier2-1` | — | Celery fila `tier2`, concurrency 2. |
| `worker_tier3` | `python-api-worker_tier3-1` | — | Celery fila `tier3`, concurrency 1. |
| `worker_analysis` | `python-api-worker_analysis-1` | — | Celery fila `analysis`, concurrency 2. |
| `worker_reporting` | `python-api-worker_reporting-1` | — | Celery fila `reporting`, concurrency 2. |
| `redis` | `aperia-redis` | — | Broker + result backend do Celery. |
| `db` | `aperia-db` | — | PostgreSQL 15 (`postgres`/`postgres`, banco `aperia`). |

Camadas opcionais (compose files adicionais): `docker-compose.scanners.yml` (ZAP `:8090`, OpenCTI `:8081`, Caldera `:8888` — necessários para o Tier 3 produzir dados reais) e `docker-compose.observability.yml` (Prometheus `:9090`, Grafana `:3000`).

## 5. Plumbing do Claude

Componentes em `app/infrastructure/ai/`:

| Componente | Arquivo | Comportamento |
|---|---|---|
| `ClaudeClient` | `claude_client.py` | Expõe `call()` e `call_json()`, síncronos (workers Celery são sync). Fluxo: checa circuit breaker → roda LLM Guard no input → chama a API Anthropic. Bloco `system` marcado com `cache_control: ephemeral` se `CLAUDE_PROMPT_CACHE_ENABLED=True`. Modelos vêm de constantes (`models.py`), nunca string literal — `CLAUDE_MODEL_REASONING` (Sonnet, análise) e `CLAUDE_MODEL_FORMATTING` (Haiku, relatórios). |
| Circuit breaker | `circuit_breaker.py` | Abre após **3 falhas consecutivas**; janela de recuperação de **300s**. Singleton process-wide (`DEFAULT_BREAKER`). |
| LLM Guard | `llm_guard_client.py` | Regex-stub que bloqueia ~14-18 padrões de prompt injection (ex.: `ignore all previous instructions`, `${jndi:`, `eval(`) **antes** da chamada à API → levanta `GuardBlockedError`. Ligado/desligado por `LLM_GUARD_ENABLED`. |
| Métricas | `token_metrics.py` | Counters Prometheus: `claude_tokens_total{model,type}`, `claude_cost_usd_total{model}`, `claude_requests_total{model,outcome}` (`outcome` ∈ `success`/`circuit_open`/`blocked_by_guard`/`error`). |

**Modo degradado:** se o Claude falhar (circuit aberto, guard bloqueou, erro de API), `tier2_analyze`/`tier3_deep_analysis` retornam `{"degraded": True, "reason": ..., "findings": [...]}` e o pipeline continua; o worker de reporting cai para markdown de fallback com a lista crua de findings.

> **`/metrics` não está exposto.** Os counters acima existem em código, mas nenhum endpoint ASGI (`prometheus_client.make_asgi_app()`) foi registrado em `app/main.py` — os dashboards Grafana não recebem dados até isso ser corrigido.
