# aperIA — Guia de Execução Passo a Passo

Guia prático para subir a aplicação do zero, disparar uma análise de código e
acompanhar o pipeline até o relatório no PR. Para **cada etapa** está documentado
o que é gerado e qual é o output esperado de cada ferramenta.

> Todos os exemplos de output abaixo usam os nomes de campo **reais** do código
> (`app/domain/finding/entities.py`, workers em `app/presentation/workers/`,
> prompts em `app/infrastructure/ai/prompts/`).

---

## 0. Pré-requisitos

- Docker + Docker Compose v2 (`docker compose`, não `docker-compose`).
- (Opcional, para rodar testes/uvicorn local) Python 3.10+ com o `.venv` do projeto.
- Uma **chave da Anthropic com créditos** (`sk-ant-api03-...`) se quiser que o
  Claude gere análise de verdade. Sem ela o pipeline roda, mas degrada (ver §7).

### Correções já aplicadas nesta base

Estes 3 bugs bloqueavam a execução e **já foram corrigidos** neste repositório:

| Arquivo | Problema | Correção |
|---|---|---|
| `Dockerfile` | `python:3.11-slim` virou Debian 13 (Trivy apt vazio); `trivy=0.49.1` não existe mais em nenhuma fonte | Base fixada em `bookworm`; Trivy via tarball pinado do GitHub (`0.71.0`) |
| `app/infrastructure/database/sqlalchemy.py` | Engine síncrono recebia URL `+asyncpg` + `hostaddr` → `TypeError` no startup | `_normalize_scheme` converte `+asyncpg` → `+psycopg` |
| `app/core/celery_app.py` | Tasks de bridge do orquestrador iam para a fila default `celery` (que ninguém consome) e não eram registradas nos workers → pipeline travava após o Gate 1 | `app.core.orchestrator` adicionado aos módulos importados + rotas explícitas no `task_routes` |

---

## 1. Subir a aplicação

A stack tem 3 camadas. Para testar uma análise você só precisa da **base**.

### 1.1 Stack base (obrigatória)

```bash
docker compose -f docker-compose.base.yml up -d
```

Sobe **8 containers**:

| Serviço | Container | Porta | Papel |
|---|---|---|---|
| `api` | aperia-api | `8000` | FastAPI (webhook, health, auth) |
| `worker_tier1` | python-api-worker_tier1-1 | — | Celery `tier1`, concurrency 4 |
| `worker_tier2` | python-api-worker_tier2-1 | — | Celery `tier2`, concurrency 2 |
| `worker_tier3` | python-api-worker_tier3-1 | — | Celery `tier3`, concurrency 1 |
| `worker_analysis` | python-api-worker_analysis-1 | — | Celery `analysis`, concurrency 2 |
| `worker_reporting` | python-api-worker_reporting-1 | — | Celery `reporting`, concurrency 2 |
| `redis` | aperia-redis | — | Broker + result backend |
| `db` | aperia-db | — | PostgreSQL 15 (`postgres/postgres`, db `aperia`) |

> **Gotcha do `.env`:** o `docker-compose.base.yml` injeta
> `DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/aperia`, que
> **sobrescreve** qualquer `DB_HOST` do seu `.env` (ex.: Supabase). Dentro do
> Docker, o banco usado é sempre o `db` local.

### 1.2 Camadas opcionais

```bash
# + scanners pesados do Tier 3 (ZAP :8090, OpenCTI :8081, Caldera :8888)
docker compose -f docker-compose.base.yml -f docker-compose.scanners.yml up -d

# + observabilidade (Prometheus :9090, Grafana :3000 admin/changeme)
docker compose -f docker-compose.base.yml -f docker-compose.observability.yml up -d
```

> ⚠️ **Caldera:** o `docker-compose.scanners.yml` declara a rede
> `aperia_caldera_sandbox` com `internal: true`. **Nunca remova essa flag** —
> ela impede que técnicas MITRE ATT&CK reais executadas pelo Caldera escapem
> para a internet. O `CalderaClient` valida `CALDERA_SANDBOX_MODE=true` no boot
> e levanta `SandboxViolationError` se for `false`.

### 1.3 Aplicar migrations

```bash
docker compose -f docker-compose.base.yml exec api alembic upgrade head
```

(`alembic/env.py` converte `+asyncpg` → `+psycopg` automaticamente, pois o
Alembic precisa de driver síncrono.)

---

## 2. Verificar que está no ar

```bash
curl -s http://localhost:8000/health      # → {"status":"ok"}
docker compose -f docker-compose.base.yml ps   # todos "healthy"/"Up"
```

A documentação interativa da API fica disponível assim que a app sobe:

```bash
open http://localhost:8000/docs      # Swagger UI
open http://localhost:8000/redoc     # ReDoc
curl -s http://localhost:8000/openapi.json | head   # schema OpenAPI cru
```

Um snapshot versionado do schema está em `openapi.yaml` (OpenAPI 3.1). Ele é
**gerado** a partir do código — após mudar rotas/schemas, regenere com:

```bash
.venv/bin/python scripts/export_openapi.py
```

Rotas disponíveis (registradas em `app/main.py`):

| Método | Caminho | O que faz |
|---|---|---|
| `GET` | `/health` | Healthcheck → `{"status":"ok"}` |
| `POST` | `/webhook/github` | Recebe webhook do GitHub (HMAC obrigatório) |
| `POST` | `/users` | Cria usuário |
| `GET` | `/users/{user_id}` | Consulta usuário por UUID |
| `POST` | `/auth/login` | Login + tokens JWT |
| `POST` | `/auth/refresh` | Rotação de refresh token |
| `POST` | `/auth/logout` | Revoga refresh token (204 sempre) |
| `GET` | `/findings` | Lista findings (filtros `commit_sha`/`severity`/`tier`/`source` + paginação; exige JWT) |
| `GET` | `/findings/{finding_id}` | Detalhe de um finding, com `raw_output` (exige JWT) |
| `GET` | `/scans` | Lista scans recentes com paginação (exige JWT) |
| `GET` | `/scans/{commit_sha}` | Status por tier + `findings_summary` de um commit (exige JWT) |
| `GET` | `/scans/{commit_sha}/report` | Relatórios (markdown + analysis_json) de todos os tiers (exige JWT) |
| `GET` | `/scans/{commit_sha}/tiers/{tier}/report` | Relatório de um tier específico (exige JWT) |

> ⚠️ **`/metrics` não está conectado.** O README cita `GET /metrics`, mas
> nenhum router de métricas é incluído em `app/main.py`. Os counters Prometheus
> existem em `app/infrastructure/ai/token_metrics.py`, porém **falta expor** o
> endpoint (ex.: `prometheus_client.make_asgi_app()`). Até isso ser corrigido,
> os dashboards Grafana não terão dados.

---

## 3. Disparar uma análise (webhook)

O pipeline é iniciado por um webhook `pull_request` do GitHub. Para testar
localmente, montamos o payload e assinamos o HMAC. Como
`GITHUB_WEBHOOK_SECRET` tem default `""`, dá para assinar com **chave vazia**.

### 3.1 Contrato do webhook

- **Path:** `POST /webhook/github`
- **Headers:** `X-GitHub-Event: pull_request` e `X-Hub-Signature-256: sha256=<hmac>`
- **Actions que disparam:** `opened` ou `synchronize`
- **Campos lidos do payload** (`webhook_routes.py:42-76`):

| Campo JSON | Vira |
|---|---|
| `installation.id` | `installation_id` (sem ele → `{"status":"ignored"}`) |
| `pull_request.head.sha` | `commit_sha` / `head_sha` |
| `pull_request.base.sha` | `base_sha` |
| `pull_request.number` | `pr_number` |
| `repository.full_name` | `repo_full_name` |
| `repository.clone_url` | `repo_url` |

### 3.2 Comando

```bash
cat > /tmp/pr.json <<'JSON'
{"action":"opened","installation":{"id":12345},
 "pull_request":{"number":1,
   "head":{"sha":"deadbeefcafebabe0000000000000000deadbeef"},
   "base":{"sha":"0000000000000000000000000000000000000000"}},
 "repository":{"full_name":"OCR-aperIA/demo-repo",
   "clone_url":"https://github.com/OCR-aperIA/demo-repo.git"}}
JSON

SIG="sha256=$(openssl dgst -sha256 -hmac '' < /tmp/pr.json | sed 's/^.*= //')"

curl -sS -X POST http://localhost:8000/webhook/github \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: pull_request" \
  -H "X-Hub-Signature-256: $SIG" \
  --data-binary @/tmp/pr.json
```

**Resposta esperada:**

```json
{"status":"queued","commit_sha":"deadbeefcafebabe0000000000000000deadbeef"}
```

Isso monta o canvas Celery (`app/core/orchestrator.py:start_pipeline`) e dispara
de forma assíncrona. Acompanhe com:

```bash
docker compose -f docker-compose.base.yml logs -f \
  worker_tier1 worker_tier2 worker_analysis worker_reporting worker_tier3
```

---

## 4. O pipeline, etapa por etapa

Ordem do canvas (`app/core/orchestrator.py:build_pipeline_canvas`), com a fila de
cada passo:

```
group(run_trufflehog, run_semgrep_changed)         [tier1]
  → gate1_check                                     [analysis]   ← Gate 1: bloqueia se secret verificado
  → _t1_to_t2_scan_bridge → run_tier2_scan          [tier2]
  → _bridge_t1_findings_into_analyze → tier2_analyze[analysis]   ← Claude Sonnet (chain_of_events)
  → post_tier2_report                               [reporting]  ← Claude Haiku (markdown no PR)
  → tier3_gate                                      [analysis]   ← Gate 2: para se severidade < high
  → _prepare_tier3_payload → run_tier3_scan         [tier3]      ← ZAP + OpenCTI + Caldera
  → _deep_analysis_bridge → tier3_deep_analysis     [analysis]   ← Claude Sonnet (attack_path)
  → post_tier3_deep_report                          [reporting]  ← Claude Haiku (relatório final)
```

> **Propagação de `Ignore`:** quando um gate decide parar, ele levanta
> `celery.exceptions.Ignore()`. Em modo eager o resultado vira `None`, e cada
> "bridge" checa `if not input` e devolve `None`, encerrando o restante sem
> efeitos colaterais.

> **Persistência de findings (novo):** cada scan worker grava seus findings na
> tabela `findings` **antes** de devolver os dicts para o canvas — T1 (após cada
> scanner), T2 (após o dedup) e T3 (findings do ZAP). É um **side-effect
> best-effort**: roda fora do caminho crítico, e uma falha de banco é apenas
> logada (`finding_persistence_failed`) sem interromper o pipeline. Os gates e o
> Claude continuam operando sobre os dicts do canvas, **não** sobre o banco.
> Detalhes em "Persistência de findings" abaixo.

---

### Como os outputs viram score e relatório

Existem **dois mecanismos** distintos — não confunda:

**1. Decisões dos gates — determinísticas, baseadas em `severity` / `secret_verified`:**
- `secret_verified=True` em **qualquer** finding (só o TruffleHog seta isso) → **Gate 1 bloqueia o PR**.
- `_max_severity(findings) ∈ {high, critical}` → **Gate 2 escala para Tier 3**.
  O rank vem direto do campo `severity` de cada finding
  (`critical(4) > high(3) > medium(2) > low(1) > info(0)`).

**2. O `risk_score` exibido no relatório — produzido pelo Claude:**
- `tier2_analyze` (prompt `chain_of_events`) devolve `risk_score: {score 0-100, level}`,
  raciocinando sobre os findings + dados de CTI + Caldera.
- `tier3_deep_analysis` (prompt `attack_path`) devolve `risk_score_adjusted`.
- Os findings (`severity`, `title`, `cve_id`, `file_path`) são as **evidências** que o
  Claude pondera; quanto mais severo e correlacionável o conjunto, maior o score atribuído.

**3. ⚠️ O `RiskScorer` determinístico existe, mas NÃO está plugado.**
`app/domain/finding/services.py:RiskScorer` define um score ponderado
(**CVSS 25% · CTI 25% · Caldera 30% · Business 20%**, com regra hard
`secret_verified → mínimo 90`), e o comentário do prompt o chama de "fonte de verdade".
Porém **ele não é chamado em nenhum lugar do pipeline** — hoje o score real é o do Claude.
(Além disso, `_cti_component` lê a chave `active_campaigns`, enquanto o scan T3 produz
`active_threat` — divergência latente, ficaria sempre no ramo `else 25.0`.)
Nos comentários "**contribui para o score**" abaixo descrevo tanto a **intenção** do
design ponderado quanto o que **de fato** acontece hoje.

---

### Etapa 1 — Tier 1 (fila `tier1`): TruffleHog + Semgrep em paralelo

Ambos rodam sobre `repo_path` e devolvem `list[dict]` de Findings serializados.

#### `run_trufflehog` (`tier1_scan_worker.py`)

- **Comando:**
  ```
  trufflehog git file://<repo> --since-commit <base_sha> --branch <head_sha> \
             --only-verified --json --no-update
  ```
- **Parsing:** lê JSONL, mantém só itens com `"Verified": true`.
- **Severidade:** sempre `CRITICAL` (secret verificado).
- **Output (Finding dict):**
  ```python
  {
    "source": "trufflehog", "severity": "critical",
    "title": "Secret verificado: AWS",
    "description": "AKIAIOSFODNN7EXAMPLE",
    "file_path": "config/secrets.env", "line_number": 12,
    "secret_verified": True, "secret_type": "AWS",
    "commit_sha": "deadbeef...", "repo_url": "https://github.com/...",
    "tier": 1, "cve_id": None, "cwe_id": None, "raw_output": { ... }
  }
  ```
- **Log:** `tier1_trufflehog_complete findings_count=<n>`
- **Para que serve / como contribui:** cada item indica **qual credencial vazou**
  (`secret_type` = AWS/GitHub/GCP/...) e **onde** (`file_path:line_number`); o
  `description` carrega o valor bruto (uso interno, não vai para o comentário do PR).
  É o **único gatilho do Gate 1**: 1 secret verificado bloqueia o PR imediatamente,
  ignorando todo o resto. No design ponderado do `RiskScorer`, `secret_verified=True`
  força score **≥ 90** (regra hard). Severidade sempre `critical`, então também
  garante escalonamento ao Tier 3 (se o Gate 1 não bloqueasse antes).

#### `run_semgrep_changed` (`tier1_scan_worker.py`)

- **Comando:** `semgrep --config=p/security-audit --json --quiet <changed_files>` (cwd=`repo_path`)
- **Parsing:** lê o objeto JSON, extrai `results[]`.
- **Severidade:** `ERROR→HIGH`, `WARNING→MEDIUM`, `INFO→LOW`.
- **Output (Finding dict):**
  ```python
  {
    "source": "semgrep", "severity": "high",
    "title": "python.lang.security.audit.sql-injection.formatted-sql-query",
    "description": "Detected a formatted SQL query. Use parameterized queries instead.",
    "cwe_id": "CWE-89: SQL Injection", "cve_id": None,
    "file_path": "app/db.py", "line_number": 42,
    "secret_verified": False, "tier": 1, "raw_output": { ... }
  }
  ```
- **Log:** `tier1_semgrep_complete findings_count=<n>`
- **Para que serve / como contribui:** aponta **vulnerabilidade no código alterado**
  (SAST rápido, só o diff) — `title` é a regra (`check_id`), `cwe_id` classifica a
  fraqueza (ex. `CWE-89` = SQL injection) e `file_path:line_number` localiza. O
  `severity` mapeado (`ERROR→HIGH`) entra no `_max_severity` que decide o **Gate 2**,
  e a regra + CWE viram **evidência** para o Claude montar a `event_chain` e estimar o
  `risk_score`. Não bloqueia o PR sozinho (só secret verificado bloqueia).

---

### Etapa 2 — Gate 1 (fila `analysis`): `gate1_check`

Recebe **lista de listas** (`[[trufflehog...], [semgrep...]]`), achata e decide:

- **BLOQUEIA** se **qualquer** finding tem `secret_verified == True`:
  - GitHub status check → `failure` ("aperIA: secret verificado detectado — PR bloqueado")
  - Comentário 🚨 no PR
  - `raise Ignore()` → **Tier 2 e Tier 3 não rodam**
  - Log: `gate1_blocked_secret_verified`
- **PASSA** caso contrário:
  - Retorna `{"findings": [...], "blocked": False}`
  - Log: `gate1_passed findings_count=<n>`

---

### Etapa 3 — Tier 2 (fila `tier2`): `run_tier2_scan`

Roda 3 scanners (cada um isolado por `run_safe` — se um falhar, vira `[]` e o
pipeline segue), depois **deduplica**.

| Scanner | Comando | Observação |
|---|---|---|
| **Trivy** | `trivy <repo> --format json --quiet --exit-code 0` | SCA + IaC + container; parseia `Vulnerabilities` + `Misconfigurations` |
| **Semgrep (expanded)** | `semgrep --config=auto --json --quiet .` | Repo inteiro (vs. só arquivos alterados no T1) |
| **Prowler** | `prowler <provider> -M json --no-banner --quiet` | **Só roda se houver arquivos IaC** (`.tf/.yaml/Dockerfile/...`); filtra `Status==FAIL` |

- **Dedup** (`FindingDeduplicator`): chave `source:cve_id|title:file:line:commit` —
  mesmo CVE vindo de Trivy e Semgrep conta como **2 findings** (não funde).
- **Output:** `list[dict]` de Findings com `tier: 2`.
- **Log:** `tier2_scan_complete trivy=<n> semgrep_expanded=<n> prowler=<n> aggregated=<n> after_dedup=<n>`
- **Para que serve / como contribui:**
  - **Trivy** aponta **CVEs em dependências/containers e misconfigs de IaC**. O
    `cve_id` aqui é o que **liga** o finding ao enriquecimento OpenCTI no Tier 3
    (CVE → TTP MITRE). Sem `cve_id`, o finding não gera consulta de threat intel.
  - **Semgrep expanded** varre o **repo inteiro** (não só o diff) → cobertura maior
    que o T1.
  - **Prowler** aponta **misconfigs de nuvem** (`asset` = `ResourceId`), só quando há
    arquivos IaC no PR.
  - Todos contribuem com `severity` para o `_max_severity` (**Gate 2**) e como
    evidências para o `chain_of_events`. O **`after_dedup`** é a contagem que de fato
    segue para a análise; no design do `RiskScorer`, o maior `severity` do conjunto é
    o componente CVSS (25%).

---

### Etapa 4 — Tier 2 análise (fila `analysis`): `tier2_analyze` → **Claude Sonnet**

- **Prompt:** `prompts.chain_of_events` — correlaciona findings em cadeia de
  ataque, mapeando para MITRE ATT&CK. Campos ausentes recebem sentinelas
  (`"sem dados CTI disponíveis..."`) para evitar alucinação.
- **Output esperado (JSON do Claude):**
  ```json
  {
    "event_chain": [
      {"step": 1, "technique": "T1592", "description": "...", "finding_ids": ["<uuid>"]}
    ],
    "risk_score": {"score": 78, "level": "high"},
    "business_impact": {"description": "...", "estimated_cost_brl": 250000.0},
    "attack_narrative": "Cadeia de ataque em 3 passos...",
    "cti_status": "unavailable",
    "caldera_status": "unavailable"
  }
  ```
- **Modo degradado** (Claude falhou — circuit breaker / guard / erro de API):
  ```json
  {"degraded": true, "reason": "ClaudeClientError", "findings": [...],
   "cti_status": "unavailable", "caldera_status": "unavailable"}
  ```
- **Para que serve cada campo:**
  - `event_chain` → vira a seção **"Cadeia de eventos"** do comentário do PR (passos
    correlacionados + TTP MITRE por passo).
  - `risk_score` → a **nota exibida** no PR (0-100 + nível). É a saída de score que o
    pipeline usa hoje (o `RiskScorer` determinístico não está plugado).
  - `business_impact` → traduz o técnico em **risco de negócio / custo estimado**.
  - `attack_narrative` → **resumo executivo** em PT-BR.
  - `cti_status` / `caldera_status` → honestidade sobre dados ausentes; força o Claude
    a **não inventar** campanhas/exploração quando não há dado (anti-alucinação).
  - No **modo degradado**, nada disso é gerado: o relatório cai para a lista crua de
    findings (ainda útil — os scanners determinísticos não dependem do Claude).

---

### Etapa 5 — `post_tier2_report` (fila `reporting`): **Claude Haiku** → comentário no PR

- **Prompt:** `prompts.pr_report` (Haiku) transforma o JSON em markdown (≤25 linhas).
- **Comentário gerado:**
  ```markdown
  ## 🛡️ aperIA — Análise de Segurança (Tier 2)

  **Risk Score:** 78/100 (high)

  **Resumo do ataque:**
  Cadeia de 3 passos: enumeração de bucket S3 público, credencial AWS hardcoded,
  SQL injection para exfiltrar dados.

  **Cadeia de eventos:**
  1. [T1592] Reconnaissance — enumera bucket S3
  2. [T1078] Initial Access — credencial AWS hardcoded
  3. [T1005] Exfiltration — SQL injection + S3 público

  **Status de inteligência:**
  - CTI: unavailable
  - Caldera: unavailable
  ```
- **Degradado:** usa `_fallback_markdown` (lista crua de até 20 findings).
- **Retorno:** análise + `"_post_meta": {"comment_id": <id>, "posted": true|false, "error": ...}`

---

### Etapa 6 — Gate 2 (fila `analysis`): `tier3_gate`

- **Escala para Tier 3** se `max_severity ∈ {high, critical}` → repassa a análise.
  - Log: `tier3_escalated max_severity=high`
- **Encerra** se severidade ≤ medium → `raise Ignore()`.
  - Log: `tier3_skipped reason=below_threshold`

Rank: `critical(4) > high(3) > medium(2) > low(1) > info(0)`.

---

### Etapa 7 — Tier 3 scan (fila `tier3`): `run_tier3_scan`

> Requer a camada `docker-compose.scanners.yml`. Sem ela, ZAP/OpenCTI/Caldera
> não respondem e cada um degrada para vazio (`run_safe`).

| Sistema | O que faz | Output |
|---|---|---|
| **ZAP** (DAST) | spider → active scan → coleta alerts no `target_url` (pulado se `target_url=None`) | Findings `source="zap"`, `tier=3` |
| **OpenCTI** | GraphQL: CVE → técnicas MITRE | `{"active_threat": true, "mitre_techniques": ["T1190"], "cvss_base": 9.8}` |
| **Caldera** | emula as TTPs em sandbox isolado | `{"status":"ok","success_rate":0.5,"ttps_used":["T1190"],"caldera_validated":true}` |

- **Output combinado:** `{"findings": [...], "cti_data": {...}, "caldera_results": {...}}`
- **Para que serve / como contribui:**
  - **ZAP** confirma vulnerabilidades **explotáveis em runtime** (DAST, ataca o
    `target_url` de verdade) → evidência forte de exploitabilidade real, com peso
    alto no raciocínio do Claude.
  - **OpenCTI** responde *"esse CVE está sendo usado por atacantes hoje?"* —
    `active_threat` + `mitre_techniques` + `cvss_base`. No design do `RiskScorer`
    seria **25% (CTI)**; hoje alimenta o contexto do prompt `attack_path` e as TTPs
    que o Caldera vai emular.
  - **Caldera** mede o `success_rate` da emulação no **sandbox isolado** —
    *"o ataque realmente funciona neste ambiente?"*. É o **maior peso (30%)** no
    design do `RiskScorer` e marca cada passo do `attack_path` com
    `caldera_validated: true/false`, separando teoria de exploração comprovada.

---

### Etapa 8 — Tier 3 análise (fila `analysis`): `tier3_deep_analysis` → **Claude Sonnet**

- **Prompt:** `prompts.attack_path` — kill chain com fases MITRE + flag
  `caldera_validated` por passo.
- **Output esperado (JSON):**
  ```json
  {
    "attack_path": [
      {"step": 1, "phase": "initial_access", "technique": "T1190",
       "description": "RCE via SQL Injection", "finding_ids": ["<uuid>"],
       "caldera_validated": true}
    ],
    "kill_chain_complete": false,
    "prioritized_actions": [
      {"priority": 1, "action": "Usar prepared statements", "rationale": "T1190 é o vetor inicial"}
    ],
    "risk_score_adjusted": {"score": 87, "level": "critical"},
    "cti_status": "available", "caldera_status": "available"
  }
  ```
- **Para que serve cada campo:**
  - `attack_path` (com `phase` / `technique` / `caldera_validated`) → a **kill chain**
    do relatório final; o `✓`/`—` ao lado de cada passo vem do `caldera_validated`.
  - `kill_chain_complete` → indica se o ataque vai do acesso inicial até o **impacto**
    (cadeia fechada) ou para no meio.
  - `prioritized_actions` → lista **priorizada de remediação**; é a base conceitual das
    **code suggestions** (premissa inviolável: patch só com aprovação humana).
  - `risk_score_adjusted` → o score **recalculado** com a evidência do Tier 3
    (exploração ZAP/Caldera tende a elevar; sem confirmação tende a manter/baixar).

---

### Etapa 9 — `post_tier3_deep_report` (fila `reporting`): **Claude Haiku** → relatório final

- Markdown final no PR (`_T3_REPORT_SYSTEM`):
  ```markdown
  ## 🛡️ aperIA — Análise Profunda (Tier 3)

  **Risk Score (ajustado):** 87/100 (critical) — kill chain incompleta

  **Attack path:**
  1. [initial_access] [T1190] RCE via SQL Injection · ✓
  2. [execution] [T1110] Coleta de credenciais · —

  **Ações priorizadas:**
  1. Implementar prepared statements — T1190 é o vetor inicial
  2. WAF rules para SQLi — camada defensiva imediata

  **Status de inteligência:**
  - CTI: available
  - Caldera: available
  ```
- **Premissa inviolável:** patches saem como **GitHub code suggestions** para
  aprovação humana — aperIA nunca aplica código sozinho.

---

### Persistência de findings (tabela `findings`)

Os scan workers persistem os findings no Postgres conforme rodam — antes o
pipeline só trafegava dicts em memória e nada chegava ao banco.

- **Quem grava:** `tier1_scan_worker` (TruffleHog + Semgrep), `tier2_scan_worker`
  (após o dedup) e `tier3_scan_worker` (findings do ZAP). Cada worker chama
  `persist_findings(...)` (`app/infrastructure/persistence/finding_writer.py`).
- **Como grava:** abre sua própria `Session` síncrona via `SessionLocal`
  (workers Celery são síncronos) e usa
  `SQLAlchemyFindingRepository.bulk_save(...)`, que faz
  **`INSERT ... ON CONFLICT (dedup_key) DO NOTHING`**.
- **Dedup em duas barreiras:** o `FindingDeduplicator` remove duplicatas em
  memória (1ª barreira); a UNIQUE `findings_dedup_key` segura o que escapar —
  ex.: o mesmo finding visto em T1 e re-visto em T2, ou corrida entre workers
  paralelos (2ª barreira). Re-scan do mesmo commit **não** duplica linhas.
- **Best-effort:** se o banco estiver indisponível ou o schema desalinhado, o
  worker loga `finding_persistence_failed` e **segue** — o resultado do scan e o
  fluxo do canvas não são afetados. Em sucesso: `findings_persisted count=<n> tier=<n>`.
- **Liga/desliga:** flag `FINDINGS_PERSISTENCE_ENABLED` (default `True`; ver §9).
  A suíte de testes desliga por padrão (`tests/conftest.py`) para não exigir
  Postgres; os testes de persistência religam e injetam SQLite em memória.

> Pré-requisito: a tabela `findings` é criada pela migration
> `alembic upgrade head` (§1.3). Sem migration aplicada, a gravação cai no ramo
> best-effort e só loga o warning.

```bash
# inspecionar findings persistidos de um commit
docker compose -f docker-compose.base.yml exec -T db \
  psql -U postgres -d aperia -c \
  "select tier, source, severity, title from findings where commit_sha='deadbeefcafebabe0000000000000000deadbeef';"
```

---

## 5. Acompanhar a execução

```bash
# logs por worker
docker compose -f docker-compose.base.yml logs --tail 50 worker_analysis

# mensagens presas? a fila default "celery" tem que ficar em 0
docker compose -f docker-compose.base.yml exec -T redis redis-cli LLEN celery

# resultados das tasks
docker compose -f docker-compose.base.yml exec -T redis redis-cli KEYS 'celery-task-meta-*'
```

---

## 6. Modelo de dados `Finding` (referência)

`app/domain/finding/entities.py`:

| Campo | Tipo | Exemplo |
|---|---|---|
| `source` | str | `"trufflehog"`, `"semgrep"`, `"trivy"`, `"zap"`, `"prowler"` |
| `severity` | Severity | `critical`/`high`/`medium`/`low`/`info` |
| `title` | str | `"Secret verificado: AWS"` |
| `description` | str | mensagem da regra / valor do secret |
| `commit_sha` | str | hash de 40 chars |
| `repo_url` | str | URL HTTPS |
| `cve_id` | CVEId\|None | `CVE-2021-44228` |
| `cwe_id` | str\|None | `CWE-89` |
| `file_path` / `line_number` | str\|None / int\|None | `app/db.py` / `42` |
| `asset` | str\|None | `arn:aws:s3:::bucket` (Trivy/Prowler/ZAP) |
| `secret_verified` | bool | `True` só no TruffleHog |
| `secret_type` | str\|None | `"AWS"` |
| `raw_output` | dict | JSON nativo do scanner |
| `tier` | int | `1` / `2` / `3` |

> **Persistido em `findings`:** o `FindingModel`
> (`app/infrastructure/persistence/models/finding_model.py`) materializa
> `Finding.dedup_key()` na coluna `dedup_key` com UNIQUE `findings_dedup_key` —
> é o que garante idempotência via `ON CONFLICT DO NOTHING`. A `dedup_key` é
> `source:cve_id|title:file:line:commit`, então o **mesmo CVE vindo de scanners
> diferentes conta como 2 linhas** (o `source` faz parte da chave, por design).

Severidade vs. gate:

| Nível | Efeito |
|---|---|
| CRITICAL | bloqueia no Tier 1 se `secret_verified=true` |
| HIGH / CRITICAL | escala Tier 2 → Tier 3 |
| MEDIUM / LOW / INFO | encerra no Tier 2 |

---

## 7. O que esperar SEM créditos / SEM repo real

No estado atual do MVP, ao disparar o webhook com o payload de exemplo você verá:

1. ✅ Tier 1 roda (TruffleHog + Semgrep) → **0 findings**, porque o
   `repo_path` é um stub (`/tmp/aperia/<sha>`) — o checkout real do repositório
   é "pós-MVP". Você verá `scanner_skipped ... No such file or directory`.
   Com 0 findings, `persist_findings` é no-op (nada a gravar na tabela `findings`).
2. ✅ Gate 1 passa (`blocked=False`).
3. ✅ Tier 2 roda (Trivy executa) → 0 findings.
4. ⚠️ `tier2_analyze` chama o Claude:
   - **Sem chave / chave inválida:** erro de auth.
   - **Chave sem créditos:** `claude_api_error ... credit balance is too low` →
     degrada gracioso (`degraded: true`) e o pipeline continua.
5. ⚠️ `post_tier2_report` degrada; o post no GitHub falha (sem App key).
6. ✅ Gate 2 → `tier3_skipped` (0 findings → severidade `info` < high).

Ou seja: **o encanamento funciona de ponta a ponta**. Para ver a análise real do
Claude faltam: (a) **créditos** na conta Anthropic, (b) **checkout real** do
repo para os scanners acharem algo, (c) **credenciais do GitHub App** para postar
no PR.

---

## 8. Rodar a suíte de testes (não precisa de chaves/créditos)

A suíte mocka Claude e scanners — é o jeito determinístico de validar a lógica:

```bash
# local (venv com deps instaladas)
source .venv/bin/activate
pytest tests/ -q                          # 401 testes
pytest tests/e2e/test_full_pipeline.py -v # canvas completo mockado
pytest tests/ --cov=app --cov-fail-under=70

# ou dentro do container
docker compose -f docker-compose.base.yml exec api pytest tests/ -q
```

Estrutura: `tests/unit/` (domínio, prompts, circuit breaker), `tests/integration/`
(scanners mockados via respx, SQLite em memória, Celery eager),
`tests/e2e/test_full_pipeline.py` (canvas inteiro). Fixtures globais em
`tests/conftest.py` ligam o modo eager do Celery, resetam o circuit breaker e
**desligam a persistência de findings** (para os testes de worker não exigirem
Postgres).

Cobertura da persistência: `test_finding_repository.py` e `test_dedup_e2e.py`
(repositório síncrono + dedup via UNIQUE, em SQLite) e
`test_finding_persistence_worker.py` (worker grava no banco, `ON CONFLICT`
não duplica, flag off = nada gravado, e falha de banco não quebra o scan).

---

## 9. Tabela de variáveis de ambiente (`app/config.py`)

| Variável | Default | Necessária para |
|---|---|---|
| `ANTHROPIC_API_KEY` | `""` | Tier 2/3 (análise Claude) |
| `CLAUDE_MODEL_REASONING` | `claude-sonnet-4-6` | análise (Sonnet) |
| `CLAUDE_MODEL_FORMATTING` | `claude-haiku-4-5-20251001` | relatórios (Haiku) |
| `CLAUDE_PROMPT_CACHE_ENABLED` | `True` | cache de prompt |
| `LLM_GUARD_ENABLED` | `True` | bloqueio de prompt injection |
| `GITHUB_APP_ID` / `GITHUB_PRIVATE_KEY_PATH` | `""` | postar no PR |
| `GITHUB_WEBHOOK_SECRET` | `""` | HMAC do webhook (vazio = assina com chave vazia) |
| `ZAP_BASE_URL` / `ZAP_API_KEY` | `http://zap:8090` / `""` | Tier 3 DAST |
| `OPENCTI_URL` / `OPENCTI_TOKEN` | `http://opencti:8081` / `""` | Tier 3 CTI |
| `CALDERA_URL` / `CALDERA_API_KEY` | `http://caldera:8888` / `""` | Tier 3 emulação |
| `CALDERA_SANDBOX_MODE` | `True` | **inviolável** — `false` → `SandboxViolationError` |
| `REDIS_URL` | `redis://redis:6379/0` | broker/result Celery |
| `CELERY_TASK_ALWAYS_EAGER` | `False` | só testes (nunca prod) |
| `FINDINGS_PERSISTENCE_ENABLED` | `True` | grava findings na tabela `findings` (workers); `false` desliga a escrita |
| `SECRET_KEY` | `change-this-...` | JWT (trocar em prod) |

> `DATABASE_URL` não está no `config.py`: é montada em
> `app/infrastructure/database/sqlalchemy.py` a partir das vars `DB_*`, mas o
> `docker-compose.base.yml` a sobrescreve para o Postgres local.

---

## 10. Plumbing do Claude (referência rápida)

- **ClaudeClient** (`app/infrastructure/ai/claude_client.py`): `call` e `call_json`.
  Bloco `system` marcado com `cache_control: ephemeral` se cache ligado.
- **Circuit breaker** (`circuit_breaker.py`): abre após **3 falhas**
  consecutivas, janela de recuperação **300s**. Singleton process-wide.
- **LLM Guard** (`llm_guard_client.py`): bloqueia ~14 padrões de prompt
  injection (ex.: `ignore all previous instructions`, `${jndi:`, `eval(`)
  **antes** de chamar a API → levanta `GuardBlockedError`.
- **Métricas** (`token_metrics.py`, ⚠️ endpoint não exposto ainda):
  `claude_tokens_total{model,type}`, `claude_cost_usd_total{model}`,
  `claude_requests_total{model,outcome}` (outcome ∈ success / circuit_open /
  blocked_by_guard / error).

---

## Apêndice — Comando único para "do zero ao queued"

```bash
docker compose -f docker-compose.base.yml up -d --build
docker compose -f docker-compose.base.yml exec api alembic upgrade head
curl -s http://localhost:8000/health
cat > /tmp/pr.json <<'JSON'
{"action":"opened","installation":{"id":12345},
 "pull_request":{"number":1,"head":{"sha":"deadbeefcafebabe0000000000000000deadbeef"},"base":{"sha":"0000000000000000000000000000000000000000"}},
 "repository":{"full_name":"OCR-aperIA/demo-repo","clone_url":"https://github.com/OCR-aperIA/demo-repo.git"}}
JSON
SIG="sha256=$(openssl dgst -sha256 -hmac '' < /tmp/pr.json | sed 's/^.*= //')"
curl -sS -X POST http://localhost:8000/webhook/github \
  -H "X-GitHub-Event: pull_request" -H "X-Hub-Signature-256: $SIG" \
  --data-binary @/tmp/pr.json
docker compose -f docker-compose.base.yml logs -f worker_tier1 worker_tier2 worker_analysis
```
