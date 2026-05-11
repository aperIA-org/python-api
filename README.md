# aperIA — ASPM com Heurística Ofensiva de IA

> **Application Security Posture Management** powered by Claude.
> 100% open source (exceto Claude API). Raciocina como um atacante, entrega patches como code suggestions, nunca auto-aplica código.

---

## Índice

1. [O que é a aperIA](#1-o-que-é-a-aperia)
2. [Como funciona — Pipeline completo](#2-como-funciona--pipeline-completo)
3. [Stack tecnológica](#3-stack-tecnológica)
4. [Arquitetura — Domain-Driven Design](#4-arquitetura--domain-driven-design)
5. [Módulos implementados](#5-módulos-implementados)
   - [Fase 0 — Infraestrutura base](#fase-0--infraestrutura-base)
   - [Fase 1 — Pipeline de scan (7 scanners)](#fase-1--pipeline-de-scan-7-scanners)
   - [Fase 2 — Inteligência de ameaças e risk scoring](#fase-2--inteligência-de-ameaças-e-risk-scoring)
   - [Fase 3 — Análise Claude e code suggestions](#fase-3--análise-claude-e-code-suggestions)
   - [Business Context Inferrer](#business-context-inferrer)
   - [Fase 4 — API REST, persistência e workers](#fase-4--api-rest-persistência-e-workers)
6. [Risk Score — fórmula e componentes](#6-risk-score--fórmula-e-componentes)
7. [Regra de remediação inviolável](#7-regra-de-remediação-inviolável)
8. [Variáveis de ambiente](#8-variáveis-de-ambiente)
9. [Configuração de desenvolvimento](#9-configuração-de-desenvolvimento)
10. [Deploy em produção](#10-deploy-em-produção)
11. [Executando os testes](#11-executando-os-testes)
12. [Estrutura de diretórios](#12-estrutura-de-diretórios)
13. [Regras de segurança do próprio código](#13-regras-de-segurança-do-próprio-código)

---

## 1. O que é a aperIA

A aperIA é uma plataforma de **ASPM (Application Security Posture Management)** que usa IA para raciocinar como um atacante real — não apenas listar vulnerabilidades, mas construir a narrativa de como elas seriam exploradas em cadeia.

**Premissa central:** o merge de um PR nunca é desbloqueado automaticamente. Todo patch gerado é entregue como **GitHub code suggestion**, aguardando revisão e aprovação humana.

### O que a aperIA faz automaticamente

Quando um pull request é aberto ou atualizado:

1. **Detecta segredos ativos** no código com TruffleHog — bloqueia o merge imediatamente se verificado
2. **Executa 6 scanners em paralelo**: SAST, SCA, DAST, infra, cloud posture, agente de runtime
3. **Enriquece** cada CVE encontrado com dados do OpenCTI (TTPs MITRE ATT&CK, campanhas ativas)
4. **Emula** os attack paths no MITRE Caldera (sandbox isolado) — valida se são realmente exploráveis
5. **Infere automaticamente** o contexto de negócio do repositório (fintech? healthcare? SaaS?)
6. **Calcula** um Risk Score de 0–100 ponderado por CVSS, CTI, Caldera e impacto de negócio
7. **Claude raciocina** como red teamer: constrói a cadeia de eventos, attack paths, patches e relatório
8. **Posta** patches como code suggestions inline no PR e um relatório completo como PR review
9. **Bloqueia o merge** (REQUEST_CHANGES) até que o desenvolvedor revise e aprove

---

## 2. Como funciona — Pipeline completo

```
Push / Pull Request
        │
        ▼
   Webhook GitHub ──► validação HMAC SHA-256
        │
        ▼
   Celery Worker (fila: scan)
        │
        ├─ [Etapa 1] Clone do repositório com installation token
        │
        ├─ [Etapa 2] TruffleHog ──► verified secret?
        │                              └─ SIM → block_merge() imediato + continua
        │
        ├─ [Etapa 3] 6 scanners em paralelo (ThreadPoolExecutor)
        │             ├─ Semgrep    (SAST — padrões de vulnerabilidade no código)
        │             ├─ Trivy      (SCA + IaC — CVEs em dependências e containers)
        │             ├─ OWASP ZAP  (DAST — aplicação em execução, black-box)
        │             ├─ OpenVAS    (infra — CVEs em serviços de rede)
        │             ├─ Wazuh      (SIEM — postura de runtime, anomalias)
        │             └─ Prowler    (CSPM — misconfigurations cloud AWS/Azure/GCP)
        │
        ├─ [Etapa 4] Normalização + Deduplicação de findings
        │             └─ chave: source:cve_id:file_path:line_number
        │
        ├─ [Etapa 4.5] Business Context Inferrer ─── AUTO, sem config manual
        │               ├─ Extrai sinais do repo (deps, .env.example, modelos, rotas)
        │               ├─ Claude sintetiza: fintech? healthcare? PII? compliance?
        │               └─ Fallback heurístico se Claude indisponível
        │
        ├─ [Etapa 5] OpenCTI — enriquecimento CTI
        │             └─ CVE → TTPs MITRE ATT&CK + campanhas ativas
        │
        ├─ [Etapa 6] MITRE Caldera — emulação em sandbox
        │             ├─ Cria adversário com TTPs dos findings
        │             ├─ Executa operação no agente sandbox
        │             └─ Valida quais técnicas foram executáveis (success_rate)
        │
        ├─ [Etapa 7] Risk Score (0–100)
        │             = CVSS×25% + CTI×25% + Caldera×30% + Business×20%
        │             └─ secret verificado: mínimo 90, independente do cálculo
        │
        ├─ [Etapa 8] Commit status no GitHub (pending → success/failure)
        │
        └─ [Etapa 9] Claude — Heuristic Engine (só para PRs)
                      ├─ Prompt 1: chain_of_events   → cadeia de ataque narrativa
                      ├─ Prompt 2: attack_path       → paths validados pelo Caldera
                      ├─ Prompt 3: remediation       → patches em unified diff
                      ├─ Prompt 4: pr_report         → relatório Markdown para o PR
                      │
                      ├─ Code suggestions inline por finding com file_path
                      └─ PR Review: REQUEST_CHANGES / COMMENT / APPROVE
```

### Exemplo de output no PR

```markdown
## 🔴 aperIA Security Analysis — Risk Score: 87/100 CRITICAL

### Sumário
Foram encontrados 3 segredos verificados (AWS Key ativa, Stripe key ativa) e
1 SQL injection crítico. O Caldera validou T1078 com 100% de sucesso.
O merge está bloqueado até resolução dos itens críticos.

### Risk Score Breakdown
| Componente       | Valor                          |
|------------------|--------------------------------|
| CVSS Base        | 95/100 (secret verificado)     |
| Threat Intel     | 2 campanhas ativas (APT28)     |
| Emulação Caldera | 100% de técnicas com sucesso   |
| Impacto negócio  | CRITICAL — fintech, PCI-DSS    |
| **Score Final**  | **87/100 — CRITICAL**          |

### Attack Path Identificado
[1] TruffleHog: AWS_ACCESS_KEY verificada (T1552.001)
      ↓
[2] Acesso à conta AWS com credenciais reais (T1078)
      ↓
[3] Exfiltração de dados do S3 com dados de usuários (T1530)
      ↓
IMPACTO: Exposição de PII de 50k usuários
CUSTO ESTIMADO: R$ 500.000 – R$ 2.000.000 (LGPD + resposta a incidente)

**Decisão: REQUEST_CHANGES — merge bloqueado**
```

---

## 3. Stack tecnológica

| Camada | Tecnologia | Função |
|---|---|---|
| Backend | **Python 3.11 + FastAPI** | API REST assíncrona |
| Arquitetura | **DDD (Domain-Driven Design)** | Separação domain/application/infrastructure |
| Fila | **Celery + Redis 7** | Workers assíncronos para scans pesados |
| Banco | **PostgreSQL 15 + asyncpg** | Persistência de findings e scan jobs |
| LLM | **Claude API** (`claude-sonnet-4-20250514`) | Motor central de heurística ofensiva |
| AI Security | **LLM Guard** (biblioteca Python) | Proteção contra prompt injection |
| Threat Intel | **OpenCTI** (GraphQL) | TTPs MITRE ATT&CK + campanhas ativas |
| Emulação | **MITRE Caldera** (REST v2) | Validação de attack paths em sandbox |
| Secrets | **TruffleHog CLI** (`--only-verified`) | Credenciais ativas em código |
| SAST | **Semgrep CLI** (`--config=auto`) | Vulnerabilidades por padrão de código |
| SCA + IaC | **Trivy CLI** | CVEs em dependências, containers, Terraform |
| DAST | **OWASP ZAP** (REST API) | Vulnerabilidades em app em execução |
| Infra | **OpenVAS/Greenbone** (GMP) | CVEs em serviços de rede |
| SIEM | **Wazuh** (REST API) | Postura de runtime e anomalias |
| CSPM | **Prowler CLI** | Misconfigurations cloud |
| Git | **GitHub App** (JWT RS256) | Webhooks, code suggestions, PR reviews |
| Observabilidade | **Prometheus + Grafana** | Métricas do pipeline |
| Deploy | **Coolify** (self-hosted PaaS) | Deploy via Docker Compose |

---

## 4. Arquitetura — Domain-Driven Design

A dependência flui apenas para dentro — camadas externas dependem de internas, nunca o contrário:

```
┌─────────────────────────────────────────────────────────────┐
│  presentation/  ←── FastAPI routes + Celery workers         │
│  (depende de application/ e infrastructure/)                 │
├─────────────────────────────────────────────────────────────┤
│  infrastructure/  ←── scanners, AI, git, persistence        │
│  (implementa contratos de domain/, usa libs externas)        │
├─────────────────────────────────────────────────────────────┤
│  application/  ←── use cases, orquestração                  │
│  (depende só de domain/, sem lógica de negócio própria)      │
├─────────────────────────────────────────────────────────────┤
│  domain/  ←── entidades, value objects, repositórios, srvcs │
│  (zero dependências externas — Python puro)                  │
└─────────────────────────────────────────────────────────────┘
        ↑ core/ é transversal: config, db, celery, exceptions
```

**Regra inviolável:** `domain/` nunca importa de `infrastructure/` ou `presentation/`.

---

## 5. Módulos implementados

### Fase 0 — Infraestrutura base

| Arquivo | O que faz |
|---|---|
| `core/config.py` | `Settings` via pydantic-settings — todas as credenciais via `.env` |
| `core/database.py` | Engine async SQLAlchemy, pool 10+20, `get_db()` generator |
| `core/exceptions.py` | Hierarquia: `AperIAError` → 13 exceções específicas |
| `core/celery_app.py` | 3 filas (scan, analysis, remediation), acks_late, prefetch=1 |
| `core/security.py` | `safe_repo_path()` e `verify_github_signature()` HMAC SHA-256 |
| `domain/finding/entities.py` | `Finding`, `AttackPath`, `EventChain`, `RiskScore` |
| `domain/finding/value_objects.py` | `Severity`, `CVEId` (validação regex), `CWEId`, `BusinessImpact` |
| `domain/finding/services.py` | `FindingDeduplicator`, `RiskScorer`, `AttackPathBuilder` |
| `domain/shared/value_objects.py` | `BusinessContext`, `AssetCriticality`, `ThreatLevel` |
| `docker-compose.yml` | Dev completo: PostgreSQL, Redis, Caldera (rede sandbox isolada), Prometheus, Grafana |

### Fase 1 — Pipeline de scan (7 scanners)

Cada scanner segue o mesmo contrato: `scan(*args) → list[Finding]`. Nunca usa `shell=True`.

| Scanner | Arquivo | Detalhes |
|---|---|---|
| **TruffleHog** | `infrastructure/scanners/trufflehog_scanner.py` | `--only-verified` — só credenciais ativas. Sempre `Severity.CRITICAL`. Bloqueia PR imediatamente se `secret_verified=True`. |
| **Semgrep** | `infrastructure/scanners/semgrep_scanner.py` | `--config=auto`. Mapeamento: `ERROR→CRITICAL`, `WARNING→HIGH`, `INFO→MEDIUM`. Extrai CWE ID dos metadados. |
| **Trivy** | `infrastructure/scanners/trivy_scanner.py` | Processa `Vulnerabilities` e `Misconfigurations`. Extrai `CVEId` do campo `VulnerabilityID`. |
| **OWASP ZAP** | `infrastructure/scanners/zap_scanner.py` | Spider + active scan com polling. `High→HIGH`, `Medium→MEDIUM`. Skippado se `ZAP_TARGET_URL` vazio. |
| **OpenVAS** | `infrastructure/scanners/openvas_scanner.py` | Protocolo GMP via TLS. Ciclo: create_target → create_task → start → poll → parse. Skippado se `OPENVAS_TARGET_IP` vazio. |
| **Wazuh** | `infrastructure/scanners/wazuh_scanner.py` | Auth JWT próprio. Busca vulnerabilidades por `agent_id`. Skippado se `WAZUH_AGENT_ID` vazio. |
| **Prowler** | `infrastructure/scanners/prowler_scanner.py` | `prowler aws -M json`. Só falhas (`Status == FAIL`). Provider configurável. |

**Orquestrador** (`core/orchestrator.py`):
- TruffleHog roda primeiro (prioridade máxima)
- 6 scanners em `ThreadPoolExecutor(max_workers=6)` — paralelo real
- Findings deduplicados pela chave `source:cve_id:file_path:line_number`
- Repo clonado em `tempdir` com installation token, removido no `finally`

**GitHub App** (`infrastructure/git/github_client.py`):
- JWT RS256 com chave privada RSA (`iat-60`, `exp+600`)
- Installation token por repositório (expira em 1h)
- `set_commit_status()`, `block_merge()`, `create_pr_review()`, `create_inline_suggestion()`

**Webhook** (`presentation/api/webhooks.py`):
- Validação HMAC SHA-256 com `hmac.compare_digest()` (constant-time)
- Eventos `push` (ignora main/master) e `pull_request` (opened/synchronize/reopened)
- Dispara `run_scan.delay()` → Celery

### Fase 2 — Inteligência de ameaças e risk scoring

#### LLM Guard (`infrastructure/ai/llm_guard_client.py`)

Proteção obrigatória contra prompt injection antes de qualquer chamada ao Claude.

```
Repositório analisado pode ter payloads de injection em comentários, nomes
de variáveis ou mensagens de commit → LLM Guard intercepta antes do Claude.
```

Usa a biblioteca Python `llm_guard` (não HTTP):
- `validate_input()`: `PromptInjection + Secrets + TokenLimit(4096)` → levanta `PromptInjectionError` se bloqueado
- `validate_output()`: `Sensitive + NoRefusal` → sanitiza, nunca bloqueia

#### Claude Client (`infrastructure/ai/claude_client.py`)

Wrapper sync do `anthropic.Anthropic`:
- `call(system, user_prompt, commit_sha)` → string (com guard input+output)
- `call_json(...)` → dict (chama `call` + `parse_json_response`)
- `parse_json_response()`: remove markdown code fences antes do `json.loads`

#### OpenCTI (`infrastructure/intelligence/opencti_client.py`)

GraphQL client via `gql[requests]`:
- `enrich_cve(cve_id)` → `{mitre_techniques, active_threat, cvss_base}` ou `None`
- `get_active_campaigns(ttp_ids)` → `{active_campaigns, techniques}`
- Falha silenciosa com log de warning

#### MITRE Caldera (`infrastructure/intelligence/mitre_caldera_client.py`)

Cliente sync httpx — **sandbox obrigatório** (`CALDERA_SANDBOX_MODE=True` verificado em `__init__`):
- `run_emulation(ttp_ids, commit_sha)` → pipeline completo:
  1. `_create_adversary()`: lookup de abilities via `/api/v2/abilities?technique_id=T1234`
  2. `_run_operation()`: inicia operação no grupo `CALDERA_AGENT_GROUP`
  3. `_await_results()`: polling a cada 10s, timeout 10 min
  4. `_parse_results()`: `success_rate = técnicas_bem_sucedidas / total`

#### Use cases (Fase 2)

| Use Case | O que faz |
|---|---|
| `EnrichFindingsUseCase` | CVEs dos findings → OpenCTI → dict `{per_cve, active_campaigns, techniques}` |
| `RunEmulationUseCase` | TTPs do CTI → Caldera → `{success_rate, caldera_validated, ttps_used}` |
| `ScoreFindingsUseCase` | Calcula `RiskScore` com os 4 componentes |

### Fase 3 — Análise Claude e code suggestions

#### Heuristic Engine (`infrastructure/ai/heuristic_engine.py`)

Orquestra 4 prompts Claude em sequência — cada um alimenta o próximo:

```
Prompt 1: chain_of_events
  → Cadeia de ataque narrativa (initial_access → steps → impact → risk_score)
  → Usa: findings + CTI data + business_context

Prompt 2: attack_path
  → Attack paths validados + probabilidade de sucesso
  → Usa: chain (P1) + caldera_results + repo_context

Prompt 3: remediation
  → Patches em unified diff para cada finding com file_path
  → Usa: findings + attack_paths (P2) + repo_context

Prompt 4: pr_report
  → Relatório Markdown completo para o PR review
  → Usa: chain (P1) + paths (P2) + remediations (P3) + repo_context
```

#### Use cases (Fase 3)

| Use Case | O que faz |
|---|---|
| `GeneratePatchUseCase` | Invoca `HeuristicEngine.run()` → dict com chain, paths, remediations, pr_report |
| `SuggestPatchUseCase` | Para cada remediação: cross-referencia `finding_id` → `file_path + line_number` → `create_inline_suggestion()` |
| `BlockMergeUseCase` | `github.block_merge()` com mensagem de risco estruturada |
| `GeneratePRReportUseCase` | `create_pr_review()` com event: `CRITICAL/HIGH → REQUEST_CHANGES`, `MEDIUM → COMMENT`, `LOW → APPROVE` |

### Business Context Inferrer

Analisa automaticamente o repositório clonado para inferir contexto de negócio **sem nenhuma configuração manual**.

#### Extração de sinais (`infrastructure/analysis/_repo_signals.py`)

Lê arquivos (nunca executa código):

| Sinal | Fonte | Exemplo de inferência |
|---|---|---|
| Dependências | `requirements.txt`, `package.json`, `go.mod`, `Gemfile`, `pom.xml` | `stripe` → fintech, PCI-DSS |
| Variáveis de ambiente | `.env.example` (apenas nomes, nunca valores) | `STRIPE_KEY` → financial data |
| Entidades | regex `class User/Payment/Patient…` em até 25 arquivos fonte | `class Patient` → healthcare, HIPAA |
| Rotas | regex `/auth`, `/payment`, `/admin` nos arquivos fonte | `/checkout` → ecommerce |
| Campos sensíveis | `cpf`, `credit_card`, `medical_record`, `ssn` | `cpf` → PII, LGPD |
| Frameworks | mapeamento de deps | `fastapi` → web_api, internet-facing |
| Cloud/CI | existência de arquivos | `.github/workflows` → CI/CD detectado |

#### Síntese com Claude (`infrastructure/analysis/business_context_inferrer.py`)

```python
# Com Claude (confiança ≥ 0.75):
inferrer.infer(repo_path, commit_sha)
→ BusinessContext(domain="fintech", asset_criticality=CRITICAL,
                  contains_financial_data=True, compliance_scope=("PCI-DSS", "LGPD"),
                  breach_cost_brl_min=500_000, breach_cost_brl_max=5_000_000, ...)

# Fallback heurístico (confiança 0.40, sem LLM):
inferrer.infer_without_llm(repo_path)
→ BusinessContext(..., inference_confidence=0.40)
```

**Regras do fallback heurístico:**
- `stripe/braintree` em deps → `CRITICAL + PCI-DSS`
- `class Patient` ou `fhir` em deps → `CRITICAL + HIPAA`
- `class User + fastapi` → `HIGH + LGPD + internet-facing`
- Repo sem sinais → `LOW`, sem compliance

**Integração no pipeline:** etapa 4.5, enquanto o repo está clonado. O `BusinessContext` flui para:
1. `RiskScorer._business_component()` — score de negócio calibrado com dados reais
2. `repo_context["business_context"]` — incluso nos prompts do Claude (custo BRL, compliance)

### Fase 4 — API REST, persistência e workers

Camada `presentation/` completa com persistência no PostgreSQL via Alembic.

#### Endpoints disponíveis

| Método | Rota | Descrição |
|---|---|---|
| `POST` | `/webhook/github` | Recebe push/PR do GitHub, valida HMAC, enfileira scan |
| `GET` | `/scans/` | Lista os 20 scans mais recentes |
| `GET` | `/scans/{scan_id}` | Status de um scan por UUID |
| `GET` | `/scans/commit/{sha}` | Status de um scan por commit SHA |
| `GET` | `/findings/commit/{sha}` | Todos os findings de um commit |
| `GET` | `/findings/commit/{sha}/secrets` | Apenas secrets verificados |
| `GET` | `/findings/{finding_id}` | Finding individual por UUID |
| `GET` | `/reports/commit/{sha}` | Relatório completo: scan + findings + severidade breakdown |
| `GET` | `/reports/scan/{scan_id}` | Mesmo relatório, por scan ID |
| `GET` | `/health` | Health check |

#### ScanJob lifecycle (persistência)

```
scan_worker.run_scan()
    │
    ├─ ScanJob.PENDING  → save_scan_job()
    ├─ ScanJob.RUNNING  → update_scan_job()
    ├─ run_pipeline()   → PipelineResult(findings, risk_score, business_ctx)
    ├─ ScanJob.COMPLETED → update_scan_job()
    └─ bulk_save_findings()  # todos os findings no banco
```

#### Workers

| Worker | Celery queue | Função |
|---|---|---|
| `scan_worker.run_scan` | `scan` | Pipeline completo + persistência ScanJob + findings |
| `analysis_worker.run_analysis` | `analysis` | Re-enriquecimento CTI + recálculo risk score para scan existente |
| `remediation_worker.run_remediation` | `remediation` | Re-geração de patches + PR report para scan existente com PR |

`analysis_worker` e `remediation_worker` são usados para **re-execução** sem re-clonar o repo — útil quando novos dados CTI chegam ou quando o report inicial falhou.

#### Migrations Alembic

```bash
# Criar tabelas (primeira vez)
DATABASE_URL=postgresql+asyncpg://... alembic upgrade head

# Nova migration após mudança de modelo
alembic revision --autogenerate -m "descricao"
alembic upgrade head

# Rollback
alembic downgrade -1
```

A migration `0001_initial_tables.py` cria as tabelas `scan_jobs` e `findings` com todos os índices necessários.

#### `db_utils.py` — bridge async/sync

Celery workers são síncronos. Os repositórios SQLAlchemy são async. O módulo `infrastructure/persistence/db_utils.py` resolve isso com `asyncio.run()`:

```python
# Em qualquer Celery worker:
save_scan_job(scan_job)           # sync — internamente usa asyncio.run()
bulk_save_findings(findings)      # sync
job = load_scan_job(scan_job_id)  # sync → ScanJob
```

---

## 6. Risk Score — fórmula e componentes

```
Score (0–100) = CVSS_component    × 0.25
              + CTI_component      × 0.25
              + Caldera_component  × 0.30
              + Business_component × 0.20
```

| Componente | Como é calculado |
|---|---|
| **CVSS** | `max(severity_score for finding in findings)` onde `critical=100, high=75, medium=50, low=25` |
| **CTI** | `min(active_campaigns × 25, 100)` — campanhas ativas do OpenCTI |
| **Caldera** | `success_rate × 100` — % de técnicas executáveis no sandbox |
| **Business** | Base por `AssetCriticality` + modificadores: `financial+12`, `health+12`, `pii+8`, `internet+5`, `multi-compliance+5` |

**Regra especial — TruffleHog verified:** `score = max(calculado, 90)` — mínimo 90 se qualquer finding tiver `secret_verified=True`.

**Ação por nível:**

| Score | Level | Ação aperIA |
|---|---|---|
| 80–100 | `critical` | `REQUEST_CHANGES` + merge bloqueado |
| 70–79 | `high` | `REQUEST_CHANGES` + merge bloqueado |
| 40–69 | `medium` | `COMMENT` — merge com aviso |
| 0–39 | `low` | `APPROVE` — PR ok |

---

## 7. Regra de remediação inviolável

> **A aperIA nunca aplica código automaticamente.**

Todo patch gerado pelo Claude é entregue como **GitHub code suggestion inline**. O desenvolvedor vê o diff diretamente no PR, clica em "Accept suggestion" e faz merge. A aperIA nunca faz commit, nunca abre PR próprio, nunca modifica arquivos diretamente.

Modelo: **GitHub Copilot** para segurança — sugestão + aprovação humana.

---

## 8. Variáveis de ambiente

Copie `.env.example` para `.env` e preencha:

```env
# GitHub App (obrigatório)
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY_PATH=/secrets/github.pem
GITHUB_WEBHOOK_SECRET=seu_secret_hmac
GITHUB_TOKEN=ghp_...

# Claude API (obrigatório)
ANTHROPIC_API_KEY=sk-ant-...

# Database
DATABASE_URL=postgresql+asyncpg://aperia:senha@postgres:5432/aperia

# Redis
REDIS_URL=redis://redis:6379/0
REDIS_PASSWORD=senha_redis

# Caldera — NUNCA desabilitar em produção
CALDERA_URL=http://caldera:8888
CALDERA_API_KEY=sua_chave
CALDERA_SANDBOX_MODE=true
CALDERA_AGENT_GROUP=aperia-sandbox

# OpenCTI
OPENCTI_URL=http://opencti:8080
OPENCTI_TOKEN=seu_token

# LLM Guard
LLM_GUARD_ENABLED=true

# Scanners opcionais (vazio = pulado no pipeline)
ZAP_BASE_URL=http://zap:8080
ZAP_API_KEY=sua_chave
ZAP_TARGET_URL=https://sua-app.com      # vazio = ZAP pulado
OPENVAS_HOST=openvas
OPENVAS_PORT=9390
OPENVAS_USERNAME=admin
OPENVAS_PASSWORD=senha
OPENVAS_TARGET_IP=10.0.0.1             # vazio = OpenVAS pulado
WAZUH_BASE_URL=https://wazuh:55000
WAZUH_USERNAME=wazuh-wui
WAZUH_PASSWORD=senha
WAZUH_AGENT_ID=001                     # vazio = Wazuh pulado

# AWS (Prowler)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1

# App
ENV=production
LOG_LEVEL=INFO
```

---

## 9. Configuração de desenvolvimento

### Pré-requisitos

- Docker + Docker Compose
- Python 3.11+ (para rodar testes localmente)
- Conta GitHub com uma GitHub App criada

### Criar a GitHub App

1. GitHub → Settings → Developer settings → GitHub Apps → New GitHub App
2. Permissões necessárias:
   - `contents: read`
   - `pull_requests: write`
   - `statuses: write`
   - `issues: write`
3. Webhook URL: `https://seu-dominio/webhook/github`
4. Gerar chave privada RSA → salvar como `/secrets/github.pem`

### Subir o ambiente de desenvolvimento

```bash
# Copiar env
cp .env.example .env
# Editar .env com suas credenciais

# Subir todos os serviços
docker compose up -d

# Rodar migrations
docker compose run --rm api alembic upgrade head

# Ver logs da API
docker compose logs -f api

# Ver logs dos workers
docker compose logs -f worker
```

A API estará disponível em `http://localhost:8000`.
Documentação Swagger em `http://localhost:8000/docs` (apenas em desenvolvimento).

### Endpoints disponíveis

| Método | Rota | Função |
|---|---|---|
| `POST` | `/webhook/github` | Recebe eventos do GitHub App |
| `GET` | `/health` | Health check básico |
| `GET` | `/health/db` | Health check com ping no banco |
| `GET` | `/findings` | Lista findings do banco |
| `GET` | `/scans` | Lista scan jobs |
| `GET` | `/reports` | Lista relatórios gerados |

---

## 10. Deploy em produção

### Opção A — Oracle Cloud Free Tier + Coolify (€0/mês)

Perfeito para começar sem custo:

```bash
# 1. Criar VM no Oracle Cloud
# Shape: VM.Standard.A1.Flex (ARM) — Always Free
# 4 OCPUs, 24GB RAM, Ubuntu 22.04
# Abrir portas: 22, 80, 443, 8000

# 2. Instalar Coolify
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash
# Acesse http://<ip-vm>:8000 → configure o painel

# 3. PostgreSQL: Neon.tech (free tier)
# DATABASE_URL=postgresql+asyncpg://user:pass@ep-xxx.neon.tech/aperia?sslmode=require

# 4. Redis: Upstash (free até 10k req/dia)
# REDIS_URL=rediss://default:pass@xxx.upstash.io:6379

# 5. No Coolify: New Resource → Docker Compose
# Apontar para o repositório → selecionar docker-compose.prod.yml → Deploy
```

### Opção B — Hetzner CX32 (~€7/mês)

Mais estável para produção real:

```bash
# Servidor Hetzner CX32 (4 vCPU, 8GB RAM, Ubuntu 22.04)
curl -fsSL https://get.docker.com | sh
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash
git clone https://github.com/OCR-aperIA/python-api.git
cd python-api && cp .env.example .env
# Editar .env com credenciais de produção
docker compose -f docker-compose.prod.yml up -d
```

### Migrations em produção

```bash
docker compose -f docker-compose.prod.yml run --rm api alembic upgrade head
```

---

## 11. Executando os testes

```bash
# Instalar dependências de teste
pip install -r requirements.txt

# Todos os testes
pytest

# Apenas unitários (rápidos, sem I/O externo)
pytest tests/unit/ -v

# Apenas integração (mocks HTTP via respx)
pytest tests/integration/ -v

# Com cobertura
pytest --cov=. --cov-report=html

# Teste específico
pytest tests/unit/test_repo_signals.py -v
```

### Cobertura de testes atual

| Suite | Arquivo de teste | O que testa |
|---|---|---|
| Unit | `test_trufflehog_scanner.py` | Parsing JSON, flag `--only-verified`, malformed lines, timeout |
| Unit | `test_semgrep_scanner.py` | Mapeamento de severidade, extração de CWE, `shell=False` |
| Unit | `test_trivy_scanner.py` | Vulnerabilidades + misconfigurations, parsing de CVE |
| Unit | `test_finding_deduplicator.py` | Dedup por chave, fontes diferentes mantidas, ordem preservada |
| Unit | `test_webhook_hmac.py` | Assinatura válida/inválida/adulterada/vazia |
| Unit | `test_risk_scorer.py` | Secret verificado mínimo 90, score capped a 100 |
| Unit | `test_suggest_patch_use_case.py` | Inline suggestion, cross-reference finding_id, aviso de rotação |
| Unit | `test_generate_pr_report_use_case.py` | REQUEST_CHANGES/COMMENT/APPROVE por risk level |
| Unit | `test_block_merge_use_case.py` | block_merge com razão estruturada |
| Unit | `test_repo_signals.py` | Extração de deps, env vars, padrões de código, frameworks |
| Unit | `test_business_context_inferrer.py` | Fallback heurístico, conversão Claude response, RiskScorer com ctx |
| Integration | `test_opencti_client.py` | enrich_cve (encontrado/não encontrado), get_active_campaigns |
| Integration | `test_caldera_client.py` | Sandbox enforcement, parse_results, ciclo completo (respx) |
| Integration | `test_scan_persistence.py` | ScanJob lifecycle, db_utils wrappers, scan_worker com persistência |

---

## 12. Estrutura de diretórios

```
aperia/
├── core/                          # Transversal — config, db, celery, exceções
│   ├── config.py                  # pydantic-settings
│   ├── database.py                # SQLAlchemy async engine
│   ├── celery_app.py              # 3 filas: scan, analysis, remediation
│   ├── exceptions.py              # Hierarquia de exceções
│   ├── security.py                # safe_repo_path + verify_github_signature
│   ├── logging.py                 # structlog com commit_sha + repo_url
│   └── orchestrator.py            # Pipeline principal (9 etapas)
│
├── domain/                        # Python puro — zero dependências externas
│   ├── finding/
│   │   ├── entities.py            # Finding, AttackPath, EventChain, RiskScore
│   │   ├── value_objects.py       # Severity, CVEId, CWEId, BusinessImpact
│   │   ├── repositories.py        # ABCs de acesso a dados
│   │   └── services.py            # FindingDeduplicator, RiskScorer, AttackPathBuilder
│   ├── scan/                      # ScanJob, ScanResult, CommitSha
│   ├── remediation/               # Remediation, PatchDiff, RemediationStatus
│   └── shared/
│       ├── value_objects.py       # BusinessContext, AssetCriticality, ThreatLevel
│       └── events.py              # Domain events: VerifiedSecretDetected, ScanCompleted
│
├── application/                   # Use cases — orquestram domínio
│   ├── scan/                      # start_scan, cancel_scan
│   ├── finding/                   # enrich_findings, infer_business_context, score_findings
│   ├── attack_path/               # build_attack_path, run_emulation
│   ├── remediation/               # generate_patch, suggest_patch, block_merge
│   └── report/                    # generate_pr_report
│
├── infrastructure/                # Implementações concretas
│   ├── scanners/                  # trufflehog, semgrep, trivy, zap, openvas, wazuh, prowler
│   ├── intelligence/              # opencti_client, mitre_caldera_client
│   ├── ai/
│   │   ├── llm_guard_client.py    # Proteção contra prompt injection
│   │   ├── claude_client.py       # Wrapper sync do Claude API
│   │   ├── heuristic_engine.py    # 4 prompts em sequência
│   │   └── prompts/               # chain_of_events, attack_path, remediation, pr_report, business_context
│   ├── analysis/
│   │   ├── _repo_signals.py       # Extração de sinais do repositório
│   │   └── business_context_inferrer.py  # Auto-inferência de contexto de negócio
│   ├── git/
│   │   └── github_client.py       # JWT RS256, installation token, code suggestions
│   └── persistence/
│       ├── models/                # SQLAlchemy ORM: finding_model, scan_model
│       ├── repositories/          # Implementações: sqlalchemy_finding_repository, sqlalchemy_scan_repository
│       └── db_utils.py            # Bridge async→sync para Celery workers
│
├── presentation/
│   ├── api/                       # FastAPI: webhooks, findings, scans, reports, health
│   └── workers/                   # Celery: scan_worker, analysis_worker, remediation_worker
│
├── tests/
│   ├── unit/                      # Testes sem I/O externo (11 arquivos, ~70 testes)
│   ├── integration/               # Mocks HTTP via respx (2 arquivos)
│   └── e2e/                       # Pipeline completo mockado
│
├── docker-compose.yml             # Dev: todos os serviços incluindo Caldera
├── docker-compose.prod.yml        # Prod: sem ZAP/OpenVAS/Wazuh pesados
├── Dockerfile                     # python:3.11-slim, usuário não-root
├── requirements.txt               # Todas as dependências pinadas
├── pytest.ini                     # asyncio_mode=auto
└── DEPLOY.md                      # Guia detalhado de deploy
```

---

## 13. Regras de segurança do próprio código

A aperIA analisa repositórios de terceiros mas também precisa ser segura. Regras invioláveis:

| Regra | Implementação |
|---|---|
| **Nunca `shell=True`** | Todos os subprocess usam lista de argumentos |
| **Nunca f-string em SQL** | ORM SQLAlchemy ou `text()` com `:param` |
| **Credenciais sempre em `.env`** | pydantic-settings — nunca hardcoded |
| **LLM Guard obrigatório** | `ClaudeClient` chama `validate_input()` antes de toda chamada |
| **Caldera sandbox-only** | `CALDERA_SANDBOX_MODE=True` verificado em `__init__` e no use case |
| **TruffleHog verified = bloqueio** | `block_merge()` antes de continuar qualquer análise |
| **Patches nunca auto-aplicados** | `create_inline_suggestion()` — nunca commit direto |
| **Domain nunca importa infra** | Verificado por convenção + code review |

---

## Histórico de versões

| Commit | Fase | O que foi entregue |
|---|---|---|
| `2724553` | Fase 0 | Infraestrutura base: DDD, domínio, docker-compose, core modules |
| `a7317e8` | Fase 1 | 7 scanners, GitHub App, orchestrator, HMAC, 6 suites de testes |
| `92c3795` | Fase 2 | LLM Guard (biblioteca), Claude Client sync, OpenCTI GraphQL, Caldera lifecycle, HeuristicEngine, risk scoring |
| `5b26cf8` | Fase 3 | Code suggestions inline, PR review, block merge, 17 testes |
| `9069e6f` | BCI | Business Context Inferrer: extração de sinais, fallback heurístico, RiskScorer atualizado, 34 testes |
| `(fase-4)` | Fase 4 | API REST completa, Alembic migrations, ScanJob persistence, 3 workers, 9 endpoints, 14 testes integração |

---

*Mantido por [OCR-aperIA](https://github.com/OCR-aperIA) · Atualizado automaticamente a cada mudança no codebase.*
