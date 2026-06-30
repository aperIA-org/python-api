---
name: aperia
description: Contexto de arquitetura, estrutura e convenções do projeto aperIA — um ASPM (FastAPI + Celery) que roda um pipeline de scanners de segurança em 3 tiers e usa Claude para raciocínio ofensivo. Use SEMPRE que for implementar, debugar, revisar ou explicar qualquer parte deste codebase, para entender camadas (Clean Architecture/DDD), o pipeline Celery, a integração com Claude, scanners, persistência síncrona e convenções de código.
---

# aperIA — contexto do projeto

## O que é

**aperIA** é um **ASPM** (Application Security Posture Management) open-source. Captura webhooks de PR do GitHub, roda uma esteira de 7+ ferramentas OSS de segurança em **3 tiers** via Celery, e usa **Claude** como motor central para raciocinar como atacante: correlaciona findings, monta attack paths e entrega patches como **GitHub code suggestions**.

> **Premissa inviolável:** aperIA **nunca** aplica código autonomamente. Todo patch sai como code suggestion para aprovação humana.

Stack: FastAPI (API/webhook) · Celery + Redis (pipeline assíncrono) · PostgreSQL + SQLAlchemy + Alembic · Anthropic SDK (Claude) · structlog · pytest.

## Arquitetura — Clean Architecture / DDD

Direção de dependência: **Presentation → Application → Domain ← Infrastructure**. O domínio é puro (sem imports externos); infra implementa as interfaces (repositories, services) declaradas no domínio. **Não há container de DI** — o wiring é manual (repos/use-cases instanciados nas rotas via `Depends(get_db)`; scanners/clients instanciados direto nos workers).

```
app/
├── domain/                  # núcleo puro: entidades, value objects, interfaces de repo, serviços
│   ├── finding/             #   Finding (entities), Severity/CVEId (value_objects),
│   │                        #   FindingDeduplicator + RiskScorer (services), FindingRepository (ABC)
│   ├── scan/                #   ScanJob, ScanTier/TierStatus, ScanJobRepository
│   ├── remediation/         #   Remediation + RemediationRepository
│   ├── entities/            #   User, AuthTokens
│   ├── repositories/        #   UserRepository, RefreshTokenRepository (interfaces)
│   ├── services/            #   PasswordService (interface)
│   └── shared/events.py     #   DomainEvent, VerifiedSecretDetected, AttackPathCreated
├── application/             # casos de uso (orquestram domínio)
│   ├── use_cases/           #   CreateUser, GetUser, Login, RefreshToken
│   ├── remediation/         #   SuggestPatchUseCase
│   └── exceptions.py        #   InvalidCredentialsError, TokenExpiredError, ...
├── core/                    # cross-layer
│   ├── celery_app.py        #   singleton Celery + validação de import + task_routes
│   ├── orchestrator.py      #   o canvas do pipeline (chain/group + bridges) + start_pipeline
│   └── exceptions.py        #   AperiaError, SandboxViolationError, PipelineHaltedError, ...
├── infrastructure/          # adaptadores técnicos
│   ├── ai/                  #   claude_client, circuit_breaker, llm_guard_client, token_metrics, prompts/
│   ├── scanners/            #   base_scanner + semgrep/trivy/trufflehog/prowler/zap
│   ├── intelligence/        #   opencti_client, mitre_caldera_client
│   ├── git/                 #   github_client, github_auth, diff_utils
│   ├── persistence/         #   models/ (SQLAlchemy) + finding_writer.py
│   ├── repositories/        #   SQLAlchemy{Finding,User,RefreshToken,Remediation}Repository (SYNC)
│   ├── database/sqlalchemy.py  # engine SÍNCRONO, SessionLocal, get_db
│   ├── security/            #   argon2_password_service, jwt_handler, token_service
│   └── common/datetime_provider.py
└── presentation/
    ├── api/routes/          #   auth, user, health, webhook
    ├── schemas/             #   Pydantic request/response (separados das entidades)
    └── workers/             #   tier1/tier2/tier3_scan_worker, analysis_worker, reporting_worker
```

**Entry points:** `main.py` (raiz) → `from app.main import app` (uvicorn `main:app`). `app/main.py` registra 4 routers + startup que testa conexão DB. `app/core/celery_app.py` cria o Celery e valida import dos 5 workers + orchestrator via `importlib` no boot.

## O pipeline de scan (Celery canvas)

Definido em `app/core/orchestrator.py` (`build_pipeline_canvas` / `start_pipeline`). Disparado por `POST /webhook/github` (HMAC obrigatório; actions `opened`/`synchronize`).

```
group(run_trufflehog, run_semgrep_changed)          [tier1]
  → gate1_check                                       [analysis]  Gate 1: bloqueia se secret_verified
  → _t1_to_t2_scan_bridge → run_tier2_scan            [tier2]
  → _bridge_t1_findings_into_analyze → tier2_analyze  [analysis]  Claude Sonnet (chain_of_events)
  → post_tier2_report                                 [reporting] Claude Haiku (markdown no PR)
  → tier3_gate                                        [analysis]  Gate 2: para se severidade < high
  → _prepare_tier3_payload → run_tier3_scan           [tier3]     ZAP + OpenCTI + Caldera
  → _deep_analysis_bridge → tier3_deep_analysis       [analysis]  Claude Sonnet (attack_path)
  → post_tier3_deep_report                            [reporting] Claude Haiku (relatório final)
```

**Workers** (cada um numa fila própria; escala independente):

| Worker | Tasks | Fila | Usa |
|---|---|---|---|
| `tier1_scan_worker` | `run_trufflehog`, `run_semgrep_changed` | tier1 | TruffleHog, Semgrep (changed) |
| `tier2_scan_worker` | `run_tier2_scan` | tier2 | Trivy, Semgrep (expanded), Prowler (condicional IaC) |
| `tier3_scan_worker` | `run_tier3_scan` | tier3 | ZAP, OpenCTIClient, CalderaClient |
| `analysis_worker` | `gate1_check`, `tier2_analyze`, `tier3_gate`, `tier3_deep_analysis` | analysis | ClaudeClient, GitHubClient |
| `reporting_worker` | `post_tier2_report`, `post_tier3_deep_report` | reporting | ClaudeClient (Haiku), GitHubClient |

**Gates:** Gate 1 bloqueia o PR se **qualquer** finding tem `secret_verified=True` (só TruffleHog seta) → `raise Ignore()`. Gate 2 escala ao Tier 3 só se `max_severity ∈ {high, critical}` (rank `critical>high>medium>low>info`), senão `raise Ignore()`.

**Convenções críticas do pipeline:**
- **Dicts, não entidades, atravessam o canvas** — Celery serializa JSON. Workers convertem `Finding` → dict via `_findings_to_dicts` antes de retornar.
- **Bridges** são tasks mínimas no orchestrator que combinam o output da task anterior com state fixo (`commit_sha` etc.). Em modo eager, `Ignore()` upstream vira `None` → cada bridge checa `if not input: return None` (propaga a parada sem side-effects).
- **Idempotência:** `task_acks_late=True`; persistência usa `ON CONFLICT DO NOTHING`.

## Integração Claude (`app/infrastructure/ai/`)

- **ClaudeClient** (`claude_client.py`): `call()` e `call_json()`. Síncrono (workers são sync). Checa circuit breaker → roda LLM Guard no input → chama Anthropic. System prompt com `cache_control: ephemeral` se `CLAUDE_PROMPT_CACHE_ENABLED`. Modelos vêm de constantes (`models.py`: `REASONING`/`FORMATTING`), nunca string literal.
- **Modelos** (`app/config.py`): `CLAUDE_MODEL_REASONING="claude-sonnet-4-6"` (análise), `CLAUDE_MODEL_FORMATTING="claude-haiku-4-5-20251001"` (relatórios). Ao mexer em modelos/pricing/params, **carregue a skill `claude-api`**.
- **Circuit breaker** (`circuit_breaker.py`): abre após **3** falhas consecutivas, janela de **300s**. Singleton process-wide (`DEFAULT_BREAKER`).
- **LLM Guard** (`llm_guard_client.py`): regex-stub que bloqueia ~14-18 padrões de prompt injection **antes** da API → `GuardBlockedError`.
- **Prompts** (`prompts/`): `chain_of_events` (Sonnet, JSON, Tier 2) · `attack_path` (Sonnet, JSON, Tier 3) · `pr_report` (Haiku, markdown) · `remediation` (Haiku, JSON, patch sob demanda).
- **Anti-alucinação:** prompts injetam sentinelas (`"sem dados CTI disponíveis..."`) e devolvem `cti_status`/`caldera_status` quando falta dado; o SYSTEM proíbe inventar CVE/TTP/campanhas.
- **Modo degradado:** se Claude falha (circuit/guard/API), `tier2_analyze`/`tier3_deep_analysis` retornam `{"degraded": True, "reason": ..., "findings": [...]}` e o pipeline **continua**; reporting cai para markdown de fallback.

## Scanners e intelligence (`app/infrastructure/`)

- **BaseScanner.run_safe()** — padrão de **isolamento de falha**: qualquer exceção em `scan()` é logada (`scanner_skipped`) e vira `[]`. Scanner indisponível ≠ pipeline quebrado (aceita falso-negativo, evita falso-positivo).
- Severidade nativa de cada scanner → enum canônico `Severity` (CRITICAL/HIGH/MEDIUM/LOW/INFO). TruffleHog sempre CRITICAL (`--only-verified`). Semgrep ERROR→HIGH/WARNING→MEDIUM/INFO→LOW.
- Semgrep tem `scan_changed` (T1, só diff) e `scan_expanded` (T2, repo inteiro via `_SemgrepExpandedAdapter`). Prowler só roda se `has_iac_files(changed_files)`.
- **OpenCTIClient**: CVE → TTPs MITRE via GraphQL; falha → `None`. **CalderaClient**: emulação adversária em sandbox; valida `CALDERA_SANDBOX_MODE` no `__init__` (senão `SandboxViolationError`); retorna **métricas** (dict), não findings.
- **GitHub**: `github_auth` gera JWT do App + installation token por chamada; `github_client` posta status checks, comentários e code suggestions.

## Domínio e persistência

- **Finding** (`domain/finding/entities.py`): dataclass. `dedup_key()` = `f"{source}:{cve_id or title}:{file_path}:{line_number}:{commit_sha}"`. Mesmo CVE de scanners diferentes = findings separados (source na chave).
- **Repositories são SÍNCRONOS** (`Session`, não `AsyncSession`). Um engine async foi removido e o `FindingRepository` foi convertido async→sync. (Algumas interfaces de auth ainda têm `async def` na assinatura mas a impl é sync — smell conhecido, não replicar em código novo.)
- **finding_writer.py** (`persist_findings`): helper **best-effort** chamado pelos scan workers (T1 após cada scanner, T2 após dedup, T3 findings do ZAP). Abre `SessionLocal`, faz `bulk_save` com `ON CONFLICT (dedup_key) DO NOTHING`. Erro de banco → loga `finding_persistence_failed` e segue. Gated por `settings.FINDINGS_PERSISTENCE_ENABLED` (default `True`; testes desligam).
- **Dedup em 2 barreiras:** `FindingDeduplicator` em memória + UNIQUE `findings_dedup_key` no banco.
- **Models** (`persistence/models/`): `findings`, `scan_jobs`, `users`, `refresh_tokens`, `remediations`. `FindingModel`/`ScanJobModel`/`RemediationModel` têm `from_entity`/`to_entity`. Migration única em `alembic/versions/b64896ca3325_add_aperia_tables.py`.
- **Engine** (`database/sqlalchemy.py`): SÍNCRONO. **Gotcha:** `_normalize_scheme` converte `postgresql+asyncpg://` → `postgresql+psycopg://` (asyncpg não aceita `hostaddr`). `DATABASE_URL` ou vars `DB_*`.
- **RiskScorer** (`finding/services.py`) existe (CVSS 25% · CTI 25% · Caldera 30% · Business 20%; secret_verified→≥90) mas **NÃO está plugado** no pipeline — hoje o `risk_score` exibido vem do Claude.

## Auth

Login: `LoginUseCase` normaliza email, busca via repo, verifica Argon2 (com dummy-hash contra timing attack), emite **access token** (JWT HS256, ~15min) + **refresh token** (opaco, SHA-256 no banco, 7 dias, com `family_id`). Refresh faz **rotação** com detecção de reuse (revoga a família). Logout sempre retorna 204. Rotas: `POST /auth/login`, `/auth/refresh`, `/auth/logout`, `POST /users`, `GET /users/{id}`.

## Convenções de código

- **Idioma:** comentários, docstrings e mensagens de log/commit em **PT-BR**. Siga isso.
- `from __future__ import annotations` no topo; type hints sempre; union `X | None` (3.10+); `list[...]`/`dict[...]`.
- **Dataclasses** para entidades de domínio (`field(default_factory=...)`).
- **structlog** estruturado: `logger.info("evento_snake_case", chave=valor, commit_sha=...)`. Nunca logar secret cru.
- **Filosofia best-effort/degradado** é central: scanner falho → `[]`; Claude falho → degraded; persistência falha → loga e segue; gate → `Ignore()`. Código novo deve preservar esse "nunca derrube o pipeline por uma dependência".
- Exceções: base `AperiaError` em `core/exceptions.py`; auth em `application/exceptions.py`. Rotas mapeiam exceções → HTTP status.
- Settings via pydantic `BaseSettings` (`app/config.py`, singleton `settings`, lê `.env`, `case_sensitive`, `extra="ignore"`).

## Testes

`tests/{unit,integration,e2e}/`. **401 testes**, cobertura alvo ≥70%. `pytest.ini`: `asyncio_mode=strict`.

Fixtures autouse em `tests/conftest.py`: `celery_eager_mode` (eager + backend memory), `reset_circuit_breaker`, `disable_findings_persistence` (desliga escrita p/ não exigir Postgres — testes de persistência religam + injetam SQLite).

Padrões: mockar scanner **no namespace do worker** (`patch.object(tier2_scan_worker, "TrivyScanner")`); HTTP via `respx`; DB via SQLite in-memory com `StaticPool`; tasks via `.delay().get()` em eager.

## Comandos

```bash
# testes (venv do projeto)
.venv/bin/python -m pytest tests/ -q
.venv/bin/python -m pytest tests/e2e/test_full_pipeline.py -v

# app (Docker) — o código é baked na imagem, rebuild ao mudar código
docker compose -f docker-compose.base.yml up -d --build
docker compose -f docker-compose.base.yml exec api alembic upgrade head
curl -s http://localhost:8000/health   # {"status":"ok"}
# + scanners T3: -f docker-compose.scanners.yml | + observabilidade: -f docker-compose.observability.yml
```

Git: branch principal `main`. Docs de execução detalhadas em `GUIA_EXECUCAO.md` e `README.md`.

## Estado / pendências conhecidas

- `RiskScorer` determinístico não está plugado (score vem do Claude); `_cti_component` lê `active_campaigns` mas o scan T3 produz `active_threat` (divergência latente).
- `/metrics` Prometheus **não exposto** (counters existem em `token_metrics.py`, falta `make_asgi_app()`).
- Checkout real do repo é "pós-MVP" — `repo_path` é stub (`/tmp/aperia/<sha>`), então scans reais retornam 0 findings localmente.
- `changed_files`/`target_url` chegam vazios/None do webhook no MVP.
