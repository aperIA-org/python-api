# aperIA

ASPM (Application Security Posture Management) open-source. Webhook de PR do GitHub (ou scan manual via API) → pipeline de scanners de segurança em **3 tiers** via Celery → **Claude** raciocina como atacante (correlaciona findings, monta attack paths) → entrega patches como **GitHub code suggestions**.

> **Premissa inviolável:** aperIA **nunca** aplica código sozinho. Todo patch sai como code suggestion para aprovação humana.

Stack: FastAPI · Celery + Redis · PostgreSQL + SQLAlchemy + Alembic · Anthropic SDK (Claude) · structlog · pytest.

## Contexto profundo → skill `aperia`

Para arquitetura detalhada (canvas do pipeline, integração Claude, scanners, domínio/persistência, auth), **carregue a skill `aperia`** (`.claude/skills/aperia/SKILL.md`). Este arquivo cobre só o essencial sempre-presente.
Ao mexer em modelos/pricing/params do Claude, carregue também a skill `claude-api`.

## Arquitetura (Clean Architecture / DDD)

Dependência: **Presentation → Application → Domain ← Infrastructure**. Domínio é puro (sem imports externos); infra implementa as interfaces do domínio. **Sem DI container** — wiring manual (repos/use-cases nas rotas via `Depends(get_db)`; scanners/clients instanciados direto nos workers).

```
app/domain/         entidades, value objects, interfaces de repo, serviços (puro)
app/application/    casos de uso (use_cases/, remediation/)
app/core/           celery_app.py, orchestrator.py (canvas), exceptions.py
app/infrastructure/ ai/, scanners/, intelligence/, git/, persistence/, repositories/, database/, security/
app/presentation/   api/routes/, schemas/, workers/
```

Entry: `main.py` (raiz) → `app.main:app` (uvicorn). Celery: `app.core.celery_app`.

## Pipeline (Celery canvas — `app/core/orchestrator.py`)

Dois gatilhos, um único ponto de disparo (`dispatch_pipeline` em `app/application/use_cases/trigger_scan_use_case.py`): `POST /webhook/github` (PR) e `POST /repositories/{id}/scan` (manual, HEAD do branch default, `pr_number=None` → workers de reporting pulam o comentário no PR; status check no commit continua). 5 workers, cada um em sua fila:
`tier1` (TruffleHog + Semgrep changed) → **Gate 1** (bloqueia se `secret_verified`) → `tier2` (Trivy + Semgrep expanded + Prowler) → `tier2_analyze` (Sonnet) → report (Haiku) → **Gate 2** (escala se severidade ≥ high) → `tier3` (ZAP + OpenCTI + Caldera) → `tier3_deep_analysis` (Sonnet) → report final.

- **Dicts, não entidades, trafegam no canvas** (Celery serializa JSON; workers fazem `_findings_to_dicts`).
- **Bridges** combinam output anterior + state fixo; `Ignore()` upstream vira `None` → bridge faz `if not input: return None`.

## Convenções inegociáveis

- **Idioma PT-BR** em comentários, docstrings, logs e mensagens de commit.
- `from __future__ import annotations` no topo; type hints sempre; `X | None`, `list[...]`.
- **Dataclasses** para entidades de domínio; **structlog** estruturado (`logger.info("evento_snake", chave=valor, commit_sha=...)`); **nunca logar secret cru**.
- **Repositories são SÍNCRONOS** (`Session`). Um engine async foi removido e o `FindingRepository` virou sync. Não introduza async no acesso a dados.
- **Filosofia best-effort / nunca derrubar o pipeline:** scanner falho → `[]` (`BaseScanner.run_safe`); Claude falho → `{"degraded": True, ...}`; persistência falha → loga `finding_persistence_failed` e segue; gate → `Ignore()`. Preserve isso em código novo.
- **`run_safe` engole a exceção, e é o único lugar que ainda a vê.** Por isso é lá dentro que a linha de `scan_tool_runs` é gravada (`status=done` com contagem, ou `status=failed` com o tipo da exceção): depois do `return []` não existe mais diferença entre "rodou e não achou nada" e "quebrou". Ao acrescentar um scanner, passe `tool_id=` e `tier=` no `run_safe` e registre o id em `app/domain/scan/tool_catalog.py` — os gates usam esse catálogo para marcar como `skipped` as ferramentas dos tiers que barraram, e a rota `GET /scans/{id}/tools` o devolve em `expected`. Ferramentas que não passam por `run_safe` (threat intel, Caldera, os passos de I.A) chamam `scan_tool_run_writer.record_tool_run` no próprio worker.
- Exceções: base `AperiaError` (`core/exceptions.py`); `application/exceptions.py` guarda as de caso de uso (auth + disparo de scan: `RepositoryInactiveError`/`ScanAlreadyInProgressError`→409, `GithubResolutionError`→502, `GithubAppNotConfiguredError`→503); rotas mapeiam exceção → HTTP status.
- Config via pydantic `BaseSettings` (`app/config.py`, singleton `settings`, lê `.env`).

## Persistência

- `Finding.dedup_key()` = `source:cve_id|title:file:line:commit`. Dedup em 2 barreiras: `FindingDeduplicator` (memória) + UNIQUE `findings_dedup_key` (banco, `ON CONFLICT DO NOTHING`).
- `finding_writer.persist_findings` é **best-effort**, chamado pelos scan workers (T1/T2/T3), gated por `settings.FINDINGS_PERSISTENCE_ENABLED` (default `True`; testes desligam).
- Engine síncrono (`database/sqlalchemy.py`). **Gotcha:** normaliza `postgresql+asyncpg://` → `postgresql+psycopg://`.

## Comandos

```bash
# testes (494 testes, cobertura alvo ≥70%)
.venv/bin/python -m pytest tests/ -q

# app (código é baked na imagem — rebuild ao mudar código)
docker compose -f docker-compose.base.yml up -d --build
docker compose -f docker-compose.base.yml exec api alembic upgrade head
curl -s http://localhost:8000/health   # {"status":"ok"}
```

Testes: mockar scanner **no namespace do worker** (`patch.object(tier2_scan_worker, "TrivyScanner")`); HTTP via `respx`; DB via SQLite in-memory + `StaticPool`; tasks via `.delay().get()` em eager. Fixtures autouse em `tests/conftest.py`.

Git: branch principal `main`. Execução detalhada em `GUIA_EXECUCAO.md` e `README.md`.

## Pendências conhecidas

- `RiskScorer` determinístico **não está plugado** (score vem do Claude).
- `/metrics` Prometheus **não exposto** (counters existem em `token_metrics.py`).
- ZAP (DAST) roda quando o repositório tem `target_url` cadastrada (a URL da aplicação
  publicada). Sem ela o Tier 3 registra `reason="no_target_url"` e faz só a análise de
  código. A validação recusa alvos internos — um scan DAST dispara requisições ativas.
- Tier 3 no deploy AWS: ZAP e Caldera sobem como task ECS Fargate por scan e caem no
  fim (`app/infrastructure/scanners/{zap,caldera}_fargate.py`, ligados pelas
  `*_FARGATE_*`). O Caldera roda numa subnet sem rota para a internet e sem task
  role — é a tradução do `internal: true` do compose, e o agente só é considerado
  pronto quando registra no grupo.
