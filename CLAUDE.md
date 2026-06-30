# aperIA

ASPM (Application Security Posture Management) open-source. Webhook de PR do GitHub → pipeline de scanners de segurança em **3 tiers** via Celery → **Claude** raciocina como atacante (correlaciona findings, monta attack paths) → entrega patches como **GitHub code suggestions**.

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

Disparado por `POST /webhook/github`. 5 workers, cada um em sua fila:
`tier1` (TruffleHog + Semgrep changed) → **Gate 1** (bloqueia se `secret_verified`) → `tier2` (Trivy + Semgrep expanded + Prowler) → `tier2_analyze` (Sonnet) → report (Haiku) → **Gate 2** (escala se severidade ≥ high) → `tier3` (ZAP + OpenCTI + Caldera) → `tier3_deep_analysis` (Sonnet) → report final.

- **Dicts, não entidades, trafegam no canvas** (Celery serializa JSON; workers fazem `_findings_to_dicts`).
- **Bridges** combinam output anterior + state fixo; `Ignore()` upstream vira `None` → bridge faz `if not input: return None`.

## Convenções inegociáveis

- **Idioma PT-BR** em comentários, docstrings, logs e mensagens de commit.
- `from __future__ import annotations` no topo; type hints sempre; `X | None`, `list[...]`.
- **Dataclasses** para entidades de domínio; **structlog** estruturado (`logger.info("evento_snake", chave=valor, commit_sha=...)`); **nunca logar secret cru**.
- **Repositories são SÍNCRONOS** (`Session`). Um engine async foi removido e o `FindingRepository` virou sync. Não introduza async no acesso a dados.
- **Filosofia best-effort / nunca derrubar o pipeline:** scanner falho → `[]` (`BaseScanner.run_safe`); Claude falho → `{"degraded": True, ...}`; persistência falha → loga `finding_persistence_failed` e segue; gate → `Ignore()`. Preserve isso em código novo.
- Exceções: base `AperiaError` (`core/exceptions.py`), auth em `application/exceptions.py`; rotas mapeiam exceção → HTTP status.
- Config via pydantic `BaseSettings` (`app/config.py`, singleton `settings`, lê `.env`).

## Persistência

- `Finding.dedup_key()` = `source:cve_id|title:file:line:commit`. Dedup em 2 barreiras: `FindingDeduplicator` (memória) + UNIQUE `findings_dedup_key` (banco, `ON CONFLICT DO NOTHING`).
- `finding_writer.persist_findings` é **best-effort**, chamado pelos scan workers (T1/T2/T3), gated por `settings.FINDINGS_PERSISTENCE_ENABLED` (default `True`; testes desligam).
- Engine síncrono (`database/sqlalchemy.py`). **Gotcha:** normaliza `postgresql+asyncpg://` → `postgresql+psycopg://`.

## Comandos

```bash
# testes (401 testes, cobertura alvo ≥70%)
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
- Checkout real do repo é pós-MVP — `repo_path` é stub, scans locais retornam 0 findings.
