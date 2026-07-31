# Como subir a stack

Suba o aperIA localmente com Docker Compose, aplique as migrations e confirme
que os 8 containers da stack base estão de pé.

## Pré-requisitos

- Docker + Docker Compose v2 (comando `docker compose`, **não** `docker-compose`).
- Python 3.10+ com o `.venv` do projeto, se for rodar testes/uvicorn fora do container.
- Uma chave da Anthropic com créditos (`sk-ant-api03-...`) se quiser que o Claude
  gere análise de verdade. Sem ela o pipeline roda, mas degrada — ver
  [tutorial-primeiro-scan.md](../tutorial-primeiro-scan.md).

## 1. Subir a stack base

```bash
docker compose -f docker-compose.base.yml up -d
```

Isso sobe 8 containers:

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
> Docker, o banco usado é sempre o `db` local, não o que você configurou fora
> do compose.

Se quiser recompilar a imagem (código é baked na imagem — necessário após
mudar código Python):

```bash
docker compose -f docker-compose.base.yml up -d --build
```

## 2. Subir camadas opcionais (se precisar)

Para exercitar o Tier 3 (ZAP, OpenCTI, Caldera):

```bash
docker compose -f docker-compose.base.yml -f docker-compose.scanners.yml up -d
```

> ⚠️ **Gotcha do Caldera:** o `docker-compose.scanners.yml` declara a rede
> `aperia_caldera_sandbox` com `internal: true`. **Nunca remova essa flag** —
> ela impede que técnicas MITRE ATT&CK reais executadas pelo Caldera escapem
> para a internet. O `CalderaClient` valida `CALDERA_SANDBOX_MODE=true` no
> boot e levanta `SandboxViolationError` se a variável estiver `false`.

Para observabilidade (Prometheus + Grafana):

```bash
docker compose -f docker-compose.base.yml -f docker-compose.observability.yml up -d
```

Isso expõe Prometheus em `:9090` e Grafana em `:3000` (login `admin`/`changeme`).

## 3. Aplicar as migrations

```bash
docker compose -f docker-compose.base.yml exec api alembic upgrade head
```

Sem esse passo, a tabela `findings` não existe e a persistência de findings
cai no ramo best-effort (só loga um warning e segue).

## 4. Confirmar que subiu

```bash
curl -s http://localhost:8000/health          # {"status":"ok"}
docker compose -f docker-compose.base.yml ps  # todos "healthy"/"Up"
```

## Próximos passos

- Confirmar que a stack está pronta para uma análise de ponta a ponta →
  [tutorial-primeiro-scan.md](../tutorial-primeiro-scan.md).
- Entender o que cada etapa do pipeline faz →
  [explicacao-pipeline.md](../explicacao-pipeline.md).
- Consultar todas as variáveis de ambiente disponíveis →
  [referencia.md](../referencia.md).
