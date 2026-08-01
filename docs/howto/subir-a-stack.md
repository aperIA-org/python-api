# Como subir a stack

Suba o aperIA localmente com Docker Compose, aplique as migrations e confirme
que os 8 containers da stack base estão de pé.

## Pré-requisitos

- Docker + Docker Compose v2 (comando `docker compose`, **não** `docker-compose`).
- Python 3.10+ com o `.venv` do projeto, se for rodar testes/uvicorn fora do container.
- Uma chave da Anthropic com créditos (`sk-ant-api03-...`) se quiser que o Claude
  gere análise de verdade. Sem ela o pipeline roda, mas degrada — ver
  [tutorial-primeiro-scan.md](../tutorial-primeiro-scan.md).

## 1. Colocar a chave do GitHub App em `secrets/`

A chave privada `.pem` do GitHub App **não vai para dentro da imagem** — ela
entra por bind mount. `app/secrets/`, `secrets/` e `**/*.pem` estão no
`.dockerignore` justamente para isso: chave assada na imagem viaja em toda
camada, todo cache de registry e todo `docker push`.

Copie o `.pem` que o GitHub gerou (nome no formato
`<slug>.<AAAA-MM-DD>.private-key.pem`) para `secrets/`, mantendo o nome, e
aponte o `.env` para o caminho **absoluto de dentro do container**:

```bash
cp ~/Downloads/aperia-aspm.2026-07-28.private-key.pem secrets/
chmod 600 secrets/aperia-aspm.2026-07-28.private-key.pem
```

```dotenv
# .env
GITHUB_PRIVATE_KEY_PATH=/app/secrets/aperia-aspm.2026-07-28.private-key.pem
```

O `docker-compose.base.yml` monta `./secrets:/app/secrets:ro` em `api`,
`worker_tier1`, `worker_tier2`, `worker_analysis` e `worker_reporting` — todos
os serviços que emitem *installation token*. `worker_tier3` não monta porque não
fala com o GitHub.

> **Gotcha:** o valor de `GITHUB_PRIVATE_KEY_PATH` tem que bater exatamente com
> o nome do arquivo dentro de `secrets/`. Se divergir (ou se você usar um
> caminho relativo, que o container resolveria a partir do WORKDIR `/app`), o
> `get_installation_token()` estoura `FileNotFoundError` e o pipeline morre
> antes do checkout — sem token os workers de T1/T2 não clonam o repositório.
> Fora do Docker não existe `/app`: exporte o caminho do host na hora de rodar
> o uvicorn no `.venv`. Ver [`secrets/README.md`](../../secrets/README.md).

## 2. Subir a stack base

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
| `redis` | aperia-redis | — | Broker + result backend (AOF ligado, volume `aperia_redis_data`) |
| `db` | aperia-db | — | PostgreSQL 15 (`postgres/postgres`, db `aperia`), volume `aperia_db_data` |

> **Volumes — por que o Redis tem um:** o Postgres guarda a *projeção* do scan
> (a linha em `scan_jobs`) e o Redis guarda o *trabalho* (as tarefas Celery na
> fila). Enquanto só o Postgres tinha volume, um `docker compose down` entre o
> disparo e o consumo da fila apagava as tarefas e preservava a linha — um
> `ScanJob` órfão, preso em `running`, que ainda por cima bloqueava novos scans
> daquele commit (`409`). Hoje o Redis sobe com `--appendonly yes` e volume
> próprio. Se você **quiser** descartar tudo, é `docker compose -f
> docker-compose.base.yml down -v` (apaga banco **e** fila). E se um job ainda
> assim ficar preso, a API o libera sozinha no próximo boot — ver
> `SCAN_STALE_AFTER_MINUTES` em [referencia.md](../referencia.md).

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

## 3. Subir camadas opcionais (perfis)

As ferramentas pesadas do Tier 3 estão atrás de **perfis** do Compose e **não
sobem por padrão**. A regra de ouro é: o **conjunto de arquivos nunca muda** —
o que varia é o perfil.

Rodando de dentro de `python-api/`:

```bash
docker compose -f docker-compose.base.yml \
               -f docker-compose.scanners.yml \
               -f docker-compose.targets.yml \
               up -d
```

Isso sobe **apenas a base** (api, db, redis e os 5 workers) — o suficiente para
front, auth, telas e o pipeline de Tier 1/2. Para incluir as ferramentas
pesadas, acrescente o perfil **antes** de `up -d`:

| O que você quer | Acrescente | Sobe também |
|---|---|---|
| Tier 3 com DAST | `--profile dast` | ZAP e Juice Shop |
| Emulação MITRE ATT&CK | `--profile emulation` | Caldera e o agente sandcat |
| CTI | `--profile cti` | OpenCTI — hoje **não sobe**, ver [pendências §3](../pendencias.md) |

Perfis se combinam. O comando completo para DAST + emulação:

```bash
docker compose -f docker-compose.base.yml \
               -f docker-compose.scanners.yml \
               -f docker-compose.targets.yml \
               --profile dast --profile emulation up -d
```

> Essa é a configuração de **maior consumo** da stack. Se a máquina for
> apertada, valide um perfil de cada vez: `dast` prova `zap_findings > 0`,
> `emulation` prova `caldera_validated = true`, e são independentes.

<details>
<summary>Atalho opcional (você precisa criar)</summary>

Os exemplos acima são autocontidos de propósito. Se preferir encurtar, defina o
alias no seu shell — lembrando que os caminhos são relativos, então ele só
funciona dentro de `python-api/`:

```bash
alias dc='docker compose -f docker-compose.base.yml \
                         -f docker-compose.scanners.yml \
                         -f docker-compose.targets.yml'
```

Aí `dc --profile dast up -d` equivale ao comando completo. Para valer em toda
sessão, a mesma linha no `~/.zshrc`.

</details>

### Por que perfis, e por que sempre o mesmo conjunto de arquivos

**Carga.** Subir tudo de uma vez (Postgres, Redis, API, 5 workers, ZAP, Caldera,
OpenCTI, Juice Shop) esgota os recursos do WSL2 — a ponto de derrubar o DNS
embutido do Docker no meio de uma varredura. Os containers pesados têm
`mem_limit` justamente para que um scan falhe antes da máquina travar.

**Rede.** Invocar `docker compose` com **conjuntos diferentes de arquivos**
recria a rede `aperia_net` e deixa containers presos numa instância antiga de
mesmo nome. O sintoma é cruel: o worker perde resolução de `zap`/`caldera` e
nada no compose parece errado. Se acontecer:

```bash
docker compose -f docker-compose.base.yml \
               -f docker-compose.scanners.yml \
               -f docker-compose.targets.yml \
               --profile dast --profile emulation \
               up -d --force-recreate zap caldera juice-shop
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

## 4. Aplicar as migrations

```bash
docker compose -f docker-compose.base.yml exec api alembic upgrade head
```

Sem esse passo, a tabela `findings` não existe e a persistência de findings
cai no ramo best-effort (só loga um warning e segue).

## 5. Confirmar que subiu

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
