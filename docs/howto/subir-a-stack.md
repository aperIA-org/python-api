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

### Conferir que o Caldera tem UM agente

O grupo `red` deve ter exatamente um agente — a operação executa cada ability em
**todos** os agentes do grupo, então um agente órfão multiplica a execução de
técnicas reais e falseia o `success_rate`:

```bash
curl -s -H "KEY: aperia-dev-caldera-red" http://localhost:8888/api/v2/agents \
  | python3 -c 'import sys,json; a=json.load(sys.stdin); print(len(a), [x["paw"] for x in a])'
```

Se vier mais de um (registros antigos, de antes do `-paw` fixo no compose):

```bash
.venv/bin/python scripts/caldera_limpar_agentes.py --dry-run   # confere
.venv/bin/python scripts/caldera_limpar_agentes.py             # remove
```

O porquê está na [explicação §14](../explicacao-pipeline.md#14-por-que-o-caldera-tem-um-agente-e-não-vinte).

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

**Rode isso de novo toda vez que atualizar o código**, não só na primeira
subida. Uma migration pendente é *silenciosa*: toda a persistência aqui é
best-effort, então a tabela ausente vira um `warning` no log do worker e o
pipeline segue como se nada tivesse acontecido. O sintoma aparece longe da
causa — na tela.

Dois exemplos reais desse mesmo mecanismo:

| Migration pendente | O que você vê |
|---|---|
| `findings` | scan "conclui" sem nenhum finding |
| `scan_tool_runs` | a faixa de ferramentas da tela de Scans diz "Sem status por ferramenta nesta execução" e cai para o status da etapa |

Para checar qual revisão está aplicada:

```bash
docker compose -f docker-compose.base.yml exec db \
  psql -U postgres -d aperia -tAc "select version_num from alembic_version"
```

Se ela não bater com o `head` do `alembic/versions/`, é isso. E os workers
precisam ser reiniciados junto quando o código deles muda — a migration sozinha
não basta.

## 5. Confirmar que subiu

```bash
curl -s http://localhost:8000/health          # {"status":"ok"}
docker compose -f docker-compose.base.yml ps  # todos "healthy"/"Up"
```

## 6. Derrubar a stack

A regra do `up` vale igual aqui: **o mesmo conjunto de arquivos**. Um `down` com
menos arquivos do que o `up` é a receita para containers órfãos (ver o gotcha
no fim desta seção).

```bash
docker compose -f docker-compose.base.yml \
               -f docker-compose.scanners.yml \
               -f docker-compose.targets.yml \
               down --remove-orphans
```

Isso para e remove os containers e a rede `aperia_net`, **preservando os
volumes** — banco e fila continuam lá quando você subir de novo. O
`--remove-orphans` limpa containers de serviços que não existem mais no compose
(ou que ficaram de uma invocação com outro conjunto de arquivos).

Não precisa repetir os `--profile` do `up`: o `down` age sobre o projeto
inteiro e leva junto os containers dos perfis que estiverem de pé.

| Você quer | Comando | Estado que sobrevive |
|---|---|---|
| Pausar e voltar depois | `... stop` | Containers, volumes e rede |
| Liberar recursos, manter os dados | `... down --remove-orphans` | Volumes (banco + fila) |
| Começar do zero | `... down -v --remove-orphans` | **Nada** |

> **`down -v` apaga banco e fila.** Some `aperia_db_data` (repositórios,
> `scan_jobs`, `findings`, usuários) e `aperia_redis_data` (tarefas Celery
> enfileiradas). Depois de um `-v` você precisa rodar as migrations do passo 4
> de novo, senão a tabela `findings` não existe e a persistência cai no ramo
> best-effort.

> ⚠️ **Gotcha — derrubar só o base mata o Tier 3 depois:** `docker compose -f
> docker-compose.base.yml down` (sem os outros dois arquivos) remove a rede
> `python-api_aperia_net`, mas deixa ZAP, Caldera e Juice Shop para trás,
> apontando para um ID de rede que não existe mais. Eles não voltam nunca mais:
> qualquer start falha com `Error response from daemon: failed to set up
> container networking: network <id> not found` e sai com **exit 255** — antes
> de o processo iniciar, então `docker logs` mostra a execução *anterior*,
> saudável, e nada parece errado no compose. O conserto é o
> `--force-recreate` da [seção 3](#por-que-perfis-e-por-que-sempre-o-mesmo-conjunto-de-arquivos).

## Próximos passos

- Confirmar que a stack está pronta para uma análise de ponta a ponta →
  [tutorial-primeiro-scan.md](../tutorial-primeiro-scan.md).
- Entender o que cada etapa do pipeline faz →
  [explicacao-pipeline.md](../explicacao-pipeline.md).
- Consultar todas as variáveis de ambiente disponíveis →
  [referencia.md](../referencia.md).
