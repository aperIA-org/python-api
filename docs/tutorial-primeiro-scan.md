# Tutorial: seu primeiro scan no aperIA

Neste tutorial vamos subir a stack completa do aperIA localmente e disparar o
pipeline de segurança: do webhook do GitHub até o resultado nos logs dos
workers. Tudo isso **sem nenhuma credencial externa** — sem GitHub App, sem
chave da Anthropic e sem domínio público.

O preço de não ter credencial é que a análise não vai até o fim: sem o GitHub
App, os workers não conseguem baixar o código do commit e o Tier 1 falha no
checkout (falamos disso em "O que você acabou de ver"). O que este tutorial
mostra, então, é o **encanamento**: assinatura do webhook, fila, workers,
persistência e o registro honesto de uma falha. Para ver a análise de verdade,
o próximo passo é conectar um repositório real.

## Pré-requisitos

Vamos precisar apenas de:

- **Docker** e **Docker Compose v2** (o comando é `docker compose`, sem
  hífen).

Não precisamos de Python nem de `.venv` para este tutorial — a aplicação roda
inteira dentro dos containers. Um ambiente Python local só é necessário se
você quiser rodar a suíte de testes fora do Docker; isso é assunto de outro
dia (veja "[Rodar a suíte de testes](../GUIA_EXECUCAO.md#8-rodar-a-suíte-de-testes-não-precisa-de-chavescréditos)").

## Passo 1 — Preparar as variáveis de ambiente

Vamos copiar o arquivo de exemplo:

```bash
cp .env.example .env
```

Para este passeio local **não precisamos editar nada** nesse `.env` — todas
as chaves (Anthropic, GitHub App, ZAP, OpenCTI, Caldera) são opcionais e o
pipeline sabe degradar graciosamente quando elas estão vazias.

## Passo 2 — Subir a stack

Vamos construir as imagens e subir os 8 containers da stack base (API +
5 workers Celery + Redis + Postgres):

```bash
docker compose -f docker-compose.base.yml up -d --build
```

## Passo 3 — Aplicar as migrations

Com os containers no ar, vamos criar o schema do banco:

```bash
docker compose -f docker-compose.base.yml exec api alembic upgrade head
```

## Passo 4 — Confirmar que a API está de pé

```bash
curl -s http://localhost:8000/health
```

Devemos ver:

```json
{"status":"ok"}
```

## Passo 5 — Disparar um webhook simulado

No uso normal, o pipeline é iniciado por um webhook `pull_request` do GitHub.
Como ainda não temos um GitHub App configurado, vamos simular esse webhook
localmente:
montamos o payload e assinamos o HMAC com uma chave vazia (o default de
`GITHUB_WEBHOOK_SECRET` é `""`, então isso funciona sem nenhuma configuração
extra).

Primeiro, vamos montar o payload:

```bash
cat > /tmp/pr.json <<'JSON'
{"action":"opened","installation":{"id":12345},
 "pull_request":{"number":1,
   "head":{"sha":"deadbeefcafebabe0000000000000000deadbeef"},
   "base":{"sha":"0000000000000000000000000000000000000000"}},
 "repository":{"full_name":"aperIA-org/demo-repo",
   "clone_url":"https://github.com/aperIA-org/demo-repo.git"}}
JSON
```

Agora vamos assinar e enviar:

```bash
SIG="sha256=$(openssl dgst -sha256 -hmac '' < /tmp/pr.json | sed 's/^.*= //')"

curl -sS -X POST http://localhost:8000/webhook/github \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: pull_request" \
  -H "X-Hub-Signature-256: $SIG" \
  --data-binary @/tmp/pr.json
```

Devemos receber:

```json
{"status":"queued","commit_sha":"deadbeefcafebabe0000000000000000deadbeef"}
```

Isso já montou o canvas Celery e disparou o pipeline de forma assíncrona.

## Passo 6 — Acompanhar o pipeline nos logs

Vamos seguir os logs dos workers para ver cada etapa acontecer:

```bash
docker compose -f docker-compose.base.yml logs -f \
  worker_tier1 worker_tier2 worker_analysis
```

Deixe rodando por alguns segundos. O worker de Tier 1 recebe a tarefa, tenta
fazer o checkout do commit e registra `scan_checkout_falhou` — o repositório
do payload é fictício e não há App instalado para autenticar. Pressione
`Ctrl+C` quando quiser parar de acompanhar — os containers continuam de pé.

## O que você acabou de ver

Com um repositório de demonstração inventado no payload e sem créditos na
conta Anthropic, o encanamento inteiro é exercitado — HMAC, fila, worker,
persistência — mas a análise em si não vai longe. É esperado ver:

- **Tier 1 falhando no checkout**: os workers clonam o commit antes de
  escanear. Como `aperIA-org/demo-repo` e o SHA acima não existem (ou o App
  não tem acesso a eles), o log mostra `scan_checkout_falhou` e as tarefas
  falham — de propósito: sem os arquivos não há o que escanear, e concluir
  "0 findings" seria uma afirmação falsa. Os tiers pendentes são marcados
  como `failed`, então o commit não fica preso em `running`. Para ver o
  pipeline inteiro com dados reais, use um repositório conectado de verdade
  (veja [howto/conectar-github.md](howto/conectar-github.md)) e um commit que
  exista nele.
- **O canvas para no Tier 1**: uma tarefa que falha interrompe a chain, então
  Gate 1, Tier 2 e os relatórios não chegam a rodar. O `ScanJob` fica com os
  tiers pendentes em `failed` — visível em `GET /scans/<commit_sha>`.
- **Quando o pipeline chega ao Claude, ele degrada em vez de quebrar**: sem
  `ANTHROPIC_API_KEY` (ou sem créditos), a chamada falha e o worker devolve
  `{"degraded": true, ...}` em vez de travar o pipeline — é a filosofia
  best-effort do aperIA em ação. (Você verá isso assim que rodar com um
  repositório real.)

Ou seja: webhook, assinatura, fila, workers e persistência funcionam mesmo sem
nenhuma peça externa configurada. O conteúdo da análise, esse depende de um
repositório real (para o checkout) e da chave da Anthropic (para o Claude).

## Próximos passos

- Conectar um GitHub real e rodar em repositórios seus →
  [`howto/conectar-github.md`](howto/conectar-github.md)
- Entender o pipeline por dentro (tiers, gates, score) →
  [`explicacao-pipeline.md`](explicacao-pipeline.md)
- Referência de rotas e variáveis de ambiente →
  [`referencia.md`](referencia.md)
