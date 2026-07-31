# Tutorial: seu primeiro scan no aperIA

Neste tutorial vamos subir a stack completa do aperIA localmente e disparar um
scan de segurança de ponta a ponta: do webhook do GitHub até o resultado do
pipeline nos logs dos workers. Ao final, você vai ter visto o canvas Celery
inteiro rodar — Tier 1, Gate 1, Tier 2, análise do Claude, Gate 2 — sem
precisar de nenhuma credencial externa: **sem GitHub App, sem chave da
Anthropic e sem domínio público**. O resultado vem degradado (falamos disso no
passo 4), e está tudo bem — é exatamente o que esperamos ver aqui.

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
 "repository":{"full_name":"OCR-aperIA/demo-repo",
   "clone_url":"https://github.com/OCR-aperIA/demo-repo.git"}}
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

Deixe rodando por alguns segundos e observe as etapas passando: Tier 1
(TruffleHog + Semgrep), Gate 1, Tier 2 (scan), análise do Claude e Gate 2.
Pressione `Ctrl+C` quando quiser parar de acompanhar — os containers
continuam de pé.

## O que você acabou de ver

Sem checkout real do repositório e sem créditos na conta Anthropic, o
pipeline roda de ponta a ponta, mas com resultado degradado. É esperado ver:

- **Tier 1 com 0 findings**: o `repo_path` é um stub (`/tmp/aperia/<sha>`) —
  não existe checkout real do código ainda (isso é pós-MVP). Os scanners
  logam `scanner_skipped ... No such file or directory` e seguem.
- **Gate 1 passa**: sem findings, não há `secret_verified`, então o PR não é
  bloqueado e o canvas continua para o Tier 2.
- **Tier 2 também sem findings relevantes**: os scanners rodam, mas sobre o
  mesmo stub vazio.
- **Análise do Claude degradada**: sem `ANTHROPIC_API_KEY` (ou sem créditos),
  a chamada falha e o worker devolve `{"degraded": true, ...}` em vez de
  travar o pipeline — é a filosofia best-effort do aperIA em ação.

Ou seja: o encanamento inteiro funciona — webhook, fila, gates, persistência —
mesmo sem nenhuma peça externa configurada.

## Próximos passos

- Conectar um GitHub real e rodar em repositórios seus →
  [`howto/conectar-github.md`](howto/conectar-github.md)
- Entender o pipeline por dentro (tiers, gates, score) →
  [`explicacao-pipeline.md`](explicacao-pipeline.md)
- Referência de rotas e variáveis de ambiente →
  [`referencia.md`](referencia.md)
