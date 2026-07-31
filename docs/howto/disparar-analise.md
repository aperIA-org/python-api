# Como disparar uma análise

Existem três formas de disparar o pipeline de segurança do aperIA:

| Receita | Quando usar | Precisa de PR? | Precisa do GitHub App? |
|---|---|---|---|
| **A — PR real** | Fluxo normal de trabalho | Sim | Sim |
| **B — Scan manual via API** | Analisar o branch default agora, sem abrir PR | Não | Sim |
| **C — Webhook simulado** | Validar o pipeline localmente | Não | Não |

O pipeline é **o mesmo** nas três: mesmo canvas Celery, mesmos tiers, mesmos
gates. A única diferença é a origem do commit analisado e, sem PR, o fato de
não haver onde postar comentários.

## Receita A — Via PR real num repositório conectado

Pré-requisito: o repositório precisa estar conectado via GitHub App — siga
[conectar-github.md](./conectar-github.md) antes de continuar.

Com um repositório ativo conectado, basta abrir ou atualizar um Pull Request
normalmente no GitHub:

1. Abra um PR (`opened`) ou empurre um novo commit para um PR existente
   (`synchronize`) no repositório conectado.
2. O GitHub envia o webhook `pull_request` para `POST /webhook/github`
   automaticamente — não é necessário nenhum comando manual. O pipeline é
   montado e disparado de forma assíncrona a partir daí.

Para acompanhar o resultado, veja [consumir-resultados.md](./consumir-resultados.md).

## Receita B — Scan manual via API (sem PR)

Use quando quiser analisar o estado atual de um repositório sem esperar por um
PR: uma primeira varredura logo depois de ativar o repositório, uma reanálise
depois de um merge, ou um botão "Analisar agora" no front-end.

Pré-requisitos: o repositório já ativado (`POST /repositories`, veja
[conectar-github.md](./conectar-github.md)), com `active=true`, e as
credenciais do App (`GITHUB_APP_ID` e `GITHUB_PRIVATE_KEY_PATH`) configuradas
— é com elas que a API emite o installation token para resolver o commit.

### 1. Dispare

```bash
curl -sS -X POST http://localhost:8000/repositories/<repository_id>/scan \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

O `<repository_id>` é o `id` devolvido por `GET /repositories` (ou pelo
próprio `POST /repositories`). Não há corpo de requisição: o alvo é sempre o
HEAD do `default_branch` do repositório, resolvido ao vivo no GitHub.

### 2. Confirme a resposta

```json
{"status":"queued","commit_sha":"c3f9a1b8d2e40567890abcdef1234567890abcde","branch":"main"}
```

`202 Accepted` — o canvas foi montado e disparado de forma assíncrona.
`commit_sha` é o SHA completo (40 hex) que o GitHub resolveu para o HEAD do
branch; use-o direto nas rotas de leitura
(`GET /scans/{commit_sha}`, `GET /scans/{commit_sha}/report`).

### 3. Códigos de erro

| Código | Quando | O que fazer |
|---|---|---|
| `404` | O repositório não existe **ou** pertence a outro usuário | Confira o `id` em `GET /repositories`. O 404 cobre os dois casos de propósito — a API não confirma a existência de recursos de terceiros. |
| `409` | Repositório com `active=false` | Reative com `PATCH /repositories/{id}` `{"active": true}` (ou repetindo o `POST /repositories`) e tente de novo. |
| `409` | Já existe um scan `queued`/`running` para aquele commit | Espere terminar — o HEAD não mudou, um segundo pipeline no mesmo commit seria trabalho duplicado. Acompanhe com `GET /scans/{commit_sha}`. |
| `502` | O GitHub não respondeu o HEAD do branch | Verifique se o App ainda está instalado e se enxerga o repositório (`GET /github/repos`), e se o `default_branch` cadastrado existe de fato. |
| `503` | `GITHUB_APP_ID` ou `GITHUB_PRIVATE_KEY_PATH` vazios | Complete o registro do App — passo 1 de [conectar-github.md](./conectar-github.md). |

Os dois `409` se distinguem pelo `detail` da resposta:

```json
{"detail":"Repositorio desativado: reative antes de iniciar um scan."}
{"detail":"Ja existe um scan em andamento para o commit c3f9a1b8…."}
```

### 4. O que muda por não haver PR

O scan manual roda com `pr_number = None`. Consequências, todas visíveis no
resultado:

- **Nenhum comentário é postado no GitHub.** Nem o aviso de bloqueio do Gate 1,
  nem os relatórios de Tier 2 e Tier 3. Os workers de reporting detectam a
  ausência de PR e pulam o post (log `tier2_report_sem_pr` /
  `tier3_report_sem_pr`).
- **O status check no commit continua sendo criado.** O Gate 1 marca o commit
  como `failure` quando encontra secret verificado, exatamente como faria num
  PR.
- **Os relatórios continuam sendo gerados e persistidos**, disponíveis em
  `GET /scans/{commit_sha}/report` e `GET /repositories/{id}/reports`. A
  entrega muda de canal, não de conteúdo.

## Receita C — Simulação local via webhook assinado

Use esta receita para disparar o pipeline sem um PR real, assinando o payload
manualmente com HMAC.

### 1. Conheça o contrato do webhook

- **Path:** `POST /webhook/github`
- **Headers obrigatórios:** `X-GitHub-Event: pull_request` e
  `X-Hub-Signature-256: sha256=<hmac>`
- **Actions que disparam o pipeline:** `opened` ou `synchronize`

Campos lidos do payload (`webhook_routes.py:42-76`):

| Campo JSON | Vira |
|---|---|
| `installation.id` | `installation_id` (sem ele → `{"status":"ignored"}`) |
| `pull_request.head.sha` | `commit_sha` / `head_sha` |
| `pull_request.base.sha` | `base_sha` |
| `pull_request.number` | `pr_number` |
| `repository.full_name` | `repo_full_name` |
| `repository.clone_url` | `repo_url` |

### 2. Monte o payload, assine e envie

Como `GITHUB_WEBHOOK_SECRET` tem default `""`, dá para assinar com chave vazia:

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

Se você tiver um `GITHUB_WEBHOOK_SECRET` diferente de vazio configurado, troque
o `-hmac ''` pelo valor do secret.

### 3. Confirme a resposta

```json
{"status":"queued","commit_sha":"deadbeefcafebabe0000000000000000deadbeef"}
```

Isso monta o canvas Celery (`app/core/orchestrator.py:start_pipeline`) e
dispara de forma assíncrona.

### 4. Acompanhe a execução

```bash
docker compose -f docker-compose.base.yml logs -f \
  worker_tier1 worker_tier2 worker_analysis worker_reporting worker_tier3
```

## Próximos passos

- Consumir os resultados (findings, scans, relatórios) via API →
  [consumir-resultados.md](./consumir-resultados.md).
- Entender por dentro o que cada etapa do pipeline faz →
  [explicacao-pipeline.md](../explicacao-pipeline.md).
