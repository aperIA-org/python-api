# Como disparar uma análise

Existem duas formas de disparar o pipeline de segurança do aperIA: um PR real
num repositório conectado, ou uma simulação local via webhook assinado. Use a
receita (B) para validar o pipeline sem depender do GitHub App.

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

## Receita B — Simulação local via webhook assinado

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
