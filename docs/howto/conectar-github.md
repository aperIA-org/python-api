# Como conectar uma conta GitHub e ativar repositórios

O aperIA analisa PRs através de um **GitHub App**: cada usuário instala esse
App na sua conta/org e escolhe quais repositórios ativar para análise — a
conexão e os repositórios ativados são isolados por usuário (veja o modelo em
[explicacao-pipeline.md](../explicacao-pipeline.md)).

## 1. Registrar o GitHub App

Só precisa ser feito **uma vez** por instância do aperIA (é o admin que
registra, não cada usuário). Passo a passo resumido — detalhes e comentários
completos estão em `.env.example`:

1. Acesse `https://github.com/settings/apps` → **New GitHub App**.
2. **GitHub App name:** escolha um nome. O slug (nome em minúsculas com
   hífens, ex.: `aperia-scanner`) vai em `GITHUB_APP_SLUG`.
3. **Homepage URL:** qualquer URL válida (campo obrigatório).
4. **Webhook:**
   - **Webhook URL:** `https://<seu-host>/webhook/github`
   - **Secret:** gere com `openssl rand -hex 32` e cole no campo Secret do
     GitHub — o mesmo valor vai em `GITHUB_WEBHOOK_SECRET`.
5. **Setup URL** (em "Post installation"): `https://<seu-host>/github/callback`,
   com "Redirect on update" marcado. É para onde o GitHub redireciona o
   usuário depois de instalar, entregando `installation_id` + o `state` que
   amarra a instalação ao usuário logado.
6. **Permissions** (Repository permissions):
   - Pull requests: **Read and write** (postar comentários/code suggestions)
   - Contents: **Read-only** (ler arquivos para contexto)
   - Commit statuses: **Read and write** (status check do PR)

   **Subscribe to events:** `Pull request` e `Installation`.
7. **Where can this GitHub App be installed?:** `Any account` — deixa o App
   público (sem Marketplace/aprovação) para qualquer usuário instalar via a
   URL que `GET /github/connect` gera.
8. Clique **Create GitHub App** e, na página do App:
   - **App ID** (topo da página) → `GITHUB_APP_ID`
   - **Generate a private key** → baixa um `.pem`. Guarde o arquivo e aponte
     `GITHUB_PRIVATE_KEY_PATH` para o caminho dele (montado no container).

Preencha as 4 variáveis (`GITHUB_APP_ID`, `GITHUB_APP_SLUG`,
`GITHUB_PRIVATE_KEY_PATH`, `GITHUB_WEBHOOK_SECRET`) no `.env` e reinicie a
API.

## 2. Expor o localhost sem domínio (dev)

Em dev, sem HTTPS público, o Webhook URL e o Setup URL do passo 1 precisam de
um túnel. Com ngrok, no Linux/WSL:

```bash
curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null && \
  echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list && \
  sudo apt update && sudo apt install ngrok

ngrok config add-authtoken <seu-token>
ngrok http 8000
```

O ngrok imprime uma URL `https://<algo>.ngrok-free.app`. Ela muda a cada
`ngrok http` (plano free) — se for reiniciar o túnel com frequência, vale
reservar um **domínio estático grátis** na conta ngrok para não ter que
reeditar o Webhook URL/Setup URL do App a cada vez.

Use essa URL HTTPS como base tanto do **Webhook URL**
(`https://<url-do-tunel>/webhook/github`) quanto do **Setup URL**
(`https://<url-do-tunel>/github/callback`) no GitHub App.

**Alternativas:**

- **cloudflared** (`cloudflared tunnel --url http://localhost:8000`): mesmo
  papel do ngrok, sem conta obrigatória.
- **smee.io:** só reencaminha webhooks — serve para o Webhook URL, mas **não**
  serve para o Setup URL, porque o Setup URL precisa redirecionar o
  *browser* do usuário (não só entregar um POST), e o smee é um proxy só de
  webhook.

## 3. Conectar a conta

Com o App registrado e a API no ar:

1. Peça um JWT — veja [consumir-resultados.md](./consumir-resultados.md#obter-um-jwt).
2. Chame `GET /github/connect` com o JWT:

   ```bash
   curl -s http://localhost:8000/github/connect \
     -H "Authorization: Bearer $ACCESS_TOKEN"
   ```

   Retorna `{"install_url": "https://github.com/apps/<slug>/installations/new?state=..."}`.

   > Enquanto `GITHUB_APP_SLUG` estiver vazio no `.env`, esta rota responde
   > **503** — é o comportamento esperado até o passo 1 estar concluído.
3. Abra `install_url` no browser, escolha a conta/org e os repositórios (ou
   "All repositories") e confirme a instalação.
4. O GitHub redireciona para `GET /github/callback?installation_id=...&state=...`,
   que decodifica o `state` (sem exigir JWT — a identidade já está no
   `state` assinado), grava/atualiza a `GithubAccount` do usuário e:
   - redireciona (302) para `GITHUB_CONNECT_REDIRECT_URL`, se configurado;
   - ou responde `{"status": "connected", "installation_id": ...}` em JSON.

Confirme com `GET /github/accounts` (JWT) — deve listar a conta recém-conectada.

## 4. Ativar repositórios

Instalar o App só dá *visibilidade*; o pipeline só roda nos repositórios
explicitamente **ativados**:

1. **Listar o que está visível:**

   ```bash
   curl -s http://localhost:8000/github/repos \
     -H "Authorization: Bearer $ACCESS_TOKEN"
   ```

   Retorna a lista ao vivo de repositórios de todas as instalações do
   usuário, cada um com `github_account_id`, `github_repo_id`, `full_name`,
   `url`, `default_branch` e `active` (`true` se já ativado).

2. **Ativar um repositório:**

   ```bash
   curl -s -X POST http://localhost:8000/repositories \
     -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "github_account_id": "<id-da-conta-devolvido-acima>",
       "github_repo_id": 123456789,
       "full_name": "sua-org/seu-repo",
       "url": "https://github.com/sua-org/seu-repo"
     }'
   ```

   `github_account_id` precisa pertencer ao usuário logado — caso contrário
   a resposta é `404`. `default_branch` é opcional (default `"main"`).

3. **Listar os ativados:**

   ```bash
   curl -s http://localhost:8000/repositories \
     -H "Authorization: Bearer $ACCESS_TOKEN"
   ```

4. **Desativar/reativar** (`PATCH`) **ou remover** (`DELETE`) um repositório:

   ```bash
   curl -s -X PATCH http://localhost:8000/repositories/<repository_id> \
     -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"active": false}'

   curl -s -X DELETE http://localhost:8000/repositories/<repository_id> \
     -H "Authorization: Bearer $ACCESS_TOKEN"
   ```

A partir do momento em que um repositório está `active=true`, qualquer PR
aberto ou atualizado nele dispara o pipeline automaticamente — veja
[disparar-analise.md](./disparar-analise.md).

## Próximos passos

- Obter/renovar o JWT usado nas rotas acima →
  [consumir-resultados.md](./consumir-resultados.md).
- Entender o isolamento por usuário (contas, repos, scans, findings) →
  [explicacao-pipeline.md](../explicacao-pipeline.md).
- Referência completa de rotas e schemas →
  [referencia.md](../referencia.md).
