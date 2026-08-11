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
   - **Generate a private key** → baixa um `.pem`. Copie o arquivo para
     `secrets/` na raiz do repositório: `docker-compose.base.yml` monta essa
     pasta como `/app/secrets` (read-only) na API e nos workers, que é o
     caminho sugerido em `GITHUB_PRIVATE_KEY_PATH` no `.env.example`.

     ```bash
     cp ~/Downloads/seu-app.private-key.pem secrets/github-app.private-key.pem
     ```

     Os **workers** precisam da chave tanto quanto a API: desde o checkout
     real, `worker_tier1` e `worker_tier2` clonam o repositório antes de
     escanear, e para isso emitem o installation token igual à API.

Preencha as 4 variáveis (`GITHUB_APP_ID`, `GITHUB_APP_SLUG`,
`GITHUB_PRIVATE_KEY_PATH`, `GITHUB_WEBHOOK_SECRET`) no `.env` e reinicie a
stack (`docker compose -f docker-compose.base.yml up -d`) — a API **e** os
workers leem essas variáveis.

Se houver um front-end, preencha também `GITHUB_CONNECT_REDIRECT_URL` — é a
tela para onde o callback devolve o browser depois da instalação. Em
desenvolvimento local:

```dotenv
GITHUB_CONNECT_REDIRECT_URL=http://localhost:3000/dash/repositorios?github=conectado
```

Sem ela o callback responde JSON e o usuário fica parado no host da API; veja
[Quando o `state` é inválido ou expirou](#quando-o-state-é-inválido-ou-expirou).

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

### Quando o `state` é inválido ou expirou

O `state` vale **10 minutos**. Se o usuário demorar na tela de instalação do
GitHub, ou abrir uma URL de callback antiga, o callback não consegue
identificar quem iniciou o fluxo. Quem chega ali é um browser, não um cliente
de API, então a resposta depende de `GITHUB_CONNECT_REDIRECT_URL`:

| `GITHUB_CONNECT_REDIRECT_URL` | Sucesso | `state` inválido/expirado |
|---|---|---|
| Configurada | `302` para a URL, como configurada | `302` para a mesma URL, com `github=erro&motivo=state` |
| Vazia | `200 {"status":"connected", ...}` | `400 {"detail":"state invalido ou expirado"}` |

No caso de erro, a query string é **mesclada**, não concatenada: um
`github=conectado` já presente na URL é substituído por `github=erro`, e os
demais parâmetros são preservados. Por isso o valor recomendado em
`.env.example` já traz o marcador de sucesso embutido:

```dotenv
GITHUB_CONNECT_REDIRECT_URL=http://localhost:3000/dash/repositorios?github=conectado
```

Com isso a tela do front distingue os dois casos lendo um único parâmetro:
`github=conectado` (recarrega a lista de repositórios) ou
`github=erro&motivo=state` (mostra o erro e oferece tentar de novo, chamando
`GET /github/connect` para gerar um `state` novo).

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
   `url`, `default_branch` e `active` (`true` se já ativado), mais três
   metadados úteis para montar a tela de ativação:

   | Campo | Tipo | Observação |
   |---|---|---|
   | `private` | `bool` | `false` quando o payload da instalação não informa. |
   | `language` | `str \| null` | Linguagem principal detectada pelo GitHub. |
   | `pushed_at` | `datetime \| null` | Último push (ISO 8601) — serve para ordenar por atividade. |

   Os três vêm do mesmo payload de `GET /installation/repositories` que a
   rota já consome: **nenhuma chamada extra ao GitHub**, nenhum custo de
   rate limit adicional.

   ```json
   {
     "github_account_id": "3f1c…",
     "github_repo_id": 123456789,
     "full_name": "sua-org/seu-repo",
     "url": "https://github.com/sua-org/seu-repo",
     "default_branch": "main",
     "active": false,
     "private": true,
     "language": "Python",
     "pushed_at": "2024-06-29T16:00:00Z"
   }
   ```

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
   a resposta é `404`. `default_branch` é opcional (default `"main"`), e
   `target_url` também — veja o passo 5 abaixo.

   > **O POST é um upsert**, não um "criar". A chave é
   > `(user_id, github_repo_id)`: repetir o POST no mesmo repositório — para
   > reativar um que você desativou, ou depois de o `full_name` mudar por um
   > rename no GitHub — **atualiza a linha existente e devolve o mesmo `id`
   > de antes**, com `active` de volta em `true`. Use o `id` da resposta
   > direto em `PATCH`/`DELETE`; ele é o da linha que está no banco.

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

   > O `PATCH` é **parcial**: ele aplica só as chaves que você mandar. Omitir
   > `active` não desativa nada, omitir `target_url` não apaga nada. Um corpo
   > vazio (`{}`) é recusado com `422` de propósito — assim um payload montado
   > errado aparece como erro, e não como uma chamada que "funcionou" sem
   > fazer nada.

A partir do momento em que um repositório está `active=true`, qualquer PR
aberto ou atualizado nele dispara o pipeline automaticamente, e você também
pode disparar um scan sob demanda com
`POST /repositories/{id}/scan` — veja
[disparar-analise.md](./disparar-analise.md).

## 5. Informar a URL da aplicação (liberar o DAST do Tier 3)

Os Tiers 1 e 2 analisam **código**; o Tier 3 inclui um **DAST** (OWASP ZAP),
que precisa de uma aplicação no ar para atacar. Enquanto o repositório não
tiver uma URL cadastrada, o ZAP é pulado e o log registra
`reason="no_target_url"` — o resto do pipeline roda normalmente.

O campo é `target_url`, e aponta para onde **aquele** repositório está
publicado (staging, preview, homologação). É diferente de `url`, que é o
endereço do repositório no GitHub.

```bash
curl -s -X PATCH http://localhost:8000/repositories/<repository_id> \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://staging.suaempresa.com"}'
```

Dá para informar já na ativação, junto do `POST /repositories`. Como o POST é
upsert, **omitir o campo preserva** a URL que já estiver gravada — reativar um
repositório não apaga o alvo.

Para **remover** o alvo (e voltar a pular o DAST), mande `null` explícito:

```bash
curl -s -X PATCH http://localhost:8000/repositories/<repository_id> \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_url": null}'
```

> **Aponte só para ambiente que é seu, e que pode apanhar.** O ZAP não navega
> na URL: ele faz spider e depois **active scan**, disparando payloads reais
> de SQLi, XSS e path traversal contra tudo que encontrar. Use staging ou
> preview — nunca produção, nunca o sistema de outra empresa.

### O que a API recusa (`422`)

Aceitar qualquer URL transformaria o aperIA em origem de ataque contra
terceiros e, com um alvo interno, em um SSRF rodando de dentro da nossa
rede — o pior caso sendo `http://169.254.169.254`, o endpoint de metadata de
AWS/GCP/Azure, que devolve credenciais IAM da máquina e as entregaria de volta
dentro dos findings do relatório. Por isso a validação é restritiva:

| Recusado | Exemplos | `type` no `422` |
|---|---|---|
| URL não absoluta ou malformada | `staging.acme.com`, `https://` | `target_url_malformada` |
| Esquema fora de http/https | `file:///etc/passwd`, `ftp://…` | `target_url_esquema_invalido` |
| Credenciais embutidas | `https://admin:senha@acme.com` | `target_url_com_credenciais` |
| Rede interna | `localhost`, `127.0.0.1`, `10.x`, `172.16–31.x`, `192.168.x`, `169.254.169.254`, `::1`, `fe80::/10`, `100.64.0.0/10`, `0.0.0.0`, `http://2130706433`, `*.local`, `*.internal` | `target_url_alvo_bloqueado` |
| Host sem domínio (só resolve dentro) | `http://zap:8090`, `http://api-interna` | `target_url_host_sem_dominio` |
| String vazia | `""` (use `null` para limpar) | `target_url_vazia` |

O `msg` de cada erro vem em português e pode ser exibido direto ao usuário; o
`type` é estável, então dá para tratar cada caso sem comparar string.

> Um domínio público cujo DNS aponta para dentro da rede (DNS rebinding)
> **não** é pego aqui: resolver DNS no cadastro seria inútil, porque o
> registro pode mudar entre a validação e o scan. A defesa desse caso é de
> rede — negar saída do container do ZAP para faixas internas.

## 6. Desconectar uma conta GitHub

```bash
curl -s -X DELETE http://localhost:8000/github/accounts/<account_id> \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

Responde `204`, ou `404` se a conta não pertencer ao usuário logado.

**O que some e o que fica.** A remoção acontece em uma única transação:

| Registro | Efeito |
|---|---|
| `github_accounts` (a conta) | **Removida.** |
| `repositories` daquela conta | **Removidos** — todos, ativos ou não. |
| `findings` | Preservados. |
| `scan_jobs` (scans) | Preservados. |
| `scan_reports` (relatórios) | Preservados. |

Os repositórios saem junto porque não existe `ForeignKey` entre as duas
tabelas: sem essa limpeza explícita eles ficariam **fantasmas** —
`GET /repositories` continuaria listando-os como ativos, enquanto
`GET /github/repos` já não os mostraria (a instalação deixou de existir).

O histórico de segurança, ao contrário, é o produto: apagá-lo destruiria
auditoria por uma ação reversível (você pode reinstalar o App a qualquer
momento). Ele continua acessível por `GET /findings`, `GET /scans` e
`GET /scans/{commit_sha}/report`, todos no escopo do seu usuário. O que deixa
de funcionar são as rotas `GET /repositories/{id}/…`, porque o repositório em
si não existe mais — passam a responder `404`.

Para reconectar, repita os passos 3 e 4: instalar o App de novo cria uma
`GithubAccount` nova e você reativa os repositórios com `POST /repositories`.
Os scans e findings antigos continuam onde estavam.

Se a intenção for só **pausar** a análise sem perder o vínculo, prefira
`PATCH /repositories/{id}` com `{"active": false}` — o repositório continua
cadastrado e o histórico segue ligado a ele.

## Próximos passos

- Obter/renovar o JWT usado nas rotas acima →
  [consumir-resultados.md](./consumir-resultados.md).
- Entender o isolamento por usuário (contas, repos, scans, findings) →
  [explicacao-pipeline.md](../explicacao-pipeline.md).
- Referência completa de rotas e schemas →
  [referencia.md](../referencia.md).
