# Como consultar findings, scans e relatórios

Depois que o pipeline roda sobre um commit (veja
[disparar-analise.md](./disparar-analise.md)), os resultados ficam
disponíveis via API, isolados por usuário: cada usuário só vê os próprios
scans, findings e relatórios.

Vale tanto para scans nascidos de um PR quanto para scans manuais
(`POST /repositories/{id}/scan`). Nos manuais, aliás, a API é o **único**
canal de entrega: sem PR, nenhum relatório vira comentário no GitHub.

## Obter um JWT

1. **Criar um usuário** (`POST /users`, senha mínimo 8 caracteres):

   ```bash
   curl -s -X POST http://localhost:8000/users \
     -H "Content-Type: application/json" \
     -d '{
       "username": "heitor",
       "password": "senha-forte-123",
       "email": "heitor@example.com"
     }'
   # → {"id": "<uuid>"}
   ```

2. **Fazer login** (`POST /auth/login`) para obter o par de tokens:

   ```bash
   curl -s -X POST http://localhost:8000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "heitor@example.com", "password": "senha-forte-123"}'
   # → {"access_token": "...", "refresh_token": "...", "token_type": "bearer"}
   ```

   Guarde o `access_token` numa variável para reusar nos exemplos abaixo:

   ```bash
   ACCESS_TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "heitor@example.com", "password": "senha-forte-123"}' \
     | jq -r .access_token)
   ```

Use `Authorization: Bearer $ACCESS_TOKEN` em **todas** as rotas de leitura a
seguir. O `access_token` expira em 15 minutos (default); troque o
`refresh_token` por um novo par em `POST /auth/refresh` quando expirar.

## Rotas globais (isoladas por usuário)

**`GET /findings`** — lista findings do usuário logado. Filtros opcionais via
query string: `commit_sha`, `severity` (`critical|high|medium|low|info`),
`tier` (1-3), `source` (ex.: `semgrep`), `secret_verified` (bool), mais
`limit`/`offset` para paginação (default `limit=50`, máx. `200`).

```bash
curl -s "http://localhost:8000/findings?severity=high&tier=2&limit=20" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

**`GET /findings/{finding_id}`** — detalhe de um finding, incluindo
`raw_output` (omitido na listagem acima).

```bash
curl -s http://localhost:8000/findings/<finding_id> \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

**`GET /scans`** — lista os `ScanJob` do usuário, paginados (mais recentes
primeiro), com `limit`/`offset`.

```bash
curl -s "http://localhost:8000/scans?limit=10" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

**`GET /scans/{commit_sha}`** — status de um scan específico, com
`findings_summary` (contagens por `severity` e por `tier`) embutido.

```bash
curl -s http://localhost:8000/scans/<commit_sha> \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

**`GET /scans/{commit_sha}/report`** — todos os relatórios (um por tier já
concluído) daquele commit. Lista vazia se o pipeline ainda estiver rodando.

**`GET /scans/{commit_sha}/tiers/{tier}/report`** — relatório de um tier
específico (1-3):

```bash
curl -s http://localhost:8000/scans/<commit_sha>/tiers/2/report \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

## Rotas por repositório

Equivalentes às rotas globais, mas restritas a um repositório ativado
(`repository_id` obtido em `GET /repositories`; veja
[conectar-github.md](./conectar-github.md)):

- `GET /repositories/{id}/scans` — scans do repositório (paginado).
- `GET /repositories/{id}/findings` — findings do repositório, todos os
  commits (mesmos filtros de `severity`/`tier`/`source` + paginação).
- `GET /repositories/{id}/reports` — relatórios do repositório.

```bash
curl -s http://localhost:8000/repositories/<repository_id>/findings \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

## Isolamento por usuário

Um usuário só enxerga os próprios recursos. Se você tentar acessar um
`finding_id`, `commit_sha`, `repository_id` ou `account_id` que existe, mas
pertence a **outro** usuário, a resposta é **`404`** — nunca `403`. Isso é
proposital, para não vazar a existência do recurso a quem não é dono; a
justificativa completa está em
[explicacao-pipeline.md](../explicacao-pipeline.md).

## Inspecionar direto no banco (opcional)

Para depuração local, dá para consultar a tabela `findings` diretamente:

```bash
docker compose -f docker-compose.base.yml exec -T db \
  psql -U postgres -d aperia -c \
  "select tier, source, severity, title from findings where commit_sha='<commit_sha>';"
```

## Próximos passos

- Conectar contas/repositórios GitHub →
  [conectar-github.md](./conectar-github.md).
- Entender por que o isolamento usa 404 em vez de 403 →
  [explicacao-pipeline.md](../explicacao-pipeline.md).
