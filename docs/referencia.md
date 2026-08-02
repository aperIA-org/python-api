# Referência

Este documento é material de **referência** (fatos: rotas, variáveis, modelos, serviços, plumbing do Claude). Descreve o sistema como ele é, sem instruções passo a passo. Para uso prático, veja os how-tos em [`howto/`](howto/) (ex.: [`howto/subir-a-stack.md`](howto/subir-a-stack.md)); para entender o "porquê" do pipeline, veja [`explicacao-pipeline.md`](explicacao-pipeline.md).

Fontes: `openapi.yaml`, `.env.example`, `app/config.py`, `app/domain/{finding,scan,github}/entities.py`, `app/infrastructure/persistence/models/`, `GUIA_EXECUCAO.md`.

## 1. Rotas da API

27 rotas HTTP registradas em `app/main.py`, agrupadas em 8 tags. `Auth` indica exigência de `Authorization: Bearer <access_token>` (JWT); rotas sem essa exigência estão marcadas "—". O webhook usa um esquema de autenticação próprio (HMAC), não JWT.

| Método | Caminho | Descrição | Auth |
|---|---|---|---|
| `GET` | `/health` | Healthcheck — `{"status":"ok"}`; não verifica dependências externas. | — |
| `POST` | `/users` | Cria usuário (senha com hash Argon2, e-mail único). Retorna só o `id`. | — |
| `GET` | `/users/{user_id}` | Consulta dados públicos de um usuário por UUID. | — |
| `POST` | `/auth/login` | Autentica e retorna `access_token` (15 min) + `refresh_token` (7 dias). | — |
| `POST` | `/auth/refresh` | Troca um `refresh_token` válido por novo par (rotação); reuso detectado invalida a família. | — |
| `POST` | `/auth/logout` | Invalida o `refresh_token` fornecido. Sempre `204` (evita oracle). | — |
| `GET` | `/findings` | Lista findings do usuário logado (filtros `commit_sha`/`severity`/`tier`/`source`/`secret_verified`/`title` + paginação). Omite `raw_output`. `title` é **igualdade exata** — é o drill-down de um grupo, não busca livre. | JWT |
| `GET` | `/findings/groups` | Findings agrupados por tipo (`source`+`severity`+`tier`+`title`+`asset`), com `ocorrencias`, `caminhos` distintos, intervalo de datas e uma `amostra` de caminhos. Sem paginação: o agrupamento derruba a cardinalidade em três ordens de grandeza. Declarada **antes** de `/findings/{finding_id}`, senão `groups` seria capturado como uuid. | JWT |
| `GET` | `/findings/{finding_id}` | Detalhe de um finding, incluindo `raw_output`. 404 se não pertencer ao usuário. | JWT |
| `GET` | `/scans` | Lista scans do usuário logado, paginados. Ordenado por **`COALESCE(tier1_started_at, created_at)` desc** — ou seja, pela execução mais recente, não pela entrada do commit: reescanear um commit antigo preserva o `created_at` e o job ficaria no fim da lista. | JWT |
| `GET` | `/scans/{scan_id}` | Status de uma execução, com `findings_summary`. `scan_id` aceita o **uuid da execução** ou um **commit sha** (resolve para a execução *corrente* daquele commit). | JWT |
| `GET` | `/scans/{scan_id}/report` | Relatórios (um por tier) **daquela execução**. Lista vazia se o pipeline ainda não gerou nenhum. | JWT |
| `GET` | `/scans/{scan_id}/tiers/{tier}/report` | Relatório de um tier específico (1-3) daquela execução. | JWT |
| `GET` | `/scans/{scan_id}/history` | Todas as execuções do mesmo commit, da mais recente para a mais antiga (inclui a consultada). | JWT |
| `GET` | `/github/connect` | Gera `install_url` do GitHub App com `state` assinado (10 min). Retorna 503 se `GITHUB_APP_SLUG` vazio. | JWT |
| `GET` | `/github/callback` | Recebe o redirect pós-instalação (`installation_id` + `state` + `setup_action`); vincula a instalação ao usuário via `state` assinado (não via header). Upsert de `GithubAccount`. Com `GITHUB_CONNECT_REDIRECT_URL` configurada responde `302` (inclusive em erro de `state`, com `github=erro&motivo=state`); sem ela, JSON no sucesso e `400` no erro. | — |
| `GET` | `/github/repos` | Lista, ao vivo, os repositórios visíveis pelas instalações do usuário; marca `active` nos já ativados. Traz também `private`, `language` e `pushed_at`, lidos do próprio payload da instalação. | JWT |
| `GET` | `/github/accounts` | Lista as contas GitHub (instalações) conectadas pelo usuário. | JWT |
| `DELETE` | `/github/accounts/{account_id}` | Desconecta uma conta GitHub **e remove, na mesma transação, os `repositories` vinculados a ela**. Findings, scans e relatórios são preservados. 404 se não pertencer ao usuário. | JWT |
| `GET` | `/repositories` | Lista repositórios ativados para análise pelo usuário. | JWT |
| `POST` | `/repositories` | Ativa um repositório, vinculado a uma `github_account_id` do usuário. **Upsert** por `(user_id, github_repo_id)`: reativar devolve o `id` da linha já existente, não um novo. Aceita `target_url` (opcional) — omitir **preserva** a URL já gravada. 404 se a conta não pertencer ao usuário; `422` se a `target_url` for recusada. | JWT |
| `GET` | `/repositories/{repository_id}` | Detalhe de um repositório. 404 se não pertencer ao usuário. | JWT |
| `PATCH` | `/repositories/{repository_id}` | Atualização **parcial**: aplica só as chaves presentes no corpo (`active` e/ou `target_url`). `{"active": false}` segue idêntico; `{"target_url": null}` limpa o alvo de DAST. 404 se não pertencer ao usuário; `422` para corpo vazio, `active: null` ou `target_url` recusada. Ver "Alvo de DAST" abaixo. | JWT |
| `DELETE` | `/repositories/{repository_id}` | Remove o vínculo do repositório. 404 se não pertencer ao usuário. | JWT |
| `POST` | `/repositories/{repository_id}/scan` | Dispara um scan manual no HEAD do `default_branch` — mesmo pipeline do webhook, com `pr_number=None`. `202` com `{"status","commit_sha","branch"}`; `409` se desativado ou se já há scan em andamento no commit; `502` se o GitHub não resolver o HEAD; `503` sem credenciais do App. | JWT |
| `GET` | `/repositories/{repository_id}/scans` | Lista scans (`ScanJob`) do repositório, paginados. | JWT |
| `GET` | `/repositories/{repository_id}/findings` | Lista findings do repositório (todos os commits), com filtros. | JWT |
| `GET` | `/repositories/{repository_id}/reports` | Lista relatórios (por commit/tier) do repositório. | JWT |
| `POST` | `/webhook/github` | Recebe eventos GitHub; dispara o pipeline em `pull_request` `opened`/`synchronize`. | HMAC (`X-Hub-Signature-256`, segredo `GITHUB_WEBHOOK_SECRET`) — não é JWT |

> Documentação interativa em runtime: `/docs` (Swagger) e `/redoc`. `openapi.yaml` é gerado a partir do código via `scripts/export_openapi.py`.

## 2. Variáveis de ambiente

Fonte: `app/config.py` (singleton `settings`, pydantic `BaseSettings`, `case_sensitive=True`, `extra="ignore"`, lê `.env`) e `.env.example`.

| Variável | Default | Necessária para |
|---|---|---|
| `SECRET_KEY` | `change-this-secret-key-with-at-least-32-characters` | Assinatura dos JWT (access token e `state` do GitHub connect) — trocar em produção. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Duração do access token. |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Duração do refresh token. |
| `GITHUB_APP_ID` | `""` | Autenticação do GitHub App (JWT do App). Junto com `GITHUB_PRIVATE_KEY_PATH`, é o par exigido pelo `POST /repositories/{id}/scan` — vazio → rota responde 503. |
| `GITHUB_PRIVATE_KEY_PATH` | `""` | Caminho do `.pem` da chave privada do App. Ver `GITHUB_APP_ID`. |
| `GITHUB_WEBHOOK_SECRET` | `""` | HMAC do `POST /webhook/github` (vazio = assina com chave vazia). |
| `GITHUB_APP_SLUG` | `""` | Monta `install_url` em `GET /github/connect`; vazio → rota responde 503. |
| `GITHUB_CONNECT_REDIRECT_URL` | `""` | Tela do front-end que recebe o retorno da instalação (ex.: `http://localhost:3000/dash/repositorios?github=conectado`). No sucesso o `GET /github/callback` redireciona (`302`) para a URL exatamente como configurada; num `state` inválido/expirado redireciona para a mesma URL com `github=erro&motivo=state` (substitui `github=conectado`, preserva os demais parâmetros). Vazio → callback responde JSON no sucesso e `400` no erro, sem `302`. |
| `ANTHROPIC_API_KEY` | `""` | Chamadas ao Claude nos tiers 2/3; sem ela a análise roda em modo degradado. |
| `CLAUDE_MODEL_REASONING` | `claude-sonnet-4-6` | Modelo usado em `tier2_analyze`/`tier3_deep_analysis` (raciocínio). |
| `CLAUDE_MODEL_FORMATTING` | `claude-haiku-4-5-20251001` | Modelo usado nos workers de `reporting` (markdown). |
| `CLAUDE_PROMPT_CACHE_ENABLED` | `True` | Ativa `cache_control: ephemeral` no bloco `system` dos prompts. |
| `ZAP_BASE_URL` | `http://zap:8090` | Endpoint do OWASP ZAP (Tier 3 DAST). |
| `ZAP_API_KEY` | `changeme` | Autenticação no ZAP. O default é igual ao de `docker-compose.scanners.yml` de propósito — divergir faz o ZAP recusar toda chamada. |
| `ZAP_SPIDER_MAX_DURATION_MIN` | `3` | Teto de duração do spider, aplicado **no ZAP**. `0` = sem limite. |
| `ZAP_SPIDER_MAX_CHILDREN` | `10` | Filhos por nó que o crawler expande; corta listagem/paginação. `0` = sem limite. |
| `ZAP_ASCAN_MAX_DURATION_MIN` | `10` | Teto do active scan, aplicado **no ZAP** para que ele encerre sozinho e os alertas parciais sejam coletados. |
| `ZAP_ASCAN_MAX_RULE_DURATION_MIN` | `2` | Teto por regra; impede que uma regra cara consuma o orçamento inteiro. |
| `ZAP_ASCAN_THREADS_PER_HOST` | `2` | Concorrência de ataque por host. |
| `ZAP_ASCAN_DISABLED_RULES` | `40026` | Ids de regras desligadas. `40026` é o DOM XSS, que sobe Firefox headless dentro do container do ZAP. Vazio = política completa. |
| `OPENCTI_URL` | `http://opencti:8081` | Endpoint do OpenCTI (Tier 3 threat intel). |
| `OPENCTI_TOKEN` | `""` | Autenticação no OpenCTI. |
| `CALDERA_URL` | `http://caldera:8888` | Endpoint do MITRE Caldera (Tier 3 emulação adversária). |
| `CALDERA_API_KEY` | `""` | Autenticação no Caldera. |
| `CALDERA_SANDBOX_MODE` | `True` | **Inviolável** — `false` levanta `SandboxViolationError` no `__init__` do `CalderaClient`. |
| `CALDERA_POLL_INTERVAL` | `10` | Intervalo (s) de polling de status da emulação; testes injetam `0` via construtor. |
| `CALDERA_AGENT_GROUP` | `"red"` | Grupo de agentes usado na emulação Caldera. |
| `CALDERA_AGENT_PAW` | `aperia-sandbox` | **Só no compose** (a API não lê): PAW fixo do agente sandcat. Sem ele, cada reinício do container registra um agente novo, e a operação roda cada ability em todos eles. Ver [explicação §14](explicacao-pipeline.md#14-por-que-o-caldera-tem-um-agente-e-não-vinte). |
| `LLM_GUARD_ENABLED` | `True` | Bloqueio de padrões de prompt injection antes de chamar a API do Claude. |
| `FINDINGS_PERSISTENCE_ENABLED` | `True` | Escrita best-effort de `Finding` na tabela `findings` pelos scan workers; testes desligam. |
| `SCAN_PERSISTENCE_ENABLED` | `True` | Escrita best-effort do ciclo de vida do `ScanJob` (criação + updates de status por tier); testes desligam. Também controla a varredura de jobs travados no boot da API. |
| `SCAN_STALE_AFTER_MINUTES` | `30` | Minutos sem progresso a partir dos quais um `ScanJob` ainda `queued`/`running` é considerado **travado** e marcado como `failed`. Ver "Recuperação de scans travados" abaixo. Suba o valor se o Tier 3 (ZAP/Caldera) passa rotineiramente de 30 min. |
| `REDIS_URL` | `redis://redis:6379/0` | Broker e result backend do Celery (hostname do container, não `localhost`). |
| `CELERY_BROKER_URL` | `""` | Override do broker; vazio deriva de `REDIS_URL`. |
| `CELERY_RESULT_BACKEND` | `""` | Override do result backend; vazio deriva de `REDIS_URL`. |
| `CELERY_TASK_ALWAYS_EAGER` | `False` | Execução síncrona (só testes — nunca produção). |
| `CELERY_TASK_EAGER_PROPAGATES` | `False` | Propaga exceções em modo eager (só testes). |

> **Nota — `DATABASE_URL`/`DB_*`:** essas variáveis **não** fazem parte de `Settings` (`app/config.py`). São lidas diretamente do `os.environ` em `app/infrastructure/database/sqlalchemy.py`: `DATABASE_URL` (se definida) tem precedência total sobre as partes separadas `DB_HOST`/`DB_PORT`/`DB_NAME`/`DB_USER`/`DB_PASSWORD` (defaults `db`/`5432`/`postgres`/`postgres`/`postgres`) e `DB_FORCE_IPV4` (`false`, força IPv4 quando `true`). `_normalize_scheme` converte automaticamente `postgresql+asyncpg://` → `postgresql+psycopg://`. O `docker-compose.base.yml` injeta `DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/aperia`, que sobrescreve qualquer `DB_HOST` apontando para um banco externo.

## 3. Modelos de dados

### `Finding` (`app/domain/finding/entities.py`) — tabela `findings`

| Campo | Tipo | Observação |
|---|---|---|
| `id` | `UUID` | `default_factory=uuid4`. |
| `source` | `str` | Ferramenta de origem (`trufflehog`, `semgrep`, `trivy`, `prowler`, `zap`). |
| `severity` | `Severity` | Enum `critical`/`high`/`medium`/`low`/`info`. |
| `title` | `str` | Título/regra do finding. |
| `description` | `str` | Mensagem detalhada (nunca logar valor de secret cru). |
| `commit_sha` | `str` | SHA do commit analisado. |
| `repo_url` | `str` | URL do repositório. |
| `cve_id` | `CVEId \| None` | Value object; liga o finding ao enriquecimento OpenCTI no Tier 3. |
| `cwe_id` | `str \| None` | Classificação CWE. |
| `file_path` | `str \| None` | Caminho do arquivo. |
| `line_number` | `int \| None` | Linha do arquivo. |
| `asset` | `str \| None` | Recurso afetado (ex.: ARN, `ResourceId`). |
| `asset_criticality` | `str \| None` | Criticidade do ativo. |
| `secret_verified` | `bool` | Default `False`; só o TruffleHog seta `True` — único gatilho do Gate 1. |
| `secret_type` | `str \| None` | Ex.: `"AWS"`. |
| `raw_output` | `dict` | JSON nativo do scanner (`default_factory=dict`). |
| `tier` | `int` | `1`/`2`/`3`; default `1`. |
| `created_at` | `datetime` | `default_factory=datetime.utcnow`. |

`dedup_key()` = `f"{source}:{cve_id or title}:{file_path}:{line_number}:{commit_sha}"`. Método adicional: `is_critical_secret()` = `secret_verified and severity == CRITICAL`.

**UNIQUE:** `findings_dedup_key` em `dedup_key` (coluna materializada pelo `FindingModel`) — garante idempotência via `ON CONFLICT (dedup_key) DO NOTHING`. Mesmo CVE de scanners diferentes gera 2 linhas (o `source` é parte da chave).

### `ScanJob` (`app/domain/scan/entities.py`) — tabela `scan_jobs`

| Campo | Tipo | Observação |
|---|---|---|
| `id` | `UUID` | `default_factory=uuid4`. |
| `commit_sha` | `str` | Chave de busca do scan. |
| `repo_url` | `str` | URL do repositório. |
| `installation_id` | `int` | Instalação do GitHub App que originou o evento. |
| `pr_number` | `int \| None` | Número do PR. `None` em scan manual (`POST /repositories/{id}/scan`) — o pipeline é o mesmo, mas os workers de reporting não comentam em PR nenhum (o status check no commit continua sendo criado). |
| `repo_full_name` | `str \| None` | `org/repo`. |
| `tier1_status` / `tier2_status` / `tier3_status` | `TierStatus \| None` | Status por tier: `queued`, `running`, `done`, `failed`, `skipped` — ou `None` (o tier ainda não foi alcançado). `skipped` é **decisão de gate**, não ausência de dado: ver "Gates" abaixo. |
| `tier1_started_at` / `tier1_completed_at` (idem tier2/tier3) | `datetime \| None` | Timestamps de início/fim por tier. |
| `blocked_at_tier` | `ScanTier \| None` | Tier em que um gate interrompeu o pipeline. |
| `final_risk_score` | `int \| None` | Score final (produzido pelo Claude). |
| `final_risk_level` | `str \| None` | Nível textual do score final. |
| `user_id` | `UUID \| None` | Dono do scan (desnormalizado p/ filtro rápido); nullable p/ scans legados. |
| `repository_id` | `UUID \| None` | `Repository` que originou o scan; nullable p/ scans legados. |
| `created_at` | `datetime` | `default_factory=datetime.utcnow`. |

**Uma linha = uma EXECUÇÃO, não um commit.** Redisparar o mesmo commit (rescan
da mesma branch, novo push com o mesmo HEAD, retry) **empilha uma linha nova** e
preserva a anterior — é o que dá histórico de relatórios. `id` é a identidade da
execução; `commit_sha` sozinho não identifica mais um scan.

**UNIQUE:** índice parcial `uq_scan_jobs_commit_em_andamento` em `commit_sha`,
com predicado "algum tier em `queued`/`running`". Ou seja: **no máximo uma
execução em andamento por commit**, quantas encerradas quiser. Isso preserva a
idempotência que o antigo `UNIQUE(commit_sha)` garantia (dois webhooks do mesmo
push não geram dois pipelines, via `ON CONFLICT DO NOTHING`) sem impedir o
histórico. O método `restart_execution` deixou de existir.

**Como os workers acham a execução certa:** o canvas Celery só carrega
`commit_sha` — nenhuma task conhece o id da execução. O repositório resolve isso
com a subquery `_id_execucao_corrente(commit_sha)` (a execução mais recente
daquele commit), usada no `WHERE` de `update_tier_status`, `set_blocked`,
`set_final_risk` e `fail_pending_tiers`. É unívoco porque o índice parcial impede
duas execuções vivas ao mesmo tempo e uma nova só nasce depois que a anterior
encerra. *Ressalva:* um redisparo no intervalo entre o último tier encerrar e uma
task atrasada escrever faria a escrita atrasada cair na execução nova — fechar
isso exige levar o id da execução no canvas (ver `pendencias.md`).

`created_at` passou a ser o início desta execução (antes era preservado da
primeira vez que o commit entrou no sistema).

Métodos do domínio (`ScanJob`):

| Método | O que é |
|---|---|
| `em_andamento()` | Algum tier em `queued`/`running`. É o que produz o `409` do disparo manual. |
| `ultimo_progresso_em` | O **mais recente** entre todos os `tier*_started_at`/`tier*_completed_at` e o `created_at`. O `created_at` entra porque pode ser o único timestamp existente: a linha nasce com o Tier 1 em `running` e, se ninguém consumir a fila, nenhum outro é escrito. |
| `esta_travado(agora, limiar_minutos)` | `em_andamento()` **e** `ultimo_progresso_em` mais velho que o limiar (`SCAN_STALE_AFTER_MINUTES`). |
| `status_do_tier(tier)` | `TierStatus \| None` do tier pedido (`ScanTier.ONE/TWO/THREE`). |
| `tier_concluido(tier)` | Tier já tem desfecho real (`done`/`failed`). É o que impede um gate de sobrescrever com `skipped` o resultado de um tier que de fato rodou. |

#### Gates — o que cada decisão grava

Os dois gates do pipeline interrompem o chain com `Ignore()`, e **a interrupção
em si é o dado mais importante do scan**. Por isso ambos persistem a decisão
antes do `raise` (best-effort, via `scan_job_writer`):

| Gate | Condição | O que grava |
|---|---|---|
| **Gate 1** (`gate1_check`) | Passa | `tier1_status = done` |
| | Bloqueia (`secret_verified`) | `tier1_status = done`, `blocked_at_tier = 1` e `tier2_status = tier3_status = skipped` — T2 e T3 nunca vão rodar neste commit |
| **Gate 2** (`tier3_gate`) | Escala (`high`/`critical`) | `tier3_status = running` |
| | Pula (severidade abaixo do limiar) | `tier3_status = skipped` |

`skipped` e `NULL` significam coisas diferentes e a UI deve distingui-las:
`skipped` é "um gate decidiu que este tier não roda"; `NULL` é "o pipeline ainda
não chegou aqui". A gravação usa `scan_job_writer.mark_tier_skipped`, que checa
`tier_concluido()` antes de escrever — um gate rodando fora de ordem (retry do
canvas, redisparo) não apaga um tier `done`/`failed`.

A identidade do scan usada pelo Gate 2 vem **do payload**: `tier2_analyze`
injeta `commit_sha` no dict de análise, que trafega pelo canvas até o gate (o
`tier3_gate` recebe só o resultado da task anterior como argumento posicional).
Ler o commit de dentro dos `findings` não funciona — o caso mais comum hoje é
justamente o de zero findings, e a decisão sairia sem identificação no log
(`tier3_skipped commit_sha=`) e sem persistência.

#### Recuperação de scans travados

Um `ScanJob` fica **travado** quando a tarefa Celery correspondente deixa de
existir (fila perdida num restart da stack, worker morto) mas a linha no
Postgres sobrevive dizendo `running`. Além de mentir em `GET /scans`, ela
bloqueia o commit: `POST /repositories/{id}/scan` responde `409` enquanto algum
tier estiver `queued`/`running`, e a UNIQUE em `commit_sha` faz todo redisparo
cair na mesma linha — o commit vira permanentemente não-escaneável.

Não há celery beat na stack; a recuperação acontece em dois pontos
complementares, ambos usando `SCAN_STALE_AFTER_MINUTES`:

1. **Varredura no boot da API** (`recover_stale_scan_jobs`, `app/main.py` →
   `RecoverStaleScanJobsUseCase`): lista os jobs em andamento, marca como
   `failed` os tiers pendentes dos que estão travados e loga
   `scan_job_stale_liberado` / `scan_jobs_stale_recovery_done`. Best-effort: uma
   falha de banco é logada (`scan_jobs_stale_recovery_failed`) e a API sobe
   assim mesmo. Não roda com `SCAN_PERSISTENCE_ENABLED=false`.
2. **Checagem preguiçosa no disparo** (`TriggerRepositoryScanUseCase`): um job
   travado não bloqueia — ele é marcado como `failed`
   (`scan_job_stale_liberado_no_disparo`) e o novo scan segue. Um job realmente
   em andamento continua respondendo `409`.

Em ambos os casos só os tiers pendentes viram `failed`; tiers já `done`/`skipped`
ficam intactos.

> Tabela relacionada `scan_reports` (não é entidade de domínio própria, é o
> relatório markdown por tier): pertence à **execução**, não ao commit —
> `scan_job_id` é NOT NULL com FK para `scan_jobs.id` `ON DELETE CASCADE`, e a
> **UNIQUE** é `scan_reports_job_tier_key` em `(scan_job_id, tier)`. Era
> `(commit_sha, tier)`, e por isso rescanear a mesma branch fazia o upsert
> sobrescrever o relatório anterior. O upsert continua existindo, mas agora só
> cobre replay do canvas *dentro da mesma execução*. `commit_sha` segue na
> tabela como atalho de leitura (índice `idx_scan_reports_commit_sha`).

### `Repository` (`app/domain/github/entities.py`) — tabela `repositories`

| Campo | Tipo | Observação |
|---|---|---|
| `id` | `UUID` | `default_factory=uuid4`. |
| `user_id` | `UUID` | Dono do repositório conectado. |
| `github_account_id` | `UUID` | `GithubAccount` (instalação) à qual pertence. |
| `installation_id` | `int` | Instalação do GitHub App. |
| `github_repo_id` | `int` | ID do repositório no GitHub. |
| `full_name` | `str` | `org/repo`. |
| `url` | `str` | URL do repositório. |
| `default_branch` | `str` | Default `"main"`. |
| `active` | `bool` | Default `True`; controla se o repo está sob análise. |
| `target_url` | `str \| None` | URL onde a **aplicação** está publicada (staging/preview) — alvo do DAST no Tier 3. Não confundir com `url`, que é o endereço do repositório no GitHub. Default `None` (sem deploy conhecido). Ver "Alvo de DAST" abaixo. |
| `created_at` | `datetime` | `default_factory=datetime.utcnow`. |

**UNIQUE:** `repositories_user_repo_key` em `(user_id, github_repo_id)` — é a chave do upsert de `POST /repositories`. O `save()` usa `RETURNING`, então a rota devolve a linha realmente persistida (com o `id` original em caso de conflito), e não o `uuid4()` gerado em memória.

#### Alvo de DAST (`target_url`)

É a origem que faltava para o ZAP: `dispatch_pipeline` passava `target_url=None`
fixo, então o Tier 3 sempre pulava o DAST (`reason="no_target_url"`). Agora o
valor vem do repositório cadastrado, nos **dois** gatilhos — o manual lê
`Repository.target_url` direto; o webhook resolve o repositório pela instalação
(`_resolve_owner`, que devolve `(user_id, repository_id, target_url)`), porque o
payload do GitHub não sabe onde a aplicação está publicada. Daí em diante o valor
já corria: `dispatch_pipeline` → `build_pipeline_canvas` →
`_prepare_tier3_payload` → `run_tier3_scan` → `ZAPScanner.scan`. `None` continua
significando "sem deploy conhecido", e o ZAP segue pulado — comportamento
idêntico ao de antes para quem não preencher.

**Semântica no `PATCH`** (o schema era `active` obrigatório; virou parcial, sem
quebrar o cliente que envia `{"active": false}`): a rota decide por **presença da
chave** no JSON (`model_fields_set`), não por "veio `None`" — porque em
`target_url` o `null` é valor legítimo, não omissão.

| Corpo | Efeito |
|---|---|
| `{"active": false}` | Desativa. `target_url` intacta. |
| `{"target_url": "https://staging.acme.com"}` | Define o alvo. `active` intacto. |
| `{"target_url": null}` | **Limpa** o alvo (volta a pular o DAST). |
| `{}` | `422` `patch_sem_campos` — erro de cliente não vira no-op silencioso. |
| `{"active": null}` | `422` `active_nao_aceita_null`. |

No `POST` (upsert) a coluna usa `COALESCE`: omitir o campo **preserva** a URL já
gravada — senão um POST de reativação apagaria o alvo sem ninguém pedir. Limpar é
sempre operação explícita do `PATCH`.

**Validação anti-SSRF** (`app/domain/github/target_url.py`). O `target_url` não é
um link exibido: ele é entregue ao ZAP, que faz spider e **active scan** —
dispara payloads reais de SQLi/XSS/path traversal. Aceitar URL arbitrária
significaria (a) atacar terceiros com o IP da nossa infraestrutura no log da
vítima e (b) SSRF privilegiado, já que o worker de Tier 3 alcança a rede interna
que o usuário não alcança — inclusive `169.254.169.254`, o metadata de
AWS/GCP/Azure, que devolve credenciais IAM da instância e cujo conteúdo voltaria
ao usuário dentro dos findings.

Só passa http/https absoluta, sem credenciais embutidas, com host público. São
recusados: `localhost` e `127.0.0.0/8`, RFC1918 (`10/8`, `172.16/12`,
`192.168/16`), link-local `169.254.0.0/16` (metadata incluso), CGNAT
`100.64.0.0/10`, `0.0.0.0`, loopback/ULA IPv6 (`::1`, `fe80::/10`, `fc00::/7`),
IPv4 mapeado em IPv6, as formas decimal/hexadecimal do mesmo IP
(`http://2130706433`), os sufixos `.local`/`.internal`/`.localhost`/`.home.arpa`/`.lan`
e hosts de rótulo único (`http://zap`), que só existem dentro da rede do worker.

Erros saem como `422` com `type` estável por motivo — `target_url_malformada`,
`target_url_vazia`, `target_url_muito_longa`, `target_url_esquema_invalido`,
`target_url_com_credenciais`, `target_url_alvo_bloqueado`,
`target_url_host_sem_dominio` — e `msg` em português exibível ao usuário.

**Limite deliberado:** um domínio público cujo DNS aponta para dentro (rebinding)
passa. Resolver DNS no cadastro seria TOCTOU — o registro muda entre validar e
escanear — então a defesa desse vetor é de rede (egress policy no container do
ZAP), não de schema.

Não há `ForeignKey` para `github_accounts`: quando uma conta é desconectada (`DELETE /github/accounts/{id}`), a limpeza dos repositórios dela é explícita, feita na mesma transação.

### `GithubAccount` (`app/domain/github/entities.py`) — tabela `github_accounts`

| Campo | Tipo | Observação |
|---|---|---|
| `id` | `UUID` | `default_factory=uuid4`. |
| `user_id` | `UUID` | Usuário aperIA vinculado. |
| `installation_id` | `int` | ID da instalação do GitHub App. |
| `github_login` | `str` | Login da conta/organização no GitHub. |
| `account_type` | `str` | `"User"` ou `"Organization"`. |
| `created_at` | `datetime` | `default_factory=datetime.utcnow`. |

**UNIQUE:** `github_accounts_installation_key` em `installation_id`.

## 4. Serviços / containers

`docker-compose.base.yml` — stack obrigatória, 8 containers:

| Serviço | Container | Porta | Papel |
|---|---|---|---|
| `api` | `aperia-api` | `8000` | FastAPI (webhook, health, auth). |
| `worker_tier1` | `python-api-worker_tier1-1` | — | Celery fila `tier1`, concurrency 4. |
| `worker_tier2` | `python-api-worker_tier2-1` | — | Celery fila `tier2`, concurrency 2. |
| `worker_tier3` | `python-api-worker_tier3-1` | — | Celery fila `tier3`, concurrency 1. |
| `worker_analysis` | `python-api-worker_analysis-1` | — | Celery fila `analysis`, concurrency 2. |
| `worker_reporting` | `python-api-worker_reporting-1` | — | Celery fila `reporting`, concurrency 2. |
| `redis` | `aperia-redis` | — | Broker + result backend do Celery. Roda com `--appendonly yes` e volume `aperia_redis_data:/data` — a fila sobrevive a um `docker compose down`. |
| `db` | `aperia-db` | — | PostgreSQL 15 (`postgres`/`postgres`, banco `aperia`), volume `aperia_db_data`. |

Volumes nomeados: `aperia_db_data` (dados do Postgres) e `aperia_redis_data`
(AOF do Redis). Os dois existem pelo mesmo motivo: banco e broker precisam ter
durabilidade equivalente — ver
[explicacao-pipeline.md](explicacao-pipeline.md#7-jobs-travados-e-a-assimetria-de-durabilidade-entre-postgres-e-redis).

Camadas opcionais (compose files adicionais): `docker-compose.scanners.yml` (ZAP `:8090`, OpenCTI `:8081`, Caldera `:8888` — necessários para o Tier 3 produzir dados reais) e `docker-compose.observability.yml` (Prometheus `:9090`, Grafana `:3000`).

## 5. Plumbing do Claude

Componentes em `app/infrastructure/ai/`:

| Componente | Arquivo | Comportamento |
|---|---|---|
| `ClaudeClient` | `claude_client.py` | Expõe `call()` e `call_json()`, síncronos (workers Celery são sync). Fluxo: checa circuit breaker → roda LLM Guard no input → chama a API Anthropic. Bloco `system` marcado com `cache_control: ephemeral` se `CLAUDE_PROMPT_CACHE_ENABLED=True`. Modelos vêm de constantes (`models.py`), nunca string literal — `CLAUDE_MODEL_REASONING` (Sonnet, análise) e `CLAUDE_MODEL_FORMATTING` (Haiku, relatórios). |
| Circuit breaker | `circuit_breaker.py` | Abre após **3 falhas consecutivas**; janela de recuperação de **300s**. Singleton process-wide (`DEFAULT_BREAKER`). |
| LLM Guard | `llm_guard_client.py` | Regex-stub que bloqueia ~14-18 padrões de prompt injection (ex.: `ignore all previous instructions`, `${jndi:`, `eval(`) **antes** da chamada à API → levanta `GuardBlockedError`. Ligado/desligado por `LLM_GUARD_ENABLED`. |
| Métricas | `token_metrics.py` | Counters Prometheus: `claude_tokens_total{model,type}`, `claude_cost_usd_total{model}`, `claude_requests_total{model,outcome}` (`outcome` ∈ `success`/`circuit_open`/`blocked_by_guard`/`error`). |

**Modo degradado:** se o Claude falhar (circuit aberto, guard bloqueou, erro de API), `tier2_analyze`/`tier3_deep_analysis` retornam `{"degraded": True, "reason": ..., "findings": [...]}` e o pipeline continua; o worker de reporting cai para markdown de fallback com a lista crua de findings.

> **`/metrics` não está exposto.** Os counters acima existem em código, mas nenhum endpoint ASGI (`prometheus_client.make_asgi_app()`) foi registrado em `app/main.py` — os dashboards Grafana não recebem dados até isso ser corrigido.
