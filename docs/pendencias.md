# Pendências e próximos passos

Estado em **2026-08-01**. Cobre os dois repositórios (`python-api` e
`front-aperIA`) porque as pendências atravessam os dois.

Ordenado por **o que destrava mais coisa**, não por esforço. Cada item traz a
evidência que o sustenta — sem isso, "pendência" vira lista de desejos.

---

## 0. Carga da máquina — RESOLVIDO (2026-08-01)

O WSL2 travou duas vezes por consumo de recursos, e isso **contaminava o
diagnóstico**: a queda de DNS do §1 é sintoma dessa carga, não defeito do
Docker.

**O que foi feito.**

1. **Perfis do Compose.** ZAP, Caldera, OpenCTI e Juice Shop passaram a ficar
   atrás de `profiles:` e **não sobem mais por padrão**. Um `up -d` levanta só a
   base (8 serviços).

   O comando é sempre o mesmo conjunto de arquivos, rodando de dentro de
   `python-api/`; o que varia é o perfil acrescentado antes de `up -d`:

   ```bash
   docker compose -f docker-compose.base.yml \
                  -f docker-compose.scanners.yml \
                  -f docker-compose.targets.yml \
                  [--profile <perfil>] up -d
   ```

   | Perfil | Sobe |
   |---|---|
   | (nenhum) | base: api, db, redis, 5 workers |
   | `--profile dast` | + `zap` e `juice-shop` |
   | `--profile emulation` | + `caldera` e `caldera-agent` |
   | `--profile cti` | + `opencti` (não sobe — §3) |

   Detalhes e atalho opcional em
   [howto/subir-a-stack.md](howto/subir-a-stack.md).

2. **Tetos de memória** nos containers pesados: ZAP e OpenCTI 2 GB, Caldera e
   Juice Shop 1 GB. Prefira o scan falhar a máquina travar.

3. **OpenCTI com `restart: "no"`.** Ele nunca sobe (falta search engine, §3) e
   com restart automático virava crash-loop queimando CPU continuamente — custo
   real, benefício zero.

**Efeito colateral bem-vindo:** perfis eliminam também a armadilha de rede do
§1. Como o conjunto de arquivos deixa de variar, `aperia_net` não é mais
recriada por invocações inconsistentes.

**O que ainda depende de você (fora do repositório):** limitar os recursos que o
próprio WSL2 pode consumir, no `.wslconfig` do Windows
(`%UserProfile%\.wslconfig`):

```ini
[wsl2]
memory=8GB
processors=4
```

Sem esse teto, o WSL cresce até competir com o Windows — nenhum ajuste no
Compose protege contra isso.

---

## 1–2. Tier 3 de ponta a ponta — RESOLVIDO (2026-08-02)

O pipeline completou: **tier1 done → tier2 done → tier3 done**, risco 72/100
`high`, com o ZAP produzindo **369 alertas em 190 s** dentro do limite de
memória.

O DNS instável do §1 não voltou a acontecer. Ele era sintoma de exaustão de
recursos, e três mudanças tiraram a pressão: perfis do Compose (§0), heap da
JVM do ZAP corrigido, e a regra de DOM XSS desligada (que subia Firefox
headless real dentro do mesmo cgroup).

A armadilha de rede que o §1 também descrevia — invocar `docker compose` com
conjuntos diferentes de arquivos, deixando containers presos numa rede antiga —
continua valendo como **regra operacional**: use sempre o mesmo conjunto de
arquivos, variando só o `--profile`. Ela se manifestou uma última vez como
`network <id> not found`, resolvida removendo os containers obsoletos.

### O que o ZAP funcionando revelou

Três defeitos que estavam escondidos atrás do ZAP sempre devolver zero:

1. **Prompt estourando a janela de contexto** — `357.218 tokens > 200.000`. Os
   369 alertas iam inteiros para o prompt do relatório, cada um com o
   `raw_output` bruto. Corrigido: teto de 40 findings ordenados por severidade,
   `raw_output` descartado, descrição truncada, e um `findings_resumo` que
   declara o que ficou de fora (2.245.860 → 20.404 caracteres).
2. **Emojis nos relatórios** — removidos dos templates, proibidos no prompt, e
   removidos de forma determinística no `ClaudeClient`, porque instrução em
   prompt é pedido e não contrato.
3. **Healthcheck do ZAP mentindo** — apontava para a porta 8080 enquanto o
   daemon serve na 8090; o container vivia `unhealthy` funcionando normalmente.

---

## 3. OpenCTI não sobe: falta dependência na stack

```
[CHECK] checking if Search engine is alive → "Search engine seems down"
CONFIGURATION_ERROR: Search engine seems down
```

O OpenCTI 6.x exige um search engine (OpenSearch/Elasticsearch), e o
`docker-compose.scanners.yml` define apenas `zap`, `opencti` e `caldera`.
**Não existe search engine em lugar nenhum da stack** — não é regressão, é
incompletude estrutural. Ele nunca subiu.

Consequência: `cti_status=unavailable` em todo scan de Tier 3.

**Próximos passos.** Decidir entre:
- **(a)** completar a stack (OpenSearch + Redis + RabbitMQ + MinIO). É pesado, e
  §0 recomenda cautela nesta máquina;
- **(b)** deixar o CTI declaradamente fora do escopo e remover o serviço do
  compose, para parar de sugerir que existe;
- **(c)** substituir por uma fonte de CTI mais leve (consulta a API pública de
  CVE, por exemplo).

Enquanto não se decide, o container está parado.

---

## 4. Caldera — validado em execução, com duas ressalvas

Quatro bloqueios resolvidos: crash no boot (assets do `magma`), chave de API
aleatória por imagem, nomes de campo errados no cliente
(**`adversary_id` no adversário, `id` na operação** — ler `id` no adversário
levantava `KeyError` logo após um POST 200, e o `run_safe` traduzia para
"Caldera unavailable"), e a ausência de técnicas.

Sobre as técnicas: elas vinham **só do enriquecimento CTI**, que depende do
OpenCTI (§3) e de haver CVE nos findings. Secrets e regras do Semgrep não têm
CVE, então a lista era sempre vazia. Agora a fonte primária é o `event_chain`
do Tier 2 — que já mapeia MITRE ATT&CK e é literalmente a correlação que o
produto promete.

Provado em execução: `caldera_status=ok`, agente registrado
(`grupo=red platform=linux`), e uma operação com 44 elos executados.

**Ressalva 1 — cobertura do catálogo.** Numa execução as 6 técnicas do Tier 2
mapearam para **zero** abilities (`descartadas=0`, ou seja, nem chegaram ao
filtro): simplesmente não existem no catálogo de 162. Noutra, as 6 abilities
encontradas eram todas de exfiltração para Dropbox/GitHub/S3, que exigem
credencial externa e não rodam no sandbox `internal: true` — corretamente
descartadas agora, com o motivo no log.

Como a análise do Tier 2 não é determinística, **a emulação varia entre scans
do mesmo commit**. Vale calibrar expectativa: `caldera_validated: true` é
possível, não garantido.

**Ressalva 2 — agentes acumulando.** Há **20 agentes** registrados, todos
`trusted`. Cada reinício do container cria um novo, por causa do
`restart: unless-stopped`. Não quebra nada, mas infla as operações (3 abilities
viraram 44 elos) e piora com o tempo. Vale o agente reusar identidade entre
reinícios, ou uma limpeza periódica.

---

## 5. Telas ainda em dados de demonstração

| Tela | Fonte hoje | Caminho |
|---|---|---|
| Remediações | mock | **não existe rota na API** |
| AI Emulation | mock | sai do `analysis_json` do relatório de Tier 3 |
| Time | mock | **não existe rota na API** |
| Scanners (em Repositórios) | mock | não há estado por scanner na API |

Todas carregam `<DemoDataBadge />` quando a conexão é real — o badge sai quando
a tela passar a ler a API.

**Ordem sugerida.** AI Emulation primeiro: é a única com fonte disponível hoje,
e o `analysis_json` do Tier 3 ficou mais rico agora que a narrativa do Claude
volta a ser gerada.

---

## 6. Findings repetidos afogam a lista

O scan do Juice Shop produziu **57 findings**, dos quais ~49 são o **mesmo
detector** (`Chatbot`) repetido em arquivos de tradução. O `dedup_key` inclui o
caminho, então cada arquivo vira uma linha — correto para o banco, ruim para
leitura.

**E o ZAP expôs o problema oposto, mais grave.** Os **369 alertas** dele viraram
**8 findings**: o `dedup_key` colapsou centenas de ocorrências por URL. Os 8
tipos estão corretos (CSP ausente, Cross-Domain Misconfiguration…), mas
`file_path` ficou **vazio em todos** — o ZAP reporta URL, não arquivo, e essa
dimensão se perdeu. Você sabe *que* falta CSP, não *em quais rotas*.

O mesmo mecanismo, portanto, afoga a lista com findings idênticos do TruffleHog
e joga fora o dado mais útil do ZAP.

**Próximo passo.** Duas frentes: na UI, agrupar por `secret_type` + valor com
contagem e expansão; no mapeamento do ZAP, preservar a URL (em `file_path` ou
campo próprio) para o dedup não colapsar rotas distintas.

---

## 7. Dívidas conhecidas (não bloqueiam nada hoje)

**API**

- `app/main.py` usa `@app.on_event("startup")`, deprecado no FastAPI. Migrar
  para `lifespan` — foi mantido para não misturar refactor com correção.
- **Webhook não tem a checagem de concorrência** que o disparo manual tem: dois
  eventos de PR para o mesmo commit disparam dois pipelines. Com o reset de
  timestamps, o segundo sobrescreve o estado do primeiro.
- **`repo_url` diverge conforme o gatilho**: webhook grava `clone_url`
  (`…/repo.git`), scan manual grava `html_url`. O mesmo repositório fica com
  URLs diferentes em `ScanJob`/`Finding`. Corrigir exige migration.
- ~~`GithubAccountRepository.save()` faz `self.db.rollback()` no fallback~~ —
  **corrigido (2026-08-01)**. O rollback derrubava a transação inteira do
  caller: o callback do GitHub escreve mais coisas depois do `save`, e um
  conflito de `installation_id` descartava tudo em silêncio. Agora usa
  `begin_nested()` (SAVEPOINT) + UPDATE da linha existente, mesmo padrão do
  repositório de `Repository`. Tem teste de regressão.
- **Sem `ForeignKey`** entre `github_accounts`/`repositories` e entre
  `repositories` e `scan_jobs`/`findings`. A limpeza é aplicativa; um delete
  direto no banco deixa órfãos.
- Docstring da rota `POST /repositories/{id}/scan` descreve só o 409 antigo.

**Front-end**

- `src/components/dash/NotPortedYet.tsx` não é referenciado por nada.
- Dois pedaços do protótipo continuam só em `legacy/dash/index.html`: os três
  gráficos com cross-filter acima da tabela de Findings, e o slide-over de
  finding (substituído pelo deep link `findingRoute()`).
- `?status=` é parseado e serializado para não quebrar links antigos, mas
  ignorado com dados reais — a API não modela resolução de finding.

---

## 7.1 Descoberto ao corrigir: flag local desligava teste de segurança

`settings` lê o `.env` do desenvolvedor, e `ALLOW_INTERNAL_DAST_TARGETS=true`
(necessário para o Juice Shop local) fazia **13 testes de recusa de alvo
interno** — loopback, RFC1918, metadata de cloud — falharem na minha máquina.

O risco real é o cenário invertido: um teste que *afirma bloqueio* rodando com
o bloqueio desligado passa a não testar nada, e ninguém percebe.

**Corrigido:** `tests/conftest.py` agora força
`ALLOW_INTERNAL_DAST_TARGETS = False` por fixture autouse. A suíte sempre
exercita a postura de produção; quem testa a liberação passa
`permitir_alvo_interno=True` explicitamente.

**Vale como regra geral:** nenhuma flag de ambiente local deveria decidir se um
teste de segurança roda. Se houver outras flags nessa situação, mesmo
tratamento.

---

## 8. Segurança: dois pontos que exigem decisão consciente

**`ALLOW_INTERNAL_DAST_TARGETS=true` está ligado no `.env` de desenvolvimento.**
Ela libera alvo de DAST em rede interna — inclusive `169.254.169.254`, o
endpoint de metadata de cloud. Existe porque sem ela **não há caminho suportado
para testar DAST em dev** (um Juice Shop local é `http://juice-shop:3000`,
exatamente o que a proteção recusa). O default no código é `False`.
**Nunca ligar em produção.**

**Validação de alvo não verifica propriedade.** A proteção bloqueia alvos
internos, mas não tem como saber se um alvo *externo* pertence a quem cadastrou.
Apontar para host de terceiro faz o aperIA disparar tráfego de ataque contra
infraestrutura alheia. Hoje isso é responsabilidade de quem cadastra; se o
produto for multi-usuário de verdade, vai precisar de prova de propriedade
(arquivo em `/.well-known`, registro DNS, ou similar).

**Limite documentado do bloqueio de SSRF:** DNS rebinding não é pego — resolver
DNS no cadastro é TOCTOU. A defesa é egress policy no container do ZAP.

---

## 9. Credenciais de desenvolvimento no repositório

Seguem o mesmo padrão do `ZAP_API_KEY=changeme` que já existia: valor que
funciona de imediato, documentado como "trocar em produção".

| Onde | Valor | Trocar em produção |
|---|---|---|
| `caldera/local.yml` | `api_key_red: aperia-dev-caldera-red` | sim, e junto o `CALDERA_API_KEY` |
| `caldera/local.yml` | `crypt_salt`, `encryption_key` | sim |
| `.env.example` | `ZAP_API_KEY=changeme` | sim |

A chave privada do GitHub App **não** está nessa lista: ela saiu da imagem nesta
sessão e entra por bind mount (`secrets/`, gitignorado) — ver `secrets/README.md`.
