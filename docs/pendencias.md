# Pendências e próximos passos

Estado em **2026-08-02**. Cobre os dois repositórios (`python-api` e
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

## 3. CTI: OpenCTI não sobe — RESOLVIDO via CISA KEV + EPSS (2026-08-02)

O diagnóstico original continua válido e vale registrar:

```
[CHECK] checking if Search engine is alive → "Search engine seems down"
CONFIGURATION_ERROR: Search engine seems down
```

O OpenCTI 6.x exige um search engine (OpenSearch/Elasticsearch) mais Redis,
RabbitMQ e MinIO — vários GB de infraestrutura. O `docker-compose.scanners.yml`
define apenas `zap`, `opencti` e `caldera`; **não existe search engine em lugar
nenhum da stack** — não é regressão, é incompletude estrutural. Nesta máquina
(WSL com ~8 GB, já saturado pela stack de scanners) ele nunca subiu, e o
resultado era `cti_status=unavailable` em todo scan de Tier 3.

**A opção (c) foi implementada: uma fonte de CTI leve, sem infraestrutura.** No
lugar do OpenCTI, o Tier 3 agora consulta duas fontes públicas:

- **CISA KEV** (Known Exploited Vulnerabilities): um catálogo JSON (~1656 CVEs)
  baixado de `known_exploited_vulnerabilities.json` e cacheado em memória. Diz se
  um CVE está **comprovadamente sendo explorado no mundo real** — o sinal de
  "ameaça ativa" mais honesto que existe — e traz `knownRansomwareCampaignUse`
  (Known/Unknown), o sinal de campanha ativa. É um arquivo: zero memória local.
- **EPSS** (FIRST.org): API REST grátis e sem chave
  (`https://api.first.org/data/v1/epss?cve=…`) que dá a **probabilidade (0–1) de
  exploração nos próximos 30 dias** por CVE. É uma chamada HTTP: zero memória
  local.

Juntas entregam exatamente o que o pipeline consome de CTI — "é ameaça ativa?" e
"qual a probabilidade de exploração?" — sem ElasticSearch/RabbitMQ/MinIO.

**Implementação.** Novo cliente `app/infrastructure/intelligence/threat_intel_client.py`
(`ThreatIntelClient`), com a **mesma interface** do OpenCTI (`enrich_cve(cve_id)
-> dict | None`) e fault-isolated: falha → `None` → `cti_status: unavailable`, o
pipeline degrada como antes. O `OpenCTIClient` foi **deixado no repo mas não é
mais instanciado** — fica reservado para o passo 2.

**Correção de bug de brinde.** O contrato de retorno do `enrich_cve` agora inclui
`active_campaigns` (= uso em campanha de ransomware). O `RiskScorer._cti_component`
sempre testou `active_campaigns`, campo que o **OpenCTI nunca setava** — então o
componente de CTI do score (peso 25%) caía sempre no ramo fixo de 25, de pé o
OpenCTI ou não. Ver [explicacao-pipeline.md §3](explicacao-pipeline.md#3-gates-determinísticos-vs-score-do-claude).

**Ressalva honesta.** Num scan web (Juice Shop) quase nenhum finding tem CVE —
secrets e regras de Semgrep não têm — então o enriquecimento por CVE dispara
pouco; mas quando há CVE, o sinal agora é real. E `mitre_techniques` fica `[]`:
KEV/EPSS não fornecem técnicas MITRE por CVE. O Caldera não depende disso (usa o
`event_chain` do Tier 2, ver §4).

**Passo 2 (opcional, não bloqueia nada).** Uma fonte rica — OTX ou o próprio
OpenCTI — para máquinas com infraestrutura, que traria as técnicas MITRE por CVE
que o KEV/EPSS não têm. É por isso que o `OpenCTIClient` continua no repo.

---

## 4. Caldera — encanamento resolvido; cobertura do catálogo é decisão de produto

Quatro bloqueios de infraestrutura foram resolvidos: crash no boot (assets do
`magma`), chave de API aleatória por imagem, nomes de campo errados no cliente
(**`adversary_id` no adversário, `id` na operação** — ler `id` no adversário
levantava `KeyError` logo após um POST 200, e o `run_safe` traduzia para
"Caldera unavailable"), e a ausência de técnicas (elas vinham só do
enriquecimento CTI, que depende do OpenCTI (§3) e de haver CVE nos findings;
agora a fonte primária é o `event_chain` do Tier 2).

**Ressalva 2 (acúmulo de agentes) — resolvida, mas o diagnóstico estava
incompleto.** O `-paw` fixo (`CALDERA_AGENT_PAW`, default `aperia-sandbox`) dá
identidade estável entre reinícios, e isso resolve o caso do container
reiniciando. **Não era a única fonte.**

Em 2026-08-02, exercitando o fallback recém-implementado, os 20 agentes
voltaram em 10 minutos — com o container do agente intocado. A causa real: a
ability **"Start 54ndc47"** (`T1059.004`), cujo comando é
`nohup ./sandcat.go -server ... &`, ou seja, **inicia outro agente do Caldera**.
Como uma operação executa cada ability em *todos* os agentes do grupo, cada
execução criava um agente que entrava no grupo e recebia a mesma ability. 43
elos, operação nunca finaliza, timeout de 600s.

Ela estava latente desde sempre no catálogo — nada mapeava para `T1059` até o
fallback de pai passar a mapear.

**Corrigido:** `_implanta_agente` descarta abilities cujo comando ou payload
referencia o binário do agente (`sandcat` / `54ndc47`), e roda **antes** do
filtro de credencial porque é este que causa laço. São **5 de 70** abilities
linux do catálogo, todas de implantação — inclusive `Weak executable files`,
que parece inofensiva e injeta um lançador do sandcat em todo executável
gravável que encontra.

Efeito colateral desejável: `T1059.007` passou a ficar **sem cobertura** em vez
de "coberta" por algo que não deveria rodar.

**Ressalva 1 (cobertura do catálogo) — CONTINUA, agora medida.** No último scan
o pipeline foi de ponta a ponta (`tier3 done`, risco 62/high) e a emulação
executou **zero** técnicas: `techniques_executed: 0`, `success_rate: 0.0`,
`caldera_validated: false`, `ttps_used: []`.

A causa **não** é cadeia vazia — o Tier 2 produziu 7 elos. Reproduzindo o
mapeamento contra o Caldera no ar, com as técnicas daquele scan:

```
tecnicas do Tier 2: T1036, T1059.007, T1185, T1550.001,
                    T1552.001, T1553.001, T1598.003
abilities mapeadas: 0   (catalogo=162, descartadas=0)
```

`descartadas=0` é o dado importante: elas nem chegaram ao filtro de sandbox —
não existem no catálogo. **A divergência é no nível de sub-técnica**, e isso é
novo: o catálogo *tem* as famílias pedidas, em outras variantes.

| Pedido pelo Tier 2 | O que o catálogo tem |
|---|---|
| `T1059.007` (JavaScript) | `T1059.001`, `T1059.002`, `T1059.004` |
| `T1552.001` (Credentials In Files) | `T1552.002`, `T1552.003`, `T1552.004` |
| `T1036`, `T1185`, `T1550.001`, `T1553.001`, `T1598.003` | nada da família |

Três fatos estruturais por trás disso:

1. **O catálogo padrão (Stockpile, 162 abilities, 58 técnicas-pai) é de
   pós-exploração de host/AD**, e o alvo aqui é uma aplicação web. `T1185`
   (Browser Session Hijacking) e `T1598.003` (Phishing for Information) não são
   executáveis como ability em agente nenhum — não é lacuna de catálogo, é
   incompatibilidade de categoria.
2. **O catálogo é dominado por Windows**: 167 executores windows contra 71
   linux, e o sandbox é linux.
3. **O Tier 3 rededuz a cadeia usando técnicas-pai** (`T1190`, `T1552`, `T1036`,
   `T1083`, `T1567`, `T1059`) — que teriam abilities. Mas a emulação roda
   **antes** da análise profunda, sobre a cadeia do Tier 2, que é de
   sub-técnicas.

Medido: truncar a mesma lista para técnica-pai leva de **0 para 3 abilities**.

**O relatório não mente sobre isso**, e isso é bom: cada elo sai marcado
`validado por Caldera: não`, e o rodapé diz `Caldera: available (0/0 técnicas
executadas com sucesso — validação não completada)`. O que confunde é o campo
`status: "ok"`/`caldera_status=ok`, que significa **"o Caldera respondeu"**, não
"emulou" — vale renomear, porque lido de fora parece sucesso.

**Passos 1–3 implementados em 2026-08-02.**

1. ✅ **`status: "ok"` → `"reachable"`.** O campo responde "o Caldera
   respondeu?", não "a emulação validou?" — e `0/0 técnicas executadas` com
   `status: ok` lia-se como sucesso. Quem valida é `caldera_validated`.
2. ✅ **Fallback para a técnica-pai, rotulado.** `_map_to_abilities` faz duas
   passadas: casamento exato e, só para o que sobrou descoberto, a técnica-pai.
   Medido contra o Caldera no ar com as 7 técnicas do scan real: **0 → 3
   abilities** (`T1059.004`, `T1552.003`, `T1552.004`).

   O resultado da segunda passada **não vale como validação**: `_parse_results`
   separa os elos bem-sucedidos e só os de técnica casada exatamente ligam
   `caldera_validated`.

   **Verificado em execução real** contra o Caldera no ar, com as 7 técnicas do
   scan, depois do filtro de implantação:

   ```
   status                : reachable
   techniques_executed   : 2      techniques_successful : 2
   success_rate          : 1.0
   caldera_validated     : False   <- 100% de sucesso e mesmo assim falso
   validacao_parcial     : True
   tecnicas_por_pai      : ['T1552.001']
   tecnicas_sem_cobertura: ['T1036','T1059.007','T1185','T1550.001',
                            'T1553.001','T1598.003']
   ttps_used             : ['T1552.003','T1552.004']
   ```

   É exatamente a leitura que se queria: *"rodei tudo que consegui, e nada disso
   era o seu problema"*.
3. ✅ **`technique_parent` no schema do Tier 2 + extração por regex.** O ganho
   real aqui **não foi cobertura** — truncar `T1059.007` → `T1059` é string, e o
   passo 2 já faz. O ganho foi robustez: `technique` vem de um LLM e era usado
   verbatim, então `"T1059 - Command and Scripting"` não casava com nada e a
   emulação rodava zero técnicas **sem erro algum**. Agora o ID sai por
   `\bT\d{4}(?:\.\d{3})?\b` e `technique_parent` serve de resgate quando
   `technique` vem vazia ou ilegível.

   O pai **não** é somado à lista de técnicas pedidas: pedi-lo explicitamente
   faria o casamento parecer exato e apagaria a distinção do passo 2.

**Passo 4 continua aberto — e é o que realmente importa.** Depois dos três
acima, das 7 técnicas do scan real **6 seguem sem qualquer cobertura**
(`T1036`, `T1059.007`, `T1185`, `T1550.001`, `T1553.001`, `T1598.003`) e apenas
`T1552.001` rende validação parcial. Nenhum encanamento resolve isso: um catálogo de
pós-exploração de host valida mal achados de aplicação web. Ou entram abilities
próprias (web/API), ou a emulação passa a ser declaradamente aplicável só a
parte dos achados. **É decisão de produto.**

Como a análise do Tier 2 não é determinística, a lista de técnicas varia entre
scans do mesmo commit — então `caldera_validated: true` seguirá possível e não
garantido, mesmo depois de (2) e (3).

### Validação por evidência — 1a etapa do reenquadramento (2026-08-02)

A resposta ao passo 4 tem duas frentes: **A (reenquadrar)** — usar os sinais de
validação que a cadeia já coleta — e **B (abilities web no Caldera)**. A frente
A começou.

O Caldera valida por emulação de host; para alvo web isso quase nunca casa. Mas
TruffleHog e ZAP **já confirmam achados contra o alvo**, e esse sinal era
ignorado — o relatório dizia "validado: não" para findings que a própria
ferramenta havia confirmado. Agora ele é explícito e **determinístico**
(`app/domain/finding/validation.py`), computado da evidência do scanner, não
pedido ao modelo:

| Método | Evidência | Confirma? |
|---|---|---|
| `secret_vivo` | TruffleHog verificou a credencial contra o provedor | sim |
| `zap_ativo` | active scan enviou payload e o alvo respondeu vulnerável (`raw_output.attack`) | sim |
| `zap_observado` | ZAP passivo de alta confiança observou a condição na resposta | sim (observação) |
| `nao_validado` | Semgrep estático, segredo não verificado, ZAP de baixa confiança | não — é candidato |

O Tier 3 anexa um resumo determinístico ao relatório, ao lado da validação do
Caldera (dois eixos: emulação de adversário × evidência da ferramenta). Medido
no scan real do Juice Shop: **2.998 findings confirmados contra o alvo** (2 por
active scan, 2.996 por observação), onde o Caldera sozinho validava **0**. Os
9.054 restantes ficam honestamente como "sinalizado, não confirmado".

**Ainda aberto:** a frente B — abilities do Caldera que agem sobre o `target_url`
por HTTP (forjar JWT com segredo vazado e chamar endpoint autenticado; testar
credencial no login; refletir payload de XSS). É o que valida a **cadeia**, não
findings isolados, e o que dá substância a "adversary emulation" para web. Exige
escopar o egress do sandbox só ao alvo de DAST já validado — o guardrail de
`target_url` (rejeita interno/localhost/metadata) é a base disso. É a decisão de
produto: o Caldera é o motor de emulação para web, ou a validação web é papel do
ZAP + verificação de segredo e o Caldera fica para host/infra?

---

## 5. Telas ainda em dados de demonstração

| Tela | Fonte hoje | Caminho |
|---|---|---|
| AI Emulation | mock | sai do `analysis_json` do relatório de Tier 3 |
| Time | mock | **não existe rota na API** |
| Scanners (em Repositórios) | mock | `GET /scans/{id}/tools` já existe (§6.2) — falta a tela ler |

Todas carregam `<DemoDataBadge />` quando a conexão é real — o badge sai quando
a tela passar a ler a API.

**Ordem sugerida.** AI Emulation primeiro: é a única com fonte disponível hoje,
e o `analysis_json` do Tier 3 ficou mais rico agora que a narrativa do Claude
volta a ser gerada.

### Remediações — RESOLVIDO (2026-09-30)

A pendência dizia "mock · não existe rota na API". O diagnóstico era pior: a
fatia vertical inteira existia no back-end — entidade, tabela, migration,
repositório, prompt, `SuggestPatchUseCase` — **e nada a chamava**. A tabela
`remediations` nunca recebeu uma linha, então uma rota de leitura sobre ela
teria devolvido lista vazia para sempre.

O que entrou:

- `remediation_worker.suggest_remediations` no canvas, entre
  `post_tier2_report` e `tier3_gate`, devolvendo `analysis` intacta. Só
  findings de tier 1 e 2 com `file_path`+`line_number`, mais graves primeiro,
  teto em `REMEDIATION_MAX_PER_SCAN` (10). **DAST fica de fora**: o ZAP
  reporta o mesmo alerta uma vez por rota e nenhum deles tem linha de código
  onde ancorar um patch.
- A fatia virou síncrona. Era o último `AsyncSession` do `app/`, sem engine
  async para sustentá-lo desde que ele foi removido.
- `SuggestPatchUseCase` passou a aceitar `pr_number=None`: scan manual
  persiste a remediação com `github_comment_id=None` em vez de não gerar nada.
- `GET /remediations` e `PATCH /remediations/{id}/status`. Posse pelo join com
  `scan_jobs` (a tabela não tem `user_id`); 404 para remediação de outro dono,
  409 para decisão já tomada.

**A armadilha que custou um teste dedicado.** `remediations.finding_id` é FK
para `findings.id`, e o id que trafega no canvas é o `uuid4` que a dataclass
gerou em memória. Num re-scan do mesmo commit esse id nunca chega ao banco: o
`ON CONFLICT DO NOTHING` de `bulk_save` descarta o insert e a linha existente
mantém o id antigo. O worker resolve o id pela `dedup_key`
(`remediation_worker._id_persistido`) — sem isso, todo re-scan violaria a FK.

Fora de escopo, de propósito: `ia-remediacao` no `tool_catalog` (o id é
contrato com o front e os gates passariam a marcá-lo `skipped`); o status
`merged`, que depende de webhook de PR review; e a contagem de remediações por
scan no card de Scans, que custaria uma requisição por card.

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

**Corrigido o mapeamento (2026-08-02), a escala inverteu.** Preservando a rota em
`file_path`, um scan do Juice Shop passou a gravar **8.474 findings** — três
ordens de grandeza acima das outras fontes (50 do TruffleHog, 7 do Semgrep). Duas
consequências já sentidas:

1. Estourou o `bulk_save`: 8474 × 19 colunas = 161k parâmetros num INSERT único,
   contra o teto de 65535 do Postgres. O Tier 3 era marcado como `failed` por
   causa da **escrita**, com o scan já concluído — e como
   `persistir_ou_falhar` roda antes do Caldera, a emulação e o relatório do Tier
   3 nem chegavam a acontecer. Resolvido fatiando o insert por lote.
2. O front busca no máximo 1000 findings e já exibe o aviso de lista truncada
   permanentemente. O ZAP afoga TruffleHog e Semgrep na ordenação.

Ou seja: a agregação deixou de ser cosmética e virou pré-requisito para a tela
de Findings ser utilizável com DAST ligado.

**Resolvido em 2026-08-02.** `GET /findings/groups` agrega por
`source`+`severity`+`tier`+`title`+`asset` e devolve ocorrências, caminhos
distintos, intervalo de datas e uma amostra de caminhos. Os 12.047 findings do
banco viram **14 grupos** — a truncagem em 1000 deixa de existir na visão
agrupada, que passou a ser o padrão da tela. A visão plana continua disponível,
e o drill-down de um grupo usa `GET /findings?title=<exato>`, que restringe no
servidor em vez de depender do corte do cliente.

Duas notas de implementação que custaram tempo e valem lembrar:

- A agregação são **duas** consultas, não uma. Uma só exigiria `array_agg` para
  a amostra, que é exclusivo do Postgres — e os testes rodam em SQLite.
  `count(...) FILTER (...)` e `row_number()` existem nos dois.
- A primeira versão pegava o id representativo com `min(uuid)`. Isso **funciona
  no SQLite** (uuid é texto lá) e **não existe no Postgres**: teria passado
  verde no teste e quebrado em produção. O id passou a sair da própria consulta
  de amostra. Vale como lembrete geral — a suíte não cobre diferença de dialeto.

O mesmo mecanismo, portanto, afoga a lista com findings idênticos do TruffleHog
e joga fora o dado mais útil do ZAP.

**Próximo passo.** Duas frentes: na UI, agrupar por `secret_type` + valor com
contagem e expansão; no mapeamento do ZAP, preservar a URL (em `file_path` ou
campo próprio) para o dedup não colapsar rotas distintas.

---

## 6.2 Status por ferramenta — FEITO (2026-08-17)

`scan_tool_runs` (migration `a7b8c9d0e1f2`) + `GET /scans/{id}/tools`.

**O problema.** `ScanJob` só tinha `tier{1,2,3}_status`, então o dashboard sabia
dizer "o Tier 2 concluiu" e nunca "o Trivy concluiu e o Prowler não rodou". Pior
que a granularidade: `BaseScanner.run_safe` engole a exceção e devolve `[]`, de
modo que **"rodou e não achou nada" e "quebrou" chegavam ao banco como o mesmo
valor**. A diferença existia só na linha do structlog — e os motivos de pulo que
o pipeline já decide (`no_iac_files` do Prowler, `no_target_url` do ZAP) também.

**Onde o registro acontece, e por quê.** Nos scanners, dentro do próprio
`run_safe` (`base_scanner.py`): é o único ponto onde a exceção ainda existe.
Depois do `return []` a informação já foi perdida, então nenhum call site
conseguiria gravá-la. Os call sites passam apenas `tool_id` e `tier`, porque o
Semgrep roda em dois tiers com escopos diferentes e precisa ser duas ferramentas
(`semgrep-changed`, `semgrep-full`). Threat intel, Caldera e os dois passos de
I.A não passam por `run_safe` e são registrados no worker, a partir do desfecho
que ele já calcula.

**Os gates marcam as ferramentas dos tiers que barraram** (`skipped` +
`gate1_secret_verificado` / `gate2_abaixo_do_limiar`). Sem isso um tier pulado
não teria linha nenhuma, e "o gate decidiu que não precisava" ficaria
indistinguível de "ainda não chegou aqui" — a mesma ambiguidade que
`mark_tier_skipped` já existe para evitar no nível do tier.

**Chave `(scan_job_id, tool)`, nunca `commit_sha`.** Rescanear a mesma branch
empilha execução; chavear pelo sha faria o upsert apagar o resultado anterior —
o erro que `scan_reports` já corrigiu.

**`status` inclui `degraded`**, que não existe no nível do tier: quando o Claude
falha, o passo de I.A cai para a heurística e o tier fecha como `done` mesmo
assim. Sem esse valor, "a I.A analisou" e "a I.A caiu e seguimos com o plano B"
seriam a mesma coisa.

**Nada foi backfillado.** Execuções anteriores à migration respondem com
`tools: []`, e o cliente cai para o status do tier — por isso `expected` (o
catálogo por tier) vem preenchido mesmo com a lista vazia.

**A mesma rota devolve `ia`: o resumo da camada de I.A do Tier 3** (2026-08-18),
derivado do `analysis_json` do relatório daquele tier — attack path (fase, TTP
MITRE, descrição, se o Caldera validou), `kill_chain_complete`, risco ajustado,
CTI (KEV/EPSS/TTPs) e emulação. `null` quando não existe relatório de tier 3.

É um **resumo**, e isso é obrigatório, não estilo: o `analysis_json` carrega o
array `findings` inteiro com o `raw_output` de cada um (centenas de KB), e a
lista de Scans do dashboard chama esta rota uma vez por card (até 12). Ficaram
fora `findings`, `validacao_evidencia` e `prioritized_actions`; de cada passo do
attack path sai `finding_count` em vez de `finding_ids`, que é uma lista de
strings longas legíveis por humano. Uma resposta típica fica em ~1 KB.

Veio junto de `tools` em vez de virar rota nova porque responde à mesma pergunta
("o que aconteceu nesta execução?") e a tela já faz essa chamada — separar seria
um segundo round-trip por card.

**O blob é JSON produzido por LLM, então nada nele é confiável.** O parse
(`ScanIaSummary.from_analysis`) é best-effort campo a campo, com `isinstance`:
chave ausente, `null`, string onde se espera lista, item que não é objeto — tudo
degrada para o default e nunca vira 500. O caso degradado é real e existe no
banco: quando o Claude falha, o worker grava só `reason`/`cti_data`/`degraded`/
`findings`, sem `attack_path` nem `risk_score_adjusted`. Blocos ausentes saem
`null` em vez de zerados, para que "não rodou" não pareça "rodou e falhou".

---

## 6.1 Histórico de execuções — FEITO, com duas ressalvas (2026-08-02)

Rescanear a mesma branch deixou de sobrescrever a execução anterior: `scan_jobs`
passou a ter **uma linha por execução** (índice unique parcial garantindo no
máximo uma *em andamento* por commit) e `scan_reports` passou a ser chaveado por
`(scan_job_id, tier)`. `GET /scans/{id}/history` lista as execuções do commit e
a tela de detalhe do relatório mostra o histórico.

**Ressalva 1 — os findings não são escopados por execução.** `dedup_key` ainda
inclui `commit_sha`, não a execução, e o `ON CONFLICT DO NOTHING` faz o conjunto
de findings de um commit apenas *crescer* entre reexecuções. Duas execuções do
mesmo commit exibem a mesma lista de findings; o que difere entre elas é o
relatório, o risco final e os status de tier.

Para código isso é quase sempre correto (mesmo commit = mesmo código), mas para
**DAST é falso**: o ZAP roda contra o alvo implantado, e duas execuções do mesmo
commit podem legitimamente achar coisas diferentes.

Escopar findings por execução é uma decisão de custo, não de dificuldade: o ZAP
grava ~1800 findings por scan, então N execuções multiplicam a tabela por N e a
tela de Findings (que já corta em 1000 e mostra aviso de truncagem) passaria a
exibir a mesma vulnerabilidade N vezes. Fazer isso exige, junto, resolver a
agregação da §6 e um filtro "só a execução mais recente" no `GET /findings`.

**Ressalva 2 — o canvas Celery não carrega o id da execução.** Só o `commit_sha`
trafega entre as tasks; o repositório resolve para "a execução corrente daquele
commit" (`_id_execucao_corrente`). É unívoco na prática, mas existe uma janela:
se um redisparo acontecer entre o último tier encerrar e uma task atrasada da
execução anterior escrever, a escrita atrasada cai na execução nova. Fechar isso
é mecânico — gerar o uuid no orquestrador (antes de montar o canvas, como já é
feito hoje com o `create_scan_job`) e passá-lo como kwarg em todas as tasks —,
mas mexe em ~10 assinaturas de task e no canvas, que é a parte mais frágil do
sistema. Não foi feito junto de propósito.

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
