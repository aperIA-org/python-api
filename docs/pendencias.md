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
