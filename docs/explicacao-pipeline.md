# Por que o pipeline do aperIA é assim

Este documento é **explicação** (Diátaxis): discute o porquê das decisões de
design do pipeline de scan — tiers escalonados, canvas Celery, gates,
score, filosofia de falha e isolamento multi-tenant — não como executá-lo.
Para passos práticos, veja os how-tos em [`howto/`](howto/) (em especial
[`howto/subir-a-stack.md`](howto/subir-a-stack.md) e
[`howto/disparar-analise.md`](howto/disparar-analise.md)); para os fatos
soltos (rotas, variáveis de ambiente, modelos, plumbing do Claude), veja
[`referencia.md`](referencia.md). O guia `GUIA_EXECUCAO.md`, na raiz do
repositório, é a fonte mais detalhada de outputs reais de cada etapa e foi
usado como base factual para tudo que segue.

---

## 1. Por que 3 tiers, e por que Celery com filas separadas

A escolha de estruturar o pipeline em 3 tiers escalonados — em vez de rodar
tudo de uma vez sobre cada PR — é fundamentalmente uma decisão de **custo e
latência**. As ferramentas de segurança que o aperIA orquestra têm perfis
muito diferentes: TruffleHog e Semgrep no diff terminam em segundos; Trivy e
Semgrep no repo inteiro levam minutos; ZAP fazendo active scan
e Caldera emulando técnicas MITRE em sandbox podem levar de 30 a 60 minutos (o
Threat Intel KEV/EPSS é uma consulta HTTP rápida, não pesa nesse orçamento). Se todo PR disparasse os 3 tiers incondicionalmente,
todo PR pagaria o custo (tempo de CI, tokens de Claude, carga nos scanners
mais pesados) mesmo quando o problema já estava resolvido nos primeiros
segundos — por exemplo, quando o próprio PR só tem um secret vazado e nada
mais.

Por isso o pipeline segue a lógica **barato → caro, só escala se
necessário**: Tier 1 é o filtro mais rápido e mais barato (nenhuma chamada a
Claude — ver §5 do `README.md`, "Tier 1 nunca chama Claude"), e serve de
gate binário: se há um secret verificado, não há motivo para gastar mais
nada, o PR já está bloqueado. Tier 2 introduz o primeiro custo real (Claude
Sonnet correlacionando findings), mas ainda é uma varredura estática — não
depende de infraestrutura externa como ZAP/Caldera (o Threat Intel virou
KEV/EPSS, chamadas HTTP leves, sem container). Tier 3 é
reservado para o cenário que de fato justifica o custo alto: quando a
severidade encontrada até aqui já é `high` ou `critical`. Rodar ZAP, CTI e
emulação de ataque em todo PR trivial seria desperdício; rodar só quando o
sinal já é forte é a forma de gastar o orçamento de tempo/tokens onde ele
importa.

A escolha de Celery com **uma fila por tier** (`tier1`, `tier2`, `tier3`,
mais `analysis` e `reporting`) espelha essa mesma lógica de custo no nível de
infraestrutura: cada fila escala de forma independente. Tier 1 roda com
concorrência alta (é leve e barato, o PR quer resposta em minutos); Tier 3
roda com concorrência baixa (ZAP/Caldera são pesados e o SLA é de dezenas de
minutos, não segundos). Se tudo compartilhasse uma fila única, um PR
disparando Tier 3 (lento) enfileirado atrás de uma rajada de PRs triviais em
Tier 1 atrasaria o feedback rápido que Tier 1 promete. Separar por fila
também isola falhas de infraestrutura por tier — um worker de Tier 3 caído
não impede que Tier 1/Tier 2 continuem respondendo PRs.

---

## 2. O canvas e as bridges

O pipeline inteiro é montado como uma única `celery.chain` em
`app/core/orchestrator.py:build_pipeline_canvas`, disparada por
`start_pipeline`. Há **dois gatilhos** para essa mesma chain — o webhook de
PR (`POST /webhook/github`) e o scan manual
(`POST /repositories/{id}/scan`) — mas um **único ponto de disparo**:
`dispatch_pipeline`, em
`app/application/use_cases/trigger_scan_use_case.py`. Os dois caminhos
chamam essa função, o que é uma decisão deliberada: os argumentos do canvas
(entre eles o `changed_files` vazio e o `target_url` ainda ausente, ver §8)
ficam definidos em um lugar só, e nenhum dos gatilhos tem como divergir do
outro. O que o scan manual acrescenta — e o webhook
recebe de graça no payload do GitHub — é o commit a analisar: sem PR, o use
case resolve ao vivo o HEAD do `default_branch` e verifica que ainda não há
um scan em andamento para aquele SHA.

A única diferença real entre os dois gatilhos é o `pr_number`, que no scan
manual é `None`. Isso não altera o canvas: os mesmos tiers rodam, os mesmos
gates decidem, os relatórios são gerados e persistidos igual. O que muda é
só o **canal de entrega** — sem PR não há onde comentar, então os workers de
reporting pulam o post e o relatório fica apenas na projeção consumível pela
API. O status check no commit, esse continua sendo criado pelo Gate 1: ele
se prende ao SHA, não ao PR. É a tradução, no nível do código, de que
"analisar" e "avisar no GitHub" são responsabilidades separadas.

A ideia central da chain é que cada elo
é o resultado de uma task anterior — Celery passa esse resultado como
**primeiro argumento posicional** da próxima task da chain (`.s(kw=...)`
serve só para argumentos fixos, como `commit_sha`/`repo_full_name`, que não
vêm do elo anterior).

Isso funciona bem enquanto cada task recebe exatamente o output do vizinho
imediato. O problema aparece quando uma task precisa de **mais de uma
coisa**: `tier2_analyze` precisa dos findings de T1 *e* T2 combinados;
`tier3_deep_analysis` precisa do scan de Tier 3 como argumento posicional
*e* do resultado de `tier2_analyze` como kwarg. O canvas do Celery não tem
como mapear um único output anterior em múltiplos parâmetros de destino — daí
as **bridges**: tasks mínimas, declaradas no próprio `orchestrator.py`
(`_t1_to_t2_scan_bridge`, `_bridge_t1_findings_into_analyze`,
`_prepare_tier3_payload`, `_deep_analysis_bridge`), cujo único trabalho é
combinar o resultado da task anterior com o state fixo (`commit_sha`,
`repo_url` etc.) que precisa "atravessar" a chain, e então invocar
diretamente `.run(...)` da próxima task com os argumentos já remontados.
Nenhuma delas tem lógica de negócio — são cola estrutural entre o modelo de
canvas do Celery e a forma real das assinaturas dos workers.

O segundo motivo de existirem bridges (e não só de precisarem existir) é a
**propagação da interrupção dos gates**. `gate1_check` e `tier3_gate` param
o pipeline levantando `celery.exceptions.Ignore()` quando a decisão é não
seguir adiante (ver §3). Em modo eager — o modo usado nos testes, e o
comportamento observável do resultado de uma chain — esse `Ignore()` não
propaga automaticamente como uma exceção para as próximas tasks da chain;
elas continuam sendo chamadas, mas recebem `None` como primeiro argumento no
lugar do resultado esperado. Se as bridges não tratassem isso, elas
tentariam desempacotar um dict que não existe e quebrariam o worker com uma
exceção não relacionada ao gate. Por isso toda bridge do orchestrator começa
com a mesma defesa: `if not <input> or not isinstance(<input>, dict): return
None`. O `None` então se propaga adiante, bridge após bridge, sem nenhum
efeito colateral (nenhuma chamada a scanner, nenhuma chamada a Claude, nenhum
post no PR) — é assim que "o gate bloqueou" se traduz em "o resto da chain
não faz nada", sem precisar que cada worker downstream saiba explicitamente
que um gate rodou antes dele.

Resumindo a ordem do canvas (fila entre colchetes):

```
group(run_trufflehog, run_semgrep_changed)          [tier1]
  → gate1_check                                       [analysis]  Gate 1: bloqueia se secret_verified
  → _t1_to_t2_scan_bridge → run_tier2_scan            [tier2]
  → _bridge_t1_findings_into_analyze → tier2_analyze  [analysis]  Claude Sonnet (chain_of_events)
  → post_tier2_report                                 [reporting] Claude Haiku (markdown no PR)
  → tier3_gate                                         [analysis]  Gate 2: escala se severidade ≥ high
  → _prepare_tier3_payload → run_tier3_scan           [tier3]     ZAP + Threat Intel (KEV/EPSS) + Caldera
  → _deep_analysis_bridge → tier3_deep_analysis        [analysis]  Claude Sonnet (attack_path)
  → post_tier3_deep_report                             [reporting] Claude Haiku (relatório final)
```

Vale notar que o `group(run_trufflehog, run_semgrep_changed)` inicial é o
único ponto de paralelismo real do canvas — TruffleHog e Semgrog changed não
dependem um do outro, então correm juntos e o resultado chega a `gate1_check`
como lista de listas. Do Tier 2 em diante, tudo é sequencial dentro da chain
(mesmo que o próprio `run_tier2_scan`, internamente, rode Trivy/Semgrep
expanded/Prowler um após o outro dentro do mesmo worker).

---

## 3. Gates determinísticos vs. score do Claude

Um ponto que costuma confundir quem lê o pipeline pela primeira vez é achar
que o "score de risco" e as decisões de "bloqueia/escala" vêm do mesmo lugar.
Não vêm — são dois mecanismos deliberadamente separados, com propriedades
bem diferentes.

**As decisões dos gates são determinísticas** e não passam por Claude em
nenhum momento. `gate1_check` olha exclusivamente o campo `secret_verified`
dos findings — só o TruffleHog o define como `True`, e só quando o secret
foi de fato verificado como válido (`--only-verified`). Um `True` em
qualquer finding é suficiente para bloquear, sem gradação nenhuma: não
existe "meio bloqueado". `tier3_gate` é igualmente simples: calcula
`_max_severity(findings)` a partir do campo `severity` (rank
`critical(4) > high(3) > medium(2) > low(1) > info(0)`) e só deixa a chain
seguir para Tier 3 se o máximo for `high` ou `critical`. Essa determinismo é
intencional — os gates decidem **fluxo de controle** (rodar ou não a próxima
etapa cara), e fluxo de controle não deveria depender de um LLM que pode
falhar, alucinar ou variar de resposta para a mesma entrada. Um gate binário
sobre um campo estruturado é auditável e testável sem mock de rede.

**O `risk_score` que aparece no comentário do PR, por outro lado, é
produzido pelo Claude**, não por uma fórmula. `tier2_analyze` (prompt
`chain_of_events`, Sonnet) devolve `risk_score: {score, level}` depois de
raciocinar sobre o conjunto de findings, mais qualquer dado de CTI/Caldera
disponível; `tier3_deep_analysis` (prompt `attack_path`) devolve um
`risk_score_adjusted` recalculado com a evidência adicional do Tier 3. É o
Claude que pondera "esse conjunto de findings, correlacionado, é mais ou
menos grave que aquele outro" — não existe fórmula fixa somando pesos por
severidade no caminho que hoje está plugado.

E é aqui que fica a divergência mais interessante entre intenção de design e
realidade do código: existe, sim, um `RiskScorer` determinístico em
`app/domain/finding/services.py`, com uma fórmula ponderada explícita — CVSS
25%, CTI 25%, Caldera 30%, Business 20%, com uma regra hard de que
`secret_verified=True` força o score para no mínimo 90. O comentário no
código chega a chamar esse scorer de "fonte de verdade". Só que **ele não é
chamado em lugar nenhum do pipeline atual** — nem `tier2_analyze` nem
`tier3_deep_analysis` o invocam; o número que o usuário vê é 100% opinião do
Claude. Isso não é necessariamente um bug a corrigir às pressas: um score
"pesado" e determinístico é mais previsível e mais fácil de justificar
formalmente (útil para compliance), mas é também mais rígido — ele não
enxerga a correlação entre findings da mesma forma que um raciocínio livre
sobre a cadeia de eventos consegue. O trade-off real, hoje resolvido em favor
do Claude, é entre **auditabilidade determinística** e **capacidade de
correlação contextual**. Vale ler o `RiskScorer` como um design alternativo
já escrito e pronto para ser plugado (ou usado como piso/sanity-check do
score do Claude), não como código morto sem propósito.

Havia aqui uma divergência latente que **foi corrigida** ao trocar o CTI por
KEV/EPSS: o `_cti_component` do `RiskScorer` lia a chave `active_campaigns`,
mas o `OpenCTIClient` só produzia `active_threat` — então o componente de CTI
cairia sempre no ramo `else` (25.0 fixo), porque a chave procurada nunca
existia. O novo `ThreatIntelClient` produz `active_campaigns` (campanha de
ransomware do KEV) **e** `known_exploited` (CVE no KEV) **e** `epss_score`, e
o `_cti_component` foi reescrito para: exploração comprovada ou campanha ativa
→ 100; senão gradua pelo EPSS; senão o piso de 25. A divergência deixou de
existir e o componente passou a refletir ameaça real.

---

## 4. O papel de cada tier

**Tier 1 (TruffleHog + Semgrep changed)** existe para responder rápido a
duas classes de problema muito diferentes em urgência. TruffleHog varre só o
que mudou entre `base_sha` e `head_sha` procurando segredos, e só reporta os
que conseguiu **verificar** como válidos (`--only-verified`) — não é
heurística de regex sobre formato, é confirmação ativa de que a credencial
funciona. É por isso que só ele pode setar `secret_verified=True` e disparar
o Gate 1: uma AWS key verificada vazada em um PR é uma emergência que não
espera análise nenhuma, LLM ou não. Semgrep changed roda a mesma lógica de
SAST rápido, mas sobre uma classe de problema que não é binária
(vulnerabilidade de código não é "verdadeiro/falso" da mesma forma que um
secret válido) — por isso ele não bloqueia sozinho, apenas contribui
`severity`/`cwe_id`/regra disparada como evidência que vai alimentar o
`_max_severity` do Gate 2 e, mais adiante, o raciocínio do Claude.

**Tier 2 (Trivy + Semgrep expanded + Prowler, seguido de dedup e Claude
Sonnet)** é onde o pipeline deixa de olhar só o diff e passa a olhar o
projeto inteiro — Trivy varre dependências/containers/IaC procurando CVEs
conhecidas, Semgrep expanded roda a mesma regra de security-audit mas sobre
todo o repositório (não só os arquivos tocados pelo PR), e Prowler entra
condicionalmente, só quando o PR tem arquivos de infraestrutura como código,
para procurar misconfigurações de nuvem. A razão de ampliar o escopo aqui
(e não já no Tier 1) é de novo custo: rodar scan de repo inteiro em todo PR
seria caro demais para o SLA de poucos minutos que o Tier 1 promete; uma vez
que o Tier 1 já filtrou o caso trivial (secret vazado), vale a pena investir
mais tempo procurando o que o diff isolado não revela. O `cve_id` que o
Trivy encontra é o dado que faz a ponte para o Tier 3 — é ele que a etapa
seguinte usa para consultar KEV/EPSS e descobrir se aquele CVE específico está
sendo explorado ativamente (KEV) e com que probabilidade (EPSS). Depois da dedup (que existe porque os mesmos
findings tendem a se repetir entre execuções e entre scanners, mas
deliberadamente não funde CVEs iguais vindos de fontes diferentes — o
`source` é parte da chave), o Claude Sonnet recebe o conjunto agregado e
tenta montar uma `event_chain`: não trata cada finding como isolado, mas
como possível passo de uma sequência de ataque, mapeando técnicas MITRE por
passo e devolvendo o primeiro `risk_score`.

**Tier 3 (ZAP + Threat Intel KEV/EPSS + Caldera, seguido de Claude Sonnet
montando attack_path)** só existe porque, até aqui, tudo foi análise estática — nada
foi de fato testado em execução. ZAP ataca o `target_url` real (DAST), e por
isso é a evidência mais forte de exploitabilidade: uma vulnerabilidade
confirmada por scan ativo pesa mais que uma inferida por padrão de código.
O Threat Intel (CISA KEV + EPSS) responde a uma pergunta que nenhum scanner
estático consegue responder por si — "esse CVE está sendo explorado por
atacantes de verdade, hoje?" — via KEV (exploração comprovada + campanha de
ransomware) e EPSS (probabilidade de exploração). Técnicas MITRE por CVE ficam
para o passo 2 (OTX); hoje as técnicas da emulação vêm da cadeia do Tier 2.
Caldera vai além: emula essas mesmas técnicas dentro de um sandbox isolado
para medir se o ataque **de fato funciona** nesse ambiente específico
(`success_rate`), a diferença entre "teoricamente vulnerável" e "comprovado
explorável aqui". O Claude Sonnet recebe esse pacote combinado e monta o
`attack_path` — uma kill chain com fases MITRE, marcando cada passo com
`caldera_validated: true/false` — que é a base conceitual da lista de ações
priorizadas e, por consequência, das code suggestions que eventualmente
chegam ao PR (sempre para aprovação humana, nunca aplicadas sozinhas).

---

## 5. Por que "nunca derrubar o pipeline" é a regra central

A filosofia best-effort aparece em quase toda camada do sistema, e vale
entender por que ela foi escolhida deliberadamente em vez da alternativa
óbvia (falhar rápido e visivelmente). `BaseScanner.run_safe()` garante que
qualquer exceção dentro de um `scan()` — scanner não instalado, binário
ausente, timeout, erro de parsing — é logada como `scanner_skipped` e se
transforma em uma lista vazia, nunca em uma exceção que sobe pela chain.
`ClaudeClient`, quando o circuit breaker está aberto, o LLM Guard bloqueia o
prompt, ou a API falha, devolve um dict `{"degraded": True, ...}` em vez de
propagar o erro — o worker de análise não quebra, apenas produz uma análise
mais pobre. `finding_writer.persist_findings` grava no Postgres de forma
best-effort: se o banco estiver fora do ar ou o schema desalinhado, loga
`finding_persistence_failed` e segue, porque a persistência é observabilidade
auxiliar, não o caminho crítico do canvas (os gates e o Claude operam sobre
os dicts que atravessam o canvas, nunca sobre o que está gravado no banco).
E os próprios gates, quando decidem parar, fazem isso de forma limpa via
`Ignore()`, não via exceção não tratada.

O raciocínio por trás disso é que, num pipeline de segurança que corre
automaticamente sobre todo PR, uma dependência externa instável (um scanner
que não está instalado no ambiente, uma API da Anthropic sem crédito, um
Postgres momentaneamente fora do ar) não deveria conseguir travar a análise
inteira ou, peor, bloquear merges por um motivo que não tem nada a ver com a
segurança do código em si. A trade-off aceita aqui é explícita: prefere-se
correr o risco de um **falso-negativo** (um scanner que falhou silenciosamente
não vai revelar aquele finding específico) do que produzir um
**falso-positivo de indisponibilidade** (o PR trava porque o Trivy não
respondeu, não porque o código tem um problema). Cada falha degradada é
logada com estrutura suficiente para ser observável e investigada depois —
o objetivo não é escondê-la, é não deixá-la virar motivo de parada.

---

## 6. Modelo de isolamento multi-tenant

O aperIA nasceu de single-tenant (só um repositório vinculado por
configuração fixa) e evoluiu para multi-tenant sem reescrever o núcleo do
domínio de findings/scans. Essa evolução incremental é visível na forma como
o isolamento foi resolvido: em vez de dar a cada tabela de resultado sua
própria coluna de dono, o dono foi anexado apenas em `scan_jobs`
(`user_id`/`repository_id`), e tudo que depende de um scan — `findings`,
relatórios de tier — é isolado **transitivamente**, via join/subquery por
`commit_sha`. Como `scan_jobs.commit_sha` é única, essa cadeia
`findings.commit_sha → scan_jobs.commit_sha → scan_jobs.user_id` é 1:1 e não
ambígua, mas é importante entender que é uma decisão lógica de aplicação, não
uma constraint de banco: não há foreign key formal entre `scan_jobs` e
`users`/`repositories` (nem entre `repositories` e `users`/`github_accounts`)
— o vínculo existe porque o código sempre popula e sempre filtra por esses
UUIDs, não porque o schema o obriga. É um design pragmático (menos migração,
menos acoplamento rígido de schema) com uma contrapartida clara: a
integridade referencial depende inteiramente da disciplina do código
de aplicação, não do banco.

A conta de pagar por essa escolha aparece inteira no `DELETE
/github/accounts/{id}`. Como não há `ON DELETE CASCADE` entre
`github_accounts` e `repositories`, desconectar uma conta sem limpeza
explícita deixava para trás **repositórios fantasmas**: `GET /repositories`
continuava listando-os como ativos, enquanto `GET /github/repos` já não os
enxergava — a instalação que os revelava tinha deixado de existir. A rota
hoje remove os dois na mesma transação. O interessante é onde a cascata
**para**: findings, scans e relatórios sobrevivem, de propósito. O critério
não é "o que depende do quê" no sentido do schema, mas o que é configuração
e o que é produto. O vínculo com o GitHub é configuração, refazível em dois
cliques (o usuário pode reinstalar o App a qualquer momento). O histórico de
segurança já coletado é o produto — apagá-lo destruiria auditoria por conta
de uma ação reversível, e uma remoção acidental viraria perda permanente. O
efeito colateral aceito é que os scans preservados guardam um
`repository_id` que não resolve mais para linha nenhuma; isso não quebra as
leituras, porque o isolamento por usuário se apoia em `scan_jobs.user_id`,
não no repositório.

O ponto de decisão de quem é o dono de um scan é o próprio webhook. Quando um
evento `pull_request` chega, o aperIA já sabe `installation_id` (do payload
do GitHub App) e o id do repositório GitHub; ele resolve o dono buscando, na
tabela `repositories`, um registro que bata com esse par
`(installation_id, github_repo_id)` **e** esteja marcado como ativo. Se
encontra, o scan nasce com `user_id`/`repository_id` preenchidos e passa a
ser visível para aquele usuário nas rotas de leitura. Se não encontra — o
repositório nunca foi cadastrado por ninguém, ou foi cadastrado mas está
desativado — o scan **não é bloqueado**: ele roda do mesmo jeito (o pipeline
de segurança não deveria parar de proteger um repositório só porque a parte
de "quem é o dono" ainda não foi resolvida), só que nasce órfão, com
`user_id`/`repository_id` nulos. Um scan órfão continua produzindo findings e
relatórios normalmente — eles só não aparecem para nenhum usuário nas rotas
`GET /findings`, `/scans`, etc., porque toda leitura filtra pelo dono. Esse
comportamento é deliberadamente best-effort, na mesma linha do §5: resolver o
dono é enriquecimento, não pré-condição para o pipeline funcionar.

O scan manual inverte essa ordem, e por um motivo simples: ali o dono é o
ponto de partida, não uma dedução. `POST /repositories/{id}/scan` só chega ao
disparo depois de o JWT provar quem é o usuário e de o repositório ser
confirmado como dele — o `user_id`/`repository_id` do scan vêm direto da
linha de `repositories`, sem lookup por `(installation_id, github_repo_id)`.
Um scan manual, portanto, nunca nasce órfão. E é justamente por o dono ser
pré-condição que a rota pode se dar ao luxo de recusar casos que o webhook
tolera: um repositório desativado responde `409` em vez de rodar assim mesmo.
As duas posturas são coerentes entre si — o webhook reage a um evento externo
que ele não controla e prefere analisar demais a analisar de menos; a rota
manual atende a um pedido explícito, e um pedido explícito pode ser
respondido com um "não, e aqui está o porquê".

Uma consequência direta desse modelo é a escolha de devolver **404, não
403**, quando um usuário autenticado pede um recurso que existe mas pertence
a outro dono — seja um finding, um scan por `commit_sha`, um repositório ou
uma conta GitHub conectada. A diferença entre os dois códigos é sutil, mas
importa: 403 confirma implicitamente que o recurso existe (só que você não
pode vê-lo); 404 não confirma nada. Em um sistema que guarda achados de
segurança de repositórios de terceiros, mesmo confirmar a existência de um
`commit_sha` ou de um id de finding para alguém que não é o dono é uma
informação que não deveria escapar — daí a regra consistente em todas as
rotas de leitura: "não encontrado" cobre tanto "realmente não existe" quanto
"existe, mas não é seu", e o chamador não tem como distinguir os dois casos.

Por fim, o fluxo de conexão de conta GitHub (`GET /github/connect` →
instalação do App → `GET /github/callback`) resolve um problema de segurança
diferente: o callback do GitHub chega no browser do usuário, sem qualquer
header de autenticação da aplicação — o único jeito de saber *quem* iniciou
aquele fluxo é o parâmetro `state` que o próprio `/connect` gerou e embutiu
na URL de instalação. Por isso esse `state` não é um token aleatório opaco, é
assinado (garantindo que não foi forjado nem alterado) e carrega o
`user_id` de quem chamou `/connect`, junto com um propósito dedicado e uma
expiração curta. Sem essa assinatura, o fluxo estaria exposto a um ataque de
**account-linking/CSRF**: um atacante poderia iniciar sua própria instalação
do GitHub App, capturar a URL de callback resultante, e induzir a vítima
(já autenticada no aperIA) a abri-la — se o callback confiasse em qualquer
outro sinal fraco (por exemplo, um id de instalação sem prova de origem), a
conta GitHub do atacante acabaria vinculada à sessão da vítima, ou vice-versa.
Ao exigir que o `state` seja válido, não expirado e carregue explicitamente
o `user_id` esperado, o callback só aceita completar o vínculo para quem de
fato originou aquele fluxo específico.

Vale separar essa checagem da forma como a recusa é comunicada. Quando
`GITHUB_CONNECT_REDIRECT_URL` está configurada, um `state` inválido ou
expirado não devolve mais um `400` em JSON: redireciona para o front com
`github=erro&motivo=state`. Isso não afrouxa nada — a validação é a mesma, o
vínculo continua não sendo criado. É só o reconhecimento de que quem chega ao
callback é um **browser**, não um cliente de API: despejar um JSON de erro no
host da API deixaria o usuário numa página morta, longe da aplicação, sem
caminho de volta. Devolvendo-o à própria tela que iniciou o fluxo, o erro mais
provável (o `state` de 10 minutos que expirou enquanto a pessoa escolhia
repositórios no GitHub) se resolve com um clique em "tentar de novo", que
chama `/github/connect` e gera um `state` novo. O `400` continua existindo
para quando não há URL configurada — aí não há front para onde voltar.

---

## 7. Jobs travados e a assimetria de durabilidade entre Postgres e Redis

Um `ScanJob` do aperIA existe em dois lugares ao mesmo tempo, e por muito
tempo esses dois lugares tiveram durabilidades diferentes. Quando um scan é
disparado, a API faz duas coisas em sequência: grava a linha em `scan_jobs`
(Postgres) com o Tier 1 já em `running`, e publica as tarefas do tier 1 no
Redis, que é o broker do Celery. A linha é a **projeção** do scan, o que a API
mostra em `GET /scans`; a tarefa na fila é o **trabalho** de verdade, o que
faz o pipeline andar. Se as duas não sobrevivem às mesmas falhas, o sistema
passa a conseguir afirmar coisas que não são verdade.

Era exatamente esse o caso. O `docker-compose.base.yml` declarava um único
volume nomeado, o do Postgres; o `redis:7-alpine` subia sem volume e com
`appendonly no`, ou seja, com a fila inteira na memória do container. Bastava
recriar a stack — um `docker compose down`, um rebuild após mudar código, um
reinício da máquina — entre o disparo e o momento em que um worker consumisse
a fila para que as tarefas evaporassem. A linha no Postgres, essa, sobrevivia:
órfã, dizendo `tier1_status = running` sem que existisse mais nada no sistema
capaz de concluí-la. Foi assim que um scan real ficou permanentemente preso em
"running".

O estrago não parava na projeção mentirosa. `TriggerRepositoryScanUseCase`
recusa um disparo com `409` quando já existe um scan em andamento para aquele
commit — uma proteção sensata contra duplicar o pipeline. Só que
`scan_jobs.commit_sha` é UNIQUE: todo redisparo daquele commit cai na **mesma
linha**, a órfã, que continua dizendo `running`. O resultado é que o commit
virava permanentemente não-escaneável, e o único caminho de recuperação era um
`UPDATE` manual no banco. Uma proteção contra concorrência tinha se
transformado, na presença de uma falha de infraestrutura, em prisão perpétua.

A correção tem duas metades, e é importante entender por que nenhuma das duas
sozinha bastaria. A primeira é remover a assimetria: o Redis passou a rodar
com `--appendonly yes` e um volume `aperia_redis_data:/data`, de modo que a
fila persiste no disco e sobrevive a um `down`/`up` como os dados do Postgres
sempre sobreviveram. Isso elimina a causa raiz do incidente concreto, mas não
elimina a **classe** do problema: um worker que morre no meio de uma task, uma
fila purgada à mão, uma task que estoura um timeout e some — todos continuam
capazes de produzir uma linha órfã. Persistência do broker reduz a frequência,
não a possibilidade.

A segunda metade é assumir que jobs órfãos vão acontecer e dar ao sistema uma
forma de se recuperar sozinho. A regra que define isso mora no domínio, no
próprio `ScanJob`: um job está **travado** quando diz estar em andamento
(algum tier `queued`/`running`) e não dá sinal de vida há mais que
`SCAN_STALE_AFTER_MINUTES` (default 30). "Sinal de vida" é o mais recente
entre todos os `tier*_started_at`/`tier*_completed_at` e o `created_at` — cada
transição de tier grava um desses timestamps, então o máximo deles é a última
vez que alguém tocou no job. O `created_at` entra na conta porque existe o
caso em que ele é o único timestamp preenchido, e é justamente o caso do
incidente: a linha nasce com o Tier 1 em `running` e, se ninguém consome a
fila, nada mais é escrito depois dela.

Essa regra é aplicada em dois pontos complementares, e a escolha dos pontos
foi ditada pela stack: **não há celery beat** aqui, então não existe um
agendador para varrer o banco periodicamente, e acrescentar um container só
para isso seria caro demais para o problema. O primeiro ponto é o **boot da
API**: se o processo está subindo, a stack foi reiniciada, e tudo que estava
em voo no broker anterior já se perdeu — é o momento em que a varredura tem a
maior chance de encontrar exatamente os jobs que ela existe para encontrar. O
segundo é **preguiçoso, na hora do disparo**: antes de recusar com `409`, o
caso de uso verifica se o job que está bloqueando não é um job travado; se
for, marca os tiers pendentes como `failed` e deixa o novo scan seguir. Só o
primeiro ponto não bastaria (a API pode ficar meses no ar), e só o segundo
tampouco (a projeção continuaria mentindo até alguém tentar escanear de novo).
Em ambos os casos, tiers já `done`/`skipped` são preservados: só o que estava
pendente vira `failed`, porque é só sobre isso que se pode afirmar que
ninguém vai concluir.

Vale notar o que essa recuperação **não** é: ela não reexecuta nada. Marcar
como `failed` é uma afirmação honesta ("este scan não terminou e ninguém vai
terminá-lo"), não uma tentativa de salvar o trabalho perdido. Redisparar
automaticamente seria fazer o sistema tomar, sozinho, uma decisão de custo
(scanners pesados, chamadas ao Claude) a partir de um sinal indireto. O
caminho de volta é o disparo normal — que agora funciona, porque a linha
deixou de bloquear.

Um bug menor apareceu na mesma investigação e vale registrar, porque tem a
mesma raiz conceitual (a linha ser chaveada por commit, não por execução). Um
redisparo reaproveitava a linha existente **sem** resetar os timestamps da
execução anterior: uma linha chegou a alegar um Tier 1 de 22 horas quando a
execução real durou segundos — o `tier1_started_at` era da primeira tentativa
e o `tier1_completed_at`, da segunda. Hoje `create_scan_job` detecta que a
linha já existe e reinicia o estado de execução (status, timestamps,
`blocked_at_tier`, risco final). O `created_at` é deliberadamente preservado:
ele responde "desde quando este commit está no sistema", que é uma pergunta
diferente de "quanto durou esta execução" — essa segunda se lê pelos
`tier*_started_at`, que agora são sempre da execução corrente.

---

## 8. O checkout do repositório: por que cada tarefa clona o seu

Por um bom tempo o pipeline rodava inteiro sem nunca ter visto o código. O
`repo_path` que atravessava o canvas era um caminho inventado
(`/tmp/aperia/<sha>`) que não existia em lugar nenhum; Semgrep, TruffleHog e
Trivy tentavam ler aquele diretório, falhavam com `No such file or directory`
e — pela filosofia best-effort da §5 — devolviam lista vazia. O efeito em
cascata era pior do que "faltam alguns findings": Tier 1 entregava zero,
Gate 1 não tinha secret para bloquear, Tier 2 correlacionava nada, o risco
final fechava em `info` e o Gate 2 nunca escalava para o Tier 3. O pipeline
terminava verde, com um relatório dizendo que estava tudo bem. Num produto de
segurança, esse é o pior desfecho possível: não é uma falha visível, é uma
afirmação falsa.

O checkout real resolve isso, mas a pergunta interessante não é "como clonar"
— é **onde** o clone deveria viver.

### Um clone por tarefa, não um volume compartilhado

`repo_path` é lido em dois tiers: o Tier 1 (Semgrep changed + TruffleHog) e o
Tier 2 (Trivy). Eles rodam em **containers diferentes** — cada serviço de
worker em `docker-compose.base.yml` monta apenas o `.env`, não há filesystem
comum. Um clone feito no worker do Tier 1 simplesmente não existe no do
Tier 2.

A saída óbvia seria um volume compartilhado entre os workers. Ela resolve o
acesso e cria um problema pior: **quem apaga, e quando**. O pipeline é
assíncrono, tem gates que o interrompem no meio (Gate 1 bloqueia, Gate 2 não
escala) e tasks que podem ser reexecutadas (`acks_late=True`). Nenhum ponto do
canvas sabe, com segurança, que ninguém mais vai precisar daquela árvore — e
uma limpeza errada em qualquer direção custa caro: apagar cedo quebra um tier
que ainda ia rodar, apagar tarde (ou nunca) enche o disco do host com uma
cópia do código de cada commit já escaneado.

Com **checkout por tarefa** a pergunta desaparece: quem clonou apaga, no
`finally` do próprio context manager
(`app/infrastructure/git/repo_checkout.py`), inclusive quando a task morre por
exceção. O preço é materializar o mesmo commit mais de uma vez por pipeline.
Como cada checkout é um fetch **raso do commit exato** (`--depth 1`), o custo
é da ordem do tamanho da árvore, não do histórico — barato perto de manter
estado compartilhado e vivo entre containers.

Um detalhe do "como": não dá para usar `git clone --depth 1`, porque clone
raso só alcança a ponta de um branch e o pipeline escaneia um **commit
específico** (o HEAD do PR, que pode já não ser a ponta de nada quando o
worker roda). Por isso a sequência é `git init` → `remote add` →
`fetch --depth 1 origin <sha>` → `checkout FETCH_HEAD`, que busca exatamente
aquele objeto.

### O token nunca toca o disco nem a linha de comando

O clone é autenticado com o installation token do GitHub App — um segredo de
vida curta, mas segredo. As duas formas usuais de passá-lo ao git são ruins,
cada uma à sua maneira. Embutir na URL do remote
(`https://x-access-token:<token>@github.com/...`) grava a credencial em texto
puro no `.git/config` **dentro do diretório clonado**, onde qualquer scanner
que varre a árvore inteira pode encontrá-la (o TruffleHog, ironicamente, é
excelente nisso). Passar por `git -c http.extraHeader=...` deixa o token em
argv, legível por qualquer processo da máquina em `/proc/<pid>/cmdline`.

A opção adotada é a menos ruim das disponíveis: variáveis de ambiente
(`GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_0` / `GIT_CONFIG_VALUE_0`), que o git
aplica como se fossem `-c`, sem persistir nada no diretório e sem aparecer em
argv — `/proc/<pid>/environ` só é legível pelo dono do processo. Não existe
alternativa perfeita: autenticar exige que o segredo esteja em **algum** canal
do processo filho; a escolha é sobre qual canal tem a menor superfície.

Isso ainda deixa um vazamento clássico em aberto: o git ecoa a URL nas
mensagens de erro, e essas mensagens vão parar em log e em exceção. Por isso
tudo que sai do módulo passa por uma função de redação que troca o token (e a
sua forma base64, que é como ele viaja no header) por `***`. Há teste
provando as duas coisas — que o segredo não aparece em argv e que não aparece
nem no log nem na mensagem de erro.

### Falhar no checkout é falhar o scan

O checkout é a única peça do pipeline que **não** é best-effort, e é uma
exceção consciente à regra da §5. A filosofia "scanner falho → `[]`" existe
porque um scanner ausente ainda deixa os outros trabalharem. Sem a árvore em
disco não há trabalho nenhum: os três scanners locais leem arquivos. Fingir
sucesso reproduziria exatamente o desfecho que o checkout veio consertar —
zero findings, pipeline verde, afirmação falsa.

Então a task falha. E como uma task que falha interrompe o canvas, ninguém
mais marcaria o `ScanJob`: ele ficaria `running` até a varredura de jobs
travados descrita na §7, bloqueando novos disparos daquele commit com `409`
durante todo o intervalo. Para não deixar esse rastro, o guard
(`app/presentation/workers/checkout_guard.py`) encerra os tiers pendentes
antes de propagar a exceção, usando a **mesma** operação idempotente da
recuperação (`fail_pending_tiers`) — as duas rotas convergem em vez de
competir: se o guard rodar primeiro, o job deixa de estar em andamento e a
varredura nem o enxerga.

### `changed_files`: onde o escopo do Semgrep é decidido

O canvas nunca carregou diff. `changed_files` saía de `dispatch_pipeline`
vazio, e o Semgrep do Tier 1 tratava lista vazia como "nada a escanear" —
outro caminho silencioso para zero findings.

A correção separa duas perguntas que estavam misturadas. **Quem sabe o diff**
é quem tem os arquivos: com o checkout real, `git diff --name-only base head`
roda dentro do próprio clone. Isso funciona mesmo em fetch raso porque `diff`
compara *árvores*, não precisa da ancestralidade entre os dois commits — basta
que os dois objetos existam, e o checkout busca o `base_sha` num segundo fetch
raso justamente para isso. **Quem decide o escopo** é o worker: se há diff
(scan de PR, `base_sha != commit_sha`), o Semgrep roda só nos arquivos
tocados; se não há base contra o que comparar (scan manual de branch, onde
`base_sha == commit_sha`), o alvo passa a ser a árvore inteira.

O fallback é deliberadamente assimétrico: quando o diff **não pôde** ser
calculado (force-push apagou o commit base, por exemplo), o comportamento é o
mesmo do scan manual — varre tudo. Errar para o lado de escanear demais custa
tempo; errar para o lado de escanear nada custa a razão de existir do produto.
O mesmo diff, no Tier 2, é o que devolve utilidade ao Prowler: ele só roda
quando o PR toca arquivos IaC (`has_iac_files`), e com `changed_files` sempre
vazio essa condição nunca era verdadeira.

Continua fora do escopo o `target_url`: sem uma URL de aplicação rodando, o
ZAP (DAST) segue sendo pulado no Tier 3. Essa nota permanece honesta — é a
única peça do canvas ainda alimentada por um valor ausente.

## 9. Como o Tier 1 procura secrets: o modo depende do checkout

O checkout do pipeline é **raso** (`--depth 1`): a árvore materializada tem
**um único commit**. Isso não é detalhe de implementação — decide o que o
TruffleHog consegue examinar.

O modo `git` do TruffleHog percorre **histórico**. Sobre um checkout raso ele
tem, no melhor caso, um commit para olhar. E no scan manual de branch, onde
`base_sha == head_sha`, o intervalo `--since-commit` fica **vazio**: zero
commits examinados. O pipeline concluía com `0 findings` sem ter procurado —
que é o pior resultado possível, porque é indistinguível de "repositório
limpo".

Por isso o modo passou a ser escolhido pelo que existe para examinar:

| Gatilho | `base_sha` | Modo | O que varre |
|---|---|---|---|
| Pull request | distinto do head | `git` | os commits do PR (`--since-commit`) |
| Branch (scan manual) | ausente ou igual ao head | `filesystem` | a árvore de trabalho do commit |

### Secret não verificado agora aparece

O filtro de verificação existia **em dobro**: `--only-verified` na linha de
comando e um segundo `if item["Verified"]` no parsing. Um segredo que o
TruffleHog detectasse mas não conseguisse validar contra o provedor sumia sem
deixar rastro — o que esconde credencial revogada, de ambiente de teste, ou de
provedor para o qual não existe verificador.

A verificação virou **severidade**, não censura:

- **verificado** → `critical`, com `secret_verified=true`;
- **não verificado** → `medium`.

`medium` é deliberado. O Gate 1 bloqueia o PR apenas com `secret_verified=true`
e o Gate 2 escala para o Tier 3 apenas com `high`/`critical` — então o achado
fica visível no dashboard sem travar merge por suspeita nem inflar a análise
profunda. Quem decide o que fazer com ele é quem lê, não o scanner.

### O log diz o modo

`tier1_trufflehog_complete` passou a registrar `modo` e `verificados`. Sem isso,
`findings_count=0` é ambíguo entre "não achei" e "não procurei" — e foi
exatamente essa ambiguidade que escondeu o problema até um teste controlado
comparar as cinco variantes de invocação contra um checkout real.

## 10. Perder finding é falha, não aviso

A §5 explica por que "nunca derrubar o pipeline" é a regra central: um scanner
ausente não pode impedir os outros de trabalhar. Essa regra tem **duas
exceções**, e as duas seguem o mesmo critério.

| Falha | Best-effort? | Por quê |
|---|---|---|
| Scanner quebrou | sim → `[]` | os outros scanners ainda produzem resultado |
| Checkout falhou | **não** → task falha | sem árvore não há o que escanear |
| Gravação falhou | **não** → task falha | o produto perde o que foi encontrado |

O critério não é "quão grave é o erro", é **se ainda existe trabalho útil a
fazer depois dele**. Scanner que falha deixa os outros trabalharem. Checkout e
persistência que falham deixam o pipeline concluir dizendo "nada encontrado" —
que num produto de segurança é o pior desfecho possível, porque é
indistinguível do resultado legítimo.

A persistência era best-effort e o custo apareceu na prática: um `cwe_id` de 93
caracteres numa coluna de 50 derrubou o `INSERT`, o erro virou warning, e o
pipeline concluiu anunciando sucesso sobre um repositório onde o Semgrep tinha
acabado de achar um XSS. O finding existia no payload do canvas e alimentou o
Tier 2 — mas o dashboard lê `GET /findings`, não o canvas. Para quem usava o
produto, o repositório estava limpo.

O argumento antigo ("o gate e a análise operam sobre os dicts, não sobre o
banco") continua verdadeiro, mas descreve o **pipeline**, não o **produto**.

`persist_findings` levanta `FindingPersistenceError`; o
`persistence_guard.persistir_ou_falhar` encerra os tiers pendentes do `ScanJob`
antes de propagar — mesmo cuidado do `checkout_guard`, porque uma task que
falha interrompe o canvas e ninguém mais marcaria o job, que ficaria `running`
até a varredura de 30 minutos bloqueando novos disparos daquele commit.

Dois casos seguem devolvendo `0` sem erro, porque em nenhum deles há perda:
persistência desligada por configuração (`FINDINGS_PERSISTENCE_ENABLED`) e
lista de findings vazia.

## 11. Quando a guarda de injection briga com o produto

O `LLMGuardClient` bloqueia prompts com padrões de prompt injection, e um deles
é `BEGIN ... PRIVATE KEY`. A razão original é boa: scanner lê código, e um
atacante pode plantar payload num comentário para manipular o LLM que vai ler
aquele finding.

Só que esse padrão específico é **exatamente aquilo que um scanner de secrets
deve encontrar**. Com um repositório que tem chave privada de verdade (o
OWASP Juice Shop tem), a cadeia era:

```
TruffleHog acha a chave  →  `Raw` vai para `description` do finding
  →  prompt do relatório do Tier 2 inclui os findings completos
  →  guarda casa "BEGIN RSA PRIVATE KEY"  →  GuardBlockedError
  →  Tier 2 em modo degradado, sem IA
```

O incentivo ficava invertido: **quanto melhor o scanner trabalhava, menos
análise por IA o usuário recebia.** A guarda não distingue "atacante plantou
isto" de "nosso scanner achou um segredo real e está reportando" — e num
produto de segurança a segunda hipótese é a esperada.

### Redigir, não bloquear

`redigir_segredos()` troca o material sensível por um marcador **antes** da
guarda. Resolve os dois lados:

- o segredo **não sai da infraestrutura** — mandar chave privada real para um
  LLM de terceiros é indesejável por si só, independente da guarda;
- o texto que sobra não dispara o padrão, então a análise volta a rodar.

O modelo não precisa do segredo para raciocinar sobre ele: precisa saber que
existe, de que tipo e onde. O valor original continua no banco e em
`raw_output` — quem precisa dele é o usuário, não o modelo.

### Por que no cliente, e não no builder de prompt

A redação fica em `ClaudeClient.call`, ponto por onde **toda** chamada passa.
O incidente mostrou por quê: o bloqueio não vinha do `chain_of_events` (que nem
inclui `description`) e sim do relatório do Tier 2, que recebe os findings
completos. Corrigir no builder consertaria um caminho e deixaria os outros —
e cada prompt novo seria uma chance de reintroduzir o vazamento.

`prompt_segredos_redigidos` registra quantos segredos foram redigidos por
chamada. As outras 13 regras de injection continuam rodando sobre o texto
redigido: redigir não afrouxa a guarda, remove o falso positivo.

## 12. O Gate 2 escala por dois critérios, não um

O Gate 2 escalava só quando **algum finding individual** era `high`/`critical`.
Essa regra ignora volume e correlação — que é precisamente o que o Tier 2
acabou de calcular e entregar no `risk_score`.

O caso que expôs a lacuna: 57 possíveis secrets num repositório, todos
`medium` individualmente (não verificados não travam merge por suspeita),
somando risco agregado **`high` 74/100**. Nenhum item sozinho cruzava a barra,
então o pipeline descartava a análise profunda exatamente no cenário em que ela
é mais útil — muita coisa média que, junta, forma cadeia de ataque.

Agora escala se **qualquer** um valer:

| # | Critério | O que indica |
|---|---|---|
| 1 | `high`/`critical` em algum finding | um problema grave isolado |
| 2 | `high`/`critical` no `risk_score.level` do Tier 2 | o conjunto é grave |

`risk_score_adjusted` (Tier 3) tem precedência sobre `risk_score` (Tier 2) — a
mesma ordem que `scan_job_writer` usa para gravar `final_risk_level`. As duas
leituras precisam concordar, senão o dashboard mostraria um nível e o gate teria
decidido por outro.

O log registra **qual** critério disparou (`criterio=severidade_individual` /
`risco_agregado` / `severidade_e_risco`), porque a investigação que se segue é
diferente: severidade aponta para um finding específico, risco agregado aponta
para o conjunto.

## 13. Por que o Tier 3 custa caro, e de onde vieram os tetos

O Tier 1 lê texto. O Tier 2 lê árvores de sintaxe. O Tier 3 é o único que
**faz requisições**: o ZAP percorre a aplicação publicada e dispara payloads
reais contra cada parâmetro que encontra. É a diferença entre "esse padrão de
código costuma ser vulnerável" e "eu explorei isso agora"; e é também a razão
de o custo mudar de natureza. Nos dois primeiros tiers o custo é função do
**diff**. No Tier 3 é função da **aplicação inteira**, e cresce como
`rotas × parâmetros × regras de ataque` — um número que nada no PR limita.

Contra o alvo de teste da stack (OWASP Juice Shop, centenas de rotas) isso
significa que um active scan sem teto simplesmente não termina em tempo de
pipeline. Duas falhas distintas apareceram, e vale separar porque os consertos
são diferentes.

### O container morria: a JVM não enxergava o próprio limite

`aperia-zap` terminava com `Exited (137)` — SIGKILL do kernel, o `mem_limit:
2g` do cgroup sendo aplicado. O sintoma que chegava ao worker era outro:

```
scanner_skipped error='[Errno -5] No address associated with hostname' scanner=ZAPScanner
```

que parece problema de DNS e não é. O container já tinha morrido; o nome `zap`
deixou de resolver porque não havia mais container para resolver.

A causa está no `zap.sh`, não no ZAP. O script tenta dimensionar o heap pelo
limite do cgroup, mas lê `/sys/fs/cgroup/memory/memory.stat` — caminho de
**cgroup v1**. Docker no WSL2 usa **cgroup v2**, onde esse arquivo não existe.
O script cai no fallback e usa o `MemTotal` do host:

```
Available memory: 7942 MB   →  -Xmx1985m   dentro de um limite de 2048 MB
```

Heap de 1985 MB num teto de 2048 MB deixa 63 MB para metaspace, code cache,
stacks de thread e buffers diretos — tudo que a JVM aloca **fora** do heap. Não
há coleta de lixo que resolva: o processo cresce até ser morto. O detalhe que
fecha o diagnóstico é que a JVM 17 sozinha acerta (`MaxHeapSize` ergonômico dá
512 MB dentro do limite de 2 GB, porque `UseContainerSupport` lê cgroup v2
corretamente) — quem estraga é o `-Xmx` que o script calcula e passa por cima
da ergonomia.

Por isso o conserto **não** foi subir o teto. Subir o teto só move a parede:
com 4 GB o script pediria `-Xmx3971m` e o container morreria em 4 GB. O
conserto é informar o valor certo, e `zap.sh` aceita: ele varre os argumentos
procurando `-Xmx*` e, achando, adota o do usuário. Daí a linha em
`docker-compose.scanners.yml`.

**O número: `-Xmx1g` com `mem_limit: 2g` — heap em 50% do limite.** A regra é
essa proporção, não o valor absoluto: a JVM precisa de espaço comparável ao do
próprio heap para metaspace, code cache, buffers diretos e as ~120 threads que
o daemon mantém. Medido durante o scan do Juice Shop, o processo Java estabiliza
em torno de **600 MB de RSS** com esse heap — folga confortável. Se algum dia o
heap precisar subir, `ZAP_MEM_LIMIT` sobe junto e na mesma proporção; as duas
variáveis existem no `.env.example` lado a lado por isso.

### O que a JVM não explicava: o ZAP sobe navegadores

Com o heap corrigido, o container parou de morrer — mas ainda encostava no teto:
pico de **1.94 GiB de 2 GiB**, 3794 eventos de reclaim no cgroup e 256 MB
empurrados para swap. E o processo Java, medido no mesmo instante, usava só
594 MB. A conta não fechava porque a memória não era dele:

```
  PID   RSS    COMMAND
    1   594 MB java -Xmx1g -jar /zap/zap-2.16.1.jar -daemon …
  555   462 MB firefox-esr --marionette -headless …
  554   325 MB firefox-esr --marionette -headless …
  972   247 MB firefox-esr -contentproc …
```

A regra de active scan **DOM XSS** (id `40026`) avalia DOM executando a página,
e para isso sobe **Firefox headless de verdade** — dentro do mesmo container e
do mesmo cgroup do ZAP. Os navegadores custavam mais que o scanner inteiro.
Nenhum ajuste de `-Xmx` conserta isso: essa memória não passa pelo heap, nem
pelo processo Java. O `mem_limit` também não ajuda a diagnosticar — o container
é morto sem que nada no log do ZAP indique navegador algum.

Por isso `40026` entra desligada por padrão (`ZAP_ASCAN_DISABLED_RULES`), e o
motivo está na variável e não no código: quem tiver folga de RAM reabilita
apagando o id. É a regra mais cara da política por uma ordem de grandeza, e é
a única cujo custo não é de CPU nem de rede, mas de processo externo.

### O scan não terminava: quem precisa de teto é o ZAP, não o cliente

A outra execução mostrou o ZAP vivo, dezenas de polls bem-sucedidos por vários
minutos, e no fim `scanner_skipped error='timed out'`. Duas coisas erradas ao
mesmo tempo.

A primeira é contabilidade: `_poll_status` somava `poll_interval` a cada volta
e ignorava quanto tempo a própria requisição levou. Com o ZAP ocupado, um poll
de 30 s contava como 10 s — o teto declarado de 600 s valia muito mais que isso
na prática. Agora o tempo é medido no relógio monotônico, e existe um segundo
teto por **número de polls** (que é o que fecha o laço em teste, onde
`poll_interval=0` congela o relógio de parede).

A segunda é mais importante e é de desenho. Esperar mais **não resolve**: se o
cliente desiste, o scan é abandonado no meio e os alertas que o ZAP já havia
encontrado vão embora junto. Trocar 10 minutos por 40 apenas adia o mesmo zero.

O teto, então, foi para dentro do ZAP:

| Opção | Valor | O que corta |
|---|---|---|
| `spider maxDuration` | 3 min | tempo total de crawl |
| `spider maxChildren` | 10 | filhos por nó — listagem/paginação, que é a mesma rota repetida |
| `ascan maxScanDurationInMins` | 10 min | tempo total do active scan |
| `ascan maxRuleDurationInMins` | 2 min | uma regra cara (SQLi time-based) monopolizando o orçamento |
| `ascan threadPerHost` | 2 | concorrência — cada thread segura mensagens em memória |
| `ascan disableScanners` | `40026` | a regra de DOM XSS, que sobe Firefox headless (ver acima) |

Com isso o ZAP **encerra sozinho**, a fase chega a 100%, e `collect_alerts`
recolhe o que deu tempo de achar. Os tetos do cliente ficam deliberadamente
**acima** dos do ZAP (teto do ZAP + 2 min de folga): se o cliente estourar
primeiro, o diagnóstico não é "o alvo é grande", é "o ZAP não está respeitando
o próprio limite" — que é um defeito diferente e merece log diferente.

**O trade-off, dito por extenso:** escolhemos cobertura parcial em tempo
previsível, não cobertura total em tempo indeterminado. O Tier 3 roda depois do
Gate 2, num PR que já tem `high`/`critical` — quem está esperando esse
resultado precisa dele em minutos, e um DAST que devolve as vulnerabilidades
das primeiras dez rotas é infinitamente mais útil que um que devolve `[]` por
timeout. O `maxChildren=10` é a parte mais agressiva do corte e é a que dá o
melhor retorno: numa loja de exemplo, enumerar 200 produtos não descobre
superfície nova, é a mesma rota com id diferente. Quem tem alvo pequeno e quer
cobertura maior sobe os números no `.env` — todos são configuráveis, e `0`
desliga o teto correspondente (semântica do próprio ZAP).

### O que a medição mostrou

Duas execuções do `ZAPScanner` contra `http://juice-shop:3000`, com todo o resto
igual — a única diferença é a regra 40026:

| | DOM XSS ligado | DOM XSS desligado |
|---|---|---|
| Duração total | 300 s | **135 s** |
| Alertas | 66 | 62 |
| Pico de memória (cgroup) | 2.00 GiB — o teto | **1.06 GiB** |
| Eventos de reclaim | 3794 | **0** |
| Swap | 256 MB | 0 |

Quatro alertas de 66 (6%) custavam mais que o dobro do tempo e todo o orçamento
de memória — com o container operando encostado no limite, que é onde ele
morria antes do `-Xmx`. É a troca mais barata da lista, e a única em que
"reduzir escopo" não é escolha de gosto: sem ela, nenhum valor de `mem_limit`
que caiba nesta máquina sobrevive.

### As três falhas agora se distinguem no log

Era tudo `scanner_skipped` com a mensagem da biblioteca que estourou, e a
mensagem descreve o sintoma. Foi assim que "o container morreu por OOM" virou
um diagnóstico de DNS. Agora:

| Situação | Como aparece |
|---|---|
| O ZAP não está lá (morto, OOM, fora do ar) | `ZAPUnavailableError` — e o handshake em `/JSON/core/view/version/` a detecta **antes** de qualquer trabalho |
| O ZAP morreu no meio | `ZAPUnavailableError` depois de 3 polls seguidos falhando por erro de transporte |
| O scan não coube no teto | `ZAPScanTimeoutError`, com a fase e o **percentual em que parou** |
| Terminou e não achou nada | `zap_alerts_collected alerts_count=0` — sucesso, não falha |

`scanner_skipped` passou a registrar `error_type` além de `error`, para todos os
scanners: o tipo da exceção é o que separa "a ferramenta não está lá" de "não
terminou no tempo", e é a primeira coisa que se quer saber. Um blip isolado de
rede também deixou de custar o scan inteiro — um `ReadTimeout` num poll (cuja
mensagem é literalmente `timed out`) é tolerado até três vezes seguidas antes
de declararmos o daemon morto.

---

## 13.1 O que "Caldera ok" significa — e o que não significa

Três campos do `caldera_results` respondem perguntas diferentes, e confundi-los
já produziu leitura errada de relatório:

| Campo | Pergunta que responde |
|---|---|
| `status` | O serviço respondeu? (`reachable` / `failed`) |
| `caldera_validated` | A técnica **encontrada** foi emulada com sucesso? |
| `validacao_parcial` | Emulou-se algo da **mesma família**, mas não a técnica encontrada? |

`status` era `"ok"`, e isso se lia como sucesso mesmo num resultado com `0/0
técnicas executadas`. Foi renomeado para `reachable` justamente para não
responder uma pergunta que não é a dele.

### Fallback para a técnica-pai

O catálogo padrão do Caldera (Stockpile, ~162 abilities) não cobre todas as
sub-técnicas que o Tier 2 identifica. Num scan real as 7 técnicas da cadeia
(`T1036`, `T1059.007`, `T1185`, `T1550.001`, `T1552.001`, `T1553.001`,
`T1598.003`) mapearam para **zero** abilities: o catálogo tem
`T1059.001/.002/.004` e `T1552.002/.003/.004`, outras variantes das mesmas
famílias.

`_map_to_abilities` faz então duas passadas. A primeira casa exatamente. A
segunda, só para o que sobrou descoberto, tenta a **técnica-pai** — e recupera 3
abilities no exemplo acima.

**O que a segunda passada encontra não valida o achado.** Emular `T1059.001`
(PowerShell) quando o achado é `T1059.007` (JavaScript) é a mesma família, outro
ataque. Por isso `_parse_results` separa os elos bem-sucedidos: só os de técnica
casada **exatamente** ligam `caldera_validated`. Um sucesso vindo apenas do
fallback produz `caldera_validated: false` + `validacao_parcial: true`, e o
relatório diz explicitamente que o achado não foi validado.

Vale o alerta geral: um `success_rate` de 100% com `caldera_validated: false` não
é contradição — é a emulação dizendo "rodei tudo que consegui, e nada disso era
o seu problema".

### Por que o ID MITRE é extraído com regex

`technique` no `event_chain` vem de um LLM. O prompt pede só o identificador e
agora exige também `technique_parent`, mas instrução não é contrato: um
`"T1059 - Command and Scripting"` era usado verbatim, não casava com ability
nenhuma e a emulação rodava zero técnicas **sem erro algum**. `_tecnicas_da_cadeia`
extrai o ID com `\bT\d{4}(?:\.\d{3})?\b` e usa `technique_parent` só como
resgate — somá-lo à lista faria o casamento parecer exato e apagaria a distinção
acima.

---

## 14. Por que o Caldera tem um agente, e não vinte

O Caldera precisa de um alvo. Sem nenhum agente registrado, a operação termina
com cadeia vazia (`techniques_executed=0`, `caldera_validated=False`), e o
relatório parece dizer "a emulação não encontrou nada" quando na verdade não
havia onde executar. Por isso o compose sobe um container `caldera-agent` que
baixa o sandcat e se registra no grupo `red`.

O que não é óbvio é que **mais de um agente é tão errado quanto nenhum**, e por
um motivo que só aparece nos números.

### Uma operação roda cada ability em todos os agentes do grupo

O `CalderaClient` cria a operação apontando para um **grupo**
(`settings.CALDERA_AGENT_GROUP`, `red`), não para um agente. O planner atômico
então gera um elo por ability **por agente**. Com um agente, 3 abilities são 3
elos. Com vinte agentes, as mesmas 3 abilities viraram 44 elos executados.

O custo não é só de tempo. Cada elo é uma técnica MITRE ATT&CK sendo executada
de verdade dentro do sandbox — vinte vezes o que se pediu. E o `success_rate`,
que é `elos_bem_sucedidos / elos_totais`, passa a ser calculado sobre uma amostra
que não corresponde a alvo nenhum: ela mede vinte cópias do mesmo container, não
o ambiente que se queria avaliar. Como é o `success_rate` que alimenta o peso de
Caldera no score e o `caldera_validated` de cada passo do `attack_path`, o número
inflado atravessa o pipeline inteiro até o relatório.

### De onde vinham os vinte

Sem a flag `-paw`, o sandcat pede ao servidor um identificador novo a cada boot.
O serviço `caldera-agent` tem `restart: unless-stopped` — e esse `restart` existe
por um motivo legítimo: se o Caldera reiniciar, o agente precisa reconectar,
senão a operação seguinte encontra o grupo vazio. O resultado é que cada reinício
do container registrava um agente **a mais**, todos vivos aos olhos do servidor,
todos no grupo `red`. Vinte containers nunca existiram; existiu um container que
reiniciou vinte vezes.

### A correção: identidade, não faxina

O compose agora passa `-paw ${CALDERA_AGENT_PAW:-aperia-sandbox}`. O servidor
procura o agente pelo PAW que vem no beacon (`contact_svc.handle_heartbeat` →
`locate('agents', paw=...)`) e, encontrando, **atualiza** o registro em vez de
criar outro. Um container, um agente, para sempre.

Isso vale inclusive quando o Caldera é quem reinicia: o store de agentes vive em
RAM, então o servidor perde a lista e recria o registro no primeiro beacon — com
o mesmo PAW, continua sendo um só. E o `restart: unless-stopped` fica onde está,
porque continua sendo ele quem garante a reconexão; o que mudou é que reiniciar
deixou de ter custo.

### A segunda fonte: uma ability que instala agentes

A explicação acima estava certa e **incompleta**. Em 2026-08-02, com o `-paw`
fixo em vigor e o container do agente intocado, os vinte agentes voltaram em dez
minutos.

A fonte era a ability **"Start 54ndc47"** (`T1059.004`, plugin `stockpile`),
cujo executor linux é literalmente:

```
nohup ./sandcat.go -server #{server} &      payload: sandcat.go
```

Ela inicia um agente novo. E como uma operação executa cada ability em **todos**
os agentes do grupo, o laço se fecha sozinho: executa → nasce um agente → o
agente entra no grupo `red` → o planner atribui a mesma ability a ele → executa
de novo. A operação chegou a 43 elos e nunca finalizou; o cliente desistiu no
timeout de 600s enquanto o container continuava gerando processos.

Ela estava no catálogo desde sempre, inofensiva por falta de alcance: nada
mapeava para `T1059` até o fallback de técnica-pai passar a mapear.

**O filtro.** `_implanta_agente` descarta abilities cujo comando ou payload
referencia o binário do agente (`sandcat` ou `54ndc47`, as duas grafias que o
Stockpile usa) e roda **antes** do filtro de credencial — porque credencial
faltando só faz a ability falhar, enquanto esta multiplica o trabalho sem limite.

São 5 abilities de 70 linux no catálogo padrão: `Start 54ndc47`,
`Start 54ndc47 (2)`, `Sandcat`, `Copy 54ndc47` e `Weak executable files`. A
última merece nota: o comando dela parece uma busca inofensiva
(`find / -perm -333 …`), e o que ela faz é anexar um lançador do sandcat a todo
executável gravável que encontrar. É o payload, não o comando, que a entrega.

Perder essas cinco é ganho, não perda. Emular implantação de agente não diz nada
sobre o achado do scan — prova apenas que o Caldera consegue instalar o Caldera.

### O que não resolve, e por quê

O `untrusted_timer` do Caldera é a resposta errada para esta pergunta, por duas
razões. Ele não vive em `caldera/local.yml` (o config que montamos), e sim em
`conf/agents.yml`, que é da imagem. E, mais importante, ele **não apaga nada**:
depois de N segundos em silêncio o agente é marcado `untrusted`, o que impede
novos elos, mas o registro fica na lista para sempre. Serve para um agente que
morreu no meio de uma operação, não para higiene de identidade.

Limpar automaticamente no boot do agente também foi descartado: `DELETE
/api/v2/agents/{paw}` exige a chave de API do Caldera, e colocá-la dentro do
container do agente significaria dar credencial de red team justamente ao
container que existe para ser atacado — o oposto do que o isolamento de rede
tenta garantir. A limpeza é portanto manual, rodada do host:

```bash
.venv/bin/python scripts/caldera_limpar_agentes.py --dry-run
.venv/bin/python scripts/caldera_limpar_agentes.py
```

O critério é silêncio: um agente vivo faz beacon a cada 30–60s, então quem não é
visto há cinco minutos não vai voltar — o container que o registrou já não
existe. Agente sem `last_seen` legível nunca é removido; apagar o agente errado
custa uma operação sem alvo, e deixar um registro a mais custa nada.

### O sintoma agora é visível

O problema só apareceu porque alguém foi investigar outra coisa: em lugar nenhum
do sistema o número de agentes do grupo era registrado. `run_operation` agora
consulta `/api/v2/agents` antes de criar a operação e loga
`caldera_agentes_do_grupo` com a contagem e os PAWs — `info` quando é um,
`warning` quando não é. Como todo o resto do cliente, é best-effort: se a
consulta falhar, loga e segue, porque diagnóstico não pode derrubar o Tier 3.
