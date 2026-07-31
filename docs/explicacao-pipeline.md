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
Semgrep no repo inteiro levam minutos; ZAP fazendo active scan, OpenCTI
consultando threat intel e Caldera emulando técnicas MITRE em sandbox podem
levar de 30 a 60 minutos. Se todo PR disparasse os 3 tiers incondicionalmente,
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
depende de infraestrutura externa como ZAP/OpenCTI/Caldera. Tier 3 é
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
`start_pipeline` a partir do webhook. A ideia central é que cada elo da
chain é o resultado de uma task anterior — Celery passa esse resultado como
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
  → _prepare_tier3_payload → run_tier3_scan           [tier3]     ZAP + OpenCTI + Caldera
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

Há ainda um detalhe que reforça que esse componente está genuinamente fora
do caminho de execução, e não só "não chamado": o método `_cti_component` do
`RiskScorer` lê a chave `active_campaigns` do payload de CTI, mas o scan de
Tier 3 (`OpenCTIClient`) de fato produz a chave `active_threat`. Se o
`RiskScorer` fosse plugado hoje sem ajuste, o componente de CTI cairia
sempre no ramo `else` (25.0 fixo), porque a chave que ele procura nunca
existe no dict real. É uma divergência latente — não afeta nada porque o
código não roda, mas seria o primeiro bug a resolver no dia em que alguém
decidir plugar o scorer de verdade.

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
seguinte usa para consultar OpenCTI e descobrir se aquele CVE específico está
sendo explorado ativamente. Depois da dedup (que existe porque os mesmos
findings tendem a se repetir entre execuções e entre scanners, mas
deliberadamente não funde CVEs iguais vindos de fontes diferentes — o
`source` é parte da chave), o Claude Sonnet recebe o conjunto agregado e
tenta montar uma `event_chain`: não trata cada finding como isolado, mas
como possível passo de uma sequência de ataque, mapeando técnicas MITRE por
passo e devolvendo o primeiro `risk_score`.

**Tier 3 (ZAP + OpenCTI + Caldera, seguido de Claude Sonnet montando
attack_path)** só existe porque, até aqui, tudo foi análise estática — nada
foi de fato testado em execução. ZAP ataca o `target_url` real (DAST), e por
isso é a evidência mais forte de exploitabilidade: uma vulnerabilidade
confirmada por scan ativo pesa mais que uma inferida por padrão de código.
OpenCTI responde a uma pergunta que nenhum scanner estático consegue
responder por si — "esse CVE está sendo usado por atacantes de verdade, hoje,
no mundo real?" — trazendo `active_threat` e técnicas MITRE associadas.
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
