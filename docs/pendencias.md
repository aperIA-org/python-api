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

## 1. DNS do Docker cai sob carga (bloqueia validar o Tier 3)

**Sintoma.** No meio de um scan DAST, o worker perde resolução de nome para
*todos* os serviços ao mesmo tempo:

```
19:39:41  GET http://zap:8090/JSON/ascan/view/status/  200 OK
19:39:51  GET http://zap:8090/JSON/ascan/view/status/  200 OK
19:40:02  GET http://zap:8090/JSON/ascan/view/status/  200 OK
19:40:23  scanner_skipped  error='[Errno -3] Temporary failure in name resolution'
19:40:34  caldera_run_safe_failed  error='[Errno -3] Temporary failure in name resolution'
```

**O que já está descartado.** Não é configuração de rede nem credencial: minutos
antes do scan, os três respondiam `HTTP 200` a partir do próprio worker. O
código de erro é `EAI_AGAIN` (**-3**, servidor de DNS não respondeu), não
`EAI_NONAME` (-2, host inexistente) — timeout, não nome errado.

**Hipótese principal.** Exaustão de recursos do WSL2 derrubando o DNS embutido
do Docker (`127.0.0.11`). Encaixa com o perfil: resolve parado, falha durante a
varredura ativa, que é o momento de pico.

**Armadilha adicional já observada e corrigida.** Rodar `docker compose` com
*conjuntos diferentes de arquivos* recria a rede e deixa containers presos numa
instância antiga com o mesmo nome. Ficou assim por um tempo:

```
python-api_aperia_net → api, db, redis, 5 workers      (zap/caldera/juice-shop FORA)
```

**Regra que evita:** sempre invocar compose com o **mesmo conjunto completo** de
arquivos, ou usar `--force-recreate` nos serviços que ficaram para trás.

**Próximos passos**
1. Repetir o scan com a máquina ociosa e só `base + zap + juice-shop` no ar.
2. Se reproduzir, medir: `docker stats` durante o scan e limites de memória do
   WSL (`.wslconfig`).
3. Mitigação de código, se o ambiente não permitir folga: resolver o host uma
   vez e reusar o IP, ou retry com re-resolução nos clients de ZAP/Caldera.
   **Só depois de confirmar que é ambiente** — mitigar antes esconde a causa.

---

## 2. Tier 3 nunca completou de ponta a ponta

O caminho está **provado até o polling**: o ZAP autentica, o scan ativo é
lançado e acompanhado por mais de um minuto. O que falta é uma execução que
chegue ao fim e grave `zap_findings > 0`.

Bloqueado por §1. Sem novidade de código — é validação.

**Próximo passo.** Com a máquina folgada, disparar scan no `juice-shop` local e
conferir `tier3_scan_complete` com `zap_findings` diferente de zero.

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

## 4. Caldera — RESOLVIDO (2026-08-01), falta validar em execução

Três bloqueios distintos, resolvidos em sequência:

**1. Crash no boot.** A imagem `5.0.0` traz o código-fonte do plugin `magma` (a
UI web) mas não os assets compilados, e `rest_api.py` registra a rota estática
dele **incondicionalmente**. Contornado com `tmpfs` no caminho esperado.

**2. Chave de API.** A imagem gera `api_key_red` aleatório por versão; nosso
cliente mandava `''`. Fixada por `caldera/local.yml` montado.

```
chave vazia (antes)        HTTP 401
chave de caldera/local.yml HTTP 200
```

**3. Não havia o que executar — e este era o bloqueio real.**
`_map_to_abilities()` era um stub com `return []`: o adversário nascia **sem
nenhuma ability**, a operação terminava com cadeia vazia e
`caldera_validated` era sempre `False`. Parecia "emulação não achou nada"
quando nada havia sido executado — a mesma confusão entre *não achei* e *não
procurei* que já tinha aparecido no Tier 1.

Implementado e **validado contra o Caldera real**, o que corrigiu duas
suposições minhas que estavam erradas:

| Suposição | Realidade |
|---|---|
| `GET /api/v2/abilities?technique_id=T1082` filtra | responde **422**; filtro é local |
| N requisições, uma por técnica | catálogo tem 162 abilities — **uma** requisição basta |
| `technique_id` é sempre `T1082` | também há sub-técnicas (`T1497.003`) |

Mapeamento conferido no catálogo real: `T1082` → 2 abilities linux,
`T1059` → 1, `T1497` → 1 (via sub-técnica), as três juntas com `T1057` → 7.

**4. Agente sandcat.** Novo serviço `caldera-agent` (perfil `emulation`),
**somente** na rede `aperia_caldera_sandbox` (`internal: true`) porque executa
técnicas MITRE reais. Registrado e confirmado:

```
agentes registrados: 1
  grupo=red plataforma=linux host=8fb03b1de862
```

O probe de prontidão do agente é o **próprio download do sandcat**: usar
`GET /` não funciona, porque nesta imagem ele responde 500
(`Template 'index.html' not found`) — mesma causa do crash de boot. Esperar por
um endpoint quebrado prenderia o agente para sempre.

**O que falta:** uma operação real de ponta a ponta, com `caldera_validated`
vindo `True`. Só depende de rodar — ver §2.

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

**Próximo passo.** Agrupar na UI por `secret_type` + valor, com contagem e
expansão ("49 ocorrências em `frontend/src/assets/i18n/`"). É mudança de
apresentação; o dado no banco não precisa mudar.

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
