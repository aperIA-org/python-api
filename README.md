# aperIA — ASPM com heurística ofensiva via I.A

Plataforma de *Application Security Posture Management*. Um pull request aciona
um pipeline de scanners em três camadas; a I.A correlaciona os achados como um
atacante faria — montando o caminho que liga uma falha à outra — e devolve as
correções como **GitHub code suggestions** no próprio PR.

> **Premissa inviolável:** o aperIA **nunca** aplica código sozinho. Todo patch
> sai como sugestão para aprovação humana. O merge continua sendo decisão de
> quem revisa.

A diferença em relação a um agregador de scanners está na segunda metade: em
vez de entregar uma lista de centenas de achados isolados, o sistema pergunta
quais deles se encadeiam numa rota de ataque real, e prioriza por isso.

---

## Arquitetura

Clean Architecture. A dependência aponta sempre para dentro:

```
presentation  →  application  →  domain  ←  infrastructure
```

| Camada | Conteúdo |
|---|---|
| `app/domain/` | entidades, value objects, interfaces de repositório. **Puro** — sem import externo |
| `app/application/` | casos de uso |
| `app/infrastructure/` | scanners, clientes de I.A e Git, persistência, segurança |
| `app/presentation/` | rotas FastAPI, schemas e workers Celery |
| `app/core/` | o canvas Celery (`orchestrator.py`) e a configuração do broker |

O domínio não conhece FastAPI, SQLAlchemy nem a Anthropic. A infraestrutura
implementa as interfaces que ele declara. Não há container de injeção: o wiring
é manual, nas rotas via `Depends(get_db)` e nos workers por instanciação direta.

### O pipeline

Cinco filas Celery, uma por etapa, e dois portões que decidem se a execução
continua:

```
Tier 1   TruffleHog (credenciais) + Semgrep (arquivos alterados)
   │
  Gate 1 ──── bloqueia se houver segredo VERIFICADO
   │
Tier 2   Trivy (dependências) + Semgrep (completo) + Prowler (nuvem)
   │     → análise: correlação dos achados numa cadeia de eventos
   │     → relatório no PR
   │     → remediação: patches como code suggestion
   │
  Gate 2 ──── só escala se a severidade for alta ou crítica
   │
Tier 3   OWASP ZAP (DAST) + CISA KEV/EPSS (ameaças) + Caldera (emulação)
   │     → análise profunda: caminho de ataque, impacto, veredito
   │     → relatório final
```

> A interface do produto **não** nomeia a ferramenta por trás de cada etapa —
> ela descreve o que a etapa faz. Os nomes aparecem aqui porque este é o
> repositório do back-end, onde eles são o contrato com a API e com o banco.

A escalada é condicional de propósito: as etapas caras só rodam quando o que
veio antes justifica. Um PR sem achado relevante nunca chega ao Tier 3.

Duas decisões que moldam o resto do código:

**Nada derruba o pipeline.** Scanner que falha devolve lista vazia, I.A que
falha devolve resposta degradada, persistência que falha registra e segue. Um
scan parcial vale mais que um scan que não termina.

**Dicionários trafegam no canvas, não entidades.** O Celery serializa em JSON
entre as etapas, então os workers convertem na fronteira.

---

## Stack

FastAPI · Celery + Redis · PostgreSQL + SQLAlchemy + Alembic · Anthropic SDK ·
structlog · pytest · Docker Compose

---

## Rodar local

```bash
docker compose -f docker-compose.base.yml up -d --build
docker compose -f docker-compose.base.yml exec api alembic upgrade head
curl -s http://localhost:8000/health          # {"status":"ok"}

.venv/bin/python -m pytest tests/ -q
```

A base sobe API, worker, PostgreSQL e Redis — o suficiente para os Tiers 1 e 2.
Os scanners pesados do Tier 3 ficam em `docker-compose.scanners.yml`, atrás de
perfis (`--profile dast`, `--profile emulation`), porque consomem bem mais
recurso que o resto da stack.

Copie `.env.example` para `.env` antes de subir. Ele documenta cada variável,
incluindo o registro do GitHub App.

### Segurança operacional

Três pontos que não são configuráveis por conveniência:

- **O Caldera roda em rede isolada** (`internal: true`), sem rota para a
  internet. É emulação de adversário: o agente executa técnicas reais.
- **Toda chamada à I.A passa por um guard** que bloqueia o envio de material
  sensível — um segredo encontrado por um scanner não vai para o prompt.
- **O Tier 1 nunca chama a I.A.** É a camada que vê credenciais; mantê-la
  offline é o que garante que elas não saem da máquina.

Os logs são estruturados e nunca registram segredo em claro.

---

## Licença

[GNU General Public License v3.0](LICENSE) ou posterior.

Copyleft: trabalhos derivados precisam ser distribuídos sob a mesma licença,
com o código-fonte disponível.
