# Documentação do aperIA

A documentação é organizada segundo o [framework Diátaxis](https://diataxis.fr/):
cada documento serve a **uma** necessidade — aprender, resolver um problema,
consultar um fato ou entender um conceito. Comece pelo quadrante certo:

| Quero… | Vá para | Tipo |
|---|---|---|
| **Aprender** rodando o projeto do zero | [tutorial-primeiro-scan.md](tutorial-primeiro-scan.md) | Tutorial |
| **Resolver** uma tarefa específica | [How-to guides](#how-to-guides) | How-to |
| **Consultar** rotas, variáveis, modelos | [referencia.md](referencia.md) | Reference |
| **Entender** como o pipeline funciona e por quê | [explicacao-pipeline.md](explicacao-pipeline.md) | Explanation |
| **Saber o que falta** e por onde seguir | [pendencias.md](pendencias.md) | — |

## Tutorial

- **[Seu primeiro scan](tutorial-primeiro-scan.md)** — lição guiada que sobe a
  stack e leva um webhook simulado do disparo ao pipeline, 100% local, sem
  chaves nem domínio.

## How-to guides

Receitas orientadas a objetivo (assumem que você já conhece o básico):

- **[Como subir a stack](howto/subir-a-stack.md)** — containers base, camadas
  opcionais (scanners/observabilidade), migrations e gotchas.
- **[Como conectar uma conta GitHub](howto/conectar-github.md)** — registrar o
  GitHub App, expor o localhost sem domínio (ngrok), conectar a conta, ativar
  repositórios e desconectar.
- **[Como disparar uma análise](howto/disparar-analise.md)** — via PR real num
  repositório conectado, via scan manual pela API (sem PR) ou via webhook
  simulado local.
- **[Como consultar findings, scans e relatórios](howto/consumir-resultados.md)**
  — obter um JWT e consumir os dados, isolados por usuário.
- **[Como rodar os testes](howto/rodar-testes.md)** — suíte, cobertura e execução
  no container.

## Reference

- **[Referência](referencia.md)** — rotas da API, variáveis de ambiente, modelos
  de dados (`Finding`, `ScanJob`, `Repository`, `GithubAccount`), serviços/containers
  e o plumbing do Claude.

## Explanation

- **[O pipeline por dentro](explicacao-pipeline.md)** — arquitetura de 3 tiers,
  canvas/bridges, gates vs. score do Claude, filosofia best-effort, o modelo de
  isolamento multi-tenant e por que jobs travados existem (assimetria de
  durabilidade entre Postgres e Redis) e como o sistema se recupera deles.

---

> Fonte da verdade continua sendo o **código**. A referência de API tem um
> espelho executável em [`../openapi.yaml`](../openapi.yaml) (gerado por
> `scripts/export_openapi.py`) e na doc interativa em `/docs` (Swagger UI).
