# aperIA — Guia de Execução

Este guia foi reorganizado segundo o [Diátaxis](https://diataxis.fr/) e agora
vive em [`docs/`](docs/README.md), separado por tipo de necessidade. Use o mapa
abaixo para ir direto ao ponto.

## Comece por aqui

**Primeira vez?** Siga o tutorial — sobe a stack e roda um scan do zero, 100%
local, sem precisar de chaves nem domínio:

➡️ **[Tutorial: seu primeiro scan](docs/tutorial-primeiro-scan.md)**

## Mapa da documentação

| Objetivo | Documento |
|---|---|
| Aprender rodando do zero | [Tutorial — primeiro scan](docs/tutorial-primeiro-scan.md) |
| Subir a stack (Docker, migrations, camadas) | [How-to — subir a stack](docs/howto/subir-a-stack.md) |
| Conectar o GitHub e ativar repositórios | [How-to — conectar GitHub](docs/howto/conectar-github.md) |
| Disparar uma análise (PR real ou simulada) | [How-to — disparar análise](docs/howto/disparar-analise.md) |
| Consultar findings / scans / relatórios | [How-to — consumir resultados](docs/howto/consumir-resultados.md) |
| Rodar os testes | [How-to — rodar os testes](docs/howto/rodar-testes.md) |
| Consultar rotas, variáveis, modelos de dados | [Referência](docs/referencia.md) |
| Entender o pipeline (tiers, gates, isolamento) | [Explicação — o pipeline por dentro](docs/explicacao-pipeline.md) |

Índice completo em **[`docs/README.md`](docs/README.md)**.

## Do zero ao `queued` (atalho)

```bash
docker compose -f docker-compose.base.yml up -d --build
docker compose -f docker-compose.base.yml exec api alembic upgrade head
curl -s http://localhost:8000/health
```

O passo a passo comentado (incluindo o disparo do webhook e o que esperar sem
créditos/repo real) está no [tutorial](docs/tutorial-primeiro-scan.md).
