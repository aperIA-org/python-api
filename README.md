# python-api

API simples em Python usando FastAPI.

## Requisitos

- Docker
- Docker Compose

## Executando com Docker Compose

1. Subir a API:

```bash
docker compose up --build
```

2. Testar health check:

```bash
curl http://127.0.0.1:8000/health
```

3. Parar e remover os recursos:

```bash
docker compose down
```

## Rotas

- `GET /health`

Resposta esperada:

```json
{
  "status": "ok"
}
```