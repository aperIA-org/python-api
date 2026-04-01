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

## Executando com Docker

1. Build da imagem:

```bash
docker build -t python-api .
```

2. Subir o container:

```bash
docker run --rm -p 8000:8000 python-api
```

3. Testar health check:

```bash
curl http://127.0.0.1:8000/health
```

## Rotas

- `GET /health`

Resposta esperada:

```json
{
  "status": "ok"
}
```

## Parar o container

Pressione `Ctrl + C` no terminal onde o `docker run` estiver em execucao.