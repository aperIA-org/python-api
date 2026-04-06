# python-api

API de autenticacao em Python usando FastAPI.

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

## Endpoints

### `POST /users` (cadastro principal)

Payload esperado:

```json
{
  "username": "nome",
  "password": "Senha123!",
  "email": "email1@email.com"
}
```

Status esperado:
- `201 Created`

Resposta esperada (exemplo):

```json
{
  "message": "Usuario cadastrado com sucesso.",
  "user": {
    "id": "uuid",
    "username": "nome",
    "email": "email1@email.com",
    "createdAt": "2026-04-06T00:00:00.000Z"
  }
}
```

### `POST /auth/register` (alias de cadastro)

Mesmo payload e comportamento de `POST /users`.

### `POST /auth/login`

Payload:

```json
{
  "email": "email1@email.com",
  "password": "Senha123!"
}
```

Status esperado:
- `200 OK`

Resposta esperada (exemplo):

```json
{
  "token": "jwt.token.aqui",
  "tokenType": "Bearer"
}
```

### `GET /auth/me`

Header:

```txt
Authorization: Bearer <token>
```

Status esperado:
- `200 OK`

Resposta esperada (exemplo):

```json
{
  "user": {
    "id": "uuid",
    "username": "nome",
    "email": "email1@email.com",
    "createdAt": "2026-04-06T00:00:00.000Z"
  }
}
```

## Teste rapido com cURL (Render)

Base URL:

```txt
https://python-api-o08q.onrender.com
```

### 1) Cadastro

```bash
curl -X POST "https://python-api-o08q.onrender.com/users" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"nome\",\"password\":\"Senha123!\",\"email\":\"email1@email.com\"}"
```

### 2) Login

```bash
curl -X POST "https://python-api-o08q.onrender.com/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"email1@email.com\",\"password\":\"Senha123!\"}"
```

### 3) Rota protegida

```bash
curl -X GET "https://python-api-o08q.onrender.com/auth/me" \
  -H "Authorization: Bearer SEU_TOKEN_AQUI"
```
