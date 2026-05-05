# python-api

API simples em Python usando FastAPI.

Arquitetura organizada em DDD com camadas em `app/domain`, `app/infrastructure` e `app/presentation`.

## Estrutura criada

```text
.
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── main.py
├── app/
│   ├── main.py
│   ├── config.py
│   ├── application/
│   ├── domain/
│   ├── infrastructure/
│   └── presentation/
└── tests/
```

Observacao: a execucao do projeto agora e baseada em Docker (sem fluxo de Makefile/venv no README).

## Configuracao com .env (recomendado)

Para evitar configurar variaveis manualmente no terminal a cada execucao, prefira usar um arquivo .env na raiz do projeto.

1. Crie o arquivo .env na raiz do projeto.
2. Adicione as variaveis de conexao com o banco.

Exemplo de .env:

```env
DB_HOST=db
DB_PORT=5432
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=postgres
DB_FORCE_IPV4=false
```

Tambem e possivel informar a URL completa:

```env
DATABASE_URL=postgresql+psycopg://postgres:postgres@db:5432/postgres
```

Prioridade de leitura:

1. DATABASE_URL (se informado)
2. Montagem da URL com DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD

Obs.: O uso de export no terminal continua possivel, mas o fluxo recomendado para este projeto e manter a configuracao centralizada no arquivo .env.

### Erro de rede com IPv6

Se aparecer erro como `Network is unreachable` com endereco IPv6 no log da conexao, ative no arquivo `.env`:

```env
DB_FORCE_IPV4=true
```

## Requisitos

- Docker
- Docker Compose

## Executando com Docker Compose

1. Construir e subir a API:

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
- `POST /users`
- `GET /users/{user_id}`

Resposta esperada:

```json
{
  "status": "ok"
}
```

Exemplo de criacao de usuario:

```bash
curl -X POST http://127.0.0.1:8000/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "hideki",
    "password": "123456",
    "email": "hideki@example.com"
  }'
```