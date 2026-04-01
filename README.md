# python-api

API simples em Python usando FastAPI.

## Requisitos

- Python 3.10+

## Instalação

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Executando

```bash
uvicorn main:app --reload
```

## Makefile

O projeto possui um `Makefile` para facilitar a execução da API.

Comando disponível:

- `make run`: sobe a aplicação em `127.0.0.1:8000` com recarregamento automático.

Uso:

```bash
make run
```

## Rotas

- `GET /health`

Resposta esperada:

```json
{
	"status": "ok"
}
```