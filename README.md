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

## Rotas

- `GET /health`

Resposta esperada:

```json
{
	"status": "ok"
}
```