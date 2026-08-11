"""Exporta o schema OpenAPI da app FastAPI para openapi.yaml.

A fonte da verdade e o codigo (rotas + schemas Pydantic); este script
apenas serializa o schema gerado pela app. Rode apos alterar rotas/schemas:

    .venv/bin/python scripts/export_openapi.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

# Garante que a raiz do projeto esteja no sys.path ao rodar como script.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.main import app  # noqa: E402  (import apos ajuste do sys.path)

_HEADER = (
    "# Gerado automaticamente a partir da app FastAPI (app.main:app). NAO editar a mao.\n"
    "# Fonte da verdade = codigo (rotas + schemas Pydantic). Para regenerar:\n"
    "#   .venv/bin/python scripts/export_openapi.py\n"
    "# Documentacao interativa em runtime: /docs (Swagger UI) e /redoc.\n"
)

_OUTPUT = _ROOT / "openapi.yaml"


def main() -> None:
    schema = app.openapi()
    with _OUTPUT.open("w", encoding="utf-8") as fh:
        fh.write(_HEADER)
        yaml.safe_dump(schema, fh, allow_unicode=True, sort_keys=False, width=100)
    print(f"openapi.yaml gerado com {len(schema['paths'])} paths em {_OUTPUT}")


if __name__ == "__main__":
    main()
