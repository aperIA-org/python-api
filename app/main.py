from __future__ import annotations

import logging

from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.infrastructure.database.sqlalchemy import engine
from app.presentation.api.routes.auth_routes import router as auth_router
from app.presentation.api.routes.finding_routes import router as finding_router
from app.presentation.api.routes.health_routes import router as health_router
from app.presentation.api.routes.scan_routes import router as scan_router
from app.presentation.api.routes.user_routes import router as user_router
from app.presentation.api.routes.webhook_routes import router as webhook_router

# Descrição exibida no topo do Swagger UI (/docs) e ReDoc (/redoc).
_DESCRIPTION = """
API do **aperIA** — ASPM (Application Security Posture Management) open-source.

Um webhook de Pull Request do GitHub dispara um pipeline de scanners de
segurança em 3 tiers (via Celery). O Claude raciocina como atacante
(correlaciona findings, monta attack paths) e entrega patches como
**GitHub code suggestions** para aprovação humana.

> **Premissa inviolável:** o aperIA **nunca** aplica código sozinho.
> Todo patch sai como code suggestion para aprovação humana.
"""

# Metadados das tags — controlam a ordem e a descrição dos grupos no /docs.
_TAGS_METADATA = [
    {"name": "health", "description": "Verificação de disponibilidade do serviço."},
    {
        "name": "auth",
        "description": "Autenticação e ciclo de vida de tokens (login, refresh com rotação, logout).",
    },
    {"name": "users", "description": "Criação e consulta de usuários."},
    {
        "name": "findings",
        "description": "Consulta de findings de segurança persistidos pelo pipeline (protegido por JWT).",
    },
    {
        "name": "scans",
        "description": "Consulta do status/progresso do pipeline por commit (ScanJob) (protegido por JWT).",
    },
    {
        "name": "webhook",
        "description": "Recepção de eventos do GitHub que disparam o pipeline de segurança.",
    },
]

app = FastAPI(
    title="aperIA - Python API",
    version="1.0.0",
    description=_DESCRIPTION,
    openapi_tags=_TAGS_METADATA,
    contact={"name": "aperIA"},
    license_info={"name": "Open Source"},
)

logger = logging.getLogger(__name__)

@app.on_event("startup")
def init_database() -> None:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        logger.warning(
            "Nao foi possivel conectar no banco durante o startup. "
            "A API permaneceu ativa e tentara conectar quando houver requisicoes.",
            exc_info=True,
        )

app.include_router(health_router)
app.include_router(user_router)
app.include_router(auth_router)
app.include_router(finding_router)
app.include_router(scan_router)
app.include_router(webhook_router, prefix="/webhook")
