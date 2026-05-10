from fastapi import FastAPI
from core.config import settings
from core.logging import configure_logging
from presentation.api import webhooks, findings, scans, reports, health

configure_logging()


def create_app() -> FastAPI:
    app = FastAPI(
        title="aperIA",
        version="0.1.0",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url=None,
    )
    app.include_router(health.router,   tags=["health"])
    app.include_router(webhooks.router, prefix="/webhook", tags=["webhooks"])
    app.include_router(findings.router, prefix="/findings", tags=["findings"])
    app.include_router(scans.router,    prefix="/scans",    tags=["scans"])
    app.include_router(reports.router,  prefix="/reports",  tags=["reports"])
    return app


app = create_app()
