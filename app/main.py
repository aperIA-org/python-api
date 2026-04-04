import logging

from fastapi import FastAPI
from sqlalchemy.exc import SQLAlchemyError

from app.infrastructure.database.sqlalchemy import engine
from app.infrastructure.persistence.models.base import Base
from app.presentation.api.routes.health_routes import router as health_router
from app.presentation.api.routes.user_routes import router as user_router

app = FastAPI(title="Python API")

logger = logging.getLogger(__name__)

@app.on_event("startup")
def init_database() -> None:
    try:  
        Base.metadata.create_all(bind=engine)
    except SQLAlchemyError:
        logger.warning(
            "Nao foi possivel conectar no banco durante o startup. "
            "A API permaneceu ativa e tentara conectar quando houver requisicoes."
        )

app.include_router(health_router)
app.include_router(user_router)
