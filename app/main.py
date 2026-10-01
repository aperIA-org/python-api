from __future__ import annotations

import logging

import structlog
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.infrastructure.scanners.fargate_tasks import (
    marcador_do_scan,
    parar_tarefas_orfas,
)
from app.application.use_cases.recover_stale_scans_use_case import (
    RecoverStaleScanJobsUseCase,
)
from app.config import settings
from app.infrastructure.database.sqlalchemy import SessionLocal, engine
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.presentation.api.routes.auth_routes import router as auth_router
from app.presentation.api.routes.finding_routes import router as finding_router
from app.presentation.api.routes.github_routes import router as github_router
from app.presentation.api.routes.health_routes import router as health_router
from app.presentation.api.routes.remediation_routes import (
    router as remediation_router,
)
from app.presentation.api.routes.repository_routes import router as repository_router
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
        "name": "github",
        "description": "Conexão da conta GitHub (instalação do App) e repos disponíveis (protegido por JWT).",
    },
    {
        "name": "repositories",
        "description": "Gestão dos repositórios conectados para análise, isolados por usuário (protegido por JWT).",
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
log = structlog.get_logger()

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


@app.on_event("startup")
def recover_stale_scan_jobs() -> None:
    """Libera, no boot, os ``ScanJob`` que ficaram presos em ``queued``/``running``.

    O broker (Redis) e o banco (Postgres) têm durabilidades diferentes: se a
    stack for recriada antes de um worker consumir a fila, a tarefa evapora mas
    a linha de ``scan_jobs`` sobrevive — órfã, sem ninguém capaz de concluí-la.
    Além de mentir no ``GET /scans``, ela bloqueia novos scans daquele commit
    (409 em ``POST /repositories/{id}/scan``).

    Não há celery beat na stack, então o boot é a varredura periódica que
    temos — e é o momento certo: se a API está subindo, o que estava em voo no
    broker anterior já se perdeu.

    Best-effort, como o resto da persistência de ``ScanJob``: qualquer falha é
    logada e a API sobe do mesmo jeito.
    """
    if not settings.SCAN_PERSISTENCE_ENABLED:
        return
    try:
        with SessionLocal() as db:
            liberados = RecoverStaleScanJobsUseCase(
                SQLAlchemyScanJobRepository(db)
            ).execute()
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort: nunca impede o boot
        log.warning("scan_jobs_stale_recovery_failed", error=str(exc))
        return
    if liberados:
        log.info(
            "scan_jobs_stale_recovery_done",
            liberados=len(liberados),
            commits=liberados,
        )


@app.on_event("startup")
def stop_orphan_fargate_tasks() -> None:
    """Encerra, no boot, tarefas Fargate cujo scan já não existe.

    Mesma razão da varredura acima, um andar abaixo: um deploy recria o
    container do worker e a tarefa Celery do Tier 3 morre sem rodar o
    ``finally`` que derruba o teste dinâmico e a emulação. Elas ficam de pé
    consumindo até o teto de uma hora do próprio container — e quem tentou
    cancelar vê a tarefa viva e conclui que o cancelamento falhou.

    Roda depois de ``recover_stale_scan_jobs`` de propósito: é aquela varredura
    que encerra os scans presos, e é a lista de scans **ainda** em andamento que
    diz quais tarefas têm dono.
    """
    if not settings.SCAN_PERSISTENCE_ENABLED:
        return
    try:
        with SessionLocal() as db:
            ativos = SQLAlchemyScanJobRepository(db).list_in_progress()
        marcadores = {marcador_do_scan(job.commit_sha) for job in ativos}
        paradas = parar_tarefas_orfas(marcadores)
    except Exception as exc:  # noqa: BLE001 — best-effort: nunca impede o boot
        log.warning("fargate_orphan_sweep_failed", error=str(exc))
        return
    if paradas:
        log.warning("fargate_orphan_tasks_stopped", total=len(paradas), marcadores=paradas)

app.include_router(health_router)
app.include_router(user_router)
app.include_router(auth_router)
app.include_router(finding_router)
app.include_router(remediation_router)
app.include_router(scan_router)
app.include_router(github_router)
app.include_router(repository_router)
app.include_router(webhook_router, prefix="/webhook")
