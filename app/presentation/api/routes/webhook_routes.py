from __future__ import annotations

import hashlib
import hmac

import structlog
from fastapi import APIRouter, HTTPException, Request

from app.application.use_cases.trigger_scan_use_case import dispatch_pipeline
from app.config import settings

router = APIRouter()
logger = structlog.get_logger()

# Documentação OpenAPI da rota (o corpo é lido bruto para validar o HMAC,
# então declaramos o schema manualmente via openapi_extra).
_WEBHOOK_OPENAPI_EXTRA = {
    "parameters": [
        {
            "name": "X-Hub-Signature-256",
            "in": "header",
            "required": True,
            "description": "Assinatura HMAC-SHA256 do corpo bruto, no formato `sha256=<hex>`.",
            "schema": {"type": "string"},
            "example": "sha256=7d38cdd689735b008b3c702edd92eea23791c5f6",
        },
        {
            "name": "X-GitHub-Event",
            "in": "header",
            "required": False,
            "description": "Tipo do evento GitHub (ex.: `pull_request`, `ping`).",
            "schema": {"type": "string"},
            "example": "pull_request",
        },
    ],
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "description": "Payload de webhook do GitHub (apenas campos consumidos).",
                    "properties": {
                        "action": {"type": "string", "example": "opened"},
                        "installation": {
                            "type": "object",
                            "properties": {"id": {"type": "integer", "example": 12345678}},
                        },
                        "repository": {
                            "type": "object",
                            "properties": {
                                "clone_url": {"type": "string", "example": "https://github.com/org/repo.git"},
                                "full_name": {"type": "string", "example": "org/repo"},
                            },
                        },
                        "pull_request": {
                            "type": "object",
                            "properties": {
                                "number": {"type": "integer", "example": 42},
                                "head": {"type": "object", "properties": {"sha": {"type": "string"}}},
                                "base": {"type": "object", "properties": {"sha": {"type": "string"}}},
                            },
                        },
                    },
                }
            }
        },
    },
}

_WEBHOOK_RESPONSES = {
    200: {
        "description": "Evento processado (`queued` dispara o pipeline; `ignored` caso contrário).",
        "content": {
            "application/json": {
                "examples": {
                    "queued": {"summary": "PR aberto/atualizado", "value": {"status": "queued", "commit_sha": "9b2e1f0a..."}},
                    "ignored_event": {"summary": "Evento não relevante", "value": {"status": "ignored", "event": "ping"}},
                    "ignored_no_installation": {"summary": "Sem installation_id", "value": {"status": "ignored", "reason": "no installation_id"}},
                }
            }
        },
    },
    401: {"description": "Assinatura HMAC ausente ou inválida.", "content": {"application/json": {"example": {"detail": "Invalid HMAC signature"}}}},
}


def _resolve_owner(installation_id: int, github_repo_id: int | None) -> tuple:
    """Resolve (user_id, repository_id) do repositório cadastrado, best-effort.

    Só consulta o banco quando a persistência de scan está ligada (em teste
    fica desligada → não exige Postgres). Repositório não cadastrado ou
    inativo → ``(None, None)`` (o scan roda, mas fica órfão e não aparece na
    leitura isolada de nenhum usuário).
    """
    if not settings.SCAN_PERSISTENCE_ENABLED or not github_repo_id:
        return (None, None)
    try:
        from app.infrastructure.database.sqlalchemy import SessionLocal
        from app.infrastructure.repositories.sqlalchemy_repository_repository import (
            SQLAlchemyRepositoryRepository,
        )

        with SessionLocal() as db:
            repo = SQLAlchemyRepositoryRepository(db).get_by_installation_and_repo(
                installation_id, github_repo_id
            )
        if repo is None or not repo.active:
            return (None, None)
        return (repo.user_id, repo.id)
    except Exception as exc:  # noqa: BLE001 — best-effort: nunca quebra o webhook
        logger.warning("webhook_owner_resolve_failed", installation_id=installation_id, error=str(exc))
        return (None, None)


def _verify_hmac(payload: bytes, signature_header: str) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(
        settings.GITHUB_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()
    received = signature_header.removeprefix("sha256=")
    return hmac.compare_digest(expected, received)


@router.post(
    "/github",
    tags=["webhook"],
    summary="Webhook de eventos do GitHub",
    response_description="Desfecho do processamento do webhook.",
    openapi_extra=_WEBHOOK_OPENAPI_EXTRA,
    responses=_WEBHOOK_RESPONSES,
)
async def github_webhook(request: Request) -> dict:
    """
    Recebe eventos do GitHub (GitHub App) e dispara o pipeline de segurança.

    A assinatura HMAC-SHA256 do corpo é validada contra o header
    `X-Hub-Signature-256` (segredo `GITHUB_WEBHOOK_SECRET`); assinatura
    ausente/inválida retorna `401`.

    Apenas eventos `pull_request` com ação `opened` ou `synchronize` disparam o
    pipeline (`queued`). Payloads sem `installation.id` ou outros eventos são
    ignorados (`ignored`).
    """
    payload_bytes = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not _verify_hmac(payload_bytes, signature):
        client_host = request.client.host if request.client else "unknown"
        logger.warning("webhook_hmac_invalid", ip=client_host)
        raise HTTPException(status_code=401, detail="Invalid HMAC signature")

    payload = await request.json()
    event = request.headers.get("X-GitHub-Event", "")
    installation_id = payload.get("installation", {}).get("id")

    if not installation_id:
        return {"status": "ignored", "reason": "no installation_id"}

    if event == "pull_request" and payload.get("action") in ("opened", "synchronize"):
        commit_sha = payload["pull_request"]["head"]["sha"]
        repo_url = payload["repository"]["clone_url"]
        pr_number = payload["pull_request"]["number"]
        repo_full_name = payload["repository"]["full_name"]
        github_repo_id = payload["repository"].get("id")
        base_sha = payload["pull_request"].get("base", {}).get("sha", commit_sha)

        # Atribui o scan ao dono (repo cadastrado + ativo). Órfão se não achar.
        user_id, repository_id = _resolve_owner(installation_id, github_repo_id)

        logger.info(
            "webhook_pr_received",
            commit_sha=commit_sha,
            pr_number=pr_number,
            repo=repo_full_name,
            owned=bool(user_id),
        )

        # Mesmo ponto de disparo do scan manual (`POST /repositories/{id}/scan`)
        # — os argumentos "de MVP" do canvas vivem lá, não aqui.
        dispatch_pipeline(
            commit_sha=commit_sha,
            repo_url=repo_url,
            repo_full_name=repo_full_name,
            installation_id=installation_id,
            pr_number=pr_number,
            base_sha=base_sha,
            user_id=user_id,
            repository_id=repository_id,
        )
        return {"status": "queued", "commit_sha": commit_sha}

    return {"status": "ignored", "event": event}
