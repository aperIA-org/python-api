from __future__ import annotations

import hashlib
import hmac

import structlog
from fastapi import APIRouter, HTTPException, Request

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
        base_sha = payload["pull_request"].get("base", {}).get("sha", commit_sha)

        # Import tardio para evitar criar a app Celery durante o tempo
        # de carregamento dos testes do webhook.
        from app.core.orchestrator import start_pipeline

        logger.info(
            "webhook_pr_received",
            commit_sha=commit_sha,
            pr_number=pr_number,
            repo=repo_full_name,
        )

        # Para o MVP, o repo_path/changed_files virão de uma task de
        # checkout no início do pipeline (pós-MVP). No estado atual:
        # - repo_path: stub (scanners run_safe → [] sem path real)
        # - changed_files: lista vazia (Semgrep T1 vira no-op rápido)
        # - target_url: vem de configuração do repo ou None (ZAP skipa)
        start_pipeline(
            commit_sha=commit_sha,
            repo_url=repo_url,
            pr_number=pr_number,
            installation_id=installation_id,
            repo_full_name=repo_full_name,
            repo_path=f"/tmp/aperia/{commit_sha[:12]}",
            base_sha=base_sha,
            head_sha=commit_sha,
            changed_files=[],
            target_url=None,
        )
        return {"status": "queued", "commit_sha": commit_sha}

    return {"status": "ignored", "event": event}
