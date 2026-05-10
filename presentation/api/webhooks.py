import json
import re

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, field_validator

from core.celery_app import celery_app
from core.exceptions import InvalidWebhookSignature
from core.security import verify_github_signature
from core.config import settings
import structlog

router = APIRouter()
logger = structlog.get_logger()

_PROTECTED_REFS = {"refs/heads/main", "refs/heads/master"}


class _PushPayload(BaseModel):
    after: str
    ref: str
    before: str
    repository: dict
    installation: dict | None = None

    @field_validator("after", "before")
    @classmethod
    def validate_sha(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{40}", v):
            raise ValueError(f"SHA inválido: {v}")
        return v


class _PRPayload(BaseModel):
    action: str
    number: int
    pull_request: dict
    repository: dict
    installation: dict | None = None


@router.post("/github")
async def github_webhook(request: Request) -> dict:
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    event = request.headers.get("X-GitHub-Event", "")

    try:
        verify_github_signature(body, signature, settings.GITHUB_WEBHOOK_SECRET)
    except InvalidWebhookSignature:
        logger.warning("webhook_invalid_signature", event=event)
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        raw = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=422, detail="Invalid JSON")

    if event == "push":
        return await _handle_push(raw)

    if event == "pull_request":
        return await _handle_pull_request(raw)

    return {"status": "ignored", "event": event}


async def _handle_push(raw: dict) -> dict:
    try:
        payload = _PushPayload(**raw)
    except Exception:
        return {"status": "ignored", "reason": "invalid push payload"}

    if payload.ref in _PROTECTED_REFS:
        return {"status": "skipped", "reason": "direct push to protected branch"}

    repo_url = payload.repository.get("clone_url", "")
    repo_full_name = payload.repository.get("full_name", "")
    installation_id = (payload.installation or {}).get("id")

    celery_app.send_task(
        "presentation.workers.scan_worker.run_scan",
        kwargs={
            "commit_sha": payload.after,
            "base_sha": payload.before,
            "repo_url": repo_url,
            "repo_full_name": repo_full_name,
            "pr_number": None,
            "installation_id": installation_id,
        },
        queue="scan",
    )

    logger.bind(
        commit_sha=payload.after,
        repo_url=repo_url,
        event="push",
    ).info("webhook_accepted")
    return {"status": "queued", "commit_sha": payload.after}


async def _handle_pull_request(raw: dict) -> dict:
    try:
        payload = _PRPayload(**raw)
    except Exception:
        return {"status": "ignored", "reason": "invalid pr payload"}

    if payload.action not in ("opened", "synchronize", "reopened"):
        return {"status": "ignored", "action": payload.action}

    pr = payload.pull_request
    commit_sha = pr.get("head", {}).get("sha", "")
    base_sha = pr.get("base", {}).get("sha", "")

    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        return {"status": "ignored", "reason": "invalid head sha"}

    repo_url = payload.repository.get("clone_url", "")
    repo_full_name = payload.repository.get("full_name", "")
    installation_id = (payload.installation or {}).get("id")

    celery_app.send_task(
        "presentation.workers.scan_worker.run_scan",
        kwargs={
            "commit_sha": commit_sha,
            "base_sha": base_sha,
            "repo_url": repo_url,
            "repo_full_name": repo_full_name,
            "pr_number": payload.number,
            "installation_id": installation_id,
        },
        queue="scan",
    )

    logger.bind(
        commit_sha=commit_sha,
        repo_url=repo_url,
        pr_number=payload.number,
        event="pull_request",
    ).info("webhook_accepted")
    return {"status": "queued", "commit_sha": commit_sha, "pr_number": payload.number}
