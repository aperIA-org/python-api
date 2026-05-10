import re

from fastapi import APIRouter, Request, HTTPException, Header
from pydantic import BaseModel, field_validator

from core.celery_app import celery_app
from core.exceptions import InvalidWebhookSignature
from infrastructure.git.github_client import GitHubClient
import structlog

router = APIRouter()
logger = structlog.get_logger()


class GitHubPushPayload(BaseModel):
    after: str
    ref: str
    repository: dict
    installation: dict | None = None

    @field_validator("after")
    @classmethod
    def validate_commit_sha(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{40}", v):
            raise ValueError(f"SHA inválido: {v}")
        return v


@router.post("/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(default=""),
    x_github_event: str = Header(default=""),
) -> dict:
    body = await request.body()

    try:
        GitHubClient.verify_webhook_signature(body, x_hub_signature_256)
    except InvalidWebhookSignature:
        raise HTTPException(status_code=401, detail="Invalid signature")

    if x_github_event not in ("push", "pull_request"):
        return {"status": "ignored", "event": x_github_event}

    try:
        import json
        payload = GitHubPushPayload(**json.loads(body))
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid payload")

    repo_url = payload.repository.get("clone_url", "")
    installation_id = (payload.installation or {}).get("id")
    pr_number = None

    if x_github_event == "pull_request":
        pr_number = payload.repository.get("number")

    celery_app.send_task(
        "presentation.workers.scan_worker.run_scan",
        kwargs={
            "commit_sha": payload.after,
            "repo_url": repo_url,
            "pr_number": pr_number,
            "installation_id": installation_id,
        },
        queue="scan",
    )

    logger.bind(
        commit_sha=payload.after,
        repo_url=repo_url,
        event=x_github_event,
    ).info("webhook_accepted")

    return {"status": "accepted", "commit_sha": payload.after}
