import hmac
import hashlib

import structlog
import httpx

from core.config import settings
from core.exceptions import GitHubClientError, InvalidWebhookSignature

logger = structlog.get_logger()

# TODO: validar com doc oficial — GitHub REST API v3 + GitHub Apps


class GitHubClient:
    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            base_url="https://api.github.com",
            headers={
                "Authorization": f"token {settings.GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=httpx.Timeout(30.0, connect=5.0),
        )

    @staticmethod
    def verify_webhook_signature(body: bytes, signature_header: str) -> None:
        """Lança InvalidWebhookSignature se a assinatura HMAC for inválida."""
        if not signature_header:
            raise InvalidWebhookSignature("Signature header ausente")

        expected = "sha256=" + hmac.new(
            settings.GITHUB_WEBHOOK_SECRET.encode("utf-8"),
            body,
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected, signature_header):
            raise InvalidWebhookSignature("Assinatura inválida")

    async def create_code_suggestion(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
        file_path: str,
        line_number: int,
        suggestion_body: str,
    ) -> int:
        """
        Posta code suggestion como review comment.
        NUNCA faz auto-apply — apenas entrega a suggestion para aprovação humana.
        """
        # DEBT: implementar na Fase 3 com github_client real
        logger.bind(
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            file_path=file_path,
        ).info("code_suggestion_queued")
        return 0

    async def set_commit_status(
        self,
        owner: str,
        repo: str,
        commit_sha: str,
        state: str,
        description: str,
        context: str = "aperia/security",
    ) -> None:
        try:
            response = await self._client.post(
                f"/repos/{owner}/{repo}/statuses/{commit_sha}",
                json={
                    "state": state,
                    "description": description[:140],
                    "context": context,
                },
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise GitHubClientError(f"Falha ao definir commit status: {exc}") from exc

    async def create_pr_comment(
        self, owner: str, repo: str, pr_number: int, body: str
    ) -> None:
        try:
            response = await self._client.post(
                f"/repos/{owner}/{repo}/issues/{pr_number}/comments",
                json={"body": body},
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise GitHubClientError(f"Falha ao criar PR comment: {exc}") from exc
