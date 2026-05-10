import time
from typing import Literal

import httpx
import jwt
import structlog

from core.config import settings
from core.exceptions import GitHubClientError, InvalidWebhookSignature
from core.security import verify_github_signature

logger = structlog.get_logger()

_GITHUB_API = "https://api.github.com"
_ACCEPT = "application/vnd.github+json"
_API_VERSION = "2022-11-28"


def _generate_app_jwt() -> str:
    """JWT para autenticar como GitHub App — válido por 10 min."""
    now = int(time.time())
    with open(settings.GITHUB_PRIVATE_KEY_PATH) as f:
        private_key = f.read()
    return jwt.encode(
        {"iat": now - 60, "exp": now + 600, "iss": settings.GITHUB_APP_ID},
        private_key,
        algorithm="RS256",
    )


def get_installation_token(installation_id: int) -> str:
    """Token escopado por instalação — válido 1h."""
    try:
        resp = httpx.post(
            f"{_GITHUB_API}/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {_generate_app_jwt()}",
                "Accept": _ACCEPT,
                "X-GitHub-Api-Version": _API_VERSION,
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()["token"]
    except httpx.HTTPError as exc:
        raise GitHubClientError(f"Falha ao obter installation token: {exc}") from exc


class GitHubClient:
    def __init__(self, token: str | None = None) -> None:
        tok = token or settings.GITHUB_TOKEN
        self._client = httpx.Client(
            base_url=_GITHUB_API,
            headers={
                "Authorization": f"Bearer {tok}",
                "Accept": _ACCEPT,
                "X-GitHub-Api-Version": _API_VERSION,
            },
            timeout=30.0,
        )

    @staticmethod
    def verify_webhook(body: bytes, signature_header: str) -> None:
        verify_github_signature(body, signature_header, settings.GITHUB_WEBHOOK_SECRET)

    # ── Commit status ──────────────────────────────────────────────────────

    def set_commit_status(
        self,
        repo_full_name: str,
        commit_sha: str,
        state: Literal["pending", "success", "failure", "error"],
        description: str,
        context: str = "aperIA / security-analysis",
    ) -> None:
        try:
            self._client.post(
                f"/repos/{repo_full_name}/statuses/{commit_sha}",
                json={
                    "state": state,
                    "description": description[:140],
                    "context": context,
                },
            ).raise_for_status()
        except httpx.HTTPError as exc:
            raise GitHubClientError(f"set_commit_status failed: {exc}") from exc

    def block_merge(
        self, repo_full_name: str, commit_sha: str, reason: str
    ) -> None:
        self.set_commit_status(
            repo_full_name,
            commit_sha,
            state="failure",
            description=f"aperIA: {reason}"[:140],
        )
        logger.bind(
            repo_full_name=repo_full_name, commit_sha=commit_sha
        ).info("merge_blocked", reason=reason)

    # ── PR reviews and comments ───────────────────────────────────────────

    def create_pr_review(
        self,
        repo_full_name: str,
        pr_number: int,
        body: str,
        event: Literal["APPROVE", "REQUEST_CHANGES", "COMMENT"],
    ) -> None:
        try:
            self._client.post(
                f"/repos/{repo_full_name}/pulls/{pr_number}/reviews",
                json={"body": body, "event": event},
            ).raise_for_status()
        except httpx.HTTPError as exc:
            raise GitHubClientError(f"create_pr_review failed: {exc}") from exc

    def create_pr_comment(
        self, repo_full_name: str, pr_number: int, body: str
    ) -> None:
        try:
            self._client.post(
                f"/repos/{repo_full_name}/issues/{pr_number}/comments",
                json={"body": body},
            ).raise_for_status()
        except httpx.HTTPError as exc:
            raise GitHubClientError(f"create_pr_comment failed: {exc}") from exc

    def create_inline_suggestion(
        self,
        repo_full_name: str,
        pr_number: int,
        commit_sha: str,
        file_path: str,
        line: int,
        suggestion_code: str,
        context_message: str = "",
    ) -> None:
        """
        Code suggestion inline — o dev aceita com 1 clique.
        SEMPRE usar para patches — nunca commit direto.
        """
        prefix = f"{context_message}\n\n" if context_message else ""
        body = f"{prefix}```suggestion\n{suggestion_code}\n```"

        try:
            self._client.post(
                f"/repos/{repo_full_name}/pulls/{pr_number}/comments",
                json={
                    "body": body,
                    "commit_id": commit_sha,
                    "path": file_path,
                    "line": line,
                },
            ).raise_for_status()
        except httpx.HTTPError as exc:
            raise GitHubClientError(f"create_inline_suggestion failed: {exc}") from exc

    # ── Repo data ─────────────────────────────────────────────────────────

    def get_changed_files(
        self, repo_full_name: str, commit_sha: str
    ) -> list[dict]:
        """Retorna arquivos modificados com diff para análise SAST."""
        try:
            resp = self._client.get(
                f"/repos/{repo_full_name}/commits/{commit_sha}"
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise GitHubClientError(f"get_changed_files failed: {exc}") from exc

        return [
            {
                "filename": f["filename"],
                "status": f["status"],
                "patch": f.get("patch", ""),
                "additions": f["additions"],
                "deletions": f["deletions"],
            }
            for f in resp.json().get("files", [])
            if f["status"] != "removed"
        ]

    def get_file_content(
        self, repo_full_name: str, file_path: str, ref: str
    ) -> str:
        """Retorna conteúdo decodificado de um arquivo no commit/branch."""
        import base64
        try:
            resp = self._client.get(
                f"/repos/{repo_full_name}/contents/{file_path}",
                params={"ref": ref},
            )
            resp.raise_for_status()
            return base64.b64decode(resp.json()["content"]).decode("utf-8")
        except httpx.HTTPError as exc:
            raise GitHubClientError(f"get_file_content failed: {exc}") from exc
        except (KeyError, UnicodeDecodeError):
            return ""
