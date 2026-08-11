import httpx
import structlog

from app.infrastructure.git.github_auth import get_installation_token

logger = structlog.get_logger()


class GitHubClient:
    BASE = "https://api.github.com"

    def __init__(self, installation_id: int):
        token = get_installation_token(installation_id)
        self.client = httpx.Client(
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=15.0,
        )

    def post_pr_comment(
        self, repo_full_name: str, pr_number: int, body: str
    ) -> int:
        resp = self.client.post(
            f"{self.BASE}/repos/{repo_full_name}/issues/{pr_number}/comments",
            json={"body": body},
        )
        resp.raise_for_status()
        return resp.json()["id"]

    def create_status_check(
        self,
        repo_full_name: str,
        commit_sha: str,
        state: str,
        description: str,
        context: str = "aperIA",
    ) -> None:
        resp = self.client.post(
            f"{self.BASE}/repos/{repo_full_name}/statuses/{commit_sha}",
            json={
                "state": state,
                "description": description[:140],
                "context": context,
            },
        )
        resp.raise_for_status()

    def post_inline_suggestion(
        self,
        repo_full_name: str,
        pr_number: int,
        commit_sha: str,
        file_path: str,
        line: int,
        patch_diff: str,
        explanation: str,
    ) -> int:
        body = f"{explanation}\n\n```suggestion\n{patch_diff}\n```"
        resp = self.client.post(
            f"{self.BASE}/repos/{repo_full_name}/pulls/{pr_number}/comments",
            json={
                "body": body,
                "commit_id": commit_sha,
                "path": file_path,
                "line": line,
                "side": "RIGHT",
            },
        )
        resp.raise_for_status()
        return resp.json()["id"]

    def get_pr_diff(self, repo_full_name: str, pr_number: int) -> str:
        resp = self.client.get(
            f"{self.BASE}/repos/{repo_full_name}/pulls/{pr_number}",
            headers={"Accept": "application/vnd.github.diff"},
        )
        resp.raise_for_status()
        return resp.text

    def get_file_content(
        self, repo_full_name: str, path: str, ref: str
    ) -> str:
        """Lê o conteúdo de um arquivo do repositório no commit ``ref``.

        Usado pelo ``suggest_patch_use_case`` para alimentar o
        ``code_context`` do prompt de remediação.

        A API de Contents retorna base64 encoded por padrão. Para
        arquivos grandes (> 1 MB) a API responde sem ``content`` e com
        ``download_url`` — nesse caso seguimos o redirect.
        """
        import base64

        resp = self.client.get(
            f"{self.BASE}/repos/{repo_full_name}/contents/{path}",
            params={"ref": ref},
        )
        resp.raise_for_status()
        payload = resp.json()
        encoded = payload.get("content")
        if encoded:
            return base64.b64decode(encoded).decode("utf-8", errors="replace")
        download_url = payload.get("download_url")
        if download_url:
            raw = self.client.get(download_url)
            raw.raise_for_status()
            return raw.text
        return ""

    def get_branch_head_sha(self, repo_full_name: str, branch: str) -> str:
        """Resolve o SHA do commit HEAD de um branch.

        Usado pelo scan manual (``POST /repositories/{id}/scan``), que não tem
        PR de onde tirar o ``head.sha``. ``GET /repos/{repo}/commits/{ref}``
        aceita branch, tag ou SHA e devolve o commit resolvido.
        """
        resp = self.client.get(
            f"{self.BASE}/repos/{repo_full_name}/commits/{branch}"
        )
        resp.raise_for_status()
        return resp.json()["sha"]

    def list_repositories(self) -> list[dict]:
        """Lista os repositórios que a instalação enxerga.

        Pagina ``GET /installation/repositories`` (100 por página). Cada item
        traz ao menos ``id``, ``full_name``, ``html_url`` e ``default_branch``.
        """
        repos: list[dict] = []
        page = 1
        while True:
            resp = self.client.get(
                f"{self.BASE}/installation/repositories",
                params={"per_page": 100, "page": page},
            )
            resp.raise_for_status()
            batch = resp.json().get("repositories", []) or []
            repos.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return repos
