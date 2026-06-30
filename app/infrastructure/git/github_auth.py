import time

import httpx
import jwt

from app.config import settings


def _generate_jwt() -> str:
    now = int(time.time())
    with open(settings.GITHUB_PRIVATE_KEY_PATH) as f:
        private_key = f.read()
    return jwt.encode(
        {"iat": now - 60, "exp": now + 600, "iss": settings.GITHUB_APP_ID},
        private_key,
        algorithm="RS256",
    )


def get_installation_token(installation_id: int) -> str:
    resp = httpx.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers={
            "Authorization": f"Bearer {_generate_jwt()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()["token"]
