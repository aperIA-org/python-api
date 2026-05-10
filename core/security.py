import hmac
import hashlib
from pathlib import Path

from fastapi import HTTPException

from core.exceptions import InvalidWebhookSignature


def safe_repo_path(repo_path: str) -> Path:
    """Valida que o path é absoluto e existe antes de passar a subprocess."""
    path = Path(repo_path).resolve()
    if not path.exists():
        raise ValueError(f"Repo path inválido: {repo_path}")
    if not path.is_dir():
        raise ValueError(f"Repo path não é diretório: {repo_path}")
    return path


def verify_github_signature(body: bytes, signature_header: str, secret: str) -> None:
    """
    Valida HMAC SHA-256 do webhook GitHub.
    Usa compare_digest (constant-time) para evitar timing attacks.
    Lança InvalidWebhookSignature se inválida.
    """
    if not signature_header:
        raise InvalidWebhookSignature("X-Hub-Signature-256 ausente")

    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, signature_header):
        raise InvalidWebhookSignature("Assinatura HMAC inválida")
