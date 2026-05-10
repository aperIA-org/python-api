import hmac
import hashlib

import pytest

from core.exceptions import InvalidWebhookSignature
from core.security import verify_github_signature

_SECRET = "test-webhook-secret"
_BODY = b'{"action": "opened"}'


def _make_sig(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()


def test_valid_signature_passes():
    sig = _make_sig(_BODY, _SECRET)
    verify_github_signature(_BODY, sig, _SECRET)  # não deve lançar


def test_invalid_signature_raises():
    with pytest.raises(InvalidWebhookSignature):
        verify_github_signature(_BODY, "sha256=deadbeef", _SECRET)


def test_empty_signature_raises():
    with pytest.raises(InvalidWebhookSignature):
        verify_github_signature(_BODY, "", _SECRET)


def test_wrong_secret_raises():
    sig = _make_sig(_BODY, "wrong-secret")
    with pytest.raises(InvalidWebhookSignature):
        verify_github_signature(_BODY, sig, _SECRET)


def test_tampered_body_raises():
    sig = _make_sig(_BODY, _SECRET)
    tampered = _BODY + b" extra"
    with pytest.raises(InvalidWebhookSignature):
        verify_github_signature(tampered, sig, _SECRET)
