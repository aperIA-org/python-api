import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from app.main import app


WEBHOOK_SECRET = "test-secret-key-for-hmac-verification"


@pytest.fixture(autouse=True)
def patched_secret(monkeypatch):
    from app.presentation.api.routes import webhook_routes
    monkeypatch.setattr(webhook_routes.settings, "GITHUB_WEBHOOK_SECRET", WEBHOOK_SECRET)


@pytest.fixture
def client():
    return TestClient(app)


def _sign(payload: bytes) -> str:
    digest = hmac.new(WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_rejects_request_without_signature(client):
    resp = client.post("/webhook/github", json={"foo": "bar"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid HMAC signature"


def test_rejects_invalid_signature(client):
    payload = json.dumps({"foo": "bar"}).encode()
    resp = client.post(
        "/webhook/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": "sha256=" + "0" * 64,
            "X-GitHub-Event": "ping",
        },
    )
    assert resp.status_code == 401


def test_rejects_signature_with_wrong_prefix(client):
    payload = b'{"foo":"bar"}'
    resp = client.post(
        "/webhook/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": "md5=abc",
        },
    )
    assert resp.status_code == 401


def test_accepts_ping_with_valid_signature(client):
    payload = b'{"zen":"keep it logically awesome"}'
    resp = client.post(
        "/webhook/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": _sign(payload),
            "X-GitHub-Event": "ping",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    # Sem installation.id → ignorado
    assert body == {"status": "ignored", "reason": "no installation_id"}


def test_ignores_event_without_installation_id(client):
    payload = b'{"action":"opened","pull_request":{}}'
    resp = client.post(
        "/webhook/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": _sign(payload),
            "X-GitHub-Event": "pull_request",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"


def test_queues_pull_request_opened(client, monkeypatch):
    """Webhook chama start_pipeline com os campos extraídos do payload.

    O canvas real é exercitado em ``tests/e2e/test_full_pipeline.py``;
    aqui validamos apenas o contrato webhook → orquestrador.
    """
    from unittest.mock import MagicMock

    from app.core import orchestrator

    captured = MagicMock()
    monkeypatch.setattr(orchestrator, "start_pipeline", captured)

    payload_obj = {
        "action": "opened",
        "installation": {"id": 12345},
        "pull_request": {
            "number": 7,
            "head": {"sha": "a" * 40},
            "base": {"sha": "b" * 40},
        },
        "repository": {
            "clone_url": "https://github.com/acme/repo.git",
            "full_name": "acme/repo",
        },
    }
    payload = json.dumps(payload_obj).encode()

    resp = client.post(
        "/webhook/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": _sign(payload),
            "X-GitHub-Event": "pull_request",
        },
    )

    assert resp.status_code == 200
    assert resp.json() == {"status": "queued", "commit_sha": "a" * 40}
    captured.assert_called_once()
    kwargs = captured.call_args.kwargs
    assert kwargs["commit_sha"] == "a" * 40
    assert kwargs["base_sha"] == "b" * 40
    assert kwargs["head_sha"] == "a" * 40
    assert kwargs["pr_number"] == 7
    assert kwargs["installation_id"] == 12345
    assert kwargs["repo_full_name"] == "acme/repo"


def test_queues_pull_request_synchronize(client, monkeypatch):
    from unittest.mock import MagicMock

    from app.core import orchestrator

    captured = MagicMock()
    monkeypatch.setattr(orchestrator, "start_pipeline", captured)

    payload_obj = {
        "action": "synchronize",
        "installation": {"id": 99},
        "pull_request": {"number": 1, "head": {"sha": "b" * 40}},
        "repository": {
            "clone_url": "https://github.com/x/y.git",
            "full_name": "x/y",
        },
    }
    payload = json.dumps(payload_obj).encode()
    resp = client.post(
        "/webhook/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": _sign(payload),
            "X-GitHub-Event": "pull_request",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "queued"
    captured.assert_called_once()
    # Sem ``base`` → fallback para commit_sha
    assert captured.call_args.kwargs["base_sha"] == "b" * 40


def test_ignores_pull_request_with_unhandled_action(client):
    payload_obj = {
        "action": "closed",
        "installation": {"id": 1},
        "pull_request": {"number": 1, "head": {"sha": "c" * 40}},
        "repository": {"clone_url": "x", "full_name": "x/y"},
    }
    payload = json.dumps(payload_obj).encode()
    resp = client.post(
        "/webhook/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": _sign(payload),
            "X-GitHub-Event": "pull_request",
        },
    )
    assert resp.status_code == 200
    # action diferente de opened/synchronize → ignored com event
    assert resp.json()["status"] == "ignored"
    assert resp.json()["event"] == "pull_request"
