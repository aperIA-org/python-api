from unittest.mock import patch

import pytest
import respx
from httpx import Response

from app.infrastructure.git import github_client


@pytest.fixture
def client():
    """Constrói GitHubClient com get_installation_token mockado."""
    with patch.object(
        github_client, "get_installation_token", return_value="ghs_fake"
    ):
        return github_client.GitHubClient(installation_id=42)


@respx.mock
def test_post_pr_comment_returns_id(client):
    route = respx.post(
        "https://api.github.com/repos/acme/repo/issues/7/comments"
    ).mock(return_value=Response(201, json={"id": 999}))

    comment_id = client.post_pr_comment("acme/repo", 7, "Hello world")

    assert comment_id == 999
    sent = route.calls.last.request
    assert sent.headers["Authorization"] == "Bearer ghs_fake"
    assert b'"body"' in sent.content


@respx.mock
def test_create_status_check_uses_state_description_context(client):
    route = respx.post(
        "https://api.github.com/repos/acme/repo/statuses/abc123"
    ).mock(return_value=Response(201, json={}))

    client.create_status_check(
        "acme/repo", "abc123", "failure", "Secret detectado", context="aperIA/secrets"
    )

    body = route.calls.last.request.content.decode()
    assert '"state":"failure"' in body
    assert '"context":"aperIA/secrets"' in body


@respx.mock
def test_create_status_check_truncates_description_to_140(client):
    route = respx.post(
        "https://api.github.com/repos/acme/repo/statuses/sha1"
    ).mock(return_value=Response(201, json={}))

    long_desc = "x" * 200
    client.create_status_check("acme/repo", "sha1", "failure", long_desc)

    body = route.calls.last.request.content.decode()
    # description deve aparecer com 140 chars no body JSON
    assert '"description":"' + ("x" * 140) + '"' in body
    assert "x" * 141 not in body


@respx.mock
def test_post_inline_suggestion_formats_suggestion_block(client):
    route = respx.post(
        "https://api.github.com/repos/acme/repo/pulls/5/comments"
    ).mock(return_value=Response(201, json={"id": 1234}))

    comment_id = client.post_inline_suggestion(
        repo_full_name="acme/repo",
        pr_number=5,
        commit_sha="abc",
        file_path="app/db.py",
        line=42,
        patch_diff="SELECT 1",
        explanation="Use prepared statement",
    )

    assert comment_id == 1234
    body = route.calls.last.request.content.decode()
    assert "```suggestion\\nSELECT 1\\n```" in body
    assert '"side":"RIGHT"' in body
    assert '"path":"app/db.py"' in body


@respx.mock
def test_get_pr_diff_returns_text(client):
    diff_payload = "diff --git a/file.py b/file.py\n+++ b/file.py"
    respx.get("https://api.github.com/repos/acme/repo/pulls/8").mock(
        return_value=Response(200, text=diff_payload)
    )

    diff = client.get_pr_diff("acme/repo", 8)

    assert diff == diff_payload


@respx.mock
def test_get_pr_diff_sends_diff_accept(client):
    route = respx.get(
        "https://api.github.com/repos/acme/repo/pulls/8"
    ).mock(return_value=Response(200, text=""))

    client.get_pr_diff("acme/repo", 8)

    assert route.calls.last.request.headers["Accept"] == "application/vnd.github.diff"


@respx.mock
def test_get_branch_head_sha(client):
    respx.get("https://api.github.com/repos/acme/repo/commits/main").mock(
        return_value=Response(200, json={"sha": "f" * 40, "commit": {}})
    )

    assert client.get_branch_head_sha("acme/repo", "main") == "f" * 40


@respx.mock
def test_get_branch_head_sha_raises_on_404(client):
    respx.get("https://api.github.com/repos/acme/repo/commits/sumiu").mock(
        return_value=Response(404, json={"message": "Not Found"})
    )

    with pytest.raises(Exception):
        client.get_branch_head_sha("acme/repo", "sumiu")
