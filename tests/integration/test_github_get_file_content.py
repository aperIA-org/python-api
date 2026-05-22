"""Testes do GitHubClient.get_file_content."""
from __future__ import annotations

import base64
from unittest.mock import patch

import pytest
import respx
from httpx import Response

from app.infrastructure.git import github_client


@pytest.fixture
def client():
    with patch.object(
        github_client, "get_installation_token", return_value="ghs_fake"
    ):
        return github_client.GitHubClient(installation_id=42)


@respx.mock
def test_decodes_base64_content(client):
    raw = b"def get_user(id):\n    return db.query(f'SELECT * FROM users WHERE id = {id}')\n"
    encoded = base64.b64encode(raw).decode("ascii")
    respx.get("https://api.github.com/repos/acme/repo/contents/app/db.py").mock(
        return_value=Response(200, json={"content": encoded, "encoding": "base64"})
    )

    content = client.get_file_content(
        repo_full_name="acme/repo", path="app/db.py", ref="abc123"
    )
    assert "def get_user" in content
    assert "SELECT" in content


@respx.mock
def test_sends_ref_param(client):
    route = respx.get(
        "https://api.github.com/repos/acme/repo/contents/x.py"
    ).mock(
        return_value=Response(
            200, json={"content": base64.b64encode(b"x").decode("ascii")}
        )
    )

    client.get_file_content("acme/repo", "x.py", ref="aaaa")

    assert route.calls.last.request.url.params["ref"] == "aaaa"


@respx.mock
def test_follows_download_url_when_content_missing(client):
    """Arquivos > 1 MB vêm sem ``content`` — seguir ``download_url``."""
    respx.get("https://api.github.com/repos/acme/repo/contents/big.py").mock(
        return_value=Response(
            200,
            json={
                "size": 2_000_000,
                "download_url": "https://raw.githubusercontent.com/acme/repo/big.py",
            },
        )
    )
    respx.get("https://raw.githubusercontent.com/acme/repo/big.py").mock(
        return_value=Response(200, text="huge file content here")
    )

    content = client.get_file_content("acme/repo", "big.py", ref="x")
    assert content == "huge file content here"


@respx.mock
def test_empty_when_no_content_or_download_url(client):
    respx.get("https://api.github.com/repos/acme/repo/contents/x.py").mock(
        return_value=Response(200, json={"size": 0})
    )

    assert client.get_file_content("acme/repo", "x.py", ref="x") == ""


@respx.mock
def test_404_raises(client):
    respx.get("https://api.github.com/repos/acme/repo/contents/missing.py").mock(
        return_value=Response(404, json={"message": "Not Found"})
    )
    with pytest.raises(Exception):
        client.get_file_content("acme/repo", "missing.py", ref="x")


@respx.mock
def test_handles_non_utf8_bytes_via_replace(client):
    """Arquivos com bytes inválidos (binários renderizados como texto)
    devem decodificar com replace em vez de levantar."""
    raw = b"valid \xff\xfe invalid bytes"
    encoded = base64.b64encode(raw).decode("ascii")
    respx.get("https://api.github.com/repos/acme/repo/contents/bin.dat").mock(
        return_value=Response(200, json={"content": encoded})
    )
    content = client.get_file_content("acme/repo", "bin.dat", ref="x")
    assert "valid" in content
    # replace deve substituir os bytes inválidos
    assert "�" in content
