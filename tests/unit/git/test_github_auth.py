import time
from unittest.mock import mock_open, patch

import jwt
import pytest
import respx
from httpx import Response

from app.infrastructure.git import github_auth


FAKE_RSA_KEY = "-----FAKE-RSA-KEY-----"


@pytest.fixture
def patched_settings(monkeypatch, tmp_path):
    """Aponta GITHUB_APP_ID e GITHUB_PRIVATE_KEY_PATH para valores válidos."""
    monkeypatch.setattr(github_auth.settings, "GITHUB_APP_ID", "123456")
    monkeypatch.setattr(
        github_auth.settings, "GITHUB_PRIVATE_KEY_PATH", str(tmp_path / "key.pem")
    )


class TestGenerateJwt:
    def test_jwt_claims_have_correct_structure(self, patched_settings):
        with patch("builtins.open", mock_open(read_data=FAKE_RSA_KEY)):
            with patch.object(jwt, "encode", return_value="fake.jwt.token") as encode:
                token = github_auth._generate_jwt()

        assert token == "fake.jwt.token"
        payload, key, *_ = encode.call_args[0]
        kwargs = encode.call_args[1]
        assert payload["iss"] == "123456"
        assert payload["exp"] - payload["iat"] == 660  # 600 + 60 de skew
        # iat deve ser próximo de now - 60
        assert abs(payload["iat"] - (int(time.time()) - 60)) <= 2
        assert key == FAKE_RSA_KEY
        assert kwargs["algorithm"] == "RS256"


class TestGetInstallationToken:
    @respx.mock
    def test_returns_token_from_github(self, patched_settings):
        respx.post(
            "https://api.github.com/app/installations/777/access_tokens"
        ).mock(return_value=Response(201, json={"token": "ghs_abc123"}))

        with patch("builtins.open", mock_open(read_data=FAKE_RSA_KEY)):
            with patch.object(jwt, "encode", return_value="fake.jwt"):
                token = github_auth.get_installation_token(777)

        assert token == "ghs_abc123"

    @respx.mock
    def test_sends_bearer_jwt_and_api_version(self, patched_settings):
        route = respx.post(
            "https://api.github.com/app/installations/42/access_tokens"
        ).mock(return_value=Response(201, json={"token": "ghs_xyz"}))

        with patch("builtins.open", mock_open(read_data=FAKE_RSA_KEY)):
            with patch.object(jwt, "encode", return_value="my.jwt.here"):
                github_auth.get_installation_token(42)

        sent = route.calls.last.request
        assert sent.headers["Authorization"] == "Bearer my.jwt.here"
        assert sent.headers["X-GitHub-Api-Version"] == "2022-11-28"
        assert sent.headers["Accept"] == "application/vnd.github+json"

    @respx.mock
    def test_raises_on_non_2xx(self, patched_settings):
        respx.post(
            "https://api.github.com/app/installations/1/access_tokens"
        ).mock(return_value=Response(401, json={"message": "Bad credentials"}))

        with patch("builtins.open", mock_open(read_data=FAKE_RSA_KEY)):
            with patch.object(jwt, "encode", return_value="x"):
                with pytest.raises(Exception):
                    github_auth.get_installation_token(1)
