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


class TestRS256EstaDisponivel:
    """O ambiente precisa CONSEGUIR assinar em RS256, nao so pedir por ele.

    Regressao real: `requirements.txt` declarava `PyJWT` sem o extra `[crypto]`,
    e o RS256 so funcionava porque o `pip install semgrep prowler` do Dockerfile
    arrastava `cryptography` para o Python do sistema. Ao isolar as duas
    ferramentas em venvs proprios, a dependencia acidental sumiu e
    `POST /repositories/{id}/scan` passou a devolver 502 com
    "Algorithm 'RS256' could not be found".

    Os testes acima nao pegaram isso porque MOCKAM `jwt.encode`: eles verificam
    que pedimos `algorithm="RS256"`, nao que a biblioteca consegue cumprir. Um
    mock sempre consegue. Estes dois exercitam a capacidade real.
    """

    def test_pyjwt_registra_rs256(self):
        """`RS256` so entra no registro do PyJWT quando `cryptography` existe."""
        assert "RS256" in jwt.algorithms.get_default_algorithms()

    def test_assina_e_verifica_de_verdade(self):
        """Round-trip com chave real: e o que o JWT do GitHub App faz."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        privada = chave.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        publica = chave.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormatSubjectPublicKeyInfo
            if hasattr(serialization, "PublicFormatSubjectPublicKeyInfo")
            else serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        token = jwt.encode({"iss": "123456"}, privada, algorithm="RS256")
        assert jwt.decode(token, publica, algorithms=["RS256"])["iss"] == "123456"
