from uuid import uuid4

import pytest

from app.application.exceptions import InvalidCredentialsError, TokenExpiredError
from app.infrastructure.security.jwt_handler import create_access_token, decode_access_token

_SECRET = "test-secret-that-is-at-least-32-chars-long"


def test_create_and_decode_token():
    user_id = uuid4()
    token = create_access_token(user_id, _SECRET, expire_minutes=15)
    payload = decode_access_token(token, _SECRET)
    assert payload["sub"] == str(user_id)
    assert payload["iss"] == "python-api"
    assert payload["aud"] == "python-api-clients"


def test_expired_token_raises_domain_exception():
    user_id = uuid4()
    token = create_access_token(user_id, _SECRET, expire_minutes=-1)
    with pytest.raises(TokenExpiredError):
        decode_access_token(token, _SECRET)


def test_tampered_token_raises_domain_exception():
    with pytest.raises(InvalidCredentialsError):
        decode_access_token("not.a.valid.token", _SECRET)


def test_wrong_secret_raises_domain_exception():
    user_id = uuid4()
    token = create_access_token(user_id, _SECRET, expire_minutes=15)
    with pytest.raises(InvalidCredentialsError):
        decode_access_token(token, "wrong-secret")
