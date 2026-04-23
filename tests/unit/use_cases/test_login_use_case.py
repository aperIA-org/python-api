from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.application.exceptions import InvalidCredentialsError
from app.application.use_cases.login_use_case import LoginCommand, LoginUseCase


# -- Helpers -------------------------------------------------------------------


class FakePasswordVerifier:
    """Substitui Argon2 nos testes. Controla o resultado sem infra real."""

    def __init__(self, result: bool) -> None:
        self._result = result

    def verify(self, hashed: str, plain: str) -> bool:
        return self._result


def make_use_case(user, password_ok: bool) -> LoginUseCase:
    user_repo = AsyncMock()
    user_repo.find_by_email.return_value = user
    token_repo = AsyncMock()
    return LoginUseCase(
        user_repo=user_repo,
        token_repo=token_repo,
        password_verifier=FakePasswordVerifier(result=password_ok),
    )


@pytest.fixture
def mock_user():
    user = MagicMock()
    user.id = uuid4()
    user.password = "$argon2id$fake"
    user.email = "user@example.com"
    return user


# -- Testes --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_success_returns_tokens(mock_user):
    use_case = make_use_case(mock_user, password_ok=True)
    tokens = await use_case.execute(
        LoginCommand(email="user@example.com", password="correct")
    )
    assert tokens.access_token
    assert tokens.refresh_token
    assert tokens.token_type == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password_raises(mock_user):
    use_case = make_use_case(mock_user, password_ok=False)
    with pytest.raises(InvalidCredentialsError):
        await use_case.execute(LoginCommand(email="user@example.com", password="wrong"))


@pytest.mark.asyncio
async def test_login_user_not_found_raises():
    use_case = make_use_case(user=None, password_ok=False)
    with pytest.raises(InvalidCredentialsError):
        await use_case.execute(LoginCommand(email="ghost@example.com", password="any"))


@pytest.mark.asyncio
async def test_login_normalizes_email(mock_user):
    user_repo = AsyncMock()
    user_repo.find_by_email.return_value = mock_user
    token_repo = AsyncMock()
    use_case = LoginUseCase(
        user_repo=user_repo,
        token_repo=token_repo,
        password_verifier=FakePasswordVerifier(result=True),
    )
    await use_case.execute(LoginCommand(email="  USER@EXAMPLE.COM  ", password="pass"))
    user_repo.find_by_email.assert_called_once_with("user@example.com")
