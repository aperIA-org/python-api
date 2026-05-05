from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.application.exceptions import TokenExpiredError, TokenReusedError, TokenRevokedError
from app.application.use_cases.refresh_token_use_case import RefreshTokenUseCase


def make_token_record(
    *,
    revoked: bool = False,
    expired: bool = False,
) -> MagicMock:
    record = MagicMock()
    record.user_id = uuid4()
    record.family_id = uuid4()
    record.revoked = revoked
    if expired:
        record.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    else:
        record.expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    return record


def make_use_case(record):
    token_repo = AsyncMock()
    token_repo.find_by_hash.return_value = record
    return RefreshTokenUseCase(token_repo=token_repo), token_repo


@pytest.mark.asyncio
async def test_refresh_success_returns_new_tokens():
    use_case, _ = make_use_case(make_token_record())
    tokens = await use_case.execute("valid-raw-token")
    assert tokens.access_token
    assert tokens.refresh_token


@pytest.mark.asyncio
async def test_refresh_revoked_token_raises():
    use_case, _ = make_use_case(make_token_record(revoked=True))
    with pytest.raises(TokenReusedError):
        await use_case.execute("reused-token")


@pytest.mark.asyncio
async def test_refresh_revoked_token_revokes_family():
    use_case, repo = make_use_case(make_token_record(revoked=True))
    with pytest.raises(TokenReusedError):
        await use_case.execute("reused-token")
    repo.revoke_family.assert_called_once()


@pytest.mark.asyncio
async def test_refresh_expired_token_raises():
    use_case, _ = make_use_case(make_token_record(expired=True))
    with pytest.raises(TokenExpiredError):
        await use_case.execute("expired-token")


@pytest.mark.asyncio
async def test_refresh_not_found_raises():
    token_repo = AsyncMock()
    token_repo.find_by_hash.return_value = None
    use_case = RefreshTokenUseCase(token_repo=token_repo)
    with pytest.raises(TokenRevokedError):
        await use_case.execute("unknown-token")
