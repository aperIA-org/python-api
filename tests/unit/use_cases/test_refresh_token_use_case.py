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
    revoked_at: datetime | None = None,
) -> MagicMock:
    record = MagicMock()
    record.user_id = uuid4()
    record.family_id = uuid4()
    record.revoked = revoked
    # Explicito: sem isso o MagicMock auto-cria um atributo (nao-None) e a
    # logica de graca o interpretaria como um instante de revogacao valido.
    record.revoked_at = revoked_at
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
async def test_refresh_revoked_ha_muito_e_reuso():
    """Token revogado ha mais que a janela (ou sem revoked_at) -> reuso."""
    velho = datetime.now(timezone.utc) - timedelta(minutes=5)
    use_case, _ = make_use_case(make_token_record(revoked=True, revoked_at=velho))
    with pytest.raises(TokenReusedError):
        await use_case.execute("reused-token")


@pytest.mark.asyncio
async def test_refresh_reuso_revoga_familia():
    velho = datetime.now(timezone.utc) - timedelta(minutes=5)
    use_case, repo = make_use_case(make_token_record(revoked=True, revoked_at=velho))
    with pytest.raises(TokenReusedError):
        await use_case.execute("reused-token")
    repo.revoke_family.assert_called_once()


@pytest.mark.asyncio
async def test_revoked_at_nulo_e_tratado_como_reuso():
    """Linha revogada antes da coluna existir: conservador -> reuso, nao graca."""
    use_case, repo = make_use_case(make_token_record(revoked=True, revoked_at=None))
    with pytest.raises(TokenReusedError):
        await use_case.execute("legacy-revoked")
    repo.revoke_family.assert_called_once()


@pytest.mark.asyncio
async def test_replay_concorrente_dentro_da_graca_emite_par_sem_revogar():
    """O coracao do fix: token revogado ha instantes (rotacao concorrente) ->
    emite par novo, NAO levanta erro e NAO revoga a familia."""
    agora = datetime.now(timezone.utc)
    use_case, repo = make_use_case(
        make_token_record(revoked=True, revoked_at=agora)
    )
    tokens = await use_case.execute("replay-concorrente")
    assert tokens.access_token and tokens.refresh_token
    repo.revoke_family.assert_not_called()


@pytest.mark.asyncio
async def test_replay_benigno_mantem_a_mesma_familia():
    agora = datetime.now(timezone.utc)
    record = make_token_record(revoked=True, revoked_at=agora)
    use_case, repo = make_use_case(record)
    await use_case.execute("replay-concorrente")
    repo.save.assert_called_once()
    assert repo.save.call_args.kwargs["family_id"] == record.family_id


@pytest.mark.asyncio
async def test_replay_perto_do_fim_da_graca_ainda_e_benigno():
    """Logo dentro da janela (nao a borda exata, que dependeria do relogio do
    use case) ainda conta como replay benigno."""
    from app.config import settings

    quase = datetime.now(timezone.utc) - timedelta(
        seconds=settings.REFRESH_ROTATION_GRACE_SECONDS - 2
    )
    use_case, repo = make_use_case(
        make_token_record(revoked=True, revoked_at=quase)
    )
    tokens = await use_case.execute("quase-no-fim")
    assert tokens.refresh_token
    repo.revoke_family.assert_not_called()


@pytest.mark.asyncio
async def test_replay_logo_apos_a_graca_e_reuso():
    """Passado o limite, volta a ser reuso -> familia revogada."""
    from app.config import settings

    passou = datetime.now(timezone.utc) - timedelta(
        seconds=settings.REFRESH_ROTATION_GRACE_SECONDS + 5
    )
    use_case, repo = make_use_case(
        make_token_record(revoked=True, revoked_at=passou)
    )
    with pytest.raises(TokenReusedError):
        await use_case.execute("tarde-demais")
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
