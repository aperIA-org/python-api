"""Repositorio de refresh tokens — foco no carimbo de ``revoked_at``.

``revoked_at`` sustenta a janela de graca da rotacao: sem carimbar o instante da
revogacao, nao da para distinguir um replay concorrente benigno (rotacao ha
milissegundos) de um reuso de fato. Antes a coluna nem existia.
"""
import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.infrastructure.persistence.models import (  # noqa: F401 — metadata
    refresh_token_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.persistence.models.refresh_token_model import RefreshTokenModel
from app.infrastructure.repositories.sqlalchemy_refresh_token_repository import (
    SQLAlchemyRefreshTokenRepository,
)


@pytest.fixture
def session():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(eng)
    factory = sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
    s = factory()
    try:
        yield s
    finally:
        s.close()
        eng.dispose()


def _inserir_token(session, raw: str, *, family_id=None, revoked=False):
    """Insere um refresh token com id/family explicitos (os server_default sao
    do Postgres e nao rodam em sqlite no insert)."""
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    session.add(
        RefreshTokenModel(
            id=uuid4(),
            user_id=uuid4(),
            token_hash=token_hash,
            family_id=family_id or uuid4(),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            revoked=revoked,
            created_at=datetime.now(timezone.utc),
        )
    )
    session.flush()
    return token_hash


def test_revoke_by_hash_carimba_revoked_at(session):
    repo = SQLAlchemyRefreshTokenRepository(session)
    h = _inserir_token(session, "tok-1")

    asyncio.run(repo.revoke_by_hash(h))
    session.flush()

    rec = session.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token_hash == h)
    ).scalar_one()
    assert rec.revoked is True
    assert rec.revoked_at is not None


def test_revoke_family_carimba_e_preserva_o_primeiro_instante(session):
    repo = SQLAlchemyRefreshTokenRepository(session)
    fam = uuid4()
    # um token ja revogado antes (com revoked_at antigo) e um vivo
    antigo = datetime.now(timezone.utc) - timedelta(hours=1)
    h_velho = _inserir_token(session, "velho", family_id=fam, revoked=True)
    session.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token_hash == h_velho)
    ).scalar_one().revoked_at = antigo
    h_vivo = _inserir_token(session, "vivo", family_id=fam)
    session.flush()

    asyncio.run(repo.revoke_family(fam))
    session.flush()

    velho = session.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token_hash == h_velho)
    ).scalar_one()
    vivo = session.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token_hash == h_vivo)
    ).scalar_one()
    # COALESCE preserva o instante original do que ja estava revogado (nao o
    # sobrescreve com "agora") — o sqlite perde o tzinfo no round-trip, entao a
    # verificacao e por ordenacao, nao por igualdade exata.
    assert vivo.revoked is True and vivo.revoked_at is not None
    assert velho.revoked_at < vivo.revoked_at
    # o antigo continua ~1h atras, nao carimbado agora
    delta = vivo.revoked_at - velho.revoked_at
    assert delta > timedelta(minutes=50)
