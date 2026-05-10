import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from presentation.api.main import app
from infrastructure.persistence.models.base import Base
from core.database import get_db

TEST_DATABASE_URL = "postgresql+asyncpg://aperia:test@localhost:5432/aperia_test"


@pytest.fixture(autouse=True)
def mock_settings(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-fake-do-not-use")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret-fake")
    monkeypatch.setenv("GITHUB_APP_ID", "12345")
    monkeypatch.setenv("GITHUB_PRIVATE_KEY_PATH", "/tmp/fake.pem")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake_token")
    monkeypatch.setenv("CALDERA_API_KEY", "fake-caldera-key")
    monkeypatch.setenv("OPENVAS_USERNAME", "admin")
    monkeypatch.setenv("OPENVAS_PASSWORD", "fake")
    monkeypatch.setenv("WAZUH_BASE_URL", "http://localhost:55000")
    monkeypatch.setenv("WAZUH_USERNAME", "wazuh")
    monkeypatch.setenv("WAZUH_PASSWORD", "fake")
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "fake-token")
    monkeypatch.setenv("DATABASE_URL", TEST_DATABASE_URL)
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")


@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
