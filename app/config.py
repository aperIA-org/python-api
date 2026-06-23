from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_PATH = Path(__file__).resolve().parents[1] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_PATH,
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ---- Auth (existente — preservado) ----
    SECRET_KEY: str = "change-this-secret-key-with-at-least-32-characters"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ---- GitHub App ----
    GITHUB_APP_ID: str = ""
    GITHUB_PRIVATE_KEY_PATH: str = ""
    GITHUB_WEBHOOK_SECRET: str = ""

    # ---- Anthropic / Claude ----
    ANTHROPIC_API_KEY: str = ""
    CLAUDE_MODEL_REASONING: str = "claude-sonnet-4-6"
    CLAUDE_MODEL_FORMATTING: str = "claude-haiku-4-5-20251001"
    CLAUDE_PROMPT_CACHE_ENABLED: bool = True

    # ---- DAST (ZAP) ----
    ZAP_BASE_URL: str = "http://zap:8090"
    ZAP_API_KEY: str = ""

    # ---- Threat Intel (OpenCTI) ----
    OPENCTI_URL: str = "http://opencti:8081"
    OPENCTI_TOKEN: str = ""

    # ---- Adversary Emulation (Caldera) ----
    CALDERA_URL: str = "http://caldera:8888"
    CALDERA_API_KEY: str = ""
    CALDERA_SANDBOX_MODE: bool = True
    CALDERA_POLL_INTERVAL: int = 10  # testes injetam 0 via construtor
    CALDERA_AGENT_GROUP: str = "red"

    # ---- AI Security ----
    LLM_GUARD_ENABLED: bool = True

    # ---- Persistência de findings ----
    # Liga a escrita best-effort dos findings no banco a partir dos
    # scan workers. Default True em produção; testes desligam por padrão
    # (ver tests/conftest.py) para não exigir Postgres.
    FINDINGS_PERSISTENCE_ENABLED: bool = True

    # ---- Celery / Redis ----
    # Default aponta para o hostname do container (docker-compose service "redis"),
    # não localhost — produção depende de DNS interno. Override via env em dev.
    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: str = ""
    CELERY_RESULT_BACKEND: str = ""
    CELERY_TASK_ALWAYS_EAGER: bool = False
    CELERY_TASK_EAGER_PROPAGATES: bool = False


settings = Settings()
