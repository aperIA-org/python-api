from pydantic_settings import BaseSettings
from pydantic import field_validator


class Settings(BaseSettings):
    # GitHub App
    GITHUB_APP_ID: str
    GITHUB_PRIVATE_KEY_PATH: str
    GITHUB_WEBHOOK_SECRET: str
    GITHUB_TOKEN: str

    # Claude
    ANTHROPIC_API_KEY: str

    # Ferramentas OSS
    ZAP_BASE_URL: str = "http://localhost:8080"
    ZAP_API_KEY: str = ""
    OPENVAS_HOST: str = "localhost"
    OPENVAS_PORT: int = 9390
    OPENVAS_USERNAME: str
    OPENVAS_PASSWORD: str
    WAZUH_BASE_URL: str
    WAZUH_USERNAME: str
    WAZUH_PASSWORD: str

    # AWS (Prowler)
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_DEFAULT_REGION: str = "us-east-1"

    # OpenCTI
    OPENCTI_URL: str
    OPENCTI_TOKEN: str

    # Caldera — sandbox obrigatório
    CALDERA_URL: str = "http://localhost:8888"
    CALDERA_API_KEY: str
    CALDERA_SANDBOX_MODE: bool = True
    CALDERA_AGENT_GROUP: str = "aperia-sandbox"

    # LLM Guard
    LLM_GUARD_ENABLED: bool = True
    LLM_GUARD_BASE_URL: str = "http://localhost:8010"

    # Database
    DATABASE_URL: str
    REDIS_URL: str

    # Scan targets opcionais (configurados por repo/ambiente)
    ZAP_TARGET_URL: str = ""        # vazio = ZAP pulado no pipeline
    OPENVAS_TARGET_IP: str = ""     # vazio = OpenVAS pulado no pipeline
    WAZUH_AGENT_ID: str = ""        # vazio = Wazuh pulado no pipeline

    # App
    ENV: str = "development"
    LOG_LEVEL: str = "INFO"

    @field_validator("CALDERA_SANDBOX_MODE")
    @classmethod
    def sandbox_must_be_true_in_prod(cls, v: bool) -> bool:
        return v

    @property
    def is_production(self) -> bool:
        return self.ENV == "production"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
