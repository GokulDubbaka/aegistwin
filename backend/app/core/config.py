"""Application configuration via pydantic-settings."""

from typing import List
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_INSECURE_DEFAULT_KEY = "dev-secret-key-change-in-production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # App
    APP_NAME: str = "AegisTwin"
    APP_ENV: str = "development"
    APP_DEBUG: bool = True
    SECRET_KEY: str = "dev-secret-key-change-in-production"
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Database
    DATABASE_URL: str = (
        "postgresql+asyncpg://aegistwin:aegistwin_dev_password@localhost:5432/aegistwin"
    )

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/2"

    # JWT
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # LLM
    LLM_PROVIDER: str = "mock"  # mock | openai | anthropic
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""

    # Tool Broker
    TOOL_MODE: str = "mock"  # mock | real

    @model_validator(mode="before")
    @classmethod
    def _parse_allowed_origins(cls, values: dict) -> dict:
        """Accept comma-separated string OR JSON list from env var.

        Docker env vars pass strings — pydantic-settings v2 cannot auto-split
        'http://a,http://b' into List[str]. This validator handles both formats.
        """
        raw = values.get("ALLOWED_ORIGINS")
        if isinstance(raw, str):
            raw = raw.strip()
            if raw.startswith("["):
                # JSON list: '["http://localhost:3000","http://localhost:5173"]'
                import json
                values["ALLOWED_ORIGINS"] = json.loads(raw)
            else:
                # Comma-separated: "http://localhost:3000,http://localhost:5173"
                values["ALLOWED_ORIGINS"] = [o.strip() for o in raw.split(",") if o.strip()]
        return values

    @model_validator(mode="after")
    def _validate_secrets(self) -> "Settings":
        if self.APP_ENV not in ("development", "test"):
            if self.SECRET_KEY == _INSECURE_DEFAULT_KEY:
                raise ValueError(
                    "SECRET_KEY must be changed from the insecure default before "
                    "running in a non-development environment. "
                    "Set SECRET_KEY in your .env file to a cryptographically random string."
                )
            if len(self.SECRET_KEY) < 32:
                raise ValueError(
                    f"SECRET_KEY must be at least 32 characters long (got {len(self.SECRET_KEY)})."
                )
        return self


settings = Settings()
