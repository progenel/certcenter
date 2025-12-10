from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent  # .../code
DATA_DIR = BASE_DIR / "data"


class Settings(BaseSettings):
    """Application settings loaded from environment or .env."""

    # App
    app_name: str = "etucrypto"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000

    # Database
    database_url: str = f"sqlite:///{DATA_DIR / 'app.db'}"

    # Local storage for artifacts (instead of S3 for now)
    artifacts_path: str = str(DATA_DIR / "artifacts")

    # Demo admin (for initial login)
    default_admin_username: str = "admin"
    default_admin_password: str = "admin"
    default_user_username: str = "user"
    default_user_password: str = "user"
    default_officer_username: str = "officer"
    default_officer_password: str = "officer"

    # JWT
    jwt_secret: str = "change_me"
    jwt_algorithm: str = "HS256"
    jwt_exp_minutes: int = 60

    # PKCS#11 / soft-HSM
    pkcs11_module: str | None = None
    pkcs11_token_label: str | None = None
    pkcs11_pin: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Cached settings instance."""
    return Settings()
