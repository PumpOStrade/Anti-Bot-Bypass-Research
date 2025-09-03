"""Application configuration via pydantic-settings."""

from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "AntiBotLab"
    database_url: str = "sqlite+aiosqlite:///antibot.db"
    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = False

    # HTTP client defaults
    default_user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    )
    request_timeout: int = 30
    max_retries: int = 3

    # Proxy
    proxy_url: str | None = None
    proxy_list_file: str | None = None
    proxy_rotate: bool = True

    # Rate limiting
    scan_cooldown_seconds: int = 60  # min seconds between scans of same domain

    # API
    api_port: int = 8001
    api_key: str | None = None

    # Session
    session_ttl_minutes: int = 30

    # Paths
    base_dir: Path = Path(__file__).resolve().parent.parent.parent
    data_dir: Path = base_dir / "data"
    signatures_dir: Path = data_dir / "signatures"

    model_config = {"env_prefix": "ANTIBOT_"}


settings = Settings()
