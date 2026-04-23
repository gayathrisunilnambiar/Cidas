from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Daemon
    daemon_host: str = "127.0.0.1"
    daemon_port: int = 7979
    daemon_log_level: str = "info"
    daemon_secret: str = Field(default="", description="Shared secret for extension auth")

    # NPM registry
    npm_registry_url: str = "https://registry.npmjs.org"
    npm_registry_timeout: int = 10
    npm_max_concurrent: int = 5

    # OSV
    osv_api_url: str = "https://api.osv.dev/v1"
    osv_timeout: int = 10

    # Embeddings
    embedding_model: str = "all-MiniLM-L6-v2"
    chroma_persist_dir: str = ".cidas_chroma"

    # SQLite cache
    sqlite_db_path: str = ".cidas_cache.db"
    cache_ttl_seconds: int = 3600

    # Scoring
    block_threshold: int = 80
    warn_threshold: int = 40


settings = Settings()
