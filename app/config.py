"""Runtime configuration, read from environment variables or a .env file."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./proofladder.db"

    llm_provider: str = "offline"
    llm_model: str = ""
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_max_steps: int = 8
    llm_max_cost_usd: float = 0.05
    llm_price_in_per_mtok: float = 0.0
    llm_price_out_per_mtok: float = 0.0

    memory_backend: str = "local"
    qdrant_url: str = ""
    qdrant_api_key: str = ""
    memory_match_threshold: float = 0.92

    readonly: bool = False
    live_replay: bool = False
    live_replay_interval_sec: float = 3.0
    seed_on_start: int = 600


@lru_cache
def get_settings() -> Settings:
    return Settings()
