"""Central configuration. Demo works offline with LLM_MOCK=1 (default)."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "PatchProof AI"
    database_url: str = "sqlite:///./patchproof.db"
    repo_root: str = "/tmp/patchproof/repos"
    llm_mock: bool = True
    meta_api_key: str = ""
    meta_api_base: str = "https://api.llama.meta.com/v1"
    meta_model: str = "llama-4-scout"
    sandbox_backend: str = "auto"  # auto | docker | subprocess
    sandbox_timeout_s: int = 20
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"


settings = Settings()
