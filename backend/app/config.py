"""Central configuration. Demo works offline with LLM_MOCK=1 (default)."""
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    app_name: str = "PatchProof AI"
    database_url: str = "sqlite:///./patchproof.db"
    repo_root: str = "/tmp/patchproof/repos"
    llm_mock: bool = True
    meta_api_key: str = ""
    meta_api_base: str = "https://api.llama.meta.com/v1"
    meta_model: str = "llama-4-scout"
    sandbox_backend: str = "auto"  # auto | docker | subprocess
    sandbox_timeout_s: int = 20
    sandbox_image: str = "python:3.12-slim"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    api_key: str = Field(default="", validation_alias="PATCHPROOF_API_KEY")
    host: str = "127.0.0.1"
    port: int = 8000


settings = Settings()


def normalize_local_path(raw: str) -> str:
    """Strip `file://` (repeatedly) and tolerate `/C:/...` Windows paths."""
    local = raw.strip()
    while local.startswith("file://"):
        local = local[len("file://"):]
    if len(local) >= 3 and local.startswith("/") and local[2] == ":":
        local = local[1:]
    return local


def is_local_scan_repo(repo_url: str) -> bool:
    """True when `repo_url` is a directory on this machine (the operator's
    own files, as opposed to a remote clone of untrusted code)."""
    return Path(normalize_local_path(repo_url)).is_dir()
