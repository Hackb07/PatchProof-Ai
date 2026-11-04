"""FastAPI entrypoint."""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import settings
from .routers import github, scans
from .store import fail_stale_scans, init_db


@asynccontextmanager
async def lifespan(app):
    del app
    init_db()
    fail_stale_scans()
    yield


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)


def _cors_options() -> dict:
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    if "*" in origins:
        # Wildcard origin cannot be combined with credentials.
        return {"allow_origins": ["*"], "allow_credentials": False,
                "allow_methods": ["*"], "allow_headers": ["*"]}
    if not origins:
        # No origins configured: emit no CORS headers (deny by default).
        return {"allow_origins": [], "allow_credentials": False,
                "allow_methods": ["*"], "allow_headers": ["*"]}
    return {"allow_origins": origins, "allow_credentials": True,
            "allow_methods": ["*"], "allow_headers": ["*"]}


app.add_middleware(CORSMiddleware, **_cors_options())


@app.middleware("http")
async def _require_api_key(request: Request, call_next):
    """Shared-secret auth for the scan endpoints (health stays open).
    Open to all requests unless PATCHPROOF_API_KEY is configured."""
    expected = (settings.api_key or "").strip()
    path = request.url.path
    if expected and (path.startswith("/api/scans") or path.startswith("/api/github")):
        provided = request.headers.get("x-api-key", "").strip()
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            provided = provided or auth[len("bearer "):].strip()
        if provided != expected:
            return JSONResponse(status_code=401, content={"detail": "invalid or missing API key"})
    return await call_next(request)


@app.get("/api/health")
def health() -> dict:
    # Effective mock mode: forced on when no API key is configured.
    mock = settings.llm_mock or not settings.meta_api_key
    return {"status": "ok", "app": settings.app_name, "llm_mock": mock}


app.include_router(scans.router)
app.include_router(github.router)
