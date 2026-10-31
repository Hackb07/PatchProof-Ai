FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN /bin/uv sync --frozen --no-dev
COPY backend/ ./backend/
ENV DATABASE_URL=sqlite:///./patchproof.db LLM_MOCK=1 PATH="/app/.venv/bin:$PATH"
EXPOSE 8000
CMD ["/app/.venv/bin/uvicorn", "app.main:app", "--app-dir", "/app/backend", "--host", "0.0.0.0", "--port", "8000"]
