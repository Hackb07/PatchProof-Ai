# PoC sandbox image: minimal Python with pytest, no network at runtime (--network none).
# Build it for fully sandboxed PoC + test runs:
#   docker build -t patchproof-sandbox sandbox/
# then set SANDBOX_IMAGE=patchproof-sandbox.
FROM python:3.12-slim
RUN pip install --no-cache-dir pytest
WORKDIR /work
CMD ["python", "--version"]
