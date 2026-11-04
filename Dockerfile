# PatchProof AI — Rust API image (replaces backend/Dockerfile).
FROM rust:1.82-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends git python3 python3-pytest ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/patchproof-api /app/patchproof-api
ENV DATABASE_URL=sqlite:////data/patchproof.db LLM_MOCK=1 HOST=0.0.0.0
EXPOSE 8000
CMD ["/app/patchproof-api"]
