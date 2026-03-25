# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Stage 1: builder
# Uses the official Rust image — Rust is NOT required on the host machine.
# ---------------------------------------------------------------------------
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /build

# Install only what the linker needs (no libssl — we use pure-Rust rustls).
# protobuf-compiler (protoc) is required by etcd-client's build script.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# ---- dependency caching layer ----
# Copy only the manifest files first and build a dummy binary.
# Docker will cache this layer as long as Cargo.toml/Cargo.lock don't change.
COPY Cargo.toml ./
# Create a minimal placeholder so `cargo build` can resolve deps.
RUN mkdir src && echo 'fn main() {}' > src/main.rs

# Download and compile all dependencies (cached unless Cargo.toml changes).
RUN cargo build --release --locked 2>/dev/null || cargo build --release

# Remove the stub artefacts so the real source compiles cleanly.
RUN rm -f target/release/pgphantom target/release/deps/pgphantom-*

# ---- real source ----
COPY src/ ./src/
# Touch main.rs so cargo detects the change.
RUN touch src/main.rs

RUN cargo build --release --locked 2>/dev/null || cargo build --release

# ---------------------------------------------------------------------------
# Stage 2: runtime
# Minimal Debian image — only the binary and CA certificates.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

# ca-certificates is needed for HTTPS calls to JWKS endpoints and STS.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/pgphantom /usr/local/bin/pgphantom

# Default location for the config file (can be overridden via CMD or env).
RUN mkdir -p /etc/pgphantom /certs

# Drop root: run as nobody.
USER nobody

EXPOSE 5432

ENTRYPOINT ["/usr/local/bin/pgphantom"]
CMD ["--config", "/etc/pgphantom/config.yaml"]

# docker build -t pgphantom .
# docker-compose up