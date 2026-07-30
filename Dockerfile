# syntax=docker/dockerfile:1.7

# --- Dependency planning -----------------------------------------------------
# cargo-chef turns the manifests into a recipe so the (slow) dependency build
# lands in its own cache layer and only re-runs when Cargo.toml/lock change.
FROM rust:1-slim-bookworm AS chef
WORKDIR /build
RUN cargo install cargo-chef --locked --version ^0.1

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo chef prepare --recipe-path recipe.json

# --- Build -------------------------------------------------------------------
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bin vega \
    && strip target/release/vega

# --- Runtime -----------------------------------------------------------------
# distroless/cc: glibc and nothing else. No shell, no package manager, and it
# runs as an unprivileged user by default.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="vega" \
      org.opencontainers.image.description="Authoritative DNS server written in Rust on top of Hickory DNS" \
      org.opencontainers.image.source="https://github.com/ismoilovdevml/vega" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /build/target/release/vega /usr/local/bin/vega

# 53/udp and 53/tcp need CAP_NET_BIND_SERVICE because we do not run as root:
#   docker run --cap-add NET_BIND_SERVICE -p 53:53/udp ...
EXPOSE 53/udp 53/tcp 9100/tcp

# Only the log format is baked in. Listen addresses deliberately are not:
# environment beats the config file, so an image that carried VEGA_UDP silently
# overrode whatever port the operator's own config asked for — the published
# Kubernetes manifest asked for 5300, got :53, and CrashLoopBackOff'd against a
# container with no NET_BIND_SERVICE. Ports belong to the config, not the image.
ENV VEGA_LOG_FORMAT=json

# The binary probes its own /healthz, so the image needs no curl or shell.
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/vega", "healthcheck", "--admin-listen", "127.0.0.1:9100"]

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/vega"]
