FROM rust:1.95.0-slim-bookworm AS builder

WORKDIR /work
COPY orchestrator/Cargo.toml orchestrator/Cargo.lock ./
COPY orchestrator/src ./src
RUN cargo build --release --locked --bin mipsorcu-orchestrator

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 orchestrator \
    && useradd --system --uid 10001 --gid 10001 --create-home --home-dir /home/orchestrator --shell /usr/sbin/nologin orchestrator \
    && mkdir -p /workspaces \
    && chown orchestrator:orchestrator /workspaces

COPY --from=builder /work/target/release/mipsorcu-orchestrator /usr/local/bin/mipsorcu-orchestrator
USER 10001:10001
WORKDIR /workspaces
ENTRYPOINT ["/usr/local/bin/mipsorcu-orchestrator"]
