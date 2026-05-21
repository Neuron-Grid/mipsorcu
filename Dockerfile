FROM rust:1.95.0-slim-bookworm AS builder

WORKDIR /work

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --release --locked --bin mipsorcu \
    && rm -rf src target/release/mipsorcu target/release/deps/mipsorcu-* target/release/.fingerprint/mipsorcu-*

COPY src ./src
RUN cargo build --release --locked --bin mipsorcu

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 mipsorcu \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /var/lib/mipsorcu --shell /usr/sbin/nologin mipsorcu \
    && mkdir -p /var/lib/mipsorcu \
    && chown mipsorcu:mipsorcu /var/lib/mipsorcu

COPY --from=builder /work/target/release/mipsorcu /usr/local/bin/mipsorcu

USER 10001
WORKDIR /var/lib/mipsorcu
VOLUME ["/var/lib/mipsorcu"]
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/mipsorcu"]
CMD ["server"]
