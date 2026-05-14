FROM rust:1.95.0-alpine AS builder

WORKDIR /work

RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static

COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --release --locked --bin mipsorcu \
    && rm -rf src target/release/mipsorcu target/release/deps/mipsorcu-* target/release/.fingerprint/mipsorcu-*

COPY src ./src
RUN cargo build --release --locked --bin mipsorcu

FROM alpine:latest AS runtime

RUN apk add --no-cache ca-certificates \
    && addgroup -g 10001 -S mipsorcu \
    && adduser -u 10001 -G mipsorcu -h /var/lib/mipsorcu -s /sbin/nologin -S mipsorcu \
    && mkdir -p /var/lib/mipsorcu \
    && chown 10001:10001 /var/lib/mipsorcu

COPY --from=builder /work/target/release/mipsorcu /usr/local/bin/mipsorcu

USER 10001:10001
WORKDIR /var/lib/mipsorcu
VOLUME ["/var/lib/mipsorcu"]
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/mipsorcu"]
CMD ["server"]