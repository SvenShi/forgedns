FROM rust:1-bookworm AS builder

ARG FORGEDNS_VERSION=dev
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches
COPY config.yaml ./config.yaml
COPY LICENSE ./LICENSE

RUN cargo build --locked --release

FROM debian:bookworm-slim

ARG FORGEDNS_VERSION=dev

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /etc/forgedns

COPY --from=builder /app/target/release/forgedns /usr/local/bin/forgedns
COPY --from=builder /app/config.yaml /etc/forgedns/config.yaml
COPY --from=builder /app/LICENSE /usr/share/licenses/forgedns/LICENSE

RUN sed -i 's/0.0.0.0:5335/0.0.0.0:53/' /etc/forgedns/config.yaml || true

ENV FORGEDNS_VERSION=${FORGEDNS_VERSION}
ENV TZ=UTC

EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 9088/tcp

ENTRYPOINT ["forgedns"]
CMD ["start", "-c", "/etc/forgedns/config.yaml"]