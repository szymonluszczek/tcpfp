FROM rust:1.92-slim AS build

RUN apt-get update && apt-get install -y pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y ca-certificates dumb-init libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/target/release/tcpfp /usr/local/bin/tcpfp

# Capturing SYNs needs CAP_NET_RAW and the host's network namespace.
ENTRYPOINT ["dumb-init", "--"]
CMD ["tcpfp"]
