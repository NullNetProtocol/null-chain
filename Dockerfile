# Reproducible build of nulld. Pin the toolchain image by digest before a
# release so two builders get byte-identical binaries.
FROM rust:1.96-slim AS build
WORKDIR /src
COPY . .
ENV SOURCE_DATE_EPOCH=1
ENV CARGO_INCREMENTAL=0
RUN cargo build --release --locked -p null-node \
    && sha256sum target/release/nulld

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/nulld /usr/local/bin/nulld
COPY deploy/testnet/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && useradd -m null
USER null
WORKDIR /home/null
ENTRYPOINT ["nulld"]
