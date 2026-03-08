ARG BUILD_IMAGE=rolodex-dns-build
FROM ${BUILD_IMAGE} AS builder

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/rolodex-dns /usr/local/bin/rolodex-dns
COPY --from=builder /src/target/release/rolodex-dns-cli /usr/local/bin/rolodex-dns-cli
EXPOSE 53/udp 53/tcp
CMD ["/usr/local/bin/rolodex-dns"]
