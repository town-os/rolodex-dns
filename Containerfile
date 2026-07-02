ARG BUILD_IMAGE=rolodex-dns-build
FROM ${BUILD_IMAGE} AS builder

FROM docker.io/library/debian:bookworm
RUN apt-get update && apt-get install -y ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/rolodex-dns /usr/local/bin/rolodex-dns
COPY --from=builder /src/target/release/rolodex-dns-cli /usr/local/bin/rolodex-dns-cli
# Record the exact source revision the binary was built from (passed by
# make/build.sh). Lets a stale checkout or a re-pushed old image be spotted with
# `skopeo inspect` / `podman inspect` instead of guessing from config digests.
ARG SOURCE_REV=unknown
LABEL org.opencontainers.image.revision="${SOURCE_REV}"
EXPOSE 53/udp 53/tcp
CMD ["/usr/local/bin/rolodex-dns"]
