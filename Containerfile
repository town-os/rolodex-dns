# Runtime image. Deliberately contains NO RUN steps.
#
# The binaries are cross-compiled on the build host (make/cross.sh) and the CA
# bundle is copied in as data, so nothing in this file has to EXECUTE anything of
# the target architecture. That is what lets `podman build --platform` produce a
# foreign-arch image on any host with no emulation and no builder VM: a single
# `RUN apt-get install` here would need to run a foreign binary, which is exactly
# the step that fails inside a podman build sandbox on hosts whose user-mode
# emulation is unavailable.
#
# The build context is .cache/stage/<arch>, assembled by `make/cross.sh stage`.
FROM docker.io/library/debian:bookworm-slim

COPY rolodex-dns /usr/local/bin/rolodex-dns
COPY rolodex-dns-cli /usr/local/bin/rolodex-dns-cli
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Record the exact source revision the binary was built from (passed by
# make/build.sh). Lets a stale checkout or a re-pushed old image be spotted with
# `skopeo inspect` / `podman inspect` instead of guessing from config digests.
ARG SOURCE_REV=unknown
LABEL org.opencontainers.image.revision="${SOURCE_REV}"
EXPOSE 53/udp 53/tcp
CMD ["/usr/local/bin/rolodex-dns"]
