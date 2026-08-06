#!/usr/bin/env bash
set -e
. make/lib.sh

# The arch every image tag is suffixed with. The Makefile derives BUILD_ARCH from
# TARGET and exports it; a direct invocation of this script falls back to the
# host arch.
ARCH="${BUILD_ARCH:-$(host_arch)}"

case "$1" in
  release)
    # Exact source revision baked into the image. Recorded as a label so a stale
    # build or a re-pushed old image is detectable. The +dirty suffix flags any
    # uncommitted change in the working tree.
    SOURCE_REV="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
    [ -z "$(git status --porcelain 2>/dev/null)" ] || SOURCE_REV="${SOURCE_REV}+dirty"
    substep "Source revision: ${SOURCE_REV}"

    # Cross-compile, then assemble. The native and the foreign arch take the SAME
    # path, so the two published images differ only in their target triple rather
    # than in how they were produced.
    make/cross.sh build "${ARCH}"
    make/cross.sh stage "${ARCH}"

    # The context is .cache/stage/<arch> and the Containerfile has no RUN steps,
    # so --platform never has to execute a foreign binary — no emulation, no
    # builder VM. Nothing in the image build resolves DNS any more, so the host
    # network is no longer shared by default; BUILD_NETWORK is still honoured for
    # anyone who needs it.
    BUILD_NETWORK="${BUILD_NETWORK-}"
    NETWORK_FLAG=""
    [ -n "${BUILD_NETWORK}" ] && NETWORK_FLAG="--network=${BUILD_NETWORK}"

    step "Building release image (${ARCH} / linux/$(oci_arch "${ARCH}"))"
    ${SUDO} podman build ${NETWORK_FLAG} \
      --platform "linux/$(oci_arch "${ARCH}")" \
      --build-arg "SOURCE_REV=${SOURCE_REV}" \
      -t "${RELEASE_IMAGE}:${IMAGE_TAG:-latest}-${ARCH}" \
      -f Containerfile ".cache/stage/${ARCH}"
    ;;
  push-arch)
    step "Pushing current-arch image (${ARCH})"
    SRC="${RELEASE_IMAGE}:${IMAGE_TAG:-latest}-${ARCH}"
    substep "Pushing ${SRC}"
    ${SUDO} podman push "${SRC}"
    ;;
  push-rc)
    step "Pushing release candidate (${ARCH})"
    SRC="${RELEASE_IMAGE}:${IMAGE_TAG:-latest}-${ARCH}"
    if [ -n "${IMAGE_TAG}" ]; then
      substep "Pushing ${SRC}"
      ${SUDO} podman push "${SRC}"
    else
      # rc.latest is suffixed with the machine name so deploy hosts can pull
      # rc.latest-$(uname -m) directly.
      for t in "rc.$(date +%Y%m%d)-${ARCH}" "rc.latest-${ARCH}"; do
        substep "Tagging ${RELEASE_IMAGE}:${t}"
        ${SUDO} podman tag "${SRC}" "${RELEASE_IMAGE}:${t}"
        substep "Pushing ${RELEASE_IMAGE}:${t}"
        ${SUDO} podman push "${RELEASE_IMAGE}:${t}"
      done
    fi
    ;;
  push-release)
    step "Pushing release (${ARCH})"
    SRC="${RELEASE_IMAGE}:${IMAGE_TAG:-latest}-${ARCH}"
    if [ -n "${IMAGE_TAG}" ]; then
      substep "Pushing ${SRC}"
      ${SUDO} podman push "${SRC}"
    else
      for t in "release.$(date +%Y%m%d)" "latest"; do
        substep "Tagging ${RELEASE_IMAGE}:${t}-${ARCH}"
        ${SUDO} podman tag "${SRC}" "${RELEASE_IMAGE}:${t}-${ARCH}"
        substep "Pushing ${RELEASE_IMAGE}:${t}-${ARCH}"
        ${SUDO} podman push "${RELEASE_IMAGE}:${t}-${ARCH}"
      done
    fi
    ;;
  manifest-rc)
    step "Assembling release candidate manifest"
    if [ -n "${IMAGE_TAG}" ]; then
      build_manifest "${IMAGE_TAG}"
    else
      build_manifest "rc.$(date +%Y%m%d)"
      build_manifest "rc.latest"
    fi
    ;;
  manifest-release)
    step "Assembling release manifest"
    if [ -n "${IMAGE_TAG}" ]; then
      build_manifest "${IMAGE_TAG}"
    else
      build_manifest "release.$(date +%Y%m%d)"
      build_manifest "latest"
    fi
    ;;
  quay-login)
    registry_login quay.io QUAY_USERNAME QUAY_PASSWORD
    ;;
  *)
    echo "Usage: $0 {release|push-arch|push-rc|push-release|manifest-rc|manifest-release|quay-login}"
    exit 1
    ;;
esac
