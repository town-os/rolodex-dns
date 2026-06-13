#!/usr/bin/env bash
set -e
. make/lib.sh

ARCH="$(host_arch)"

case "$1" in
  release)
    # RUN steps (apt-get, cargo fetch) resolve DNS in their own network
    # namespace, which can't reach a resolver on the host's loopback (e.g.
    # rolodex on 127.0.0.1). Share the host network so they use the host's
    # /etc/resolv.conf. Override with BUILD_NETWORK= to opt out, or
    # BUILD_NETWORK=<name> to pick another network.
    BUILD_NETWORK="${BUILD_NETWORK-host}"
    NETWORK_FLAG=""
    [ -n "${BUILD_NETWORK}" ] && NETWORK_FLAG="--network=${BUILD_NETWORK}"

    step "Building build image (${ARCH})"
    mkdir -p .cache/cargo-registry .cache/cargo-git
    ${SUDO} podman build ${NETWORK_FLAG} \
      --volume "$(pwd)/.cache/cargo-registry:/usr/local/cargo/registry:z" \
      --volume "$(pwd)/.cache/cargo-git:/usr/local/cargo/git:z" \
      -t "${PODMAN_BUILD_IMAGE}-${ARCH}" -f Containerfile.build .

    step "Building release image (${ARCH})"
    ${SUDO} podman build ${NETWORK_FLAG} --pull=never \
      --build-arg "BUILD_IMAGE=${PODMAN_BUILD_IMAGE}-${ARCH}" \
      -t "${RELEASE_IMAGE}:${IMAGE_TAG:-latest}-${ARCH}" -f Containerfile .
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
      # rc.latest is suffixed with uname -m so deploy hosts can pull
      # rc.latest-$(uname -m) without mapping to OCI arch names.
      for t in "rc.$(date +%Y%m%d)-${ARCH}" "rc.latest-$(uname -m)"; do
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
      build_manifest "rc.latest" "${MACHINES}"
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
