#!/usr/bin/env bash
set -e
. make/lib.sh

case "$1" in
  production)
    step "Building build image"
    mkdir -p .cache/cargo-registry .cache/cargo-git
    ${SUDO} podman build \
      --volume "$(pwd)/.cache/cargo-registry:/usr/local/cargo/registry:z" \
      --volume "$(pwd)/.cache/cargo-git:/usr/local/cargo/git:z" \
      -t "${PODMAN_BUILD_IMAGE}" -f Containerfile.build .

    step "Building production image"
    ${SUDO} podman build --pull=never \
      --build-arg "BUILD_IMAGE=${PODMAN_BUILD_IMAGE}" \
      -t "${PODMAN_IMAGE}" -f Containerfile .
    ;;
  release)
    step "Building build image"
    mkdir -p .cache/cargo-registry .cache/cargo-git
    ${SUDO} podman build \
      --volume "$(pwd)/.cache/cargo-registry:/usr/local/cargo/registry:z" \
      --volume "$(pwd)/.cache/cargo-git:/usr/local/cargo/git:z" \
      -t "${PODMAN_BUILD_IMAGE}" -f Containerfile.build .

    step "Building release image"
    ${SUDO} podman build --pull=never \
      --build-arg "BUILD_IMAGE=${PODMAN_BUILD_IMAGE}" \
      -t "${RELEASE_IMAGE}" -f Containerfile .
    ;;
  push-rc)
    step "Pushing release candidate"
    DATE_TAG="$(date +%Y%m%d)"
    substep "Tagging ${RELEASE_IMAGE}:rc.${DATE_TAG}"
    ${SUDO} podman tag "${RELEASE_IMAGE}" "${RELEASE_IMAGE}:rc.${DATE_TAG}"
    substep "Tagging ${RELEASE_IMAGE}:rc.latest"
    ${SUDO} podman tag "${RELEASE_IMAGE}" "${RELEASE_IMAGE}:rc.latest"
    substep "Pushing ${RELEASE_IMAGE}:rc.${DATE_TAG}"
    ${SUDO} podman push "${RELEASE_IMAGE}:rc.${DATE_TAG}"
    substep "Pushing ${RELEASE_IMAGE}:rc.latest"
    ${SUDO} podman push "${RELEASE_IMAGE}:rc.latest"
    ;;
  push-release)
    step "Pushing release"
    DATE_TAG="$(date +%Y%m%d)"
    substep "Tagging ${RELEASE_IMAGE}:release.${DATE_TAG}"
    ${SUDO} podman tag "${RELEASE_IMAGE}" "${RELEASE_IMAGE}:release.${DATE_TAG}"
    substep "Tagging ${RELEASE_IMAGE}:latest"
    ${SUDO} podman tag "${RELEASE_IMAGE}" "${RELEASE_IMAGE}:latest"
    substep "Pushing ${RELEASE_IMAGE}:release.${DATE_TAG}"
    ${SUDO} podman push "${RELEASE_IMAGE}:release.${DATE_TAG}"
    substep "Pushing ${RELEASE_IMAGE}:latest"
    ${SUDO} podman push "${RELEASE_IMAGE}:latest"
    ;;
  quay-login)
    registry_login quay.io QUAY_USERNAME QUAY_PASSWORD
    ;;
  *)
    echo "Usage: $0 {production|release|push-rc|push-release|quay-login}"
    exit 1
    ;;
esac
