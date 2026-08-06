#!/usr/bin/env bash
# make/cross.sh - Rust cross-compilation toolchain.
#
# Every release binary is cross-compiled with cargo-zigbuild, which uses zig as
# the C cross-compiler and linker. That matters because a plain `rustup target
# add` is NOT sufficient here: rusqlite is built with the `bundled` feature (it
# compiles SQLite's C sources) and ring compiles C and assembly, so a real cross
# C toolchain has to exist or the build dies at the `cc` step.
#
# zig was chosen over a distro cross-gcc because the whole toolchain installs
# without root — `rustup target add`, `cargo install`, and an extracted tarball
# under .cache/ — so `make deps` can provision it on any machine, and because it
# links against a pinned glibc (GLIBC_VERSION) instead of the build host's.
set -e
. make/lib.sh

ZIG_VERSION="${ZIG_VERSION:-0.16.0}"
ZIGBUILD_VERSION="${ZIGBUILD_VERSION:-0.23.0}"
ZIG_DIR=".cache/zig"

# zig_bin — print the directory holding a usable `zig`, installing one into
# .cache/ if neither a system zig nor the ziglang Python package is present.
# Prints nothing when cargo-zigbuild can already find zig on its own.
zig_bin() {
  if command -v zig > /dev/null 2>&1; then
    return 0
  fi
  # cargo-zigbuild also accepts zig installed as a Python module.
  if python3 -m ziglang version > /dev/null 2>&1; then
    return 0
  fi
  local host dir
  host="$(host_arch)"
  dir="${ZIG_DIR}/zig-${host}-linux-${ZIG_VERSION}"
  [ -x "${dir}/zig" ] && { echo "${dir}"; return 0; }
  echo "${dir}"
  return 0
}

# ensure_zig — make a `zig` available, downloading the official tarball into
# .cache/ as a last resort. Rootless by design.
ensure_zig() {
  if command -v zig > /dev/null 2>&1; then
    substep "zig: $(command -v zig)"
    return 0
  fi
  if python3 -m ziglang version > /dev/null 2>&1; then
    substep "zig: python3 -m ziglang ($(python3 -m ziglang version))"
    return 0
  fi

  local host dir tarball url
  host="$(host_arch)"
  dir="${ZIG_DIR}/zig-${host}-linux-${ZIG_VERSION}"
  if [ -x "${dir}/zig" ]; then
    substep "zig: ${dir}/zig (cached)"
    return 0
  fi

  tarball="zig-${host}-linux-${ZIG_VERSION}.tar.xz"
  url="https://ziglang.org/download/${ZIG_VERSION}/${tarball}"
  substep "Downloading ${url}"
  mkdir -p "${ZIG_DIR}"
  curl -fsSL "${url}" -o "${ZIG_DIR}/${tarball}"
  substep "Extracting ${tarball}"
  tar -C "${ZIG_DIR}" -xf "${ZIG_DIR}/${tarball}"
  rm -f "${ZIG_DIR}/${tarball}"
  [ -x "${dir}/zig" ] || {
    echo "zig extraction did not produce ${dir}/zig" >&2
    exit 1
  }
  substep "zig: ${dir}/zig"
}

case "$1" in
  deps)
    step "Installing Rust cross-compilation toolchain"

    command -v rustup > /dev/null 2>&1 || {
      echo "rustup not found — install it from https://rustup.rs (no root required)" >&2
      exit 1
    }

    # std for both targets. Cheap and idempotent, and installing both means a
    # TARGET switch never needs a second `make deps`.
    for arch in ${ARCHES}; do
      triple="$(rust_triple "${arch}")"
      substep "rustup target add ${triple}"
      rustup target add "${triple}"
    done

    if command -v cargo-zigbuild > /dev/null 2>&1; then
      substep "cargo-zigbuild: $(command -v cargo-zigbuild)"
    else
      substep "cargo install cargo-zigbuild@${ZIGBUILD_VERSION}"
      cargo install "cargo-zigbuild@${ZIGBUILD_VERSION}" --locked
    fi

    ensure_zig
    substep "Cross toolchain ready (glibc target ${GLIBC_VERSION})"
    ;;

  build)
    # build ARCH — cross-compile the release binaries for ARCH into
    # target/<triple>/release. Used for both the native and the foreign arch, so
    # both produce byte-comparable toolchain output instead of one being a host
    # build and the other a cross build.
    ARCH="${2:?usage: cross.sh build ARCH}"
    TRIPLE="$(rust_triple "${ARCH}")"

    command -v cargo-zigbuild > /dev/null 2>&1 || {
      echo "cargo-zigbuild not found — run 'make deps'" >&2
      exit 1
    }

    # Put the .cache zig on PATH when that is the copy we installed.
    ZDIR="$(zig_bin)"
    [ -n "${ZDIR}" ] && [ -x "${ZDIR}/zig" ] && PATH="${PWD}/${ZDIR}:${PATH}" && export PATH

    step "Cross-compiling ${TRIPLE} (glibc ${GLIBC_VERSION})"
    cargo zigbuild --release --target "${TRIPLE}.${GLIBC_VERSION}" \
      ${CARGO_BUILD_JOBS:+--jobs ${CARGO_BUILD_JOBS}} \
      --bin rolodex-dns --bin rolodex-dns-cli

    substep "Stripping binaries"
    # Strip with zig's llvm-strip so this works when the host strip cannot
    # handle the foreign architecture.
    for b in rolodex-dns rolodex-dns-cli; do
      strip "target/${TRIPLE}/release/${b}" 2> /dev/null \
        || llvm-strip "target/${TRIPLE}/release/${b}" 2> /dev/null \
        || substep "left ${b} unstripped (no strip for ${ARCH})"
    done
    ;;

  stage)
    # stage ARCH — assemble the container build context: the two binaries plus a
    # CA bundle. The context is deliberately tiny and RUN-free (see Containerfile)
    # so building a foreign-arch image never has to execute a foreign binary.
    ARCH="${2:?usage: cross.sh stage ARCH}"
    TRIPLE="$(rust_triple "${ARCH}")"
    STAGE=".cache/stage/${ARCH}"

    step "Staging image context (${ARCH})"
    rm -rf "${STAGE}"
    mkdir -p "${STAGE}"
    for b in rolodex-dns rolodex-dns-cli; do
      [ -f "target/${TRIPLE}/release/${b}" ] || {
        echo "missing target/${TRIPLE}/release/${b} — run 'make/cross.sh build ${ARCH}'" >&2
        exit 1
      }
      cp "target/${TRIPLE}/release/${b}" "${STAGE}/${b}"
    done

    # CA certificates are architecture-independent data, so they can be copied
    # in rather than installed with a RUN step (which a foreign-arch image
    # cannot execute without emulation).
    CERTS=""
    for c in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
      /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do
      [ -r "${c}" ] && CERTS="${c}" && break
    done
    [ -n "${CERTS}" ] || {
      echo "no CA bundle found on this host; looked in /etc/ssl and /etc/pki" >&2
      exit 1
    }
    substep "CA bundle: ${CERTS}"
    cp -L "${CERTS}" "${STAGE}/ca-certificates.crt"
    ;;

  *)
    echo "Usage: $0 {deps|build ARCH|stage ARCH}"
    exit 1
    ;;
esac
