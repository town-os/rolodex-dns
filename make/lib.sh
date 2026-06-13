# make/lib.sh - Shared helpers for make scripts.
# Source this file: . make/lib.sh

# ---------------------------------------------------------------------------
# Privileged execution
# ---------------------------------------------------------------------------

SUDO="sudo"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_cyan='\033[1;36m'
_green='\033[1;32m'
_yellow='\033[1;33m'
_reset='\033[0m'

step() {
  printf "${_cyan}==> %s${_reset}\n" "$*"
}

substep() {
  printf "${_green}  -> %s${_reset}\n" "$*"
}

warn() {
  printf "${_yellow}  ** %s${_reset}\n" "$*"
}

# ---------------------------------------------------------------------------
# Architecture
# ---------------------------------------------------------------------------

# Machine names (uname -m) that participate in multi-arch manifests. Per-arch
# image tags use these uname -m names directly (x86_64/aarch64, not the OCI
# amd64/arm64) so deploy hosts can pull <tag>-$(uname -m) without mapping.
ARCHES="x86_64 aarch64"

# host_arch — print the uname -m machine name (x86_64/aarch64) for the current
# host. Each arch is built natively: aarch64 on an arm64 host, x86_64 either on
# an x86_64 host or inside the amd64 builder VM (see make/amd64-vm.sh).
host_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) echo x86_64 ;;
    aarch64 | arm64) echo aarch64 ;;
    *)
      echo "unsupported host architecture: $(uname -m)" >&2
      return 1
      ;;
  esac
}

# build_manifest LIST_TAG [SUFFIXES] — assemble and push a multi-arch manifest
# list from the per-arch image tags (LIST_TAG-<suffix> for each suffix in
# SUFFIXES, default ${ARCHES}) already pushed to the registry from their
# respective native hosts.
build_manifest() {
  local list="$1"
  local suffixes="${2:-${ARCHES}}"
  local ref="${RELEASE_IMAGE}:${list}"
  substep "Creating manifest ${ref}"
  ${SUDO} podman manifest rm "${ref}" 2>/dev/null || true
  ${SUDO} podman manifest create "${ref}"
  local arch
  for arch in ${suffixes}; do
    substep "Adding ${ref}-${arch}"
    ${SUDO} podman manifest add "${ref}" "docker://${ref}-${arch}"
  done
  substep "Pushing manifest ${ref}"
  ${SUDO} podman manifest push --all "${ref}" "docker://${ref}"
}

# ---------------------------------------------------------------------------
# Registry login
# ---------------------------------------------------------------------------

# registry_login REGISTRY USER_VAR PASS_VAR — log in only if creds are given.
#   USER_VAR / PASS_VAR are the *names* of the env vars (e.g. QUAY_USERNAME).
# If the creds are empty, do nothing and let podman use whatever login it
# already has.
registry_login() {
  local registry="$1" user_var="$2" pass_var="$3"
  local user="${!user_var}" pass="${!pass_var}"
  if [ -n "${user}" ] && [ -n "${pass}" ]; then
    step "Logging in to ${registry}"
    ${SUDO} podman login -u "${user}" -p "${pass}" "${registry}"
  fi
}
