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

# Architectures that participate in multi-arch manifests (OCI names).
ARCHES="amd64 arm64"

# Machine names (uname -m) that participate in multi-arch manifests. The
# rc.latest per-arch tags use these so deploy hosts can pull
# rc.latest-$(uname -m) directly without mapping to OCI arch names.
MACHINES="x86_64 aarch64"

# host_arch — print the OCI arch name (amd64/arm64) for the current host.
# Builds are native-only: each arch is built on a host of that arch.
host_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
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
