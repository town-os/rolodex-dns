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
# Registry login
# ---------------------------------------------------------------------------

# registry_login REGISTRY USER_VAR PASS_VAR — log in or skip if creds are empty.
#   USER_VAR / PASS_VAR are the *names* of the env vars (e.g. QUAY_USERNAME).
registry_login() {
  local registry="$1" user_var="$2" pass_var="$3"
  local user="${!user_var}" pass="${!pass_var}"
  if [ -z "${user}" ] || [ -z "${pass}" ]; then
    step "Skipping ${registry} login (credentials not set)"
  else
    step "Logging in to ${registry}"
    sudo podman login -u "${user}" -p "${pass}" "${registry}"
  fi
}
