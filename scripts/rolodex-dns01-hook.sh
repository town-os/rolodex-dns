#!/usr/bin/env sh
# dns-01 challenge hook for the Rolodex DNS ACME issuer.
#
# Provisions and removes the `_acme-challenge` TXT record via `rolodex-dns-cli`,
# so ACME clients doing dns-01 against the Rolodex ACME endpoint can satisfy the
# challenge. Rolodex IS the DNS server, so the record is served immediately and
# the ACME server self-validates against its own database.
#
# Supports two client conventions:
#
#   lego (exec provider):
#       EXEC_PATH=scripts/rolodex-dns01-hook.sh lego --dns exec ...
#     invokes:  hook present|cleanup <fqdn> <txt-value>
#
#   certbot (--manual-auth-hook / --manual-cleanup-hook):
#       certbot ... --manual --preferred-challenges dns \
#         --manual-auth-hook scripts/rolodex-dns01-hook.sh \
#         --manual-cleanup-hook "scripts/rolodex-dns01-hook.sh cleanup"
#     passes:   CERTBOT_DOMAIN / CERTBOT_VALIDATION in the environment
#
# Configuration (environment):
#   ROLODEX_CLI       path to the rolodex-dns-cli binary (default: rolodex-dns-cli)
#   ROLODEX_ADDRESS   gRPC address           (default: 127.0.0.1:50051)
#   ROLODEX_SOCKET    gRPC unix socket path  (overrides ROLODEX_ADDRESS if set)
#   ROLODEX_TOKEN     gRPC auth token        (optional)
set -eu

CLI="${ROLODEX_CLI:-rolodex-dns-cli}"

conn_args() {
  if [ -n "${ROLODEX_SOCKET:-}" ]; then
    printf '%s' "--unix-socket ${ROLODEX_SOCKET}"
  else
    printf '%s' "--address ${ROLODEX_ADDRESS:-127.0.0.1:50051}"
    if [ -n "${ROLODEX_TOKEN:-}" ]; then
      printf ' %s' "--auth-token ${ROLODEX_TOKEN}"
    fi
  fi
}

# Resolve action, fqdn, value from either lego args or certbot env.
action="${1:-present}"
fqdn=""
value=""

if [ -n "${CERTBOT_DOMAIN:-}" ]; then
  # certbot mode: the cleanup hook is distinguished by a "cleanup" first arg.
  if [ "${1:-}" = "cleanup" ]; then action="cleanup"; else action="present"; fi
  fqdn="_acme-challenge.${CERTBOT_DOMAIN}."
  value="${CERTBOT_VALIDATION:-}"
else
  # lego exec mode: present|cleanup <fqdn> <value>
  fqdn="${2:-}"
  value="${3:-}"
fi

if [ -z "$fqdn" ] || [ -z "$value" ]; then
  echo "rolodex-dns01-hook: missing fqdn or value" >&2
  exit 1
fi

# shellcheck disable=SC2046
case "$action" in
  present)
    "$CLI" $(conn_args) add-record \
      --name "$fqdn" --record-type txt --value "$value" --ttl 60
    ;;
  cleanup)
    "$CLI" $(conn_args) remove-record \
      --name "$fqdn" --record-type txt --value "$value"
    ;;
  *)
    echo "rolodex-dns01-hook: unknown action '$action'" >&2
    exit 1
    ;;
esac
