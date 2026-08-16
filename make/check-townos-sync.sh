#!/usr/bin/env bash
#
# Verifies TOWNOS_CONTRACT.md against the Town OS and install checkouts that are
# actually on this machine.
#
# Nothing here is pinned to a revision. A pin would go stale silently and fail
# loudly on commits that changed nothing rolodex depends on — the worst of both
# — so this resolves whatever is checked out at the moment it runs. When no
# checkout is present it SKIPS rather than fails, because this repository has to
# build on a machine that has only this repository.
#
# What it checks, and why each one is a real failure rather than a tidiness rule:
#
#   1. Every method Town OS's Client interface declares exists on rolodex's own
#      Go client, which is the surface Town OS actually binds to. A Town OS
#      client calling a method rolodex does not have is a compile error there
#      and a removed method here — on a control plane whose failures are
#      otherwise silent by design, since rolodex holds programmed settings in
#      memory and a push that never lands looks exactly like one that did.
#
#   2. The forwarder scheme sets in the two hand-written parsers are identical.
#      Two parsers of one grammar in repositories that cannot see each other,
#      with no generated code between them, is the least defended thing in the
#      contract. A scheme added on one side only is a forwarder one repository
#      accepts and the other refuses.
#
#   3. The fixed addresses agree across all three repositories. Each of these is
#      written in more than one place and each pair has been wrong at least
#      once; :4443 in particular is EADDRINUSE against the ingress if it ever
#      becomes :443.
set -euo pipefail

TOWNOS_DIR="${TOWNOS_DIR:-../town-os}"
INSTALL_DIR="${INSTALL_DIR:-../install}"

fail=0
note() { printf '  %s\n' "$1"; }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }
ok() { printf '  \033[32mok\033[0m   %s\n' "$1"; }

if [ ! -d "$TOWNOS_DIR" ] && [ ! -d "$INSTALL_DIR" ]; then
  echo "check-townos-sync: no ../town-os or ../install checkout; skipping"
  echo "  (set TOWNOS_DIR= / INSTALL_DIR= to point at them)"
  exit 0
fi

echo "==> Checking TOWNOS_CONTRACT.md against local checkouts"

# ---------------------------------------------------------------------------
# 1. Every method Town OS's Client declares exists on rolodex's Go client.
# ---------------------------------------------------------------------------
#
# Checked against go/client.go rather than against the proto, because that is
# the surface Town OS actually binds to: its own `client` struct delegates
# straight through to this repository's Go package. Some of those methods are
# convenience wrappers rather than distinct rpcs — AddScopeTldWithListener is
# AddScopeTld with listen_ip set — so a proto-only check reports drift that is
# not there, and would miss a wrapper being removed, which is drift that is.
if [ -f "$TOWNOS_DIR/src/rolodex/client.go" ]; then
  missing=""
  while read -r method; do
    [ -n "$method" ] || continue
    if ! grep -qE "^func \(c \*Client\) ${method}\(" go/client.go; then
      missing="${missing} ${method}"
    fi
  done < <(awk '
    /^type Client interface \{/ { inside = 1; next }
    inside && /^\}/ { inside = 0 }
    inside && match($0, /^\t([A-Z][A-Za-z0-9]*)\(/, m) { print m[1] }
  ' "$TOWNOS_DIR/src/rolodex/client.go")

  if [ -n "$missing" ]; then
    bad "Town OS's Client declares methods rolodex's Go client does not have:${missing}"
  else
    ok "every method Town OS's Client declares exists on rolodex's Go client"
  fi
else
  note "skip: $TOWNOS_DIR/src/rolodex/client.go not found"
fi

# ---------------------------------------------------------------------------
# 2. Forwarder scheme parity between the two parsers.
# ---------------------------------------------------------------------------
if [ -f "$TOWNOS_DIR/src/rolodex/forwarder.go" ]; then
  rust_schemes="$(awk '
    /fn from_scheme/ { inside = 1 }
    inside && /=> Ok\(Transport::/ {
      while (match($0, /"[a-z0-9]+"/)) {
        s = substr($0, RSTART + 1, RLENGTH - 2)
        print s
        $0 = substr($0, RSTART + RLENGTH)
      }
    }
    inside && /^    \}/ { inside = 0 }
  ' src/forwarder.rs | sort -u)"

  go_schemes="$(awk '
    /^var forwarderSchemes = map\[string\]string\{/ { inside = 1; next }
    inside && /^\}/ { inside = 0 }
    inside && match($0, /"[a-z0-9]+":/) {
      print substr($0, RSTART + 1, RLENGTH - 3)
    }
  ' "$TOWNOS_DIR/src/rolodex/forwarder.go" | sort -u)"

  if [ -z "$rust_schemes" ] || [ -z "$go_schemes" ]; then
    bad "could not extract forwarder schemes (rust: $(echo "$rust_schemes" | tr '\n' ' '), go: $(echo "$go_schemes" | tr '\n' ' '))"
  elif [ "$rust_schemes" != "$go_schemes" ]; then
    bad "forwarder scheme sets differ between the two parsers:"
    diff <(echo "$rust_schemes") <(echo "$go_schemes") | sed 's/^/       /' || true
  else
    ok "forwarder schemes match: $(echo "$rust_schemes" | tr '\n' ' ')"
  fi
else
  note "skip: $TOWNOS_DIR/src/rolodex/forwarder.go not found"
fi

# ---------------------------------------------------------------------------
# 3. Fixed addresses, across all three repositories.
# ---------------------------------------------------------------------------
check_const() {
  # $1 label, $2 expected value, $3 file, $4 grep pattern
  [ -f "$3" ] || { note "skip: $3 not found ($1)"; return; }
  if grep -qF "$2" <(grep -E "$4" "$3" || true); then
    ok "$1 = $2 in $(basename "$3")"
  else
    bad "$1: expected $2 in $3 (pattern: $4)"
  fi
}

check_const "DoH backend" "127.0.0.2:4443" \
  "$TOWNOS_DIR/src/svc/systemcontroller/ingress_doh.go" 'RolodexDohBackend'
check_const "DoH backend" '"127.0.0.2:4443"' \
  "$INSTALL_DIR/scripts/rolodex-config.sh" 'bind:'
check_const "metrics listener" '"9153"' \
  "$TOWNOS_DIR/src/rolodex/rolodex.go" 'DefaultMetricsPort'
check_const "metrics listener" '"127.0.0.2:9153"' \
  "$INSTALL_DIR/scripts/rolodex-config.sh" 'metrics|bind'
check_const "DNS loopback" '"127.0.0.2"' \
  "$TOWNOS_DIR/src/rolodex/rolodex.go" 'DNSLoopback'
check_const "TLS subdir" '"tls/dot"' \
  "$TOWNOS_DIR/src/svc/systemcontroller/rolodex_transport_tls.go" 'RolodexTLSSubdir'
check_const "TLS subdir" '/data/tls/dot' \
  "$INSTALL_DIR/scripts/rolodex-config.sh" 'ENC_CERT|ENC_KEY'
check_const "gRPC socket" 'rolodex.sock' \
  "$INSTALL_DIR/scripts/rolodex-config.sh" 'unix_socket'

if [ "$fail" -ne 0 ]; then
  echo
  echo "check-townos-sync: contract drift. Fix the other side AND TOWNOS_CONTRACT.md together."
  exit 1
fi

echo "check-townos-sync: contract holds."
