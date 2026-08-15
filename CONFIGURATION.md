# Rolodex DNS Configuration Guide

> Languages: **English** | [繁體中文](CONFIGURATION.zh-TW.md) | [简体中文](CONFIGURATION.zh-CN.md) | [Español (España)](CONFIGURATION.es-ES.md) | [Español (México)](CONFIGURATION.es-MX.md) | [日本語](CONFIGURATION.ja-JP.md)

This is a task-oriented walkthrough: how to get a working server, then how to turn on each subsystem and why you would. For the exhaustive field list, see [Configuration Options](README.md#configuration-options) in the README.

- [How configuration is loaded](#how-configuration-is-loaded)
- [The smallest working config](#the-smallest-working-config)
- [Bind addresses](#bind-addresses)
- [Deployment shapes](#deployment-shapes) — four worked examples
- [Subsystems](#subsystems) — one section each
- [Runtime vs. restart](#runtime-vs-restart)
- [What the server refuses to start with](#what-the-server-refuses-to-start-with)
- [Troubleshooting](#troubleshooting)

## How configuration is loaded

The server reads one YAML file, `rolodex-dns.yml` by default:

```bash
rolodex-dns                        # reads ./rolodex-dns.yml
rolodex-dns -c /etc/rolodex-dns/config.yml
```

**A missing file is not an error.** The server logs `No config file found, using defaults` and starts on the built-in defaults — which is a real, usable configuration: DNS on `0.0.0.0:53`, iterative resolution from the roots with DNSSEC validation, gRPC on loopback and a Unix socket, blocklists off, encrypted transports off.

Every section is optional and every field within it has a default, so a config file only has to name what you are changing. Sections whose *presence* is the switch — `dot`, `doh`, `doq`, `proxy`, `dhcp`, `acme`, `metrics` — start nothing when omitted.

Logging is controlled by the `RUST_LOG` environment variable, not the config file:

```bash
RUST_LOG=rolodex_dns=debug rolodex-dns -c /etc/rolodex-dns/config.yml
```

## The smallest working config

```yaml
database_path: /var/lib/rolodex-dns/rolodex-dns.db

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"

grpc:
  unix_socket: /var/run/rolodex-dns.sock
  tcp_bind: ""          # manage over the socket only
```

That is a validating recursive resolver with a local record database. Add records over the socket:

```bash
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-record \
  --name nas.example.com --record-type a --value 192.168.1.10
```

Port 53 needs privilege. For development use a high port — `make dev` runs on `127.0.0.1:5300` via `dev.yml` — and in production give the binary `CAP_NET_BIND_SERVICE` or bind it through your service manager rather than running it as root.

## Bind addresses

Everywhere an address is taken (`dns.bind`, `dot.bind`, `doh.bind`, `doq.bind`, `grpc.tcp_bind`, `dhcp.bind`, `acme.bind`, `acme.portal_bind`, `metrics.bind`) four forms are accepted:

(`dns.bind` takes a list of protocol/address pairs, and `dot.bind`, `doh.bind` and `doq.bind` take **either one address or a list** — a list is how one listener covers both address families, since `0.0.0.0` is IPv4-only and a `[::]` socket collides with it on the same port. The rest take a single address.)

| Form | Example | Result |
| ---- | ------- | ------ |
| `ip:port` | `192.168.1.1:53` | One listener on that address |
| `[ipv6]:port` | `[::1]:53` | One listener; brackets required |
| `primary:port` | `primary:53` | The OS default-route outbound IP, detected at startup |
| `interface:port` | `eth0:53` | **One listener per IP on that interface** |

`primary` is resolved by a non-sending UDP connect toward `8.8.8.8:53` — it asks the routing table which source address would be used, and sends nothing. `interface:port` expands to every address assigned to the interface, so `eth0:53` on a dual-stack host creates two listeners.

`dns.bind` is a list of single-key maps, because a listener is a protocol *and* an address:

```yaml
dns:
  bind:
    - udp: "eth0:53"
    - tcp: "eth0:53"
    - udp: "127.0.0.1:53"
    - tcp: "127.0.0.1:53"
```

Interface-based binds are resolved **at startup**, not re-resolved later. An interface that gains an address after boot (a WireGuard tunnel coming up, say) is not picked up until restart — which is exactly why per-TLD ingress listeners are re-registrable at runtime, see [Owned TLDs and ingress](#owned-tlds-and-ingress).

## Deployment shapes

### 1. Home / small-office resolver

Validating, blocking ads and malware, serving a few local names, reachable from the LAN only.

```yaml
database_path: /var/lib/rolodex-dns/rolodex-dns.db

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"
  auto_ptr: true                # keep reverse PTRs in step with A/AAAA records

resolution:
  mode: auto                    # roots first, then encrypted, then the ISP resolver

dnssec:
  validate: true                # the default; stated here because it matters

dnsbl:
  enabled: true
  providers:
    - zone: dbl.spamhaus.org
      enabled: true

security:
  # the default already covers RFC 1918; narrow it if your LAN is a subset
  recursion_cidrs: ["127.0.0.0/8", "192.168.0.0/16", "::1/128"]

grpc:
  unix_socket: /var/run/rolodex-dns.sock
  tcp_bind: ""

metrics:
  bind: "127.0.0.1:9153"
```

Notes on the choices: `resolution.mode: auto` means no third party sees your queries while the roots are reachable, and resolution still survives a network that filters `:53`. `recursion_cidrs` is what keeps a `0.0.0.0:53` bind from being an open resolver — the default list is already safe, and narrowing it to your own ranges is a refinement, not a requirement.

### 2. Purely authoritative server

No upstream resolution at all: every answer comes from the local database, and anything not found is an authoritative NXDOMAIN.

```yaml
database_path: /var/lib/rolodex-dns/auth.db

forwarders: []
resolution:
  mode: forward                 # forward mode with no forwarders = no upstream

dnssec:
  validate: false               # nothing is resolved upstream, so nothing to validate

security:
  recursion_cidrs: []           # belt and braces: recursion closed to everyone

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"
```

`forwarders: []` with `mode: forward` is the switch. `recursion_cidrs: []` is redundant with it but documents the intent and closes the blocklist-provider and cache-warm paths too.

Declare the zones you are authoritative for, so a miss inside them is NXDOMAIN rather than a lookup that goes nowhere:

```bash
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-auth-zone --zone example.com.
```

(Any zone that already *has* records is treated as authoritative automatically — see [Managed zones](#managed-zones-and-authoritative-zones).)

### 3. Split-horizon overlay node (Town OS shape)

The box is on a LAN and on a WireGuard overlay. Overlay peers are partitioned into network scopes; the LAN sees everything.

```yaml
database_path: /var/lib/rolodex-dns/rolodex-dns.db

dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"
  ingress_listen_port: 53

security:
  overlay_cidrs: ["10.64.0.0/10"]     # these sources are scope-enforced
  recursion_cidrs:                    # these sources may resolve upstream
    - "127.0.0.0/8"
    - "10.0.0.0/8"                    # includes the overlay
    - "192.168.0.0/16"
    - "::1/128"

grpc:
  unix_socket: /var/run/rolodex-dns.sock
  tcp_bind: ""
```

The two CIDR lists are **different questions** and are meant to be set independently:

- `overlay_cidrs` — "who is scope-enforced?" A source inside it must have joined a network (`JoinNetwork`) or it is REFUSED, and it sees only its own scope's TLDs.
- `recursion_cidrs` — "who may make this server ask someone else?" A source outside it still gets your authoritative data; it just cannot drive an upstream lookup.

Then build the scopes at runtime, not in the config file — they live in the database:

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI create-scope --name office                       # implies office.home.
$CLI add-scope-tld -s office --tld office. --listen-ip 10.64.0.1
$CLI add-scoped-record -s office --name git.office. --record-type a --value 10.64.0.5
$CLI join-network --ip 10.64.0.7 --scope office --ttl 300
```

### 4. Resolver on a hostile/filtered network

Some networks drop outbound `:53` and DPI the `:853` DoT handshake. The `auto` chain is built for this, and the only thing worth changing is which encrypted upstreams it uses:

```yaml
resolution:
  mode: auto
  secure_upstreams:
    - transport: https            # DoH on :443 — looks like ordinary HTTPS
      addr: "1.1.1.1:443"         # dialed by IP, so it needs no prior DNS
      hostname: cloudflare-dns.com
      path: /dns-query
    - transport: https
      addr: "8.8.8.8:443"
      hostname: dns.google
      path: /dns-query
  switch_grace_failures: 3        # deviating queries before a degrade commits
  recovery_probe_secs: 60         # how often a degraded chain retries the top
```

Secure upstreams are dialed by **IP** with the certificate validated against `hostname`, so the tier bootstraps with no DNS of its own. Note that an `auto` chain degraded past tier 0 is **not** DNSSEC-validated (a forwarded answer is somebody else's summary), and it says so by leaving AD clear.

## Subsystems

### Upstream resolution

```yaml
forwarders:                       # the "local" tier, and the only upstream in forward mode
  - "8.8.8.8:53"
  - "8.8.4.4:53"

resolution:
  mode: auto                      # auto | recursive | forward
  root_hints: []                  # override the built-in IANA roots
  public_fallback: ["1.1.1.1:53", "8.8.8.8:53"]
  delegation_persist_min_ttl: 300 # persist learned delegations above this TTL
  default_ttl: 300                # used ONLY where nothing carries a TTL
```

| Mode | Use when |
| ---- | -------- |
| `auto` (default) | You want privacy first but resolution must survive a filtered network |
| `recursive` | You want the roots or nothing — no upstream resolver is ever contacted |
| `forward` | You want a plain forwarder (or, with `forwarders: []`, no upstream at all) |

**`mode` here is the startup seed, not the running setting.** It is read once at
startup; after that the mode is whatever `SetResolutionMode` last set, and
`GetResolutionMode` reports the one actually resolving queries — so the two can
disagree, and the running server is the authority. `rolodex-dns-cli
set-resolution-mode -m <mode>` / `get-resolution-mode` are the same two calls from
the shell. Changing the file and restarting also works, but restarting a box's only
resolver is a DNS outage for everything on it, which is the whole reason the RPC
exists. Unlike the file, the RPC **rejects** an unrecognized mode rather than warning
and falling back to `auto`.

`default_ttl` is a **fallback, not a floor**. A TTL that is present is honoured exactly as sent, including a zone's SOA negative TTL. If you are trying to shorten or lengthen live TTLs, that is [TTL drift](#dns64-ttl-drift-address-family), not this.

### DNSSEC

Two independent halves. **Validation** is on by default and needs no configuration:

```yaml
dnssec:
  validate: true
  trust_anchors: []        # empty = the IANA root keys
```

It applies to the iterative path only (`recursive` mode, and the roots tier of `auto`), so it does nothing in `forward` mode. Bogus data becomes SERVFAIL and is never cached. Turn it off only if you have a specific reason — a broken upstream you cannot fix, or a private hierarchy you have not anchored yet.

`trust_anchors` takes DNSKEY presentation form, the four RDATA fields as `dig DNSKEY .` prints them, and an override **replaces** the IANA keys rather than adding to them:

```yaml
dnssec:
  trust_anchors:
    - "257 3 15 <base64 key>"     # a private root; IANA is NOT also trusted
```

A malformed anchor fails startup rather than falling back to IANA — an anchor that cannot match a real DNSKEY makes every signed zone fail with nothing pointing at the anchor as the cause.

**Signing** is not configured in YAML at all; it is a runtime operation on a zone:

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type KSK
$CLI generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type ZSK
$CLI sign-zone --zone example.com.
```

Re-run `sign-zone` after changing records. Signatures are replaced, not accumulated. RSA (algorithm 8) is refused at key generation — `ring` cannot generate RSA keys — and authenticated denial (NSEC/NSEC3) is validated but never generated.

### Security: the two CIDR lists

```yaml
security:
  qname_case_randomization: true      # 0x20 encoding on forwarded queries
  overlay_cidrs: ["10.64.0.0/10"]     # scope-enforced sources
  recursion_cidrs: [ ... ]            # sources allowed to resolve upstream
```

Getting these two confused is the most common configuration mistake, so, plainly:

| | `overlay_cidrs` | `recursion_cidrs` |
| --- | --- | --- |
| Question | Which *view* does this source get? | May this source make us ask upstream? |
| Inside the list | Must have joined a network, or REFUSED; sees only its scope | May drive upstream resolution |
| Outside the list | Trusted local source; global namespace | Still gets local/authoritative answers; REFUSED for anything off-box |
| Default | `10.64.0.0/10` | loopback, RFC 1918, link-local, ULA, CGNAT |

Leave `recursion_cidrs` alone unless you are *narrowing* it. Widening it toward the public internet turns the box into an open resolver, which is a reflection/amplification asset whether or not anyone is currently abusing it.

`qname_case_randomization` should stay on. Turn it off only for an upstream that normalizes the case of the question it echoes back — such a resolver will otherwise fail every query, since the case comparison is what makes 0x20 actually defend anything.

### Blocklists (DNSBL)

**DNSBL blocks by name**, checked before any external resolution. It is disabled by default with an empty provider list, so nothing is queried and no name is handed to a blocklist operator until you add providers.

```yaml
dnsbl:
  enabled: true
  refusal_cooldown_secs: 3600
  providers:
    - zone: dbl.spamhaus.org
      enabled: true
```

Addresses are blocked by the **local list** rather than by a provider — a provider is asked about the name being resolved, and on a reverse lookup that name is one nobody publishes reputation for. See the local entries below.

Three things worth knowing before you turn these on:

1. **Local records always win.** A blocklist runs after local records and managed zones, so a third-party listing can never take out an internal service. It runs *before* the response cache and the resolver, so a listing takes effect even for a name that was cached earlier.
2. **Blocking is per queried name, not per suffix.** `doubleclick.net` being listed does not block `stats.g.doubleclick.net` — the provider has to list it too. The allowlist *is* suffix-matched, because an escape hatch that missed subdomains would not be one.
3. **Refusal codes matter at volume.** A blocklist tells you "you are over quota" with the same kind of `A` record it uses for "listed". Refusal handling is on by default with a built-in code set; the only reason to configure `refusal_codes` is a private blocklist whose real listings collide with one (`refusal_codes: ["none"]`) or a wish to narrow the set. See [Refusal Codes and Provider Rotation](README.md#refusal-codes-and-provider-rotation).

Local entries and the allowlist are runtime state, not config:

```bash
CLI="rolodex-dns-cli -u /var/run/rolodex-dns.sock"
$CLI add-local-blocklist --name 10.0.0.5 --reason "known spam source"
$CLI add-dnsbl-allow --name vendor.example.com --reason "false positive"
$CLI add-dnsbl-allow --name 192.168.1.100 --reason "our own relay"   # IP works too
```

### Managed zones and authoritative zones

There is no zone list in the config file. A zone becomes authoritative one of two ways:

- **Implicitly**, by having records. Any record anywhere in the zone makes this server authoritative for all of it — so adding `foo.example.com` as a local override means `www.example.com` answers NXDOMAIN rather than resolving from the internet. That is the split-horizon bargain, and it is worth being deliberate about: override a public domain only when you mean to own it.
- **Explicitly**, with `add-auth-zone`, which is how you claim a zone that has no records yet, or a reverse zone (the implicit rule deliberately skips `in-addr.arpa`/`ip6.arpa`, since the heuristic there would claim the entire global reverse tree).

### Encrypted transports

Each section's presence is the switch, and each needs TLS material:

```yaml
dot:
  bind: "0.0.0.0:853"
  tls:
    cert_path: /etc/rolodex-dns/cert.pem
    key_path: /etc/rolodex-dns/key.pem
    auto_self_signed: false

doh:
  bind: "0.0.0.0:443"
  tls: { cert_path: /etc/rolodex-dns/cert.pem, key_path: /etc/rolodex-dns/key.pem, auto_self_signed: false }
  enable_h3: false

doq:
  bind: "0.0.0.0:8853"
  tls:
    auto_self_signed: true            # fine on a trusted network
    self_signed_sans:                 # the names LAN clients dial this box by
      - dns.home
      - town-os.local
```

`auto_self_signed: true` (the default) generates a certificate at startup if none is configured, which is convenient for a trusted network.

**A renewed certificate needs no restart.** A listener configured with `cert_path`/`key_path` re-reads those files every 30 seconds and starts serving a new pair within that window — connections already open finish under the certificate they handshook with, and the next one to arrive gets the new one. There is nothing to signal and nothing to coordinate with whoever writes the files: a poll that lands between an ACME client's two writes sees a key that does not match the certificate, refuses it, keeps serving the old pair, and retries on the next tick. A generated (`auto_self_signed`) certificate is not polled — there is no file behind it, and regenerating on a timer would hand every client a different certificate twice a minute.

**A certificate that has not been issued yet can be named.** Pointing `cert_path`/`key_path` at a file that does not exist is a hard failure only when `auto_self_signed` is off. With it on, the listener starts on generated material and the poll above adopts the real pair the moment it lands. That is what lets these paths be written before whatever issues the certificate has run — the ordinary case on a box whose CA is created after the resolver starts, where the alternative is restarting the box's only resolver once the file exists.

**DoT, DoH and DoQ are reconfigurable at runtime**, over `SetDotConfig` / `SetDohConfig` / `SetDoqConfig`. The bind addresses, the certificate paths and the SAN list can all be changed on a running server, and `Get*Config` reports what is actually bound. The YAML below is the startup configuration; it is not the only way in, and it is not the authority once the server is up.

**HTTP/3 is a second listener, and it is off by default.** `doh.enable_h3` opens one on the DoH address and port over UDP, sharing the TCP listener's certificate. The port is the same because that is where both discovery mechanisms say it is: an `Alt-Svc` header on every DoH response, for clients already connected, and `alpn=h2,h3` in the DDR designation, for clients that have not connected at all. A QUIC bind that fails fails the whole transport rather than leaving h2 up alone — a listener that promised HTTP/3 and served h2 is a failure no client can see.

**If a DoT client reports a certificate name mismatch, this is the setting.** A generated certificate covers `localhost`, `127.0.0.1`, `::1`, and the listener's own bind addresses — so a listener on `192.168.1.5:853` already works for a client dialling that address, and nothing has to be configured. What it cannot cover is anything else the box answers to: its hostname, its mDNS `.local` name, a CNAME the LAN knows it by, or the address a NAT publishes it on. Those go in `self_signed_sans`. A listener on a **wildcard** bind (`0.0.0.0:853`, the default) gets nothing derived at all, because `0.0.0.0` is not an identity any client dials — on a wildcard bind the list is the only thing naming the box.

This is a name check, not a trust decision, and it fails first. The client still has to be told to trust the certificate — pin it, or publish and check it through DANE/TLSA — because a self-signed certificate has no chain. A client that validates nothing (`kdig +tls`, systemd-resolved in opportunistic mode) is unaffected either way.

### gRPC management

```yaml
grpc:
  tcp_bind: "127.0.0.1:50051"       # "" disables TCP
  unix_socket: /var/run/rolodex-dns.sock   # "" disables the socket
  shared_secret: ""                 # required for a non-loopback tcp_bind
```

- **The Unix socket bypasses authentication entirely**, so its file mode *is* the access control. It is created `0660` (not under the umask), so grant access by `chgrp`ing it to an admin group rather than loosening the mode.
- **TCP requires the shared secret**, compared in constant time, with per-source lockout after repeated failures. An empty secret means "no authentication", which is fine on loopback and refused at startup on anything routable.
- Prefer the socket. `tcp_bind: ""` with a socket path is the recommended shape for a single-host deployment.

### DHCP

Presence of the section enables it; `tld` is required and is where hostnames land:

```yaml
dhcp:
  bind: "0.0.0.0:67"
  tld: example.com          # a client "laptop" registers as laptop.lan.example.com.
  default_lease_duration: 3600
  reclaim_timeout: 86400
  sweep_interval: 60
```

Pools are runtime state, per network scope:

```bash
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-dhcp-pool -s office \
  --range-start 10.0.0.100 --range-end 10.0.0.200 \
  --gateway 10.0.0.1 --subnet-mask 255.255.255.0 --dns-servers 10.0.0.1
```

A pool is a single contiguous range, and allocation fails when it is exhausted — there is no cross-pool aggregation. MAC-to-IP bindings are sticky. A client-supplied hostname must be a valid single DNS label (RFC 1123) or registration is skipped with a warning; it is rejected rather than sanitized, so nothing is silently registered under a name the client did not send.

### ACME issuer and portal

Presence of the section creates the root CA at boot and starts two listeners: the client-facing ACME endpoint and the enrollment portal.

```yaml
acme:
  bind: "0.0.0.0:8555"
  portal_bind: "127.0.0.1:8500"                       # trusted network only
  directory_url: "https://dns.example.com:8555/acme"  # set this — clients see it
  root_ca_cn: "Rolodex Root CA"
  leaf_validity_days: 90
  require_eab: true
  issuance_scope: managed_zones                       # or "any"
  tls: { auto_self_signed: true }
```

`directory_url` is what ACME clients are told to talk to, so it must be the externally reachable URL, not `localhost`. **`portal_bind` must stay on a trusted address** — anyone who can reach the portal may enroll. Enrollment is confined to zones this server actually manages unless `issuance_scope: any`, and `require_eab: true` keeps account registration behind a minted credential.

### Metrics

```yaml
metrics:
  bind: "127.0.0.1:9153"
```

Absent by default, so an upgrade opens no new port. Plain HTTP and unauthenticated — it carries only aggregate counts, never query names or record values — so bind it to a private address. The series worth watching first are `rolodex_dns_answers_total{source}` (which stage answered), `rolodex_dns_dnssec_verdicts_total{verdict}`, and `rolodex_dns_blocklist_rotated_out`.

### DNS64, TTL drift, address family

```yaml
dns64:
  enabled: false
  prefix: "64:ff9b::"       # the well-known prefix

ttl_drift:
  mode: disabled            # disabled | fixed | logarithmic
  fixed_adjustment: "5m"    # "5m", "-30s", "1h30m", "2d12h"
  log_multiplier: 0.1

address_family:
  mode: auto                # auto | off | force4 | force6
  probe_interval_secs: 30
  fail_threshold: 2
```

`address_family: auto` is the default and is usually what you want: it TCP-connects to public resolvers on `:443` to test *actual* per-family reachability, and suppresses A or AAAA answers for a family the host cannot route, so clients fall back instead of stalling. Use `force4`/`force6` to pin a family without probing, `off` to always answer both.

### Owned TLDs and ingress

Not configuration — these live in the database and are managed at runtime — but two config fields interact with them:

- `dns.ingress_listen_port` (default 53) is the port every per-TLD ingress listener binds on. The IP is per-TLD, given with `add-scope-tld --listen-ip`.
- Ingress listeners are replayed from the database at boot. If the overlay interface does not exist yet, the bind fails and the entry is treated as absent, so re-adding the TLD once the tunnel is up retries the bind without a restart.

## Runtime vs. restart

Much of what looks like configuration is runtime state in SQLite, changed over gRPC with no restart:

| Changed at runtime (gRPC/CLI) | Requires a restart |
| ---- | ---- |
| Records, scoped records, scopes, associations | `dns.bind` and every other bind address |
| Authoritative zones, owned TLDs, ingress listeners | `resolution.*` **except `mode`**, and `forwarders` (initial values; `set-forwarders` changes them live) |
| DNSBL config, local entries, allowlist | `dnssec.*` |
| DNS64, TTL drift, proxy, DoT/DoH/DoQ config | `security.*` |
| DHCP pools, leases, certificate options | `database_path`, `dhcp.*`, `acme.*`, `metrics.*` |
| DNSSEC keys and zone signing; ACME CAs and EAB credentials | `<transport>.tls.*` — the paths and SAN list, not the certificate itself |
| TLS certificate **files** — rewritten in place, picked up within 30s | — |
| `resolution.mode` — `set-resolution-mode` switches it, `get-resolution-mode` reads what is in effect | — |

Records and blocklist changes take effect on the next query — record mutations flush the response cache automatically.

## What the server refuses to start with

These are deliberate hard failures, not warnings, because each one otherwise produces a server that looks healthy while doing the wrong thing:

- **A routable `grpc.tcp_bind` with an empty `shared_secret`.** That combination is an unauthenticated management plane on a reachable port. Loopback is fine and is the documented development shape; `0.0.0.0` and `::` are not loopback.
- **A malformed DNSSEC trust anchor.** Falling back to the IANA keys would leave an operator who configured a private root anchored to the wrong thing, validating happily.
- **An unparseable blocklist refusal code.** A code that silently does not apply is a refusal that reads as a listing — every name checked against that provider would NXDOMAIN.
- **An unresolvable bind address** — an interface with no addresses, or a name that is neither an IP nor an interface. This is fatal for the DNS, DoT, DoH, DoQ, gRPC, DHCP and metrics listeners; the two ACME listeners log the error and the rest of the server continues.

A parse error in the YAML is also fatal. A file that does not exist is not.

A **bind that resolves but fails at the OS** — the port is taken, or the address does not exist yet — is not fatal: it is logged per listener and the rest of the server runs. So `EADDRINUSE` on `:53` shows up as an error line, not as a failed start; check the log rather than assuming a clean boot means every listener came up.

## Troubleshooting

| Symptom | Likely cause |
| ------- | ------------ |
| Clients outside the LAN get REFUSED for everything except your own zones | Working as intended: `security.recursion_cidrs`. Add their range if they should have recursion |
| An overlay peer gets REFUSED for every name | It is inside `security.overlay_cidrs` but has not called `JoinNetwork`, or its association TTL lapsed |
| A public name under a domain you overrode returns NXDOMAIN | Adding one record made this server authoritative for the whole zone. Add the name locally, or move the override to a name you own |
| A name resolves everywhere else but SERVFAILs here | DNSSEC validation rejecting it. Check `rolodex_dns_dnssec_verdicts_total{verdict="bogus"}`; confirm with `dig +cd` (checking disabled) |
| **Every** name SERVFAILs, and the chain never degrades to the encrypted upstream | The root zone itself is not validating: a trust anchor this build does not know (a KSK rollover), a wrong `dnssec.trust_anchors`, or something on `:53` answering DNSKEY queries with its own material. This is deliberate — a root that will not validate is a verdict, not a tier failure, so the query is refused rather than quietly re-asked of an upstream that does not validate. `dnssec.validate: false` is the escape hatch while you fix the anchor |
| A name under `arpa.` is REFUSED (`ipv4only.arpa`, `dig -x` for an address you do not hold) | Working as intended: `arpa.` and everything beneath it is answered from local data or not at all, in every resolution mode. Nothing in that subtree is sent upstream. Add the record locally, or wait for the reverse-zone work |
| `rolodex_dns_dnssec_blamed_roots` is non-zero | A root server answered with DNSSEC that does not validate against your anchor and has been dropped from the root set for 15 minutes, doubling per offence. If **all** of them are dropped, suspect the anchor or the root zone, not the servers — the log says so explicitly. Blame is in memory only and resets on restart |
| Every name checked against one blocklist started NXDOMAINing | Pre-refusal-handling behaviour. Check `get-dnsbl-config` for rotated-out providers, and that provider's quota |
| A DHCP client's hostname never appears in DNS | It is not a valid single DNS label — hostnames are rejected, not sanitized. The warning names it |
| `dig -x` fails for a host that is fine | A local blocklist entry matched the address. `add-dnsbl-allow --name <ip>` lifts it |
| A renewed certificate is not being served | Give it 30 seconds. If it persists, the log says why — a reload that fails is logged every poll. The usual cause is a certificate and key that do not match, which is also what a half-finished write looks like; a renewal left permanently half-written never completes. A listener with `auto_self_signed` is not polled at all: it has no files |
| A DoT client reports a certificate name mismatch for the box's hostname or LAN address | The generated certificate names the loopback set and the listener's bind addresses only, and a wildcard bind contributes nothing. Add the name to `dot.tls.self_signed_sans` and restart. This is separate from trusting the certificate at all, which self-signed still requires |
| A DoT client fails the handshake with `no_application_protocol` | It is offering an ALPN protocol other than `dot`. The listener advertises `dot` and refuses a client that offers only something else; a client offering no ALPN at all is served normally |
| Ingress listener never came up | Its IP did not exist at boot. Re-add the TLD once the interface is up |

For the complete field reference, see [Configuration Options](README.md#configuration-options).
