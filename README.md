# Rolodex DNS

A privacy-first, split-horizon DNS server and recursive/forwarding resolver with encrypted transports, DNSSEC, and gRPC management, written in Rust.

Rolodex DNS provides DNS over UDP, TCP, TLS (DoT), HTTPS (DoH), and QUIC (DoQ) with a local record database that takes priority over external resolution. Records are managed remotely via gRPC (shared secret authentication over TCP, or unauthenticated over Unix socket). It supports TLD-level resolution with domain overlay, so internal DNS representations are always preferred. A built-in DNS response cache prevents query leakage to upstream resolvers once a record has been seen.

Names that are not local are resolved **iteratively from the root servers** by default, falling back through encrypted (DoH/DoT) and plaintext upstreams so resolution survives networks that filter outbound port 53. See [Upstream Resolution](#upstream-resolution).

Answers resolved from the roots are **DNSSEC-validated** against the IANA trust anchors by default; bogus data is never served and never cached. See [DNSSEC](#dnssec).

Rolodex DNS also supports Realtime Blackhole Lists (RBLs) and domain blocklists (DNSBLs) for spam/malware filtering, DNSSEC zone signing, DANE TLSA certificate association, a built-in ACME certificate authority, DNS64 AAAA synthesis, per-network DNS partitioning, and an integrated DHCPv4 server.

New here? Start with the **[Configuration Guide](CONFIGURATION.md)** — a task-oriented walkthrough from a minimal working config to each subsystem, with a worked example per deployment shape.

## Features

- **Privacy-first DNS cache**: Local DNS response caching prevents query leakage to upstream. Once cached, queries are answered locally without contacting any forwarder. Set `forwarders: []` for a purely authoritative server.
- **Encrypted transports**: DNS-over-TLS (DoT, port 853), DNS-over-HTTPS (DoH, port 443 with GET/POST), DNS-over-QUIC (DoQ, port 8853)
- **Split-horizon DNS**: Local database records always take priority over externally-resolved results
- **DNS over UDP and TCP**: Full protocol support for both transport layers
- **Recursive resolver with resilient fallback**: Iterative resolution from the root servers by default, then DoH/DoT to public resolvers, then the configured forwarders, then plaintext public resolvers — so resolution keeps working on networks that filter `:53` (and DPI that blocks DoT's `:853`). A sticky tier avoids paying timeouts on a dead path, and every tier switch flushes the cache
- **Resolver caching that honours TTLs**: A persistent zone→nameserver delegation cache (warm across restarts), an in-memory cache for glue/glue-less NS lookups/CNAME hops, and RFC 2308 negative caching — all served with their remaining lifetime
- **Address-family awareness**: A background probe tests real IPv4/IPv6 internet reachability and suppresses A or AAAA answers for a family the host cannot route, so clients fall back instead of stalling on a dead stack
- **Forwarding resolver**: Configurable upstream DNS forwarders, usable exclusively via `resolution.mode: forward`
- **TLD/domain overlay**: Add records at any level (including TLDs) to override public DNS
- **DNSSEC signing**: Ed25519 (preferred) and ECDSA P-256/P-384 key generation, zone signing, and DS record computation. RSA/SHA-256 is verifiable but cannot be generated (`ring` has no RSA key generation), and authenticated denial (NSEC/NSEC3) is not produced
- **DNSSEC validation**: Answers resolved iteratively are validated against the IANA root trust anchors, on by default (`dnssec.validate`). The chain is built top-down alongside the delegation walk, so a DS costs no extra query; an unsigned delegation must *prove* it is unsigned (signed NSEC/NSEC3), so signature stripping is not a downgrade. Bogus data is SERVFAIL and is never cached, and AD is set only for genuinely Secure answers
- **DANE TLSA + ACME issuer**: TLSA record generation from certificates, a built-in ACME certificate authority (per-zone intermediate CAs), self-signed root CA generation, ACME DNS-01 challenge handling (serves `_acme-challenge` TXT records natively)
- **CA distribution over DNS**: the root and per-zone intermediate CA chain is published as `CERT` records (RFC 4398) with a chunked `TXT` fallback, so any client that can resolve the zone can fetch and trust the CA — no portal access required (see [Distributing and Trusting the CA](#distributing-and-trusting-the-ca))
- **22 record types**: A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR, URI, SSHFP, DNAME, ANAME, ZONEMD, TLSA, CERT, DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM. All 22 can be stored and listed; NSEC, NSEC3 and NSEC3PARAM are never generated or served (see [DNSSEC](#dnssec))
- **DNS wildcards**: RFC 4592 compliant wildcard matching (`*.example.com.` matches single-label substitutions, exact match takes priority)
- **Authoritative DNS**: AA bit enforcement for local zones and explicitly declared authoritative zones
- **EDNS (RFC 6891)**: OPT record support, payload size negotiation, DO bit for DNSSEC, BADVERS for version > 0
- **DNS64 (RFC 6147)**: AAAA synthesis from A records with configurable prefix (default `64:ff9b::/96`)
- **TTL drift**: Fixed mode (add/subtract duration, supports compound formats like `"1h30m"`) and experimental logarithmic mode (latency-based)
- **QNAME case randomization**: 0x20 encoding randomizes QNAME case in forwarded queries for cache poisoning defense
- **gRPC management**: Remote record management via gRPC with shared secret or Unix socket auth
- **RBL support**: Realtime Blackhole List checking with in-memory caching, plus a local RBL database for custom blocklist entries
- **DNSBL support**: Domain blocklists (Spamhaus DBL, SURBL, URIBL) checked before any external resolution, so a listed name is refused even if a forwarded answer was previously cached
- **Blocklist refusal handling**: A DNSxL answers "listed" and "stop querying us" with the same kind of `A` record, so refusal codes (`127.255.255.254`, `127.0.0.1`, …) are recognized as *not* a listing and the provider is rotated out of the lookup rotation for a cooldown — instead of NXDOMAINing every name checked against it
- **Blocklist allowlist**: One escape hatch covering every list and both gates — an entry exempts a name and its subdomains from the DNSBL/local check, and an address (by reverse name or IP literal) from the RBL check
- **Recursion access control**: `security.recursion_cidrs` decides who may drive *upstream* resolution, defaulting to ranges unroutable from the internet, so a default `0.0.0.0:53` bind is not an open recursive resolver. Strangers still receive this server's authoritative answers
- **Network scoping**: Split-horizon DNS views with per-scope records and IP-based access control. Scope enforcement is confined to the configured overlay (WireGuard) CIDRs; loopback, LAN, and container sources are trusted and never refused
- **Per-network owned TLDs**: Globally-unique TLDs owned by a scope, partitioned across overlay peers and never forwarded upstream, with optional per-TLD **ingress DNS listeners** that answer on a network's own address and rewrite programmed names to its ingress controller
- **Integrated DHCPv4 server**: Per-scope address pools with sticky MAC bindings, automatic A/PTR registration, certificate delivery via site-specific options, and a background lease sweep
- **Automatic reverse PTR records**: Optional (`dns.auto_ptr`) maintenance of matching `in-addr.arpa`/`ip6.arpa` PTRs for A/AAAA records added through gRPC
- **Proxy support**: Forward DNS queries through HTTP CONNECT, SOCKS5, or DoH proxy
- **Prometheus metrics**: an optional, off-by-default `/metrics` endpoint exposing 77 metric families with bounded label cardinality — including per-stage answer attribution and per-TLD isolation, so the split-horizon pipeline is legible from outside. Query names are never labels
- **SQLite persistence**: DNS records persist across restarts
- **TLS hot-reload (partial)**: `TlsManager` rebuilds its `rustls::ServerConfig` from the configured PEM files on demand and publishes it to watchers, keeping the previous certificate serving if the rebuild fails. **Not yet wired to the listeners** — each of DoT/DoH/DoQ/ACME takes a one-time config snapshot at startup, so a renewed certificate still requires a restart to be served
- **Performance**: Multi-threaded tokio runtime, lock-free RBL and resolver state (`AtomicBool` + `ArcSwap` + atomics), in-memory boot caches for scopes/zones/TLDs/RBL entries, UDP socket pool for upstream forwarding, and DashMap/DashSet concurrent caching throughout

## Building

```
make build
```

## Testing

```
make test
```

Runs lint (`cargo fmt --check` + `clippy --all-targets -D warnings`), the Go integration and unit tests, the Rust integration and unit tests, and the JavaScript lint/integration/unit tests. The Rust integration layer includes real-socket suites for DNSSEC signing and validation (against a signed mock hierarchy whose responses are tampered with at serialization time, so each test is "a valid deployment, attacked"), the blocklist NXDOMAIN contract, blocklist refusal codes, DoQ, proxying, TLS reload, ZONEMD, ACME administration, and a `security_*` suite per security finding. Use `make test-log` for the same run tee'd into a timestamped log file under `/tmp/rolodex-dns/log` (override with `LOG_DIR`), printed at the end even on failure. Individual layers: `make lint`, `make rust-test`, `make rust-integration-test`, `make go-test`, `make go-integration-test`, `make js-test`, `make js-integration-test`.

`make prometheus-test` is separate and opt-in: it runs every PromQL query documented in this file through a real Prometheus container scraping a live server, catching a query that is malformed *as PromQL* rather than merely naming a series that does not exist. It needs podman and, on a cold image cache, the network, which is why it is not part of `make test` — the always-on half of that check (do the named series and label values exist?) runs there as `promql_docs_test`.

## Development

Start a local dev server for testing and development:

```
make dev
```

This will:
1. Build the project in debug mode (`cargo build`)
2. Start the server using `dev.yml` with the following settings:
   - DNS listeners on `127.0.0.1:5300` and the primary outbound IP on port `5300` (UDP and TCP)
   - gRPC Unix socket at `/tmp/rolodex-dns.sock` (no TCP gRPC listener)
   - SQLite database at `/tmp/rolodex-dns-dev.db`
   - No authentication required
   - RBL checking disabled
   - Default upstream forwarders (`8.8.8.8:53`, `8.8.4.4:53`), used as the `local` tier of the default `auto` resolution chain

`make help` lists every target with a description, grouped by section (it is also the default goal, so a bare `make` prints it).

For a release-optimized dev server:
```
make dev-release
```

To install the binaries to your Cargo bin directory:
```
make install
```

After the dev server is running, you can manage it using the `rolodex-dns-cli` binary or the Go client library connected to `/tmp/rolodex-dns.sock`. Press Ctrl+C to stop the server.

## Container Images

Rolodex DNS cross-compiles its binaries on the build host with `cargo-zigbuild`, then assembles a lean runtime image (`debian:bookworm-slim`) containing only the stripped binaries and a CA bundle. The `Containerfile` deliberately contains **no `RUN` steps**, which is what lets any host build an image for any architecture with no emulation and no builder VM.

Images are published to `quay.io/town/rolodex` as multi-arch manifest lists covering `linux/amd64` and `linux/arm64`.

### Multi-Architecture Builds

Builds are **native**: each architecture is compiled on a host of that architecture. Every image is tagged with an arch suffix using the `uname -m` machine name (`-x86_64` or `-aarch64`, *not* the OCI `amd64`/`arm64` names), so a deploy host can pull `` <tag>-`uname -m` `` with no mapping. A separate manifest step assembles the per-arch images into a single multi-arch tag.

#### Choosing the architecture: `TARGET`

`TARGET` selects the architecture for every container target (`image`, `push-arch`, `push-rc`, `push-release`). It defaults to the host architecture, and matches the `TARGET=` model used by the town-os `install` repo so the same value can be passed to either:

| `TARGET` | Builds |
| -------- | ------ |
| *(unset)* | the host architecture |
| `x86_64`, `x86`, `amd64` | amd64 image, tagged `-x86_64` |
| `aarch64`, `arm64` | arm64 image, tagged `-aarch64` |
| `rpi` | arm64 image, tagged `-aarch64` |
| `rg35xxpro`, `rg35xx-pro`, `rg35xx`, `anbernic` | arm64 image, tagged `-aarch64` |

Any other value is an error listing the accepted ones. The board flavors don't change the image — rolodex-dns ships one container image per architecture, not per board — they're accepted so a `TARGET=rg35xxpro` that means something specific in `install` still resolves sensibly here.

**Any host builds any architecture.** A foreign `TARGET` is cross-compiled rather than emulated, so there are no rejected combinations and no builder VM — see Cross-Compilation below.

`podman build` RUN steps share the host network (`--network=host`) so they can use a DNS resolver on the host's loopback (e.g. rolodex itself); override with `BUILD_NETWORK=` to opt out.

The end-to-end flow for publishing a multi-arch image — one host per arch:

1. On an amd64 host: `make push-release` → pushes `…:latest-x86_64` (and the date tag).
2. On an arm64 host: `make push-release` → pushes `…:latest-aarch64` (and the date tag).
3. On either host (once both are pushed): `make manifest-release` → creates and pushes the multi-arch `…:latest` manifest list.

A consumer that pulls `quay.io/town/rolodex:latest` then transparently receives the image matching their architecture.

#### Cross-Compilation

Both architectures are cross-compiled on whichever host runs `make`, using `cargo-zigbuild` with zig as the C cross-compiler and linker. `make deps` provisions the whole toolchain **without root**:

```bash
make deps        # rustup targets + cargo-zigbuild + zig, and the JS dev deps
make cross-deps  # just the Rust cross toolchain
```

A plain `rustup target add` would not be enough: `rusqlite` compiles SQLite's bundled C sources and `ring` compiles C and assembly, so a real cross **C** toolchain has to be present or the build fails at the `cc` step. zig provides one without any distro-specific packages, and links against a pinned glibc (`GLIBC_VERSION`, default `2.36` to match `debian:bookworm`) so the binary runs on the runtime image whatever the build host carries.

Version pins, all overridable: `ZIG_VERSION`, `ZIGBUILD_VERSION`, `GLIBC_VERSION`.

```bash
make image TARGET=x86_64         # cross-compile + assemble an amd64 image
make push-release TARGET=aarch64 # cross-compile + push an arm64 image
make push-release-all            # both arches + the manifest, from one host
```

`make image-amd64`, `push-rc-amd64`, and `push-release-amd64` remain as aliases for the `TARGET=x86_64` forms.

### Building

Build the release image for the **host** architecture (tagged as `quay.io/town/rolodex:latest-<arch>`):

```
make image
```

Build for a specific architecture:

```
make image TARGET=x86_64
make image TARGET=aarch64
```

Build with a specific tag:

```
make IMAGE_TAG=v1.2.3 image
```

Cargo registry and git caches are persisted in `.cache/` to speed up rebuilds.

### Pushing

Login to Quay.io (reads `QUAY_USERNAME` and `QUAY_PASSWORD` from the environment or `.env`):

```
make quay-login
```

Build and push the release candidate image for `TARGET` (auto-tags `rc.YYYYMMDD-<arch>` and `rc.latest-<arch>`, e.g. `rc.latest-x86_64` / `rc.latest-aarch64`):

```
make push-rc
make push-rc TARGET=x86_64    # explicit architecture
```

Build and push the release image for `TARGET` (auto-tags `release.YYYYMMDD-<arch>` and `latest-<arch>`):

```
make push-release
make push-release TARGET=aarch64
```

#### Assembling the Multi-Arch Manifest

After the per-arch images for **all** architectures have been pushed (run `push-rc`/`push-release` on each native host), assemble and push the multi-arch manifest list from any host:

```
make manifest-rc       # combines rc.latest-x86_64 + rc.latest-aarch64 → rc.latest (and the rc.YYYYMMDD date tag)
make manifest-release  # combines latest-x86_64 + latest-aarch64 → latest (and the release.YYYYMMDD date tag)
```

The manifest is assembled from the images already in the registry (`podman manifest add docker://…`), so it does not require the per-arch images to be present locally.

#### Pushing a Specific Tag

Use `IMAGE_TAG` to build and push an exact tag instead of the auto-generated date-based tags. The arch suffix is still applied to the per-arch images:

```
make IMAGE_TAG=v1.2.3 push-release    # pushes quay.io/town/rolodex:v1.2.3-<arch>
make IMAGE_TAG=v1.2.3 manifest-release # combines v1.2.3-x86_64 + v1.2.3-aarch64 → v1.2.3
```

The same works with `push-rc` / `manifest-rc`:

```
make IMAGE_TAG=v1.2.3-rc1 push-rc
make IMAGE_TAG=v1.2.3-rc1 manifest-rc
```

To push an already-built image under a different tag without rebuilding:

```
sudo podman tag quay.io/town/rolodex:latest quay.io/town/rolodex:v1.2.3
sudo podman push quay.io/town/rolodex:v1.2.3
```

To push to a different registry entirely:

```
sudo podman tag quay.io/town/rolodex:latest registry.example.com/myorg/rolodex:v1.2.3
sudo podman push registry.example.com/myorg/rolodex:v1.2.3
```

### Cleanup

Remove local container images:

```
make clean-containers
```

## Configuration

Rolodex DNS reads configuration from a YAML file (default: `rolodex-dns.yml`, overridable with `-c`/`--config`). Every section is optional — a missing file starts the server on defaults.

For a walkthrough that builds a configuration up one subsystem at a time, with a worked example per deployment shape, see the **[Configuration Guide](CONFIGURATION.md)**. The reference below is the complete field list.

### Bind Address Syntax

Bind address strings (used by `dns.bind`, `dot.bind`, `doh.bind`, `doq.bind`, `grpc.tcp_bind`, `dhcp.bind`) accept four forms:

| Form | Example | Description |
| ---- | ------- | ----------- |
| `ip:port` | `192.168.1.1:53` | Bind to a specific IPv4 address and port |
| `[ipv6]:port` | `[::1]:53` | Bind to a specific IPv6 address and port (brackets required) |
| `primary:port` | `primary:53` | Detect the OS default-route outbound IP and bind to it |
| `interface:port` | `eth0:53` | Bind to all IPs on the named network interface |

The `primary` keyword detects which IP address the OS would use to reach the public internet (via a non-sending UDP connect to `8.8.8.8:53`) and binds a single listener on that address. The keyword is case-insensitive.

Interface binding resolves all IPv4 and IPv6 addresses assigned to the interface and creates a separate listener for each. For example, if `eth0` has `192.168.1.5` and `fe80::1`, then `eth0:53` creates listeners on both `192.168.1.5:53` and `[fe80::1]:53`.

The `dns.bind` field is a list of protocol/address pairs. Each entry is a single-key map with `udp` or `tcp` as the key and a bind address as the value:

```yaml
dns:
  bind:
    - udp: "eth0:53"
    - udp: "lo:53"
    - tcp: "eth0:53"
```

### Example Configuration

```yaml
# Database file path
database_path: rolodex-dns.db

# Upstream DNS forwarders (address:port format). Used as the "local" tier of the
# auto chain, or as the only upstream when resolution.mode is "forward".
# Set to empty list (with resolution.mode: forward) for a purely authoritative server
forwarders:
  - "8.8.8.8:53"
  - "8.8.4.4:53"

# Upstream resolution strategy (all fields optional; defaults shown)
resolution:
  mode: auto              # "auto" (tier chain), "recursive" (roots only), "forward"
  root_hints: []          # override the built-in IANA root addresses
  secure_upstreams:       # encrypted tier, tried when root recursion fails
    - transport: https    # "https" (DoH :443, preferred) or "tls" (DoT :853)
      addr: "1.1.1.1:443" # dialed by IP, so it needs no prior DNS
      hostname: cloudflare-dns.com  # SNI / certificate name validated
      path: /dns-query
    - transport: https
      addr: "8.8.8.8:443"
      hostname: dns.google
      path: /dns-query
  public_fallback:        # plaintext Do53, tried last
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  switch_grace_failures: 3      # deviating queries before a tier degrade commits
  recovery_probe_secs: 60       # how often a degraded chain retries from the top
  delegation_persist_min_ttl: 300  # persist delegations with a TTL above this
  default_ttl: 300              # fallback only where nothing carries a TTL

# DNSSEC validation of answers resolved from the roots (iterative path only)
dnssec:
  validate: true          # bogus data becomes SERVFAIL and is never cached
  trust_anchors: []       # empty = the IANA root keys; an override REPLACES them

# Each entry pairs a protocol (udp/tcp) with a bind address.
# Bind addresses accept ip:port, [ipv6]:port, primary:port, or interface:port.
dns:
  bind:
    - udp: "0.0.0.0:53"     # or "eth0:53" to bind to a specific interface
    - tcp: "0.0.0.0:53"
  auto_ptr: false           # maintain reverse PTRs for A/AAAA added via gRPC
  ingress_listen_port: 53   # port for per-TLD ingress listeners (IP is per-TLD)

# DNS-over-TLS (RFC 7858)
dot:
  bind: "0.0.0.0:853"
  tls:
    cert_path: /etc/rolodex-dns/cert.pem
    key_path: /etc/rolodex-dns/key.pem
    auto_self_signed: false

# DNS-over-HTTPS (RFC 8484)
doh:
  bind: "0.0.0.0:443"
  tls:
    cert_path: /etc/rolodex-dns/cert.pem
    key_path: /etc/rolodex-dns/key.pem
    auto_self_signed: false
  enable_h3: false

# DNS-over-QUIC (RFC 9250)
doq:
  bind: "0.0.0.0:8853"
  tls:
    cert_path: /etc/rolodex-dns/cert.pem
    key_path: /etc/rolodex-dns/key.pem
    auto_self_signed: false

grpc:
  # TCP gRPC listener (empty string to disable)
  tcp_bind: "127.0.0.1:50051"
  # Unix socket path (empty string to disable)
  unix_socket: /var/run/rolodex-dns.sock
  # Shared secret for TCP gRPC authentication (not required for Unix socket)
  shared_secret: your-secret-here

rbl:
  # Enable/disable RBL checking globally (default: false)
  enabled: false
  # Seconds a provider that refuses our queries stays out of rotation
  refusal_cooldown_secs: 3600
  # RBL providers
  providers:
    - zone: zen.spamhaus.org
      enabled: true
      # Codes meaning "query refused", not "listed". Omit for the built-in set;
      # the single entry "none" disables refusal detection for this provider.
      refusal_codes: []
      # Per-provider override of the rotate-out duration (omit to inherit)
      refusal_cooldown_secs: 3600
    - zone: bl.spamcop.net
      enabled: true
    - zone: b.barracudacentral.org
      enabled: true
    - zone: dbl.spamhaus.org
      enabled: true

# Domain blocklists (checked by name, before any external resolution)
dnsbl:
  enabled: false
  refusal_cooldown_secs: 3600   # independent of the RBL default
  providers:
    - zone: dbl.spamhaus.org
      enabled: true

# Integrated DHCPv4 server (omit the section to disable)
dhcp:
  bind: "0.0.0.0:67"
  tld: example.com          # required: hostnames register as <host>.lan.<tld>.
  default_lease_duration: 3600
  reclaim_timeout: 86400
  sweep_interval: 60

# ACME issuer / certificate authority (omit the section to disable)
acme:
  bind: "0.0.0.0:8555"                    # client-facing ACME HTTPS listener
  portal_bind: "127.0.0.1:8500"           # trusted-network enrollment portal
  directory_url: "https://dns.example.com:8555/acme"  # advertised to clients
  root_ca_cn: "Rolodex Root CA"
  leaf_validity_days: 90
  tlsa_port: 443
  tlsa_proto: tcp
  require_eab: true
  issuance_scope: managed_zones           # or "any"

# HTTP proxy for forwarded DNS queries
proxy:
  url: "http://proxy:8080"
  auth: "user:pass"
  mode: "connect"  # "connect" (HTTP CONNECT tunnel), "socks5" (SOCKS5 proxy), or "doh" (proxy DoH queries)

# TTL drift adjustment
ttl_drift:
  mode: "fixed"          # "fixed" or "logarithmic" (experimental)
  fixed_adjustment: "5m" # e.g. "5m", "-30s", "1h30m", "2d12h" (fixed mode only)
  log_multiplier: 1.0    # multiplier (logarithmic mode only, experimental)

# DNS64 AAAA synthesis
dns64:
  enabled: false
  prefix: "64:ff9b::"    # default well-known prefix (64:ff9b::/96)

# Address-family answer preference
address_family:
  mode: auto              # "auto" (probe and suppress), "off", "force4", "force6"
  probe_interval_secs: 30
  fail_threshold: 2       # failed cycles before a family is marked down
  probe_timeout_secs: 2
  targets_v4: ["1.1.1.1:443", "8.8.8.8:443"]
  targets_v6: ["[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"]

# Security settings
security:
  qname_case_randomization: true  # 0x20 encoding for forwarded queries
  overlay_cidrs: ["10.64.0.0/10"] # source ranges subject to network-scope enforcement
  # Who may drive UPSTREAM resolution. Sources outside this list still get the
  # answers this server is authoritative for, but are REFUSED for anything that
  # would reach off-box. An empty list = purely authoritative to everyone.
  recursion_cidrs:
    - "127.0.0.0/8"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "169.254.0.0/16"
    - "100.64.0.0/10"
    - "::1/128"
    - "fe80::/10"
    - "fc00::/7"

# Prometheus scrape endpoint (omit the section to start no listener)
metrics:
  bind: "127.0.0.1:9153"
  # TLDs given their own `tld` label on the per-TLD query metrics. Owned TLDs
  # are tracked automatically; everything untracked folds into `other`.
  tracked_tlds:
    - common
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `database_path` | `"rolodex-dns.db"` | Path to the SQLite database file |
| `forwarders` | `["8.8.8.8:53", "8.8.4.4:53"]` | Upstream DNS resolver addresses (the `local` tier in `auto` mode; the only upstream in `forward` mode) |
| `resolution.mode` | `"auto"` | Upstream strategy: `"auto"` (tier chain), `"recursive"` (roots only), `"forward"` (forwarders only) |
| `resolution.root_hints` | `[]` (built-in IANA roots) | Override the root server hints used in `recursive`/`auto` mode |
| `resolution.secure_upstreams` | Cloudflare + Google over DoH | Encrypted upstreams for the `secure` tier: `{transport, addr, hostname, path}` |
| `resolution.public_fallback` | `["1.1.1.1:53", "8.8.8.8:53"]` | Plaintext public resolvers, tried last in `auto` mode |
| `resolution.switch_grace_failures` | `3` | Consecutive deviating queries before an `auto` tier degrade commits |
| `resolution.recovery_probe_secs` | `60` | How often a degraded `auto` chain retries from the top tier |
| `resolution.delegation_persist_min_ttl` | `300` | Minimum TTL for a learned delegation to be persisted to SQLite |
| `resolution.default_ttl` | `300` | Fallback TTL where a record/response carries none of its own |
| `dnssec.validate` | `true` | Validate DNSSEC on iteratively-resolved answers (`recursive` mode and the roots tier of `auto`). Bogus and indeterminate data becomes SERVFAIL and is never cached |
| `dnssec.trust_anchors` | `[]` (IANA root keys) | Anchors in DNSKEY presentation form, `"<flags> <protocol> <algorithm> <base64 key>"` — the RDATA fields as `dig DNSKEY .` prints them. Every field is validated at startup and a bad one is a hard failure. An override **replaces** the IANA keys rather than adding to them |
| `dns.bind` | `[{udp: "0.0.0.0:53"}, {tcp: "0.0.0.0:53"}]` | DNS listeners; list of `{udp: addr}` / `{tcp: addr}` entries |
| `dns.auto_ptr` | `false` | Maintain reverse PTR records for A/AAAA added via gRPC |
| `dns.ingress_listen_port` | `53` | UDP/TCP port for per-TLD ingress listeners (bind IP is per-TLD) |
| `dns.udp_shards` | `0` (one per core) | `SO_REUSEPORT` sockets bound per UDP listen address. A single socket serialises the listener — one receive loop, one socket for every reply — capping throughput well below CPU saturation. Sharding lets the kernel spread datagrams across cores. Set `1` for the old single-socket behaviour |
| `dot.bind` | `""` (disabled) | DoT listener; supports interface:port (typically port 853) |
| `dot.tls.cert_path` | `""` | TLS certificate path for DoT |
| `dot.tls.key_path` | `""` | TLS private key path for DoT |
| `dot.tls.auto_self_signed` | `true` | Auto-generate a self-signed certificate for DoT |
| `doh.bind` | `""` (disabled) | DoH listener; supports interface:port (typically port 443) |
| `doh.tls.cert_path` | `""` | TLS certificate path for DoH |
| `doh.tls.key_path` | `""` | TLS private key path for DoH |
| `doh.tls.auto_self_signed` | `true` | Auto-generate a self-signed certificate for DoH |
| `doh.enable_h3` | `false` | Enable HTTP/3 (QUIC) transport for DoH |
| `doq.bind` | `""` (disabled) | DoQ listener; supports interface:port (typically port 8853) |
| `doq.tls.cert_path` | `""` | TLS certificate path for DoQ |
| `doq.tls.key_path` | `""` | TLS private key path for DoQ |
| `doq.tls.auto_self_signed` | `true` | Auto-generate a self-signed certificate for DoQ |
| `grpc.tcp_bind` | `"127.0.0.1:50051"` | TCP gRPC listener; supports interface:port (empty to disable) |
| `grpc.unix_socket` | `"/var/run/rolodex-dns.sock"` | Unix socket path (empty to disable) |
| `grpc.shared_secret` | `""` | Shared secret for TCP gRPC auth (empty = no auth) |
| `rbl.enabled` | `false` | Enable IP-based RBL checking globally |
| `rbl.providers[].zone` | -- | RBL zone to query (reversed IP is prepended) |
| `rbl.providers[].enabled` | `true` | Enable/disable individual provider |
| `rbl.providers[].refusal_codes` | `[]` (built-in set) | Answers meaning "query refused" rather than "listed". Each entry is an IPv4 address or `address/prefix`. Empty means the built-in set; the single entry `none` disables detection for that provider. An explicit list replaces the defaults rather than extending them, and an unparseable code is rejected at startup (see [Refusal Codes](#refusal-codes-and-provider-rotation)) |
| `rbl.providers[].refusal_cooldown_secs` | (list default) | Per-provider rotate-out duration after a refusal |
| `rbl.refusal_cooldown_secs` | `3600` | Seconds a refusing RBL provider stays out of rotation, for providers that set none. `0` means "use the default", not "no cooldown" |
| `dnsbl.enabled` | `false` | Enable domain-blocklist (DNSBL) checking globally |
| `dnsbl.providers[].zone` | -- | DNSBL zone to query (the queried name is prepended) |
| `dnsbl.providers[].enabled` | `true` | Enable/disable individual DNSBL provider |
| `dnsbl.providers[].refusal_codes` | `[]` (built-in set) | As `rbl.providers[].refusal_codes` |
| `dnsbl.providers[].refusal_cooldown_secs` | (list default) | As `rbl.providers[].refusal_cooldown_secs` |
| `dnsbl.refusal_cooldown_secs` | `3600` | DNSBL rotate-out default, independent of the RBL one |
| `dhcp.bind` | `"0.0.0.0:67"` | DHCP listener (section absent = DHCP disabled) |
| `dhcp.tld` | -- | Required when DHCP is enabled: hostnames register as `<host>.lan.<tld>.` |
| `dhcp.default_lease_duration` | `3600` | Default lease duration in seconds |
| `dhcp.reclaim_timeout` | `86400` | Seconds after expiry before an IP is reclaimed |
| `dhcp.sweep_interval` | `60` | Background lease-sweep interval in seconds |
| `acme.bind` | `"0.0.0.0:8555"` | Client-facing ACME HTTPS listener (section absent = ACME disabled) |
| `acme.portal_bind` | `"127.0.0.1:8500"` | Trusted-network enrollment portal listener |
| `acme.directory_url` | `"https://localhost:8555/acme"` | External ACME directory URL advertised to clients (set this) |
| `acme.root_ca_cn` | `"Rolodex Root CA"` | Common name of the root CA created at boot |
| `acme.leaf_validity_days` | `90` | Validity of issued leaf certificates |
| `acme.tlsa_port` / `acme.tlsa_proto` | `443` / `"tcp"` | Where the DANE-TA TLSA record is published per name |
| `acme.require_eab` | `true` | Require External Account Binding for account registration |
| `acme.issuance_scope` | `"managed_zones"` | `"managed_zones"` (zone must have a CA) or `"any"` |
| `proxy.url` | `""` (disabled) | HTTP proxy URL for forwarded DNS queries |
| `proxy.auth` | `""` | Proxy authentication (`"user:pass"`) |
| `proxy.mode` | `"connect"` | Proxy mode: `"connect"` (HTTP CONNECT), `"socks5"` (SOCKS5), or `"doh"` |
| `ttl_drift.mode` | `"disabled"` | TTL drift mode: `"disabled"`, `"fixed"`, or `"logarithmic"` |
| `ttl_drift.fixed_adjustment` | `""` | Fixed TTL adjustment. Supports simple (`"5m"`, `"-30s"`, `"1h"`, `"2d"`) and compound durations (`"1h30m"`, `"2d12h"`) |
| `ttl_drift.log_multiplier` | `0.1` | Logarithmic mode multiplier (adjusts TTL based on upstream latency) |
| `dns64.enabled` | `false` | Enable DNS64 AAAA synthesis |
| `dns64.prefix` | `"64:ff9b::"` | IPv6 prefix for DNS64 synthesis |
| `security.qname_case_randomization` | `true` | Enable 0x20 QNAME case randomization |
| `security.overlay_cidrs` | `["10.64.0.0/10"]` | Source ranges treated as untrusted overlay peers and scope-enforced; every other source is trusted |
| `security.recursion_cidrs` | loopback, RFC 1918, link-local, ULA, CGNAT | Source ranges allowed to drive **upstream** resolution. Others are served local/authoritative data and REFUSED for anything that would reach off-box; an empty list closes recursion to everyone (see [Recursion Access Control](#recursion-access-control)) |
| `address_family.mode` | `"auto"` | `"auto"` (probe and suppress an unroutable family), `"off"`, `"force4"`, `"force6"` |
| `address_family.probe_interval_secs` | `30` | Seconds between routability probes in `auto` mode |
| `address_family.fail_threshold` | `2` | Consecutive failed probe cycles before a family is marked down (recovery is immediate) |
| `address_family.probe_timeout_secs` | `2` | Per-target TCP-connect timeout for each probe |
| `address_family.targets_v4` / `targets_v6` | Cloudflare/Google on `:443` | Probe targets per family (literal IPs) |
| `metrics.bind` | `127.0.0.1:9153` | Prometheus `/metrics` HTTP listener; supports interface:port. The section is optional and omitted by default, in which case no listener is started (see [Prometheus Metrics](#prometheus-metrics)) |
| `metrics.tracked_tlds` | `[]` | TLDs given their own `tld` label value on the per-TLD query metrics. Owned TLDs are tracked automatically; `common` expands to the built-in common-TLD set; everything untracked folds into `other` |

## Usage

### Server

```
rolodex-dns [OPTIONS]

Options:
  -c, --config <CONFIG>  Path to configuration file [default: rolodex-dns.yml]
  -h, --help             Print help
```

### CLI Client

`rolodex-dns-cli` is a command-line client for managing a running Rolodex DNS server via its gRPC management interface. It supports both TCP and Unix socket transports.

```
rolodex-dns-cli [OPTIONS] <COMMAND>
```

#### Global Options

| Option | Default | Description |
|--------|---------|-------------|
| `-a, --address <ADDRESS>` | `127.0.0.1:50051` | gRPC server address for TCP connections (host:port). Ignored when `--unix-socket` is set. |
| `-u, --unix-socket <PATH>` | -- | Path to Unix domain socket. Overrides `--address`. Unix socket connections bypass authentication. |
| `-t, --auth-token <TOKEN>` | `""` | Authentication token for TCP connections. Required when the server has a shared secret configured. Ignored for Unix socket connections. |
| `-h, --help` | -- | Print help |
| `-V, --version` | -- | Print version |

#### Commands

| Command | Description |
|---------|-------------|
| **Records** | |
| `add-record` | Add a DNS record to the local database |
| `remove-record` | Remove DNS record(s) from the local database |
| `list-records` | List DNS records with optional filters |
| **Forwarders** | |
| `set-forwarders` | Set upstream DNS forwarders at runtime |
| **RBL / DNSBL** | |
| `set-rbl-config` | Configure IP-based RBL settings at runtime |
| `get-rbl-config` | Retrieve the current RBL configuration |
| `set-dnsbl-config` | Configure domain-blocklist (DNSBL) settings at runtime |
| `get-dnsbl-config` | Retrieve the current DNSBL configuration |
| `flush-cache` | Flush the RBL/DNSBL result cache |
| `add-local-rbl` | Add a local RBL blocklist entry |
| `remove-local-rbl` | Remove a local RBL blocklist entry |
| `list-local-rbl` | List all local RBL blocklist entries |
| `add-dnsbl-allow` | Exempt a name (and its subdomains) from the blocklist check |
| `remove-dnsbl-allow` | Remove a DNSBL allowlist entry |
| `list-dnsbl-allow` | List all DNSBL allowlist entries |
| **Network Scoping** | |
| `create-scope` | Create a new network scope |
| `delete-scope` | Delete a network scope and all its data |
| `list-scopes` | List all configured network scopes |
| `join-network` | Associate an IP with a scope |
| `leave-network` | Remove an IP's scope association |
| `list-associations` | List IP-to-scope associations |
| `add-scoped-record` | Add a DNS record within a scope |
| `remove-scoped-record` | Remove DNS records from a scope |
| `list-scoped-records` | List DNS records within a scope |
| `get-search-domains` | Get search domains for an IP |
| **Owned TLDs / Ingress** | |
| `add-scope-tld` | Register a globally-unique owned TLD for a scope (optional `--listen-ip` starts an ingress listener) |
| `remove-scope-tld` | Remove an owned TLD from a scope |
| `list-scope-tlds` | List the TLDs owned by a scope |
| `set-scope-tld-forwarders` | Set the peer forwarders for a scope's TLD |
| `list-scope-tld-forwarders` | List the peer forwarders for a scope's TLD |
| `list-scope-tld-listeners` | List the ingress DNS listeners bound to a scope's TLDs |
| **Per-Scope RBL** | |
| `add-scope-rbl` | Add an additional RBL provider for a scope |
| `remove-scope-rbl` | Remove a scope-specific RBL provider |
| `list-scope-rbl` | List RBL providers for a scope |
| **Authoritative Zones** | |
| `add-auth-zone` | Declare a zone as authoritative |
| `remove-auth-zone` | Remove a zone from the authoritative list |
| `list-auth-zones` | List all authoritative zones |
| **Cache** | |
| `cache-stats` | Show DNS cache hit/miss statistics |
| `flush-dns-cache` | Flush the DNS response cache |
| **DHCP** | |
| `add-dhcp-pool` / `remove-dhcp-pool` / `list-dhcp-pools` | Manage DHCP address pools per scope |
| `list-dhcp-leases` / `delete-dhcp-lease` | Inspect and delete DHCP leases |
| `set-dhcp-cert` / `remove-dhcp-cert` / `list-dhcp-certs` | Manage certificate delivery via DHCP options |
| **DNSSEC** | |
| `generate-dnssec-key` | Generate a DNSSEC key pair (KSK or ZSK) |
| `list-dnssec-keys` | List DNSSEC keys for a zone |
| `sign-zone` | Sign a zone with its DNSSEC keys |
| **DANE / ACME** | |
| `generate-tlsa` | Generate a TLSA record from a certificate |
| `request-acme-cert` | Request a certificate via ACME DNS-01 |
| `acme-status` | Check ACME certificate status |
| `ensure-zone-ca` | Ensure the per-zone intermediate CA exists; prints root + intermediate PEM and publishes the CA chain into DNS |
| `create-eab` / `remove-eab` | Mint or remove an EAB credential scoped to a zone |
| `list-acme-accounts` | List registered ACME accounts |
| `list-acme-certs` | List issued certificates |
| **TTL Drift** | |
| `set-ttl-drift` / `get-ttl-drift` | Configure/retrieve TTL drift settings |
| **DNS64** | |
| `set-dns64` / `get-dns64` | Configure/retrieve DNS64 settings |
| **Observability** | |
| `latency-stats` | Show per-server upstream query latency |

Transport (DoT/DoH/DoQ), proxy, and a few DNSSEC/DANE operations are available over gRPC but have no CLI subcommand — see [Additional gRPC Methods](#additional-grpc-methods). For the full set of command flags, run `rolodex-dns-cli <COMMAND> --help`.

##### `add-record`

Add a DNS record to the local database.
**gRPC path:** `/rolodex_dns.RolodexDnsService/AddRecord`

```
rolodex-dns-cli add-record -n <NAME> -v <VALUE> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | Fully qualified domain name (e.g. `"example.com."` -- trailing dot recommended) |
| `-r, --record-type <TYPE>` | `a` | DNS record type (see Record Types table) |
| `-v, --value <VALUE>` | -- | Record data. Format depends on record type (see Record Types section) |
| `--ttl <TTL>` | `300` | Time-to-live in seconds. If set to 0, the server defaults to 300 |
| `-p, --priority <PRIORITY>` | `0` | Priority for MX and SRV records. Lower values = higher priority. Ignored for other types |

Examples:
```bash
# Add an A record via TCP
rolodex-dns-cli -a 127.0.0.1:50051 -t my-secret add-record \
  -n example.com. -r a -v 10.0.0.1 --ttl 600

# Add an MX record via Unix socket
rolodex-dns-cli -u /var/run/rolodex-dns.sock add-record \
  -n example.com. -r mx -v mail.example.com. -p 10

# Add a CNAME record
rolodex-dns-cli add-record -n www.example.com. -r cname -v example.com.

# Add an SRV record
rolodex-dns-cli add-record -n _sip._tcp.example.com. -r srv \
  -v "5 5060 sip.example.com." -p 10

# Add a URI record
rolodex-dns-cli add-record -n example.com. -r uri \
  -v "10 1 \"https://example.com/\"" -p 10

# Add an SSHFP record
rolodex-dns-cli add-record -n host.example.com. -r sshfp \
  -v "2 1 123456789abcdef..."

# Add a wildcard record
rolodex-dns-cli add-record -n "*.example.com." -r a -v 10.0.0.99
```

##### `remove-record`

Remove DNS record(s) from the local database. Removes by name, with optional type and value filters.
**gRPC path:** `/rolodex_dns.RolodexDnsService/RemoveRecord`

```
rolodex-dns-cli remove-record -n <NAME> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | Fully qualified domain name of records to remove |
| `-r, --record-type <TYPE>` | -- | If specified, only remove records of this type. If omitted, removes all types for the name |
| `-v, --value <VALUE>` | -- | If specified, only remove the record with this exact value |

Examples:
```bash
# Remove all records for a name
rolodex-dns-cli remove-record -n old.example.com.

# Remove only A records for a name
rolodex-dns-cli remove-record -n example.com. -r a

# Remove a specific record by value
rolodex-dns-cli remove-record -n example.com. -r a -v 10.0.0.1
```

##### `list-records`

List DNS records from the local database with optional filters.
**gRPC path:** `/rolodex_dns.RolodexDnsService/ListRecords`

```
rolodex-dns-cli list-records [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | Filter by domain name. Supports wildcard prefix `"*."` to match all subdomains (e.g. `"*.example.com."`) |
| `-r, --record-type <TYPE>` | -- | Filter by record type. If omitted, returns all record types |

Examples:
```bash
# List all records
rolodex-dns-cli list-records

# List records for a specific name
rolodex-dns-cli list-records -n example.com.

# List all subdomains
rolodex-dns-cli list-records -n "*.example.com."

# List only AAAA records
rolodex-dns-cli list-records -r aaaa
```

##### `set-forwarders`

Set upstream DNS forwarders at runtime. Replaces the entire forwarder list.
**gRPC path:** `/rolodex_dns.RolodexDnsService/SetForwarders`

```
rolodex-dns-cli set-forwarders -f <ADDR>...
```

| Option | Default | Description |
|--------|---------|-------------|
| `-f, --forwarders <ADDR>...` | -- | Upstream DNS server addresses in `"host:port"` format. Multiple addresses separated by spaces |

Examples:
```bash
# Set Google and Cloudflare DNS
rolodex-dns-cli set-forwarders -f 8.8.8.8:53 1.1.1.1:53

# Set a single forwarder
rolodex-dns-cli set-forwarders -f 9.9.9.9:53

# Remove all forwarders (purely authoritative mode)
rolodex-dns-cli set-forwarders -f ""
```

##### `set-rbl-config`

Configure RBL (Realtime Blackhole List) settings at runtime. Replaces the entire RBL configuration.
**gRPC path:** `/rolodex_dns.RolodexDnsService/SetRblConfig`

```
rolodex-dns-cli set-rbl-config [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-e, --enabled` | `false` | Enable RBL checking globally. If flag is absent, RBL is disabled |
| `-p, --providers <SPEC>...` | -- | RBL provider specifications in `"zone:enabled"` format (e.g. `"zen.spamhaus.org:true"`) |
| `--refusal-codes <ZONE=CODE,...>` | built-in set | Per-provider refusal codes (repeatable). `none` disables refusal detection for that zone |
| `--provider-cooldown <ZONE=SECS>` | list default | Per-provider rotate-out duration after a refusal (repeatable) |
| `--refusal-cooldown <SECS>` | `3600` | List-wide rotate-out duration |

A `zone=` entry naming a zone that is not in `--providers` is an error rather than a silently dropped flag.

Examples:
```bash
# Enable RBL with Spamhaus
rolodex-dns-cli set-rbl-config -e -p "zen.spamhaus.org:true"

# Enable RBL with multiple providers (some disabled)
rolodex-dns-cli set-rbl-config -e \
  -p "zen.spamhaus.org:true" \
  -p "bl.spamcop.net:false" \
  -p "b.barracudacentral.org:true"

# Narrow one provider's refusal codes and back it off for 15 minutes on a refusal
rolodex-dns-cli set-rbl-config -e \
  -p "zen.spamhaus.org:true" \
  --refusal-codes "zen.spamhaus.org=127.255.255.0/24" \
  --provider-cooldown "zen.spamhaus.org=900"

# A private blocklist whose real listings collide with a default refusal code
rolodex-dns-cli set-rbl-config -e \
  -p "rbl.internal.example:true" \
  --refusal-codes "rbl.internal.example=none"

# Disable RBL entirely
rolodex-dns-cli set-rbl-config
```

##### `get-rbl-config`

Retrieve the current RBL configuration.
**gRPC path:** `/rolodex_dns.RolodexDnsService/GetRblConfig`

```
rolodex-dns-cli get-rbl-config
```

Example output:
```
RBL enabled: true
Refusal rotate-out: 3600s (default for providers with no value)

Providers:
ZONE                             ENABLED  COOLDOWN   REFUSAL CODES
------------------------------------------------------------------------------------------
zen.spamhaus.org                 true     default    127.255.255.0/24, 127.0.1.255, ...
bl.spamcop.net                   false    900s       127.0.0.1

Rotated out (refused our queries):
ZONE                             REFUSAL CODE       REMAINING
--------------------------------------------------------------
zen.spamhaus.org                 127.255.255.254    3241s
```

Refusal codes are reported **as they are in effect**: a provider that configured none reads back as the built-in set rather than as empty, so what is printed is what is running. The `Rotated out` block is only printed when a provider is currently backed off — that is the difference between "the blocklist is clean" and "the blocklist stopped answering us", which otherwise look identical from outside.

##### `flush-cache`

Flush the RBL result cache. Forces fresh lookups for subsequent reverse DNS queries.
**gRPC path:** `/rolodex_dns.RolodexDnsService/FlushCache`

```
rolodex-dns-cli flush-cache
```

##### `create-scope`

Create a new network scope with a reserved `.home` domain.
**gRPC path:** `/rolodex_dns.RolodexDnsService/CreateNetworkScope`

```
rolodex-dns-cli create-scope -n <NAME> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | Unique name for the network scope (e.g. `"office"`, `"lab"`) |
| `-d, --home-domain <DOMAIN>` | `"<name>.home."` | Reserved `.home` domain for this scope. If omitted, defaults to `"<name>.home."` |

Examples:
```bash
# Create a scope with default home domain
rolodex-dns-cli create-scope -n office
# Creates scope "office" with home domain "office.home."

# Create a scope with custom home domain
rolodex-dns-cli create-scope -n lab -d lab.internal.
```

##### `delete-scope`

Delete a network scope and all its records and associations.
**gRPC path:** `/rolodex_dns.RolodexDnsService/DeleteNetworkScope`

```
rolodex-dns-cli delete-scope -n <NAME>
```

| Option | Default | Description |
|--------|---------|-------------|
| `-n, --name <NAME>` | -- | Name of the scope to delete |

##### `list-scopes`

List all configured network scopes.
**gRPC path:** `/rolodex_dns.RolodexDnsService/ListNetworkScopes`

```
rolodex-dns-cli list-scopes
```

##### `join-network`

Associate an IP address with a network scope. The association has a TTL and must be refreshed regularly.
**gRPC path:** `/rolodex_dns.RolodexDnsService/JoinNetwork`

```
rolodex-dns-cli join-network -i <IP> -s <SCOPE> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-i, --ip <IP>` | -- | Client IP address to associate (e.g. `"192.168.1.100"`) |
| `-s, --scope <SCOPE>` | -- | Network scope name to join |
| `--ttl <TTL>` | `300` | TTL in seconds for the association. Must be refreshed before expiry. If 0, defaults to 300 |

Examples:
```bash
# Join with default TTL
rolodex-dns-cli join-network -i 192.168.1.100 -s office

# Join with custom TTL
rolodex-dns-cli join-network -i 10.0.0.5 -s lab --ttl 600
```

##### `leave-network`

Remove an IP address's association with its network scope.
**gRPC path:** `/rolodex_dns.RolodexDnsService/LeaveNetwork`

```
rolodex-dns-cli leave-network -i <IP>
```

| Option | Default | Description |
|--------|---------|-------------|
| `-i, --ip <IP>` | -- | Client IP address to disassociate |

##### `list-associations`

List IP-to-scope associations, optionally filtered by scope.
**gRPC path:** `/rolodex_dns.RolodexDnsService/GetNetworkAssociations`

```
rolodex-dns-cli list-associations [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | -- | Filter by scope name. If omitted, lists all associations |

##### `add-scoped-record`

Add a DNS record within a specific network scope. Scoped records are only visible to IPs associated with that scope.
**gRPC path:** `/rolodex_dns.RolodexDnsService/AddScopedRecord`

```
rolodex-dns-cli add-scoped-record -s <SCOPE> -n <NAME> -v <VALUE> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | -- | Network scope to add the record to |
| `-n, --name <NAME>` | -- | Fully qualified domain name |
| `-r, --record-type <TYPE>` | `a` | DNS record type |
| `-v, --value <VALUE>` | -- | Record data |
| `--ttl <TTL>` | `300` | Time-to-live in seconds |
| `-p, --priority <PRIORITY>` | `0` | Priority for MX and SRV records |

Examples:
```bash
# Add a scoped A record
rolodex-dns-cli add-scoped-record -s office -n printer.office.home. -v 192.168.1.50

# Add a scoped CNAME
rolodex-dns-cli add-scoped-record -s lab -n app.lab.home. -r cname -v server.lab.home.
```

##### `remove-scoped-record`

Remove DNS records from a specific network scope.
**gRPC path:** `/rolodex_dns.RolodexDnsService/RemoveScopedRecord`

```
rolodex-dns-cli remove-scoped-record -s <SCOPE> -n <NAME> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | -- | Network scope to remove records from |
| `-n, --name <NAME>` | -- | Fully qualified domain name |
| `-r, --record-type <TYPE>` | -- | Filter by record type |
| `-v, --value <VALUE>` | -- | Filter by exact value |

##### `list-scoped-records`

List DNS records within a network scope.
**gRPC path:** `/rolodex_dns.RolodexDnsService/ListScopedRecords`

```
rolodex-dns-cli list-scoped-records -s <SCOPE> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | -- | Network scope to query |
| `-n, --name <NAME>` | -- | Filter by domain name (supports wildcard `"*."` prefix) |
| `-r, --record-type <TYPE>` | -- | Filter by record type |

##### `get-search-domains`

Retrieve the search domains for a client IP address.
**gRPC path:** `/rolodex_dns.RolodexDnsService/GetSearchDomains`

```
rolodex-dns-cli get-search-domains -i <IP>
```

| Option | Default | Description |
|--------|---------|-------------|
| `-i, --ip <IP>` | -- | Client IP address to look up |

## gRPC API

The management API is defined in `proto/rolodex_dns.proto`. All methods accept an `auth_token` field for shared-secret authentication when connecting over TCP. Unix socket connections bypass authentication.

See the proto file for the full API reference. The service defines 47 RPC methods covering record management, network scoping, encrypted transports, DNSSEC, DANE/ACME, caching, DNS64, and observability.

### Service: `rolodex_dns.RolodexDnsService`

#### `AddRecord`

**Path:** `/rolodex_dns.RolodexDnsService/AddRecord`

Adds a DNS record to the local database.

**Parameters:**
- `record` (DnsRecord, required): The DNS record to add
  - `name` (string): Fully qualified domain name (e.g. `"example.com."`)
  - `record_type` (RecordType): Type of DNS record (see Record Types below)
  - `value` (string): Record data (e.g. IP address, hostname)
  - `ttl` (uint32): Time-to-live in seconds. Default: 300 if set to 0
  - `priority` (uint32): Priority for MX/SRV records (ignored for other types). Default: 0
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `RemoveRecord`

**Path:** `/rolodex_dns.RolodexDnsService/RemoveRecord`

Removes DNS record(s) from the local database.

**Parameters:**
- `name` (string, required): Fully qualified domain name
- `record_type` (RecordType): If set, only remove records of this type. If unset (A/0), removes all records for the name
- `value` (string): If non-empty, only remove the record with this exact value
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `removed_count` (uint32): Number of records removed
- `message` (string): Error message if `success` is false

#### `ListRecords`

**Path:** `/rolodex_dns.RolodexDnsService/ListRecords`

Queries the local DNS database with optional filters.

**Parameters:**
- `name_filter` (string): Filter by domain name. Supports wildcard prefix `"*."` to match all subdomains (e.g. `"*.example.com."`)
- `record_type_filter` (RecordType): Filter by record type (only applied when `filter_by_type` is true)
- `filter_by_type` (bool): Whether to apply the `record_type_filter`. Default: false
- `auth_token` (string): Shared secret for authentication

**Response:**
- `records` (repeated DnsRecord): Matching DNS records

#### `SetForwarders`

**Path:** `/rolodex_dns.RolodexDnsService/SetForwarders`

Configures upstream DNS forwarders at runtime.

**Parameters:**
- `forwarders` (repeated string): List of upstream DNS server addresses in `"host:port"` format (e.g. `"8.8.8.8:53"`)
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `SetRblConfig`

**Path:** `/rolodex_dns.RolodexDnsService/SetRblConfig`

Configures Realtime Blackhole List settings at runtime.

**Parameters:**
- `enabled` (bool): Whether RBL checking is globally enabled. Default: false
- `providers` (repeated RblConfig): List of RBL providers
  - `zone` (string): The DNSBL zone to query (e.g. `"zen.spamhaus.org"`)
  - `enabled` (bool): Whether this specific provider is enabled. Default: true
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `GetRblConfig`

**Path:** `/rolodex_dns.RolodexDnsService/GetRblConfig`

Retrieves the current RBL configuration.

**Parameters:**
- `auth_token` (string): Shared secret for authentication

**Response:**
- `enabled` (bool): Whether RBL checking is globally enabled
- `providers` (repeated RblConfig): Current RBL providers

#### `FlushCache`

**Path:** `/rolodex_dns.RolodexDnsService/FlushCache`

Clears the RBL lookup cache.

**Parameters:**
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `CreateNetworkScope`

**Path:** `/rolodex_dns.RolodexDnsService/CreateNetworkScope`

Creates a new network scope with a reserved `.home` domain.

**Parameters:**
- `scope` (NetworkScope, required): The scope to create
  - `name` (string): Unique name for the scope (e.g. `"office"`, `"lab"`)
  - `home_domain` (string): Reserved `.home` domain. Default: `"<name>.home."` if empty
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `DeleteNetworkScope`

**Path:** `/rolodex_dns.RolodexDnsService/DeleteNetworkScope`

Deletes a network scope and all its records and associations.

**Parameters:**
- `name` (string, required): Name of the scope to delete
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `ListNetworkScopes`

**Path:** `/rolodex_dns.RolodexDnsService/ListNetworkScopes`

Retrieves all configured network scopes.

**Parameters:**
- `auth_token` (string): Shared secret for authentication

**Response:**
- `scopes` (repeated NetworkScope): All configured scopes

#### `JoinNetwork`

**Path:** `/rolodex_dns.RolodexDnsService/JoinNetwork`

Associates a client IP address with a network scope. The association has a TTL that must be refreshed regularly to maintain DNS resolution.

**Parameters:**
- `ip_address` (string, required): Client IP to associate (e.g. `"192.168.1.100"`)
- `scope_name` (string, required): Network scope name to join
- `ttl_seconds` (uint64): TTL in seconds. Default: 300 if set to 0. Must be refreshed before expiry.
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `LeaveNetwork`

**Path:** `/rolodex_dns.RolodexDnsService/LeaveNetwork`

Removes an IP address's association with its network scope.

**Parameters:**
- `ip_address` (string, required): Client IP to disassociate
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `GetNetworkAssociations`

**Path:** `/rolodex_dns.RolodexDnsService/GetNetworkAssociations`

Retrieves IP-to-scope associations.

**Parameters:**
- `scope_name` (string): Filter by scope name. Empty returns all associations.
- `auth_token` (string): Shared secret for authentication

**Response:**
- `associations` (repeated NetworkAssociation): Matching associations
  - `ip_address` (string): The associated IP
  - `scope_name` (string): The scope name
  - `ttl_seconds` (uint64): TTL for the association

#### `AddScopedRecord`

**Path:** `/rolodex_dns.RolodexDnsService/AddScopedRecord`

Adds a DNS record within a specific network scope. Scoped records are only visible to IPs associated with that scope.

**Parameters:**
- `scope_name` (string, required): The scope to add the record to
- `record` (DnsRecord, required): The DNS record to add
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `RemoveScopedRecord`

**Path:** `/rolodex_dns.RolodexDnsService/RemoveScopedRecord`

Removes DNS records from a specific network scope.

**Parameters:**
- `scope_name` (string, required): The scope to remove records from
- `name` (string, required): FQDN to remove records for
- `record_type` (RecordType): Optional type filter
- `value` (string): Optional exact value filter
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `removed_count` (uint32): Number of records removed
- `message` (string): Error message if `success` is false

#### `ListScopedRecords`

**Path:** `/rolodex_dns.RolodexDnsService/ListScopedRecords`

Queries DNS records within a network scope.

**Parameters:**
- `scope_name` (string, required): The scope to query
- `name_filter` (string): Filter by domain name (supports wildcard `"*."` prefix)
- `record_type_filter` (RecordType): Filter by record type (only applied when `filter_by_type` is true)
- `filter_by_type` (bool): Whether to apply `record_type_filter`. Default: false
- `auth_token` (string): Shared secret for authentication

**Response:**
- `records` (repeated DnsRecord): Matching scoped records

#### `GetSearchDomains`

**Path:** `/rolodex_dns.RolodexDnsService/GetSearchDomains`

Retrieves the search domains for a client IP address. Returns the `.home` domain of the scope the IP is associated with.

**Parameters:**
- `ip_address` (string, required): Client IP to look up
- `auth_token` (string): Shared secret for authentication

**Response:**
- `search_domains` (repeated string): Search domains for the IP (typically the scope's `.home` domain)

#### Additional gRPC Methods

The following methods are also available. See `proto/rolodex_dns.proto` for full request/response definitions.

| Method | Description |
|--------|-------------|
| `AddAuthoritativeZone` | Declare a zone as authoritative (AA bit, no upstream forwarding) |
| `RemoveAuthoritativeZone` | Remove a zone from the authoritative list |
| `ListAuthoritativeZones` | List all authoritative zones |
| `GetCacheStats` | Retrieve DNS cache statistics (entries, hits, misses) |
| `FlushDnsCache` | Clear the DNS response cache |
| `SetTtlDriftConfig` | Configure TTL drift adjustment (fixed or logarithmic mode) |
| `GetTtlDriftConfig` | Retrieve TTL drift configuration |
| `GetQueryLatencyStats` | Retrieve per-server upstream query latency statistics |
| `AddLocalRblEntry` | Add a local RBL blocklist entry |
| `RemoveLocalRblEntry` | Remove a local RBL blocklist entry |
| `ListLocalRblEntries` | List all local RBL blocklist entries |
| `SetDnsblConfig` / `GetDnsblConfig` | Configure/retrieve domain-blocklist (DNSBL) settings |
| `AddDnsblAllowlistEntry` | Exempt a name (and its subdomains) from the blocklist check |
| `RemoveDnsblAllowlistEntry` | Remove a DNSBL allowlist entry |
| `ListDnsblAllowlistEntries` | List all DNSBL allowlist entries |
| `AddScopeRblProvider` / `RemoveScopeRblProvider` / `ListScopeRblProviders` | Manage additional RBL providers for one scope |
| `AddScopeTld` | Register a globally-unique owned TLD for a scope; an optional `listen_ip` also starts an ingress DNS listener |
| `RemoveScopeTld` | Remove an owned TLD (and its ingress listener, once unused) |
| `ListScopeTlds` | List the TLDs owned by a scope |
| `SetScopeTldForwarders` / `ListScopeTldForwarders` | Manage a TLD's peer forwarders |
| `ListScopeTldListeners` | List the ingress DNS listeners bound to a scope's TLDs |
| `AddDhcpPool` / `RemoveDhcpPool` / `ListDhcpPools` | Manage DHCP address pools per scope |
| `ListDhcpLeases` / `DeleteDhcpLease` | Inspect and delete DHCP leases |
| `SetDhcpCertOption` / `RemoveDhcpCertOption` / `ListDhcpCertOptions` | Manage certificate delivery via DHCP options |
| `EnsureZoneCa` | Create the per-zone intermediate CA if absent; returns root + intermediate PEM |
| `CreateEabCredential` / `RemoveEabCredential` | Mint or remove a zone-scoped EAB credential |
| `ListAcmeAccounts` / `ListAcmeCertificates` | List ACME accounts and issued certificates |
| `SetDotConfig` / `GetDotConfig` | Configure/retrieve DNS-over-TLS settings |
| `SetDohConfig` / `GetDohConfig` | Configure/retrieve DNS-over-HTTPS settings |
| `SetDoqConfig` / `GetDoqConfig` | Configure/retrieve DNS-over-QUIC settings |
| `SetProxyConfig` / `GetProxyConfig` | Configure/retrieve HTTP proxy settings |
| `GenerateDnssecKey` | Generate a DNSSEC key pair for a zone |
| `ListDnssecKeys` | List DNSSEC keys for a zone |
| `DeleteDnssecKey` | Delete a DNSSEC key |
| `GetDsRecords` | Retrieve DS records for parent-zone delegation |
| `SignZone` | Sign (or re-sign) a zone with its DNSSEC keys |
| `GenerateTlsaRecord` | Generate a TLSA record from a PEM certificate |
| `ListTlsaRecords` | List TLSA records for a domain |
| `GenerateDaneRootCa` | Generate a self-signed DANE root CA |
| `RequestAcmeCert` | Request a certificate via ACME DNS-01 challenge |
| `GetAcmeStatus` | Retrieve ACME certificate status for a domain |
| `SetDns64Config` / `GetDns64Config` | Configure/retrieve DNS64 synthesis settings |

### Record Types

| Enum Value | Name | Description |
|-----------|------|-------------|
| 0 | `A` | IPv4 address mapping. Value: IPv4 address (e.g. `"192.168.1.1"`) |
| 1 | `AAAA` | IPv6 address mapping. Value: IPv6 address (e.g. `"::1"`) |
| 2 | `CNAME` | Canonical name alias. Value: target FQDN (e.g. `"target.example.com."`) |
| 3 | `MX` | Mail exchange. Value: mail server FQDN. Uses `priority` field |
| 4 | `TXT` | Text record. Value: text content |
| 5 | `NS` | Name server. Value: nameserver FQDN |
| 6 | `SOA` | Start of authority. Value: `"mname rname serial refresh retry expire minimum"` (space-separated) |
| 7 | `SRV` | Service locator. Value: `"weight port target"` (space-separated). Uses `priority` field |
| 8 | `PTR` | Pointer for reverse DNS. Value: target FQDN |
| 9 | `URI` | URI resource record (RFC 7553). Value: `"priority weight \"uri\""` |
| 10 | `SSHFP` | SSH fingerprint (RFC 4255). Value: `"algorithm fp_type fingerprint"` |
| 11 | `DNAME` | Delegation name (RFC 6672). Value: target FQDN (rewrites entire subtree) |
| 12 | `ANAME` | Alias name (draft). Value: target FQDN (resolved at query time, works at zone apex) |
| 13 | `ZONEMD` | Zone message digest (RFC 9156). Value: `"serial scheme hash_algorithm digest"` |
| 14 | `TLSA` | TLS certificate association (RFC 6698). Value: `"usage selector matching_type cert_data"` |
| 15 | `DNSKEY` | DNSSEC public key. Managed automatically by DNSSEC key generation |
| 16 | `DS` | Delegation signer. Managed automatically by DNSSEC |
| 17 | `RRSIG` | DNSSEC resource record signature. Managed automatically by zone signing |
| 18 | `NSEC` | Next secure record (DNSSEC). Managed automatically by zone signing |
| 19 | `NSEC3` | Next secure record v3 (DNSSEC). Managed automatically by zone signing |
| 20 | `NSEC3PARAM` | NSEC3 parameters (DNSSEC). Managed automatically by zone signing |
| 21 | `CERT` | Certificate storage in DNS (RFC 4398). Value: `"cert_type key_tag algorithm base64_cert_data"`. Used to distribute the CA chain |

## Privacy-First Caching

Rolodex DNS caches DNS responses locally so that repeated queries for the same name are answered without contacting any upstream forwarder. This prevents DNS query leakage -- once a record has been cached, no external observer can see that the query was made again.

The cache distinguishes between two kinds of entries:

- **Local records** (from the SQLite database): Cached in-memory with stable TTLs (no decay). These entries are not persisted to the cache backing store since they already live in the database. The in-memory DNS cache is automatically invalidated whenever records are added, removed, or modified via gRPC, so changes take effect immediately.
- **Forwarded responses** (from upstream resolvers): Cached with decaying TTLs and persisted to an SQLite-backed cache table. On restart, persisted entries are reloaded so the cache is warm immediately.

Negative answers (authoritative NXDOMAIN/NODATA) are cached separately, for the RFC 2308 negative TTL (`min(SOA MINIMUM, SOA TTL)`) as the zone published it. Adding a local record for a name drops any cached negative for it, so a newly-added name resolves immediately instead of waiting out the negative TTL.

Cache statistics are available via `GetCacheStats` and the cache can be flushed via `FlushDnsCache`.

For maximum privacy, set `resolution.mode: forward` with `forwarders: []` to run Rolodex DNS as a purely authoritative server with no external resolution at all. All answers will come from the local database.

## Upstream Resolution

Names that are not satisfied locally are resolved according to `resolution.mode`:

| Mode | Behavior |
| ---- | -------- |
| `auto` (default) | The tiered fallback chain below |
| `recursive` | Iterative from the root servers only; no upstream resolver is ever contacted |
| `forward` | Forward to the configured `forwarders` only |

### The `auto` Fallback Chain

Tiers are tried most-preferred (most-trusted) first:

| Tier | Path | Why |
| ---- | ---- | --- |
| 0 | Iterative from the root servers | No third party sees your queries |
| 1 | DoH (`:443`) or DoT (`:853`) to `resolution.secure_upstreams` | Encrypted, and uses ports that survive `:53` filtering |
| 2 | Plaintext Do53 to `forwarders` | The local/DHCP-provided resolver |
| 3 | Plaintext Do53 to `resolution.public_fallback` | Last resort |

DoH is preferred over DoT because `:443` looks like ordinary HTTPS and survives deep-packet inspection that lets a DoT connection open but drops its TLS session. Secure upstreams are dialed **by IP**, with the certificate validated against the configured `hostname`, so the tier needs no prior DNS to bootstrap.

A tier only "wins" when the transport succeeded and the rcode is NoError or NXDOMAIN; SERVFAIL, REFUSED, and unparseable responses fall through. The winning tier is **sticky**, so queries do not pay a timeout on a dead path every time. Recovering to a more-preferred tier happens immediately; degrading to a lesser one commits only after `resolution.switch_grace_failures` consecutive deviating queries, so one flaky query cannot thrash the resolver. While degraded, one query per `resolution.recovery_probe_secs` restarts at tier 0 to reclaim a recovered path. Every committed tier switch flushes the DNS cache, so answers from one tier cannot linger after a switch to another.

### Iterative Resolver

The resolver walks the delegation chain from the roots — root → TLD → authoritative — with recursion-desired cleared, validating responses by transaction ID and question name against off-path spoofing, over UDP with automatic TCP fallback on truncation.

- **Root hints and priming.** The 13 IANA root addresses (IPv4 only, so a v4-only host never stalls on a v6 root) are a bootstrap: at startup Rolodex asks the roots who the roots are and caches the live `.` NS set with its real TTL. Priming never runs on the query path, and the hints remain the fallback if it fails. Override with `resolution.root_hints`.
- **Load spread across servers.** Nameservers are chosen by lowest `hits × average latency`, which allocates queries as `hits ∝ 1/latency`: fast servers carry more, but every healthy server carries some. This deliberately avoids pinning every cold query to one root (whether "the first" or "the fastest"), which earns a rate-limit and turns each lookup into a timeout-and-failover.
- **Failure backoff.** A failing server sits out 2s, doubling per consecutive failure up to 300s, cleared on its first success. Backed-off servers sort last but are never dropped, so resolution still proceeds when everything is failing.
- **Bounded work.** 1.5s per-nameserver timeout, 30 referrals, 16 CNAME hops, depth 16, 4 nameservers per glue-less delegation, and a hard ceiling of 64 upstream queries per client lookup — the per-axis limits multiply, so the total is capped outright.

### Resolver Caches

Two TTL-respecting caches sit below the answer cache and keep what a recursion learns on the way down:

- **Delegation cache** — zone → nameserver addresses, learned from every referral. A warm `.com` lookup skips the root hop entirely. Delegations whose TTL exceeds `resolution.delegation_persist_min_ttl` (default 300s) are persisted to SQLite and reloaded at boot, so a restart comes back warm; root and TLD NS sets carry multi-day TTLs, so exactly the entries worth keeping survive.
- **Record cache** — glue, glue-less NS-name lookups, and CNAME hops, keyed by `(name, type)` and served with their *remaining* lifetime.

Both survive record mutations (adding a record must not send every name in the world back to the roots) and are cleared only on an `auto`-mode tier switch.

TTLs are honoured exactly as published — including a zone's SOA negative TTL, which is never clamped. `resolution.default_ttl` applies only where nothing carries a usable TTL at all.

## Address-Family Filtering

Networks routinely advertise an IPv6 default route and then silently drop all v6 traffic (and the mirror case happens on v4-only NAT). A client handed an address in a family its host cannot route stalls on the dead family instead of falling back — the failure that wedges container image pulls on a broken-v6 link.

With `address_family.mode: auto` (the default), a background probe TCP-connects to public anycast resolvers on `:443` — the port real traffic uses, and one that survives the `:53`/`:853` filtering some networks impose — to test *actual* per-family reachability. A/AAAA records of an unreachable family are then dropped from answers (turning them into NODATA) so clients fall back to the stack that works.

The first probe runs synchronously at startup and is decisive, so a boot onto a dead-family link suppresses that family from the very first query. Afterwards, a previously-working family is only marked down after `address_family.fail_threshold` consecutive failed cycles, while recovery takes effect on the first success. Set `mode: off` to always answer both families, or `force4`/`force6` to pin one without probing.

## Encrypted Transports

Rolodex DNS supports three encrypted DNS transport protocols to prevent eavesdropping on DNS queries:

**DNS-over-TLS (DoT)** -- RFC 7858, default port 853. Standard TLS-wrapped DNS over TCP. Configure with `dot` section in YAML or `SetDotConfig` via gRPC.

**DNS-over-HTTPS (DoH)** -- RFC 8484, default port 443. DNS queries over HTTPS with support for both GET (`/dns-query?dns=<base64>`) and POST (`application/dns-message`) methods. Optionally supports HTTP/3 via QUIC (`enable_h3: true`). Configure with `doh` section in YAML or `SetDohConfig` via gRPC.

**DNS-over-QUIC (DoQ)** -- RFC 9250, default port 8853. DNS queries over QUIC transport for low-latency encrypted resolution. Configure with `doq` section in YAML or `SetDoqConfig` via gRPC.

All three protocols require TLS certificates. You can provide your own certificate and key, or set `auto_self_signed: true` to have Rolodex DNS generate a self-signed certificate automatically.

## DNSSEC

Rolodex DNS has two independent DNSSEC halves: it **signs** its own zones, and it **validates** the answers it resolves from upstream. They share no code — the signer works on database rows we wrote and controls every byte, a validator works on whatever arrives from a party whose honesty is the thing in question, and the two must be able to disagree.

### Zone Signing

Signing supports the following algorithms:

- **Ed25519** (preferred) -- compact keys and signatures, fast signing
- **ECDSA P-256/SHA-256** and **ECDSA P-384/SHA-384**

**RSA/SHA-256 (algorithm 8) cannot be generated** and `generate-dnssec-key` refuses it: `ring` has no RSA key generation. It still *parses* — an existing key row filed under it remains listable — and RSA signatures from upstream zones are verifiable, but nothing here will sign with it. An algorithm that cannot be honoured end to end is refused at key generation rather than quietly substituted, because a DNSKEY advertising one algorithm over another's key material yields a DS, a DNSKEY and a set of RRSIGs that all disagree, and that failure surfaces at a validating resolver rather than locally.

Ed448 is not supported due to a limitation in the ring cryptography crate.

#### Signing Workflow

1. Generate a Key Signing Key (KSK) and Zone Signing Key (ZSK) for your zone:
   ```bash
   rolodex-dns-cli generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type KSK
   rolodex-dns-cli generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type ZSK
   ```

2. Sign the zone:
   ```bash
   rolodex-dns-cli sign-zone --zone example.com.
   ```

3. Retrieve DS records for your registrar. There is no CLI subcommand for this — call the `GetDsRecords` gRPC method (e.g. via the Go client's `GetDsRecords(ctx, zone)`), or query the DS records from the zone with any DNS client.

Signing republishes the apex DNSKEY RRset and produces one RRSIG per RRset. Re-run `sign-zone` after adding or modifying records; existing RRSIGs are replaced rather than accumulated.

**Authenticated denial is not generated.** NSEC, NSEC3 and NSEC3PARAM are storable and listable record types, but `sign-zone` neither generates nor serves them, so a zone signed here proves what exists and not what does not.

DNSKEY, DS and RRSIG are served under their own type codes, with RDATA produced by the same canonical encoder the signer hashes — what goes on the wire is byte-for-byte what was signed.

### Upstream Validation

Answers resolved **iteratively** are validated against the IANA root trust anchors. This is on by default:

```yaml
dnssec:
  validate: true        # the default
  trust_anchors: []     # empty = the IANA root keys
```

It applies to the iterative path only — `recursive` mode, and the roots tier of `auto`. A forwarded response is somebody else's recursive summary, and validating it would mean re-resolving the chain ourselves, which is what the roots tier already is. An `auto` chain that has degraded past tier 0 is therefore unvalidated, and says so by leaving AD clear.

The four RFC 4033 §5 verdicts are kept distinct:

| Verdict | Meaning | Served? |
| ------- | ------- | ------- |
| `Secure` | Signatures chain to the trust anchor | Yes, with AD set for a client that asked |
| `Insecure` | The chain **provably** stops — a delegation on the path has no DS, and that absence is itself signed | Yes, AD clear |
| `Bogus` | The data claims to be signed and the claim does not hold | **Never.** SERVFAIL |
| `Indeterminate` | We could not obtain what was needed to decide | **Never.** SERVFAIL |

The distinction carrying the security is Insecure vs. Bogus. "No signature present" is *not* Insecure — an on-path attacker strips signatures from any response. It is Insecure only when a signed NSEC/NSEC3 proves the missing DS at the delegation above, which an attacker cannot forge without the parent's key. That proof is why the NSEC/NSEC3 machinery exists; without it, a validator is one an attacker downgrades to no validator at all.

How it behaves in practice:

- **The chain is built top-down**, alongside the delegation walk the resolver already performs, so the DS rides in the referral for free. Validated key sets (and proven-insecure delegations) are cached per zone, so a warm zone costs no re-derivation.
- **Bogus answers are never cached**, positively or negatively — a cached bogus negative would suppress the real name for its whole TTL. In `auto` mode a failed validation is a *definitive* answer rather than a tier failure, so a broken signature cannot be laundered through an upstream that does not validate.
- **AD is set only for `Secure`**, and only for a client that set DO or AD. Answers built from local data never set AD.
- **RRSIG/NSEC/NSEC3 are stripped for a client that did not set DO** (RFC 4035 §3.2.1), unless it asked for that type by name — a signed A record roughly triples in size, and a large answer to a small question is the amplification shape `security.recursion_cidrs` exists to close.
- **Unsupported algorithms are Insecure, not Bogus** (RFC 6840 §5.11): our missing algorithm is not the zone's outage. RSA/SHA-1/256/512, both ECDSA curves and Ed25519 all verify. NSEC3 iteration counts above 100 are treated as insecure rather than computed (RFC 9276).
- **Validation costs roughly one extra query per zone on the path**, so the per-lookup query budget gains 32 on top of the base 64 when validation is on.

Setting `dnssec.validate: false` resolves exactly as before: no DO bit outbound, no chain of trust, no SERVFAIL for bogus data.

**Trust anchors.** `dnssec.trust_anchors` takes DNSKEY presentation form — `"<flags> <protocol> <algorithm> <base64 key>"`, the four RDATA fields as `dig DNSKEY .` prints them. An override **replaces** the IANA keys rather than adding to them, so a private root is anchored to its own key and nothing else. Every field is validated at startup and a malformed anchor is a hard failure, not a silent fallback — an anchor that cannot match a real DNSKEY makes every signed zone fail with nothing pointing at the anchor as the cause.

Verdicts are visible over Prometheus as `rolodex_dns_dnssec_verdicts_total{verdict}`, alongside `dnssec_servfail_total` and `key_cache_entries`.

## Distributing and Trusting the CA

Rolodex DNS is itself an ACME certificate authority: a self-signed **root CA** signs a **per-zone intermediate CA**, and each intermediate signs the leaf certificates issued through the ACME endpoint. For clients to trust those certificates, they need to trust the root CA. Rolodex distributes the CA chain three ways.

### CA over DNS (CERT records with TXT fallback)

Whenever a per-zone intermediate CA is created, Rolodex publishes the root and intermediate certificates **into DNS itself**, so any client that can resolve the zone can fetch and trust the CA without ever touching the enrollment portal:

- **`CERT` records (RFC 4398)** at `_ca.<zone>.` — one record per certificate, with RDATA `"1 0 0 <base64 DER>"` (type 1 = PKIX/X.509, key tag and algorithm 0). The root is identified as the self-signed certificate. Any DNS client works:
  ```bash
  dig CERT _ca.example.com
  ```
- **`TXT` records** at `_rolodex-ca.<zone>.` — the same base64 DER split into ≤255-byte chunks framed as `rolodex-ca:v1:<root|intermediate>:<i>/<n>:<chunk>`. The unique `rolodex-ca:` prefix distinguishes the chunks from unrelated TXT data, and the explicit sequence numbers let clients reassemble them regardless of answer order. This is the fallback for resolver stacks that cannot query `CERT`.

Publication is idempotent (records are replaced, not duplicated) and happens at every point a zone CA is ensured: portal enrollment, the `EnsureZoneCa`/`CreateEabCredential` RPCs, and ACME account/finalize. Consumers should prefer `CERT` and fall back to `TXT`.

### Browser extension

The browser extension under [`extension/`](extension/) has a portal-independent **CA via DNS** panel: give it a DoH URL (e.g. `https://dns.example.com/dns-query`) and a zone, and it retrieves the chain over DNS-over-HTTPS (preferring `CERT`, falling back to `TXT`), identifies the root vs intermediate, optionally verifies the intermediate against the published DANE-TA `TLSA` record, and offers root / intermediate / chain PEM downloads. The DNS logic lives in `extension/ca_dns.js`, a dependency-free browser module reused by the JavaScript test suite.

### Portal and CLI

On the trusted network, the enrollment portal (`acme.portal_bind`, default `https://<host>:8500`) serves the root CA at `GET /api/ca`, and the management CLI prints the full chain:

```bash
# Print root + intermediate PEM for a zone
rolodex-dns-cli ensure-zone-ca --zone example.com

# Or download the root CA from the portal
curl -k https://<host>:8500/api/ca -o rolodex-root-ca.pem
```

Once you have the root CA PEM, add it to each device's trust store (e.g. `update-ca-trust` on Fedora/RHEL, `update-ca-certificates` on Debian/Ubuntu, Keychain Access on macOS, or the browser's own certificate manager for Firefox). Servers issued through the ACME endpoint present a `leaf + intermediate` chain that validates against this root; DANE-aware clients can additionally pin the intermediate via the `TLSA` records Rolodex publishes automatically on issuance.

## DNS64

DNS64 (RFC 6147) synthesizes AAAA records from A records for IPv6-only clients that need to reach IPv4-only hosts. When a client queries for a AAAA record and none exists, but an A record does, Rolodex DNS constructs a synthetic AAAA by embedding the IPv4 address in the configured IPv6 prefix.

The default prefix is `64:ff9b::/96` (the well-known NAT64 prefix). For example, an A record of `192.0.2.1` would be synthesized as `64:ff9b::192.0.2.1` (`64:ff9b::c000:201`).

Configure via YAML:
```yaml
dns64:
  enabled: true
  prefix: "64:ff9b::"
```

Or at runtime via gRPC: `SetDns64Config` / `GetDns64Config`.

## Prometheus Metrics

An optional `metrics` section starts a plain-HTTP scrape endpoint at `/metrics`. The section is **absent by default**, so no listener is started and an upgrade opens no new port.

```yaml
metrics:
  bind: "127.0.0.1:9153"
  # TLDs that get their own `tld` label. Owned TLDs are tracked automatically.
  tracked_tlds:
    - common          # expands to the built-in common-TLD set
    - lab.internal    # anything else you want isolated, by name
```

The endpoint is unauthenticated and carries only aggregate counts — no query names, no record values, no certificate material. Bind it to a private address; the default is loopback. TLS is deliberately not offered here, since it would mean shipping a self-signed certificate to every scraper for an endpoint that should not be publicly reachable in the first place.

77 metric families are exposed, all prefixed `rolodex_dns_`, covering queries, the response cache, blocklists (including refusals and rotated-out providers), upstream tiers, the iterative resolver, DNSSEC verdicts, split-horizon state, DHCP, ACME, and gRPC.

The one worth knowing about is `rolodex_dns_answers_total{source}`, which reports which stage of the resolution order produced each answer — `cache`, `local`, `scoped`, `scope_fallback`, `tld_peer`, `blocklist`, `rbl`, `dns64`, `upstream`, `authoritative_nxdomain`, `refused`, `error`. Its total equals the query total, which is what makes the split-horizon pipeline legible from outside:

```
curl -s http://127.0.0.1:9153/metrics | grep answers_total
```

### Cardinality

Bounded cardinality is a design constraint, because a metrics endpoint that a stranger can grow without limit is a memory-exhaustion bug wearing a monitoring costume. Every label is either a fixed enum or bounded by configuration. The two dimensions a *client* could otherwise inflate are both folded into a catch-all:

| Dimension | Bound | Catch-all |
|-----------|-------|-----------|
| `qtype` | 23 known record types | `OTHER` — a flood of `TYPE4242` queries mints nothing |
| `tld` | Owned TLDs, plus `metrics.tracked_tlds` | `other` — a scanner sweeping junk TLDs mints nothing |

**Query names are never labels.** Only the TLD suffix, and only when the operator has already opted into that suffix.

### Per-TLD isolation

`rolodex_dns_queries_by_tld_total{tld}` breaks the query stream down by TLD, which is what makes a split-horizon deployment's networks separable from each other and from the public internet. Three things feed the tracked set:

1. **Owned TLDs, automatically.** Every TLD a network scope owns — including each scope's implicit `.home` domain — is tracked without being asked for. A network's own namespace is the thing most worth isolating, and requiring it to be named twice (once to own it, once to track it) is a footgun that shows up as a silently missing series.
2. **The config list.** `metrics.tracked_tlds` in the YAML. The entry `common` expands to the built-in common-TLD set (`com.`, `net.`, `org.`, `io.`, `dev.`, …) so the usual public TLDs are one line rather than twenty. Config entries are pinned: they survive restarts and cannot be removed over the API.
3. **The stored list.** Managed at runtime, without a restart:

```bash
# Track the common set plus one exceptional TLD
rolodex-dns-cli set-tracked-tlds --tld common --tld lab.internal

# Show stored, owned and effective sets
rolodex-dns-cli list-tracked-tlds

# Clear the stored list (owned and config-pinned TLDs are unaffected)
rolodex-dns-cli set-tracked-tlds
```

The **effective** set is the union of all three, and it is what actually produces series — which is why both commands print it. The stored list alone does not tell you which series will appear.

### DNS and DHCP are separately selectable

DNS and DHCP are separate services that happen to share a process, and their series are kept apart on purpose:

- The DHCP families label their dimensions **`message_type`** and **`lease_state`**, not the generic `type` and `state`. A generic label name is what makes an aggregation spanning both subsystems — a `sum by (type) (...)` in a recording rule, say — silently blend a DHCP ACK count into a DNS one.
- The DNS rollups (`queries_total`, `traffic_bytes_total`, `records_served_total`, `queries_by_tld_total`) count **DNS only**. DHCP packets on `:67` are never counted as DNS traffic, and a DHCP-registered name contributes to the DNS metrics only when somebody actually resolves it.

> **Upgrade note:** `rolodex_dns_dhcp_messages_total{type}` became `{message_type}` and `rolodex_dns_dhcp_leases{state}` became `{lease_state}`. Dashboards and alerts selecting on the old label names need updating.

### Common queries

```promql
# Query rate by transport
sum by (proto) (rate(rolodex_dns_queries_total[5m]))

# Which stage of the resolution order is answering
sum by (source) (rate(rolodex_dns_answers_total[5m]))

# NXDOMAIN share of all answers
sum(rate(rolodex_dns_queries_total{rcode="NXDOMAIN"}[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))

# Response-cache hit ratio
sum(rate(rolodex_dns_cache_hits_total[5m]))
  / (sum(rate(rolodex_dns_cache_hits_total[5m])) + sum(rate(rolodex_dns_cache_misses_total[5m])))

# p99 query latency per transport
histogram_quantile(0.99, sum by (le, proto) (rate(rolodex_dns_query_duration_seconds_bucket[5m])))
```

Traffic volume, and how much of it is actual records rather than negative answers:

```promql
# Wire bytes in and out
sum by (direction) (rate(rolodex_dns_traffic_bytes_total[5m]))

# Amplification factor: bytes emitted per byte received. A climbing value on a
# publicly-reachable listener is the shape of a reflection attack.
sum(rate(rolodex_dns_traffic_bytes_total{direction="tx"}[5m]))
  / sum(rate(rolodex_dns_traffic_bytes_total{direction="rx"}[5m]))

# Records returned per query — a million NXDOMAINs and a million populated
# answers are the same query count and very different amounts of work.
sum(rate(rolodex_dns_records_served_total[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))
```

Blocklists — the pair that matters is blocks against refusals, because a list that has stopped answering looks identical to a clean one if only the block counter is watched:

```promql
# Blocks by which list matched
sum by (kind) (rate(rolodex_dns_blocklist_blocks_total[5m]))

# Blocked share of all traffic
sum(rate(rolodex_dns_blocklist_blocks_total[5m]))
  / sum(rate(rolodex_dns_queries_total[5m]))

# Allowlist activity by match path. Climbing here means an operator is
# continuously papering over a list that is misfiring.
sum by (kind) (rate(rolodex_dns_blocklist_allowlisted_total[5m]))

# A provider has started refusing us rather than reporting reputation
sum by (kind) (rate(rolodex_dns_blocklist_refusals_total[5m])) > 0

# Providers currently out of rotation
rolodex_dns_blocklist_rotated_out > 0
```

Per-TLD, upstream health and DNSSEC:

```promql
# Query rate per tracked TLD, ignoring the untracked catch-all
sum by (tld) (rate(rolodex_dns_queries_by_tld_total{tld!="other"}[5m]))

# What fraction of traffic is for names you do not track
sum(rate(rolodex_dns_queries_by_tld_total{tld="other"}[5m]))
  / sum(rate(rolodex_dns_queries_by_tld_total[5m]))

# Degraded off the iterative tier (0=roots, 1=secure, 2=local, 3=public)
rolodex_dns_upstream_active_tier > 0

# Tier churn
sum by (direction) (rate(rolodex_dns_upstream_tier_switches_total[5m]))

# Signed data that failed to validate: an attack, or a zone that broke its own
# signing. Distinct from `indeterminate`, which is a network fault.
sum(rate(rolodex_dns_dnssec_verdicts_total{verdict="bogus"}[5m])) > 0

# Referrals discarded for delegating outside the answering zone
rate(rolodex_dns_resolver_out_of_bailiwick_total[5m]) > 0

# Lookups killed by the per-lookup query budget
rate(rolodex_dns_resolver_budget_exhausted_total[5m]) > 0
```

DHCP, using the isolated label names:

```promql
# Leases by state
rolodex_dns_dhcp_leases{lease_state="active"}

# DHCP message rate by type
sum by (message_type) (rate(rolodex_dns_dhcp_messages_total[5m]))

# Pool exhaustion
rate(rolodex_dns_dhcp_allocation_failures_total[5m]) > 0
```

Control plane and host reachability:

```promql
# Someone is guessing the gRPC shared secret
rate(rolodex_dns_grpc_auth_failures_total[5m]) > 0

# An address family the host cannot route, so its records are being suppressed
rolodex_dns_address_family_reachable{family="ipv6"} == 0
```

Every query above is covered by a test that resolves its metric names and label matchers against the live exposition output, so a documented query cannot reference a series that does not exist.

## RBL (Realtime Blackhole List)

When RBL is enabled, Rolodex DNS checks IP addresses found in reverse DNS queries against configured RBL providers. If an IP is listed in any enabled provider, the query receives an `NXDOMAIN` response. RBL is **disabled by default with an empty provider list** — nothing external is queried until an operator adds providers via the `rbl` config section or `SetRblConfig`.

### Local RBL Database

In addition to external RBL providers, Rolodex DNS supports locally-managed blocklist entries. Local entries are checked alongside external providers, against both reverse-DNS IP lookups and forward domain names, and are managed via `AddLocalRblEntry`, `RemoveLocalRblEntry`, and `ListLocalRblEntries`.

```bash
# Block a specific IP with a reason
rolodex-dns-cli add-local-rbl --name 10.0.0.5 --reason "known spam source"

# List local entries
rolodex-dns-cli list-local-rbl

# Remove an entry
rolodex-dns-cli remove-local-rbl --name 10.0.0.5
```

### Commonly Used Providers

The provider list ships empty; these are the standard zones an operator typically adds (the same ones used by unbound and other resolvers):

| Zone | Description |
|------|-------------|
| `zen.spamhaus.org` | Combined Spamhaus blocklist (SBL + XBL + PBL + CSS) |
| `bl.spamcop.net` | SpamCop blocklist |
| `b.barracudacentral.org` | Barracuda Reputation Block List |
| `dbl.spamhaus.org` | Spamhaus Domain Block List |

### How RBL Works

1. A reverse DNS query arrives (e.g. `100.1.168.192.in-addr.arpa.`)
2. The IP is extracted from the query name (`192.168.1.100`)
3. Local RBL entries are checked first
4. For each enabled RBL provider, Rolodex DNS constructs a query: `<reversed-ip>.<rbl-zone>`
5. If any RBL responds with an A record, the IP is considered listed
6. Results are cached in memory for the TTL returned by the RBL
7. Listed IPs receive `NXDOMAIN` for the original query

### Caching

- Positive results (IP is listed) are cached for the TTL returned by the RBL provider
- Negative results (IP is not listed) are cached for 5 minutes
- Lookup errors are not cached and are treated as not-listed, to avoid false positives
- Refusals are not cached either, and take the provider out of rotation — see below
- The cache can be flushed via the `FlushCache` gRPC method, which also returns every rotated-out provider to rotation

### Refusal Codes and Provider Rotation

A DNSxL answers a listing and a complaint about *you* the same way: an `A` record under `127.0.0.0/8`. `zen.spamhaus.org` says "listed" with `127.0.0.2` and "you are querying via a public resolver" with `127.255.255.254`, and **only the address distinguishes them**. Reading any `A` record as a listing turns the moment a blocklist decides to stop answering you into NXDOMAIN for *every* name checked against that provider — and it starts when your query volume crosses the provider's threshold, hours or weeks after a deployment that looked fine. Spamhaus says it directly: those codes "should NOT be interpreted as any sort of reputation".

So each provider carries a set of refusal codes. A matching answer is **`Refused`**: not a listing, not a negative, nothing cached — nothing was learned about the queried name. A refusal anywhere in an answer wins over a listing in the same answer, because a provider that is complaining is not simultaneously reporting reputation, and erring this way fails *open* where the other order fails closed on every name.

The built-in set, used when a provider configures none:

| Code | Meaning |
| ---- | ------- |
| `127.255.255.0/24` | Spamhaus error range: `.252` typo in the zone name, `.254` query via a public/open resolver, `.255` excessive queries. A whole range rather than the three codes, because Spamhaus reserves it and adds to it |
| `127.0.1.255` | Spamhaus DBL answering an IP query — "IP queries not supported" |
| `127.0.2.255` | Spamhaus ZRD answering an IP query — same |
| `127.0.0.1` | URIBL/SURBL "query blocked". RFC 5782 §5 also forbids a DNSxL from listing `127.0.0.1`, so it is never a legitimate listing |
| `127.0.0.255` | URIBL "query blocked" (over quota) |

Each entry is an IPv4 address or `address/prefix`. **Empty means the built-in set** — it cannot mean "no codes", because empty is what every configuration written before this feature existed has. The single entry `none` disables detection for a private blocklist whose real listings collide with one of the above. An explicit list is exactly that list; the defaults are not merged in, so an operator who spells it out can also narrow it. An unparseable code is rejected — at startup, or with `InvalidArgument` from the RPC — rather than skipped, since a code that silently does not apply is a refusal that reads as a listing.

**Rotation.** A refusal takes the provider out of the lookup rotation for `refusal_cooldown_secs` (default 3600s, per-provider override available), so a blocklist that has just told you to stop is backed off rather than queried on every request. Rotation:

- skips **new lookups** only — already-cached verdicts still count, since "this provider will not answer new questions" is not "the answers it already gave were wrong";
- **lapses on its own**, so a transient over-quota period heals with no operator action;
- is **cleared** by `flush-cache` and by any `set-rbl-config`/`set-dnsbl-config` — a reconfiguration is often the fix for the refusal (a typo in the zone name is both a cause of `127.255.255.252` and the thing being corrected);
- is **reported** by `get-rbl-config`/`get-dnsbl-config` and by `rolodex_dns_blocklist_refusals_total{kind}` / `rolodex_dns_blocklist_rotated_out`.

Setting a cooldown to `0` means "use the default", not "no cooldown" — a zero cooldown re-asks the provider that just told you to stop, which is the behaviour rotation exists to prevent.

### Per-Scope Providers

A network scope can opt into additional RBL providers beyond the global list, checked for IPs associated with that scope. A positive from either is the same NXDOMAIN, and the allowlist exempts from either. Managed via `add-scope-rbl`, `remove-scope-rbl`, and `list-scope-rbl`; each provider carries its own refusal codes and cooldown.

Because a scope opts in row by row, per-scope providers are **not** gated on the global `rbl.enabled` flag — a scope may run a blocklist the box as a whole does not. They are skipped when outbound plaintext `:53` is unreachable, since that flag is not a policy switch: it says the lookup can only time out.

```bash
# --enabled takes a value; omitting it defaults to true
rolodex-dns-cli add-scope-rbl -s office --zone zen.spamhaus.org --enabled true
rolodex-dns-cli list-scope-rbl -s office
```

## DNSBL (Domain Blocklists)

Where RBL providers block by **IP address** (queried with a reversed IP on reverse-DNS lookups), DNSBL providers block by **domain name**: the queried name's labels are prepended to the provider zone, so `googleadservices.com` against `dbl.spamhaus.org` is queried as `googleadservices.com.dbl.spamhaus.org`. This is how Spamhaus DBL, SURBL, and URIBL operate.

DNSBL gives blocklists **precedence over external DNS**. The check runs after local records and managed/authoritative zones — so internal data always wins — but **before** the upstream response cache and any external resolution. A listed name therefore returns NXDOMAIN even if a forwarded answer for it was previously cached.

Like RBL, DNSBL is disabled by default with an empty provider list, and individual providers can be enabled or disabled independently. An enabled-but-empty DNSBL is a no-op. The standard zones an operator typically adds are `dbl.spamhaus.org`, `multi.surbl.org`, and `multi.uribl.com`. DNSBL results share the RBL result cache (positives for the provider TTL, negatives for 5 minutes).

```bash
rolodex-dns-cli set-dnsbl-config --enabled --providers dbl.spamhaus.org:true
rolodex-dns-cli get-dnsbl-config
```

### Allowlisting a Host

The allowlist is the operator's escape hatch from a false positive, and it covers **every list and both gates**: the forward-name check (DNSBL providers and the local blocklist) *and* the reverse-DNS/IP check (global RBL providers, a scope's own providers, and local entries naming an address). A wrongly-listed IP breaks `dig -x` for a host that is running fine, so an escape hatch that reached only names would not be one.

- **Names are suffix-matched.** An entry covers the name and every name beneath it, so allowlisting `example.com` also exempts `www.example.com`; matching is on label boundaries, so `notexample.com` is not exempt.
- **An address can be named either way.** A reverse query is exempted by an entry naming the `in-addr.arpa`/`ip6.arpa` name *or* the IP literal it encodes, so nobody has to hand-reverse octets. The reverse **name** is suffix-matched like any DNS name (allowlisting `1.168.192.in-addr.arpa` lifts the block on that whole /24); the IP **literal** is matched **exactly**, because an address runs most-significant-octet first — `1.100` is not a parent of `192.168.1.100`, and treating it as one would exempt addresses nobody named.
- **It short-circuits the check entirely.** An exempt name or address is checked against no provider and issues no blocklist lookup at all.
- Entries are normalized (lowercase, trailing dot), so any spelling adds or removes the same entry; they persist across restarts and take effect on the next query with no cache flush needed.

```bash
# Exempt a host that a provider is false-positiving on
rolodex-dns-cli add-dnsbl-allow --name vendor.example.com --reason "blocklist false positive"

# Exempt an address — either spelling works
rolodex-dns-cli add-dnsbl-allow --name 192.168.1.100 --reason "our own mail relay"
rolodex-dns-cli add-dnsbl-allow --name 1.168.192.in-addr.arpa --reason "whole /24"

# List the allowlist
rolodex-dns-cli list-dnsbl-allow

# Remove an entry
rolodex-dns-cli remove-dnsbl-allow --name vendor.example.com
```

## Network Scoping

Network scoping provides split-horizon DNS views, allowing different DNS responses based on which network scope a client IP is associated with.

### Concepts

- **Network Scope**: A named DNS view with its own set of DNS records and a reserved `.home` domain (e.g. `office.home.`). The `.home` domain is used as the default search domain for DHCP clients.
- **Network Association**: A mapping from a client IP to a scope, with a TTL that must be refreshed regularly. When the TTL expires, the IP loses its scope association and DNS queries are refused.
- **Scoped Records**: DNS records that belong to a specific scope and are only visible to IPs associated with that scope.

### How It Works

1. Create a network scope (e.g. `"office"` with domain `"office.home."`)
2. Add scoped DNS records to the scope
3. Client IPs join the network by associating with a scope (with a TTL)
4. When a DNS query arrives:
   - If it arrived on a per-TLD **ingress listener**: it is served within that listener's owning scope, for every name
   - If the source IP is associated with a scope: check scoped records first, then fall through to global records, then resolve externally
   - If the source IP is inside `security.overlay_cidrs` (an overlay/WireGuard peer) but joined to no scope: **REFUSED**
   - Any other source — loopback, LAN, container bridges — is trusted: it is never refused and resolves the global namespace
   - If no scopes exist at all: legacy behavior (all queries served from global records)
5. Search domains (via `GetSearchDomains`) return the `.home` domain for DHCP integration

### Trusted Sources vs. Overlay Peers

Scope enforcement applies **only** to source IPs inside `security.overlay_cidrs` (default `10.64.0.0/10`, the WireGuard overlay range). Such a peer must be joined to a network or it is refused, and it sees only its own scope's partitioned TLDs. Every other source is trusted and resolves the global view.

This is what makes the split horizon useful in practice: a name can carry a global record pointing at the box's LAN address and a scoped record pointing at its overlay address, and each side is handed an address it can actually route to.

### Recursion Access Control

Scope enforcement decides *which view* a source gets. A separate axis, `security.recursion_cidrs`, decides whether a source gets **upstream resolution** at all.

`dns.bind` defaults to `0.0.0.0:53`, so on a routable interface the listener is reachable from the whole internet, and every source outside `overlay_cidrs` is classified as a trusted local client. Without a second check that is an **open recursive resolver** — the classic reflection/amplification asset, where a small spoofed query returns a large answer aimed at the spoofed victim and the outbound resolution traffic is billed to your box.

The default list is every range that is unroutable from the internet — `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `::1/128`, `fe80::/10`, `fc00::/7` — which covers loopback, the LAN, container bridges and the WireGuard overlay (`10.64.0.0/10` sits inside `10.0.0.0/8`), so nothing that legitimately used this server loses service. An empty list closes recursion to everyone, leaving a purely authoritative server.

- **The check sits at the local/remote boundary**: after every path that answers from data this server holds, before every path that reaches for data it does not. A stranger still receives your authoritative answers and authoritative NXDOMAINs — closing recursion must not turn the box into a black hole for its own zones — but cannot make it go and ask someone else.
- **It runs before the response cache**, because a cached answer amplifies exactly as well as a freshly-resolved one, and warming the cache is how the attack is staged.
- **The refusal is REFUSED with an empty answer section**, so the reply is never larger than the question that provoked it.
- **Every transport is gated** — UDP, TCP, DoT, DoQ, and DoH (which serves with connect info so its peer address reaches classification; otherwise `:443` would reopen what `:53` closes).

### Per-Network Owned TLDs

Beyond its implicit `.home` domain, a scope can own additional TLDs that partition the namespace across networks. Each owned TLD is **globally unique** to one scope, and names under it are never forwarded upstream — an unmatched name yields an authoritative NXDOMAIN, after optionally consulting the TLD's *peer forwarders* (the overlay addresses of other Rolodex members of the same network).

- For an **overlay peer**, owned TLDs are strictly partitioned: it resolves its own network's TLD and gets NXDOMAIN for any other scope's TLD, so two networks' TLDs are never both resolvable from one endpoint.
- For a **trusted local source** (loopback/LAN), *every* owned TLD resolves from its owning scope, so all network TLDs are visible on the LAN. Dual-homed names still return their LAN-facing global value; only scope-only names are served from the scope.

A scope can therefore exist purely to own a TLD — marking it partitioned-from-peers and LAN-resolvable — without ever binding an overlay to it.

```bash
# Register an owned TLD for a scope
rolodex-dns-cli add-scope-tld -s office --tld office.
# Point unmatched names under it at other Rolodex members of the network
rolodex-dns-cli set-scope-tld-forwarders -s office --tld office. -f 10.64.0.2:53
rolodex-dns-cli list-scope-tlds -s office
```

### Ingress DNS Listeners

An owned TLD can be registered with a local **ingress IP** (`add-scope-tld --listen-ip`), typically the network's own overlay address:

```bash
rolodex-dns-cli add-scope-tld -s office --tld office. --listen-ip 10.64.0.1
rolodex-dns-cli list-scope-tld-listeners -s office
```

That does three things:

1. **Binds a DNS listener** (UDP + TCP) on that IP, at `dns.ingress_listen_port` (default 53). Listeners are re-created at boot from the database, and torn down when the last TLD referencing the IP is removed. A bind that fails — the usual case at boot, when the overlay interface does not exist yet — is retried on the next re-registration rather than being remembered as "already listening".
2. **Serves the owning scope's view for every name.** The listener is that network's dedicated resolver, so a query arriving on it belongs to the owning scope whatever the name is: owned TLDs stay partitioned, and everything else falls through to global resolution and upstream resolution — which is what lets a peer use it as its general-purpose resolver.
3. **Rewrites programmed names to the ingress IP.** A name under the TLD that has a stored A/AAAA record is answered with the ingress IP instead of its stored backend value, so the network's ingress controller receives the traffic and routes by Host/SNI. This part stays name-gated: a pass-through name keeps its resolved value, the same name on the main `:53` listener resolves to its stored value, and a name with no record still returns NXDOMAIN (no wildcard synthesis).

### Resolution Order (Scoped)

1. Parse EDNS OPT record (payload size negotiation, DO bit for DNSSEC)
2. Check RBL (for reverse DNS queries, if enabled) -- includes local RBL entries
3. Check DNS response cache
4. Check scoped records for the client's scope
5. Check scoped CNAME records
6. Check scoped DNAME records (subtree rewriting)
7. Check if name is under a scoped managed zone (authoritative NXDOMAIN)
8. Check global database records
9. Check global CNAME records
10. Check global DNAME records (subtree rewriting)
11. Check ANAME records (resolve alias at zone apex)
12. Check if name is under a global managed zone (authoritative NXDOMAIN)
13. Check wildcard records (`*.zone.`)
14. Check the local blocklist and DNSBL providers (a listed name is NXDOMAIN, taking precedence over any external answer)
15. Enforce `security.recursion_cidrs` — a source outside it is REFUSED before anything reaches off-box
16. Resolve externally per `resolution.mode` (with QNAME case randomization if enabled, via proxy if configured), validating DNSSEC on the iterative path
17. Apply DNS64 synthesis (if enabled and AAAA query returned empty but A record exists)
18. Cache the response (bogus answers are never cached)
19. Apply TTL drift adjustment (if configured)
20. Drop A/AAAA answers of an unroutable address family (if `address_family.mode: auto`)

## DHCP Server

Rolodex DNS includes an integrated DHCPv4 server with IP address management and automatic DNS registration. It is disabled unless a `dhcp` section is present in the configuration.

- **Per-scope pools.** Each pool belongs to a network scope and defines a single contiguous range, gateway, subnet mask, and DNS servers. When a pool is exhausted, allocation fails — there is no cross-pool aggregation. MAC-to-IP bindings are sticky: the same MAC always gets the same IP back.
- **Automatic DNS registration.** A client that sends a hostname (option 12) gets an A record at `<hostname>.lan.<dhcp.tld>.` and a matching `in-addr.arpa` PTR, both as scoped records in the pool's scope. The lease is also joined to the network scope (`JoinNetwork`), so the client immediately sees that network's split-horizon view. Both records are removed when the lease is released or expires.
- **Lease states.** `active`, `expired` (past its duration), `released` (client released it), and `reclaimable` (past `reclaim_timeout`, so the IP can be handed out again).
- **Certificate delivery.** Certificates can be handed to clients through site-specific DHCP options (codes 224–254), configured per scope.
- **Background sweep.** Every `sweep_interval` seconds, expired leases are retired (removing their DNS records and scope association) and leases past `reclaim_timeout` release their IP.

```bash
# A pool for the "office" scope
rolodex-dns-cli add-dhcp-pool -s office \
  --range-start 10.0.0.100 --range-end 10.0.0.200 \
  --gateway 10.0.0.1 --subnet-mask 255.255.255.0 --dns-servers 10.0.0.1

rolodex-dns-cli list-dhcp-pools -s office
rolodex-dns-cli list-dhcp-leases -s office
```

## Go Client

A Go client library is included at `go/` for programmatic access to the Rolodex DNS gRPC API. It can be imported as a Go module dependency.

### Installation

```
go get gitea.com/town-os/rolodex-dns/go
```

### Connecting

The client supports two transports:

**TCP** (with shared-secret authentication):

```go
client, err := rolodex_dns.Dial(ctx, "localhost:50051",
    rolodex_dns.WithAuthToken("my-secret"),
)
defer client.Close()
```

**Unix socket** (authentication bypassed server-side):

```go
client, err := rolodex_dns.Dial(ctx, "/var/run/rolodex-dns.sock",
    rolodex_dns.WithUnixSocket(),
)
defer client.Close()
```

### Client Options

| Option | Description |
|--------|-------------|
| `WithAuthToken(token)` | Sets the shared secret sent with every RPC for TCP authentication. Ignored by the server on Unix socket connections. Default: empty (succeeds if server has no secret configured) |
| `WithUnixSocket()` | Marks the address as a Unix domain socket path instead of a TCP address. Server bypasses authentication for Unix socket connections |
| `WithGRPCDialOption(opt)` | Appends a low-level `grpc.DialOption` (e.g. for TLS, interceptors) |

### Client Methods

All methods accept a `context.Context` for cancellation and deadlines.

#### Record Management

| Method | Description |
|--------|-------------|
| `AddRecord(ctx, record) error` | Add a DNS record |
| `RemoveRecord(ctx, name, opts) (uint32, error)` | Remove DNS records (returns count removed) |
| `ListRecords(ctx, opts) ([]*DnsRecord, error)` | List/filter DNS records |

#### Forwarders

| Method | Description |
|--------|-------------|
| `SetForwarders(ctx, forwarders) error` | Set upstream DNS forwarders |

#### RBL

| Method | Description |
|--------|-------------|
| `SetRblConfig(ctx, enabled, providers) error` | Configure RBL settings |
| `SetRblConfigWithRefusalCooldown(ctx, enabled, providers, secs) error` | The same, with the list-wide rotate-out duration for refusing providers |
| `GetRblConfig(ctx) (*RblStatus, error)` | Get current RBL config, resolved refusal codes, and rotated-out providers |
| `SetDnsblConfig(ctx, enabled, providers) error` | Configure DNSBL (domain blocklist) settings |
| `SetDnsblConfigWithRefusalCooldown(ctx, enabled, providers, secs) error` | The same, with the DNSBL rotate-out duration |
| `GetDnsblConfig(ctx) (*DnsblStatus, error)` | Get current DNSBL config |
| `FlushCache(ctx) error` | Flush the RBL/DNSBL cache and return every rotated-out provider to rotation |
| `AddLocalRblEntry(ctx, entry) error` | Add a local RBL blocklist entry |
| `RemoveLocalRblEntry(ctx, name) error` | Remove a local RBL blocklist entry |
| `ListLocalRblEntries(ctx) ([]*LocalRblEntry, error)` | List local RBL entries |
| `AddDnsblAllowlistEntry(ctx, entry) error` | Exempt a name (and its subdomains) from the blocklist check |
| `RemoveDnsblAllowlistEntry(ctx, name) error` | Remove a DNSBL allowlist entry |
| `ListDnsblAllowlistEntries(ctx) ([]*DnsblAllowlistEntry, error)` | List DNSBL allowlist entries |

#### Network Scoping

| Method | Description |
|--------|-------------|
| `CreateNetworkScope(ctx, scope) error` | Create a network scope |
| `DeleteNetworkScope(ctx, name) error` | Delete a scope and its data |
| `ListNetworkScopes(ctx) ([]*NetworkScope, error)` | List all scopes |
| `JoinNetwork(ctx, ip, scope, ttl) error` | Associate an IP with a scope |
| `LeaveNetwork(ctx, ip) error` | Remove an IP's scope association |
| `GetNetworkAssociations(ctx, scope) ([]*NetworkAssociation, error)` | List associations |
| `AddScopedRecord(ctx, scope, record) error` | Add a scoped DNS record |
| `RemoveScopedRecord(ctx, scope, name, opts) (uint32, error)` | Remove scoped records |
| `ListScopedRecords(ctx, scope, opts) ([]*DnsRecord, error)` | List scoped records |
| `GetSearchDomains(ctx, ip) ([]string, error)` | Get search domains for an IP |
| `AddScopeTld(ctx, scope, tld) error` | Register a globally-unique owned TLD for a scope |
| `AddScopeTldWithListener(ctx, scope, tld, listenIP) error` | Register an owned TLD and bind an ingress DNS listener |
| `RemoveScopeTld(ctx, scope, tld) error` | Remove an owned TLD from a scope |
| `ListScopeTlds(ctx, scope) ([]string, error)` | List the TLDs owned by a scope |
| `SetScopeTldForwarders(ctx, scope, tld, forwarders) error` | Set a TLD's peer forwarders |
| `ListScopeTldForwarders(ctx, scope, tld) ([]string, error)` | List a TLD's peer forwarders |
| `ListScopeTldListeners(ctx, scope) ([]*TldListener, error)` | List a scope's ingress DNS listeners |
| `AddScopeRblProvider(ctx, scope, zone, enabled) error` | Add a per-scope RBL provider |
| `AddScopeRblProviderWithRefusal(ctx, scope, zone, enabled, codes, secs) error` | The same, with the provider's refusal codes and rotate-out duration |
| `RemoveScopeRblProvider(ctx, scope, zone) error` | Remove a per-scope RBL provider |
| `ListScopeRblProviders(ctx, scope) ([]*ScopeRblProvider, error)` | List per-scope RBL providers |

#### DHCP

| Method | Description |
|--------|-------------|
| `AddDhcpPool(ctx, pool) (string, error)` | Add a DHCP address pool for a scope |
| `RemoveDhcpPool(ctx, poolID) error` | Remove a DHCP pool |
| `ListDhcpPools(ctx, scope) ([]*DhcpPool, error)` | List DHCP pools |
| `ListDhcpLeases(ctx, scope) ([]*DhcpLease, error)` | List DHCP leases |
| `DeleteDhcpLease(ctx, mac) error` | Delete a DHCP lease by MAC |
| `SetDhcpCertOption(ctx, opt) error` | Deliver a certificate via a DHCP option |
| `RemoveDhcpCertOption(ctx, scope, optionCode) error` | Remove a DHCP certificate option |
| `ListDhcpCertOptions(ctx, scope) ([]*DhcpCertOption, error)` | List DHCP certificate options |

#### Authoritative Zones

| Method | Description |
|--------|-------------|
| `AddAuthoritativeZone(ctx, zone) error` | Declare a zone as authoritative |
| `RemoveAuthoritativeZone(ctx, zone) error` | Remove an authoritative zone |
| `ListAuthoritativeZones(ctx) ([]string, error)` | List authoritative zones |

#### Cache

| Method | Description |
|--------|-------------|
| `GetCacheStats(ctx) (*CacheStats, error)` | Get cache statistics (entries, hits, misses) |
| `FlushDnsCache(ctx) error` | Flush the DNS response cache |

#### Encrypted Transports

| Method | Description |
|--------|-------------|
| `SetDotConfig(ctx, config) error` | Configure DNS-over-TLS |
| `GetDotConfig(ctx) (*DotConfig, error)` | Get DoT configuration |
| `SetDohConfig(ctx, config) error` | Configure DNS-over-HTTPS |
| `GetDohConfig(ctx) (*DohConfig, error)` | Get DoH configuration |
| `SetDoqConfig(ctx, config) error` | Configure DNS-over-QUIC |
| `GetDoqConfig(ctx) (*DoqConfig, error)` | Get DoQ configuration |

#### Proxy

| Method | Description |
|--------|-------------|
| `SetProxyConfig(ctx, config) error` | Configure HTTP proxy |
| `GetProxyConfig(ctx) (*ProxyConfig, error)` | Get proxy configuration |

#### DNSSEC

| Method | Description |
|--------|-------------|
| `GenerateDnssecKey(ctx, zone, algorithm, keyType) (*DnssecKey, error)` | Generate a DNSSEC key pair |
| `ListDnssecKeys(ctx, zone) ([]*DnssecKey, error)` | List DNSSEC keys for a zone |
| `DeleteDnssecKey(ctx, keyID) error` | Delete a DNSSEC key |
| `GetDsRecords(ctx, zone) ([]string, error)` | Get DS records for registrar |
| `SignZone(ctx, zone) error` | Sign a zone with its keys |

#### DANE / ACME

| Method | Description |
|--------|-------------|
| `GenerateTlsaRecord(ctx, opts) (string, error)` | Generate a TLSA record from a certificate |
| `ListTlsaRecords(ctx, domain) ([]*DnsRecord, error)` | List TLSA records for a domain |
| `GenerateDaneRootCa(ctx, name) (string, error)` | Generate a self-signed DANE root CA |
| `RequestAcmeCert(ctx, domain, providerURL) error` | Request ACME DNS-01 certificate |
| `GetAcmeStatus(ctx, domain) (*AcmeStatus, error)` | Get ACME certificate status |
| `EnsureZoneCa(ctx, zone) (*ZoneCa, error)` | Ensure the per-zone intermediate CA exists |
| `CreateEabCredential(ctx, zone) (*EabCredential, error)` | Mint a zone-scoped EAB credential |
| `RemoveEabCredential(ctx, kid) error` | Remove an EAB credential |
| `ListAcmeAccounts(ctx) ([]*AcmeAccount, error)` | List registered ACME accounts |
| `ListAcmeCertificates(ctx, zone) ([]*AcmeCertificate, error)` | List issued certificates |

#### TTL Drift

| Method | Description |
|--------|-------------|
| `SetTtlDriftConfig(ctx, config) error` | Configure TTL drift |
| `GetTtlDriftConfig(ctx) (*TtlDriftConfig, error)` | Get TTL drift configuration |

#### DNS64

| Method | Description |
|--------|-------------|
| `SetDns64Config(ctx, config) error` | Configure DNS64 synthesis |
| `GetDns64Config(ctx) (*Dns64Config, error)` | Get DNS64 configuration |

#### Observability

| Method | Description |
|--------|-------------|
| `GetQueryLatencyStats(ctx) ([]*QueryLatencyStats, error)` | Get per-server latency stats |

#### Connection

| Method | Description |
|--------|-------------|
| `Close() error` | Close the gRPC connection |

### Record Types

| Constant | Value | Description |
|----------|-------|-------------|
| `RecordTypeA` | 0 | IPv4 address (default) |
| `RecordTypeAAAA` | 1 | IPv6 address |
| `RecordTypeCNAME` | 2 | Canonical name alias |
| `RecordTypeMX` | 3 | Mail exchange (uses Priority) |
| `RecordTypeTXT` | 4 | Text record |
| `RecordTypeNS` | 5 | Name server |
| `RecordTypeSOA` | 6 | Start of authority |
| `RecordTypeSRV` | 7 | Service locator (uses Priority) |
| `RecordTypePTR` | 8 | Pointer for reverse DNS |
| `RecordTypeURI` | 9 | URI resource record (RFC 7553) |
| `RecordTypeSSHFP` | 10 | SSH fingerprint (RFC 4255) |
| `RecordTypeDNAME` | 11 | Delegation name (RFC 6672) |
| `RecordTypeANAME` | 12 | Alias name (zone apex CNAME alternative) |
| `RecordTypeZONEMD` | 13 | Zone message digest (RFC 9156) |
| `RecordTypeTLSA` | 14 | TLS certificate association (RFC 6698) |
| `RecordTypeDNSKEY` | 15 | DNSSEC public key |
| `RecordTypeDS` | 16 | DNSSEC delegation signer |
| `RecordTypeRRSIG` | 17 | DNSSEC resource record signature |
| `RecordTypeNSEC` | 18 | DNSSEC next secure record |
| `RecordTypeNSEC3` | 19 | DNSSEC next secure record v3 |
| `RecordTypeNSEC3PARAM` | 20 | DNSSEC NSEC3 parameters |
| `RecordTypeCERT` | 21 | Certificate storage in DNS (RFC 4398) |

## RFC Compliance

| RFC | Name | Support |
|-----|------|---------|
| RFC 1034 / 1035 | Domain names — concepts and implementation | Iterative resolution from the root servers, delegation following, glue and glue-less NS handling |
| RFC 2308 | Negative caching of DNS queries | Negative TTL taken as `min(SOA MINIMUM, SOA TTL)`, honoured as published |
| RFC 4033 / 4034 / 4035 | DNSSEC protocol, records, and protocol modifications | Zone signing (RRSIG over canonical RRsets, KSK/ZSK roles, DS computation) and upstream validation (chain of trust from the root, the four verdicts, AD/DO handling). NSEC/NSEC3 are validated but never generated |
| RFC 4255 | SSHFP DNS record | Full (storage, lookup, algorithm/fingerprint type) |
| RFC 4398 | CERT DNS record | Full (storage, lookup, PKIX CA-chain distribution) |
| RFC 4592 | Wildcards in DNS | Full (single-label substitution, exact match priority) |
| RFC 5155 | DNSSEC hashed authenticated denial (NSEC3) | Validation only (closest encloser, opt-out, iteration ceiling per RFC 9276); never generated |
| RFC 5782 | DNSBL (RBL) | Full (reverse-IP query format, local + external providers, `127.0.0.1` never read as a listing) |
| RFC 6147 | DNS64 | Full (AAAA synthesis from A records, configurable prefix) |
| RFC 6605 / 8080 | ECDSA and Ed25519 for DNSSEC | Full (signing and verification; Ed448 unsupported by `ring`) |
| RFC 6672 | DNAME | Full (subtree rewriting, does not apply to owner name) |
| RFC 6698 | DANE TLSA | Full (TLSA record generation, storage, DNS resolution) |
| RFC 6840 | DNSSEC clarifications | Unsupported-algorithm answers treated as Insecure (§5.11); AD set only for a client that asked (§5.7) |
| RFC 6891 | EDNS(0) | Full (OPT record, payload negotiation, DO bit, BADVERS). Outbound iterative queries carry DO with a 1232-byte payload when validating |
| RFC 7553 | URI DNS record | Full (storage and lookup) |
| RFC 7766 | DNS transport over TCP | Connection reuse with an idle timeout measured from last activity, 2-byte length framing, per-listener connection cap |
| RFC 7858 | DNS-over-TLS | Full (TLS-wrapped TCP, port 853) — server listener and upstream client |
| RFC 8484 | DNS-over-HTTPS | Full (GET + POST, application/dns-message, Cache-Control) — server listener and upstream client |
| RFC 8555 | ACME | Server side (built-in certificate authority, dns-01 self-validation, EAB) |
| RFC 9250 | DNS-over-QUIC | Full (QUIC transport, bidirectional streams) |
| RFC 9276 | NSEC3 parameter guidance | Iteration counts above 100 treated as insecure rather than computed |

## Architecture

```
                                 ┌──────────────┐
                                 │  DNS Clients  │
                                 └──────┬───────┘
                                        │
            ┌───────────────────────────┼───────────────────────────┐
            │                           │                           │
     ┌──────▼───────┐           ┌──────▼───────┐           ┌──────▼───────┐
     │  DNS Server   │           │   DoT Server  │           │  DoH Server   │
     │  (UDP + TCP)  │           │  (TLS :853)   │           │ (HTTPS :443)  │
     └──────┬───────┘           └──────┬───────┘           └──────┬───────┘
            │                           │                           │
            │    ┌──────────────────────┘          ┌───────────────┘
            │    │    ┌────────────────────────────┘
            │    │    │    ┌──────────────┐
            │    │    │    │  DoQ Server   │
            │    │    │    │ (QUIC :8853)  │
            │    │    │    └──────┬───────┘
            ▼    ▼    ▼          ▼
     ┌────────────────────────────────┐
     │        Resolution Engine       │
     │  (EDNS, Cache, Wildcards,      │
     │   DNAME, ANAME, DNS64)         │
     └──────────────┬─────────────────┘
                    │
       ┌────────────┼────────────┬───────────────┐
       │            │            │               │
 ┌─────▼────┐ ┌────▼────┐ ┌────▼──────────┐ ┌──▼───────┐
 │ Local DB  │ │RBL/DNSBL│ │   Upstream     │ │  DNSSEC  │
 │ (SQLite)  │ │ Checker │ │   Resolution   │ │ Signing  │
 └──────────┘ └─────────┘ └────┬──────────┘ └──────────┘
       │                        │
       │        ┌───────────────┼───────────┬────────────┐
       │        │               │           │            │
       │  ┌────▼─────┐  ┌──────▼─────┐ ┌──▼──────┐ ┌───▼──────┐
       │  │ Iterative │  │ DoH / DoT  │ │Forwarder│ │  Public  │
       │  │ from roots│  │  upstream  │ │ (Do53)  │ │  (Do53)  │
       │  └────┬─────┘  └────────────┘ └─────────┘ └──────────┘
       │       │  (tier 0)     (tier 1)   (tier 2)    (tier 3)
       │  ┌────▼──────────────┐   ┌────────────────────┐
       │  │ Delegation cache   │   │ DNSSEC validation  │
       │  │ + record cache     │◄──┤ (chain from root)  │
       │  └───────────────────┘   │  + key cache       │
       │                           └────────────────────┘
       │
 ┌─────▼──────┐   ┌────────────┐   ┌─────────────┐   ┌────────────┐
 │ gRPC Mgmt   │   │ HTTP Proxy │   │ DHCPv4 + AF │   │ ACME + CA  │
 │ (TCP/Unix)  │   │ (optional) │   │    probe    │   │  (portal)  │
 └─────────────┘   └────────────┘   └─────────────┘   └────────────┘
```

Resolution order (when no network scopes are configured):
1. Parse EDNS OPT record (payload size, DO bit)
2. Check RBL (for reverse DNS queries, if enabled) -- includes local RBL entries
3. Check DNS response cache
4. Check local database (split-horizon, always preferred)
5. Check for CNAME records in local database
6. Check for DNAME records (subtree rewriting)
7. Check ANAME records (alias resolution at zone apex)
8. If name is under a managed zone but not found, return authoritative NXDOMAIN
9. Check wildcard records
10. Check the local blocklist and DNSBL providers (NXDOMAIN if listed, ahead of any external answer)
11. Enforce `security.recursion_cidrs` — a source outside it is REFUSED before anything reaches off-box
12. Resolve externally per `resolution.mode` (QNAME case randomized if enabled, via proxy if configured), validating DNSSEC on the iterative path
13. Apply DNS64 AAAA synthesis (if enabled and applicable)
14. Cache the response (bogus answers are never cached)
15. Apply TTL drift adjustment (if configured)
16. Drop A/AAAA answers of an address family the host cannot route (if `address_family.mode: auto`)

When network scopes are configured, see [Network Scoping](#network-scoping) for the extended resolution order.

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See the [LICENSE](LICENSE) file for the full license text.
