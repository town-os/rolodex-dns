# Rolodex DNS

A privacy-first, split-horizon DNS server and forwarding resolver with encrypted transports, DNSSEC, and gRPC management, written in Rust.

Rolodex DNS provides DNS over UDP, TCP, TLS (DoT), HTTPS (DoH), and QUIC (DoQ) with a local record database that takes priority over forwarded queries. Records are managed remotely via gRPC (shared secret authentication over TCP, or unauthenticated over Unix socket). It supports TLD-level resolution with domain overlay, so internal DNS representations are always preferred. A built-in DNS response cache prevents query leakage to upstream resolvers once a record has been seen.

Rolodex DNS also supports Realtime Blackhole Lists (RBLs) for DNS-based spam/malware filtering, DNSSEC zone signing, DANE TLSA certificate association, ACME DNS-01 challenge handling, and DNS64 AAAA synthesis.

## Features

- **Privacy-first DNS cache**: Local DNS response caching prevents query leakage to upstream. Once cached, queries are answered locally without contacting any forwarder. Set `forwarders: []` for a purely authoritative server.
- **Encrypted transports**: DNS-over-TLS (DoT, port 853), DNS-over-HTTPS (DoH, port 443 with GET/POST), DNS-over-QUIC (DoQ, port 8853)
- **Split-horizon DNS**: Local database records always take priority over forwarded upstream results
- **DNS over UDP and TCP**: Full protocol support for both transport layers
- **Forwarding resolver**: Configurable upstream DNS forwarders for non-local queries
- **TLD/domain overlay**: Add records at any level (including TLDs) to override public DNS
- **DNSSEC**: Ed25519 (preferred), ECDSA P-256/P-384, RSA/SHA-256 key generation, zone signing, and DS record computation
- **DANE TLSA + ACME issuer**: TLSA record generation from certificates, a built-in ACME certificate authority (per-zone intermediate CAs), self-signed root CA generation, ACME DNS-01 challenge handling (serves `_acme-challenge` TXT records natively)
- **CA distribution over DNS**: the root and per-zone intermediate CA chain is published as `CERT` records (RFC 4398) with a chunked `TXT` fallback, so any client that can resolve the zone can fetch and trust the CA — no portal access required (see [Distributing and Trusting the CA](#distributing-and-trusting-the-ca))
- **22 record types**: A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR, URI, SSHFP, DNAME, ANAME, ZONEMD, TLSA, CERT, DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM
- **DNS wildcards**: RFC 4592 compliant wildcard matching (`*.example.com.` matches single-label substitutions, exact match takes priority)
- **Authoritative DNS**: AA bit enforcement for local zones and explicitly declared authoritative zones
- **EDNS (RFC 6891)**: OPT record support, payload size negotiation, DO bit for DNSSEC, BADVERS for version > 0
- **DNS64 (RFC 6147)**: AAAA synthesis from A records with configurable prefix (default `64:ff9b::/96`)
- **TTL drift**: Fixed mode (add/subtract duration, supports compound formats like `"1h30m"`) and experimental logarithmic mode (latency-based)
- **QNAME case randomization**: 0x20 encoding randomizes QNAME case in forwarded queries for cache poisoning defense
- **gRPC management**: Remote record management via gRPC with shared secret or Unix socket auth
- **RBL support**: Realtime Blackhole List checking with in-memory caching, plus a local RBL database for custom blocklist entries
- **Network scoping**: Split-horizon DNS views with per-scope records and IP-based access control
- **Proxy support**: Forward DNS queries through HTTP CONNECT, SOCKS5, or DoH proxy
- **SQLite persistence**: DNS records persist across restarts
- **TLS hot-reload**: Certificates can be reloaded at runtime (e.g. after ACME renewal) without restarting the server
- **Performance**: Multi-threaded tokio runtime, lock-free RBL state (`AtomicBool` + `ArcSwap`), in-memory boot caches for scopes/zones/RBL entries, UDP socket pool for upstream forwarding, and DashMap/DashSet concurrent caching throughout

## Building

```
make build
```

## Testing

```
make test
```

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
   - Default upstream forwarders (`8.8.8.8:53`, `8.8.4.4:53`)

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

Rolodex DNS builds with Podman using two Containerfiles: `Containerfile.build` compiles the Rust binaries in a full toolchain image, and `Containerfile` provisions a lean runtime image (`debian:bookworm-slim`) containing only the stripped binaries and CA certificates.

Images are published to `quay.io/town/rolodex` as multi-arch manifest lists covering `linux/amd64` and `linux/arm64`.

### Multi-Architecture Builds

Builds are **native-only**: each architecture is compiled on a host of that architecture (no cross-compilation or QEMU emulation). The build tooling detects the host architecture via `uname -m` and tags every image with an arch suffix (`-amd64` or `-arm64`). A separate manifest step then assembles the per-arch images into a single multi-arch tag.

The end-to-end flow for publishing a multi-arch image is:

1. On an amd64 host: `make push-release` → pushes `…:latest-amd64` (and the date tag).
2. On an arm64 host: `make push-release` → pushes `…:latest-arm64` (and the date tag).
3. On either host (once both are pushed): `make manifest-release` → creates and pushes the multi-arch `…:latest` manifest list.

A consumer that pulls `quay.io/town/rolodex:latest` then transparently receives the image matching their architecture.

### Building

Build the release image for the **host** architecture (tagged as `quay.io/town/rolodex:latest-<arch>`):

```
make image
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

Build and push the host-arch release candidate image (auto-tags `rc.YYYYMMDD-<arch>` and `rc.latest-<arch>`):

```
make push-rc
```

Build and push the host-arch release image (auto-tags `release.YYYYMMDD-<arch>` and `latest-<arch>`):

```
make push-release
```

#### Assembling the Multi-Arch Manifest

After the per-arch images for **all** architectures have been pushed (run `push-rc`/`push-release` on each native host), assemble and push the multi-arch manifest list from any host:

```
make manifest-rc       # combines rc.latest-amd64 + rc.latest-arm64 → rc.latest (and the rc.YYYYMMDD date tag)
make manifest-release  # combines latest-amd64 + latest-arm64 → latest (and the release.YYYYMMDD date tag)
```

The manifest is assembled from the images already in the registry (`podman manifest add docker://…`), so it does not require the per-arch images to be present locally.

#### Pushing a Specific Tag

Use `IMAGE_TAG` to build and push an exact tag instead of the auto-generated date-based tags. The arch suffix is still applied to the per-arch images:

```
make IMAGE_TAG=v1.2.3 push-release    # pushes quay.io/town/rolodex:v1.2.3-<arch>
make IMAGE_TAG=v1.2.3 manifest-release # combines v1.2.3-amd64 + v1.2.3-arm64 → v1.2.3
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

Rolodex DNS reads configuration from a YAML file (default: `rolodex-dns.yml`).

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

# Upstream DNS forwarders (address:port format)
# Set to empty list for a purely authoritative server (no upstream forwarding)
forwarders:
  - "8.8.8.8:53"
  - "8.8.4.4:53"

# Each entry pairs a protocol (udp/tcp) with a bind address.
# Bind addresses accept ip:port, [ipv6]:port, primary:port, or interface:port.
dns:
  bind:
    - udp: "0.0.0.0:53"     # or "eth0:53" to bind to a specific interface
    - tcp: "0.0.0.0:53"

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
  # RBL providers
  providers:
    - zone: zen.spamhaus.org
      enabled: true
    - zone: bl.spamcop.net
      enabled: true
    - zone: b.barracudacentral.org
      enabled: true
    - zone: dnsbl.sorbs.net
      enabled: true
    - zone: dbl.spamhaus.org
      enabled: true

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

# Security settings
security:
  qname_case_randomization: true  # 0x20 encoding for forwarded queries
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `database_path` | `"rolodex-dns.db"` | Path to the SQLite database file |
| `forwarders` | `["8.8.8.8:53", "8.8.4.4:53"]` | Upstream DNS resolver addresses. Empty list = purely authoritative |
| `dns.bind` | `[{udp: "0.0.0.0:53"}, {tcp: "0.0.0.0:53"}]` | DNS listeners; list of `{udp: addr}` / `{tcp: addr}` entries |
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
| `rbl.enabled` | `false` | Enable RBL checking globally |
| `rbl.providers[].zone` | -- | DNSBL zone to query |
| `rbl.providers[].enabled` | `true` | Enable/disable individual provider |
| `proxy.url` | `""` (disabled) | HTTP proxy URL for forwarded DNS queries |
| `proxy.auth` | `""` | Proxy authentication (`"user:pass"`) |
| `proxy.mode` | `"connect"` | Proxy mode: `"connect"` (HTTP CONNECT), `"socks5"` (SOCKS5), or `"doh"` |
| `ttl_drift.mode` | `"disabled"` | TTL drift mode: `"disabled"`, `"fixed"`, or `"logarithmic"` |
| `ttl_drift.fixed_adjustment` | `""` | Fixed TTL adjustment. Supports simple (`"5m"`, `"-30s"`, `"1h"`, `"2d"`) and compound durations (`"1h30m"`, `"2d12h"`) |
| `ttl_drift.log_multiplier` | `0.1` | Logarithmic mode multiplier (adjusts TTL based on upstream latency) |
| `dns64.enabled` | `false` | Enable DNS64 AAAA synthesis |
| `dns64.prefix` | `"64:ff9b::"` | IPv6 prefix for DNS64 synthesis |
| `security.qname_case_randomization` | `true` | Enable 0x20 QNAME case randomization |

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
| **RBL** | |
| `set-rbl-config` | Configure RBL settings at runtime |
| `get-rbl-config` | Retrieve the current RBL configuration |
| `flush-cache` | Flush the RBL result cache |
| `add-local-rbl-entry` | Add a local RBL blocklist entry |
| `remove-local-rbl-entry` | Remove a local RBL blocklist entry |
| `list-local-rbl-entries` | List all local RBL blocklist entries |
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
| **Authoritative Zones** | |
| `add-authoritative-zone` | Declare a zone as authoritative |
| `remove-authoritative-zone` | Remove a zone from the authoritative list |
| `list-authoritative-zones` | List all authoritative zones |
| **Cache** | |
| `get-cache-stats` | Show DNS cache hit/miss statistics |
| `flush-dns-cache` | Flush the DNS response cache |
| **Encrypted Transports** | |
| `set-dot-config` / `get-dot-config` | Configure/retrieve DNS-over-TLS settings |
| `set-doh-config` / `get-doh-config` | Configure/retrieve DNS-over-HTTPS settings |
| `set-doq-config` / `get-doq-config` | Configure/retrieve DNS-over-QUIC settings |
| **Proxy** | |
| `set-proxy-config` / `get-proxy-config` | Configure/retrieve HTTP proxy settings |
| **DNSSEC** | |
| `generate-dnssec-key` | Generate a DNSSEC key pair (KSK or ZSK) |
| `list-dnssec-keys` | List DNSSEC keys for a zone |
| `delete-dnssec-key` | Delete a DNSSEC key |
| `get-ds-records` | Get DS records for parent-zone delegation |
| `sign-zone` | Sign a zone with its DNSSEC keys |
| **DANE / ACME** | |
| `generate-tlsa-record` | Generate a TLSA record from a certificate |
| `list-tlsa-records` | List TLSA records for a domain |
| `generate-dane-root-ca` | Generate a self-signed DANE root CA |
| `request-acme-cert` | Request a certificate via ACME DNS-01 |
| `get-acme-status` | Check ACME certificate status |
| `ensure-zone-ca` | Ensure the per-zone intermediate CA exists; prints root + intermediate PEM and publishes the CA chain into DNS |
| `create-eab` | Mint an EAB credential scoped to a zone |
| `list-acme-accounts` | List registered ACME accounts |
| `list-acme-certs` | List issued certificates |
| **TTL Drift** | |
| `set-ttl-drift-config` / `get-ttl-drift-config` | Configure/retrieve TTL drift settings |
| **DNS64** | |
| `set-dns64-config` / `get-dns64-config` | Configure/retrieve DNS64 settings |
| **Observability** | |
| `get-query-latency-stats` | Show per-server upstream query latency |

See the original command sections below for detailed usage on core record management commands. For the full set of command flags, run `rolodex-dns-cli <COMMAND> --help`.

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

Examples:
```bash
# Enable RBL with Spamhaus
rolodex-dns-cli set-rbl-config -e -p "zen.spamhaus.org:true"

# Enable RBL with multiple providers (some disabled)
rolodex-dns-cli set-rbl-config -e \
  -p "zen.spamhaus.org:true" \
  -p "bl.spamcop.net:false" \
  -p "dnsbl.sorbs.net:true"

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

Providers:
ZONE                                     ENABLED
--------------------------------------------------
zen.spamhaus.org                         true
bl.spamcop.net                           false
```

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

Cache statistics are available via `GetCacheStats` and the cache can be flushed via `FlushDnsCache`.

For maximum privacy, set `forwarders: []` to run Rolodex DNS as a purely authoritative server with no upstream forwarding at all. All answers will come from the local database.

## Encrypted Transports

Rolodex DNS supports three encrypted DNS transport protocols to prevent eavesdropping on DNS queries:

**DNS-over-TLS (DoT)** -- RFC 7858, default port 853. Standard TLS-wrapped DNS over TCP. Configure with `dot` section in YAML or `SetDotConfig` via gRPC.

**DNS-over-HTTPS (DoH)** -- RFC 8484, default port 443. DNS queries over HTTPS with support for both GET (`/dns-query?dns=<base64>`) and POST (`application/dns-message`) methods. Optionally supports HTTP/3 via QUIC (`enable_h3: true`). Configure with `doh` section in YAML or `SetDohConfig` via gRPC.

**DNS-over-QUIC (DoQ)** -- RFC 9250, default port 8853. DNS queries over QUIC transport for low-latency encrypted resolution. Configure with `doq` section in YAML or `SetDoqConfig` via gRPC.

All three protocols require TLS certificates. You can provide your own certificate and key, or set `auto_self_signed: true` to have Rolodex DNS generate a self-signed certificate automatically.

## DNSSEC

Rolodex DNS supports DNSSEC zone signing with the following algorithms:

- **Ed25519** (preferred) -- compact keys and signatures, fast signing
- **ECDSA P-256/SHA-256** and **ECDSA P-384/SHA-384**
- **RSA/SHA-256** (2048-bit)

Ed448 is not supported due to a limitation in the ring cryptography crate.

### DNSSEC Workflow

1. Generate a Key Signing Key (KSK) and Zone Signing Key (ZSK) for your zone:
   ```bash
   rolodex-dns-cli generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type KSK
   rolodex-dns-cli generate-dnssec-key --zone example.com. --algorithm ED25519 --key-type ZSK
   ```

2. Sign the zone:
   ```bash
   rolodex-dns-cli sign-zone --zone example.com.
   ```

3. Retrieve DS records for your registrar:
   ```bash
   rolodex-dns-cli get-ds-records --zone example.com.
   ```

Signing produces DNSKEY, RRSIG, NSEC/NSEC3, and NSEC3PARAM records automatically. Re-run `sign-zone` after adding or modifying records.

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

## RBL (Realtime Blackhole List)

When RBL is enabled, Rolodex DNS checks IP addresses found in reverse DNS queries against configured DNSBL providers. If an IP is listed in any enabled provider, the query receives an `NXDOMAIN` response.

### Local RBL Database

In addition to external RBL providers, Rolodex DNS supports locally-managed blocklist entries. Local entries are checked before external providers and are managed via `AddLocalRblEntry`, `RemoveLocalRblEntry`, and `ListLocalRblEntries`.

```bash
# Block a specific IP with a reason
rolodex-dns-cli add-local-rbl-entry --name 10.0.0.5 --reason "known spam source"

# List local entries
rolodex-dns-cli list-local-rbl-entries

# Remove an entry
rolodex-dns-cli remove-local-rbl-entry --name 10.0.0.5
```

### Default Providers

These match the common providers used by unbound and other DNS resolvers:

| Zone | Description |
|------|-------------|
| `zen.spamhaus.org` | Combined Spamhaus blocklist (SBL + XBL + PBL + CSS) |
| `bl.spamcop.net` | SpamCop blocklist |
| `b.barracudacentral.org` | Barracuda Reputation Block List |
| `dnsbl.sorbs.net` | SORBS aggregate zone |
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
- The cache can be flushed via the `FlushCache` gRPC method

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
   - If scopes exist and the source IP is not associated with any scope: **REFUSED**
   - If the IP is associated with a scope: check scoped records first, then fall through to global records, then forward upstream
   - If no scopes exist at all: legacy behavior (all queries served from global records)
5. Search domains (via `GetSearchDomains`) return the `.home` domain for DHCP integration

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
14. Forward to upstream resolvers (with QNAME case randomization if enabled, via proxy if configured)
15. Apply DNS64 synthesis (if enabled and AAAA query returned empty but A record exists)
16. Cache the response
17. Apply TTL drift adjustment (if configured)

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
| `GetRblConfig(ctx) (*RblStatus, error)` | Get current RBL config |
| `FlushCache(ctx) error` | Flush RBL cache |
| `AddLocalRblEntry(ctx, entry) error` | Add a local RBL blocklist entry |
| `RemoveLocalRblEntry(ctx, name) error` | Remove a local RBL blocklist entry |
| `ListLocalRblEntries(ctx) ([]*LocalRblEntry, error)` | List local RBL entries |

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
| RFC 4255 | SSHFP DNS record | Full (storage, lookup, algorithm/fingerprint type) |
| RFC 4398 | CERT DNS record | Full (storage, lookup, PKIX CA-chain distribution) |
| RFC 4592 | Wildcards in DNS | Full (single-label substitution, exact match priority) |
| RFC 5782 | DNSBL (RBL) | Full (reverse-IP query format, local + external providers) |
| RFC 6147 | DNS64 | Full (AAAA synthesis from A records, configurable prefix) |
| RFC 6672 | DNAME | Full (subtree rewriting, does not apply to owner name) |
| RFC 6698 | DANE TLSA | Full (TLSA record generation, storage, DNS resolution) |
| RFC 6891 | EDNS(0) | Full (OPT record, payload negotiation, DO bit, BADVERS) |
| RFC 7553 | URI DNS record | Full (storage and lookup) |
| RFC 7858 | DNS-over-TLS | Full (TLS-wrapped TCP, port 853) |
| RFC 8484 | DNS-over-HTTPS | Full (GET + POST, application/dns-message, Cache-Control) |
| RFC 9250 | DNS-over-QUIC | Full (QUIC transport, bidirectional streams) |

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
       ┌────────────┼────────────┬────────────┐
       │            │            │            │
 ┌─────▼────┐ ┌────▼────┐ ┌────▼─────┐ ┌───▼──────┐
 │ Local DB  │ │  RBL    │ │ Forwarder │ │  DNSSEC  │
 │ (SQLite)  │ │ Checker │ │ (Upstream)│ │ Signing  │
 └──────────┘ └─────────┘ └──────────┘ └──────────┘
       │                        │
 ┌─────▼──────┐          ┌─────▼──────┐
 │ gRPC Mgmt   │          │ HTTP Proxy │
 │ (TCP/Unix)  │          │ (optional) │
 └─────────────┘          └────────────┘
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
10. Forward to upstream resolvers (QNAME case randomized if enabled, via proxy if configured)
11. Apply DNS64 AAAA synthesis (if enabled and applicable)
12. Cache the response
13. Apply TTL drift adjustment (if configured)

When network scopes are configured, see [Network Scoping](#network-scoping) for the extended resolution order.

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See the [LICENSE](LICENSE) file for the full license text.
