# Rolodex DNS Functional Specification

Rolodex DNS is a split-horizon DNS server and forwarding resolver with remote management via gRPC. It is written in Rust and licensed under AGPL-3.0-only.

## Rules

- ensure deny(dead_code) and deny(unsafe) are at the top and honored
- handle all std::result::Result in an appropriate way
- do not use unwrap
- do not use unsafe code
- write tests for everything, including integration and real tests
- use make test to validate any changes
- integration tests should not alter the host, ever
- tests: unless said otherwise, they perform with simulated input and produce output on the operations that would be performed. They never affect the running system.
- running tests: use the make tasks every time.
- tests should always include the linting checks
- lint checks should be a rust community standard of linters, run as the `lint` make tasks
- never use `let _ = expr;` to suppress unused variable warnings or work around the borrow checker. Fix the actual problem: use the variable, remove the parameter, or restructure the code.
- `#![deny(dead_code)]` and `#![deny(unsafe_code)]` are set at the crate level in both lib.rs and main.rs. Never add `#[allow(dead_code)]` or `#[allow(unsafe_code)]` to bypass them — remove dead code, and use safe abstractions (e.g., nix crate) instead of unsafe.
- do not modify the system beyond configuring hardware

## DNS Resolution

Rolodex DNS serves DNS queries over UDP, TCP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), and DNS-over-QUIC (DoQ) on configurable bind addresses (default `0.0.0.0:53` for UDP/TCP). TCP and DoT use the standard 2-byte length prefix framing. Maximum UDP message size is 4096 bytes; maximum TCP message size is 65535 bytes.

### Supported Record Types

**Basic**: A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR.

**Extended**: URI (RFC 7553), SSHFP (RFC 4255), DNAME (RFC 6672), ANAME (alias resolved at query time), ZONEMD (RFC 9156), TLSA (RFC 6698).

**DNSSEC**: DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM.

### Split-Horizon Behavior

DNS queries are resolved in the following order:

1. **Network scope check** — If network scoping is active, the source IP must be associated with a scope. Scoped records for the matched scope are checked first.
2. **RBL check** — If the query is a reverse DNS lookup (`in-addr.arpa` or `ip6.arpa`), the extracted IP is checked against enabled RBL providers and local RBL entries. If listed, NXDOMAIN is returned.
3. **Local database lookup** — The local database is queried for the requested name and type. If records exist, they are returned immediately.
4. **CNAME chain** — If no exact type match is found locally, a CNAME lookup is attempted for the queried name. If a CNAME exists, it is returned.
5. **Managed zone authority** — If the queried name falls under a zone that has records in the local database (determined by the last two labels of any stored FQDN), but the specific name was not found, an authoritative NXDOMAIN is returned. This prevents forwarding queries for names that should be resolved internally. Zones can also be explicitly declared authoritative via `AddAuthoritativeZone`.
6. **DNS64 synthesis** — If DNS64 is enabled and the query is for AAAA but only A records exist upstream, AAAA records are synthesized using the configured NAT64 prefix.
7. **Upstream forwarding** — Unmatched queries are forwarded via UDP to the configured upstream resolvers, tried in order with a 5-second timeout per attempt. If all forwarders fail or none are configured, SERVFAIL is returned.

This ordering ensures the inside representation always takes priority over external DNS, allowing TLD-level and domain-level overlays that update in real time as the gRPC control plane modifies records.

### EDNS Support

EDNS (RFC 6891) context is extracted from incoming queries. The server respects client maximum payload size, supports the DNSSEC-OK (DO) bit, and includes OPT records in responses. Only EDNS version 0 is supported.

### QNAME Case Randomization

0x20 encoding is used on forwarded queries for DNS cache poisoning resistance. This is enabled by default and configurable via `security.qname_case_randomization`.

## Local Record Database

Records are stored in SQLite with WAL mode enabled for concurrent read performance. The database path is configurable (default `rolodex-dns.db`). An in-memory mode is available for testing.

Domain names are normalized to lowercase with a trailing dot on storage and lookup, providing case-insensitive matching. The database has indices on `name` and `(name, record_type)`.

Records consist of: name, record type, value, TTL (default 300 seconds), and priority (used by MX and SRV).

SOA values are stored as `"mname rname serial refresh retry expire minimum"`. SRV values are stored as `"weight port target"`. TLSA values are stored as `"usage selector matching_type hex_data"`. URI values are stored as `"priority weight target_uri"`. SSHFP values are stored as `"algorithm fp_type hex_fingerprint"`. ZONEMD values are stored as `"serial scheme hash_algorithm hex_digest"`.

## DNS Response Cache

Rolodex DNS caches DNS responses in memory backed by SQLite for persistence across restarts. Once cached, queries are answered without contacting upstream resolvers. This is a deliberate privacy-first design to prevent DNS query leakage to upstream providers.

- **Local records** are cached with a `local` flag — TTL is returned as-is (no decay) and entries are not persisted to the SQLite cache table.
- **Upstream records** have TTL adjusted based on remaining cache time (TTL decay).
- Expired entries are evicted on access.
- The cache tracks hit and miss counters, retrievable via `GetCacheStats`.
- Cache keys use `"name:type"` or `"name:*"` format.
- The cache is automatically flushed when records are mutated via gRPC (add, remove, or scoped variants) to ensure consistency.
- The cache can be explicitly flushed via `FlushDnsCache`.
- Set `forwarders: []` to operate as a purely authoritative server with no upstream resolution.

## Realtime Blackhole Lists (RBL)

Rolodex DNS checks IPs against DNS-based blackhole lists using the standard reversed-IP lookup format:

- **IPv4**: Octets are reversed and appended to the RBL zone (e.g., `192.168.1.100` becomes `100.1.168.192.zen.spamhaus.org`).
- **IPv6**: Nibbles are expanded, reversed, and appended to the RBL zone.

RBL checking is globally togglable and disabled by default. Individual providers can also be enabled or disabled independently.

### Default Providers

These match the standard DNSBL zones used by unbound:

- `zen.spamhaus.org` — Combined Spamhaus blocklist (SBL + XBL + PBL + CSS)
- `bl.spamcop.net` — SpamCop blocklist
- `b.barracudacentral.org` — Barracuda Reputation Block List
- `dnsbl.sorbs.net` — SORBS aggregate zone
- `dbl.spamhaus.org` — Spamhaus Domain Block List

### Caching

RBL results are cached in memory using a concurrent hash map (keyed by `<ip>/<zone>`):

- **Positive results** (listed): Cached for the TTL returned by the RBL provider (default 300 seconds if no TTL provided).
- **Negative results** (not listed): Cached for 5 minutes.
- **Lookup errors**: Not cached; treated as not-listed to avoid false positives.

The cache can be flushed via gRPC.

### Local RBL Entries

In addition to DNS-based providers, Rolodex DNS supports a local RBL blocklist stored in the database. Local entries are checked alongside external providers and can block specific names or IPs with a human-readable reason. Entries are managed via `AddLocalRblEntry`, `RemoveLocalRblEntry`, and `ListLocalRblEntries`.

## Encrypted DNS Transports

All encrypted transports are optional and require TLS configuration. If no certificate is provided, a self-signed certificate is automatically generated when `auto_self_signed` is `true` (default).

### DNS-over-TLS (DoT)

RFC 7858. Listens on a configurable port (default `0.0.0.0:853`). Uses the same 2-byte length prefix framing as plain DNS TCP. Each connection spawns a new task. Configured in the `dot` section.

### DNS-over-HTTPS (DoH)

RFC 8484. Listens on a configurable port (default `0.0.0.0:443`) with TLS. Serves at the `/dns-query` endpoint. Supports both:

- **POST**: `Content-Type: application/dns-message` with binary DNS query body.
- **GET**: `?dns=<base64url-encoded query>` parameter.

Built with Axum and axum-server for TLS support. HTTP/3 (QUIC) transport can be enabled via `enable_h3` configuration flag.

### DNS-over-QUIC (DoQ)

RFC 9250. Listens on a configurable UDP port (default `0.0.0.0:8853`). ALPN protocol: `"doq"`. Each query uses a new bidirectional stream with 2-byte length prefix framing. Uses the Quinn QUIC library. Idle timeout is 30 seconds.

## DNSSEC

Rolodex DNS supports DNSSEC zone signing with the following algorithms (strongest first):

1. **Ed25519** (RFC 8080, algorithm 15) — preferred
2. **ECDSA P-384/SHA-384** (RFC 6605, algorithm 14)
3. **ECDSA P-256/SHA-256** (RFC 6605, algorithm 13)
4. **RSA/SHA-256** (RFC 5702, algorithm 8)

### Key Management

Two key types are supported:

- **ZSK** (Zone Signing Key, flag 256) — signs zone data records.
- **KSK** (Key Signing Key, flag 257) — signs the DNSKEY RRset.

Keys are generated, stored in the database, and managed via gRPC: `GenerateDnssecKey`, `ListDnssecKeys`, `DeleteDnssecKey`.

### Zone Signing

`SignZone` signs all records in a zone with its DNSSEC keys, producing RRSIG records. DS records for parent-zone delegation are computed using SHA-256 and retrievable via `GetDsRecords`. Key tags are calculated per RFC 4034.

Cryptographic operations use the `ring` crate.

## DANE and TLSA

Rolodex DNS generates DANE/TLSA records (RFC 6698) from certificates:

- **Usage**: 2 (Trust Anchor) and 3 (Domain-Issued)
- **Selector**: 0 (full certificate) and 1 (Subject Public Key Info)
- **Matching type**: 0 (exact), 1 (SHA-256), 2 (SHA-512)

TLSA DNS names follow the `_port._protocol.domain.` convention.

A self-signed DANE root CA can be generated via `GenerateDaneRootCa` for trust-anchor-based DANE deployments.

## ACME Certificate Management

Since Rolodex is the DNS server, it can serve `_acme-challenge` TXT records natively for DNS-01 challenge validation (RFC 8555). This enables automated certificate issuance without external DNS providers.

- `RequestAcmeCert` initiates a certificate request for a domain using a configurable ACME provider URL (default: Let's Encrypt).
- `GetAcmeStatus` retrieves the current certificate status: `not_configured`, `pending`, `valid`, `expired`, or `failed`.
- Challenge records use a TTL of 60 seconds.

## DNS64

DNS64 synthesizes AAAA records from A records for IPv6-only clients. When enabled and a query for AAAA yields no results but A records exist, the server synthesizes AAAA records by embedding the IPv4 address in the configured NAT64 prefix.

- Default prefix: `64:ff9b::`
- Disabled by default.
- Configurable at runtime via `SetDns64Config`/`GetDns64Config`.

## TTL Drift Adjustment

TTL drift modifies cached record TTLs to reduce thundering-herd cache expiration storms. Two modes:

- **Fixed**: Add or subtract a fixed duration from TTLs (e.g., `"30s"`, `"-10s"`, `"5m"`, `"1h30m"`). Clamped to minimum 1 second.
- **Logarithmic**: Adjust TTLs based on upstream server latency using the formula: `adjusted_ttl = original_ttl * (1 + multiplier * ln(avg_latency_ms / 50.0))`. Baseline: 50ms. Higher latency increases TTLs (fewer upstream queries); lower latency decreases TTLs (fresher data).

Disabled by default. Configurable at runtime via `SetTtlDriftConfig`/`GetTtlDriftConfig`.

### Latency Tracking

Upstream server latency is tracked using exponential moving average (EMA) with a configurable smoothing factor. Per-server latency and query count statistics are available via `GetQueryLatencyStats`.

## Network Scoping

Network scopes provide per-network DNS views, isolating DNS records by network membership.

### Scope Management

- Each scope has a unique name (e.g., `"office"`, `"lab"`) and a reserved `.home` domain (defaults to `"<name>.home."`) used as the default search domain for DHCP clients.
- Scopes are created, deleted, and listed via `CreateNetworkScope`, `DeleteNetworkScope`, and `ListNetworkScopes`. Deleting a scope removes all its records and associations.

### IP Association

- Client IPs join a scope via `JoinNetwork` with a TTL (default 300 seconds). The association must be refreshed before expiry to maintain DNS resolution.
- IPs leave a scope via `LeaveNetwork`.
- Current associations are retrievable via `GetNetworkAssociations` with optional scope filter.
- `GetSearchDomains` returns the `.home` domain for an IP's associated scope.

### Scoped Records

- Records added via `AddScopedRecord` are only visible to IPs associated with that scope.
- Records are managed via `RemoveScopedRecord` and `ListScopedRecords`, which support the same name/type filtering as global records.

## Authoritative Zone Declarations

Zones can be explicitly declared authoritative via `AddAuthoritativeZone`. Queries for names within authoritative zones are never forwarded upstream — if the specific name is not found locally, an authoritative NXDOMAIN is returned. Zones are managed via `AddAuthoritativeZone`, `RemoveAuthoritativeZone`, and `ListAuthoritativeZones`.

## DHCP Server

Rolodex DNS includes an integrated DHCPv4 server that provides IP address allocation (IPAM) with automatic DNS hostname registration. The DHCP service is disabled by default and enabled via the `dhcp` configuration section.

### IPAM (IP Address Management)

DHCP address pools are configured per network scope. Each pool defines an IP range, gateway, subnet mask, and DNS servers. There is no cross-pool aggregation: each pool is a single contiguous range, and when the pool is exhausted, allocation fails (returns `None`). MAC-to-IP bindings are persistent (sticky): once a MAC address is assigned an IP, subsequent requests from the same MAC receive the same IP.

Lease states: `active` (in use), `expired` (past duration), `released` (client released), `reclaimable` (past reclaim timeout, IP available for reuse).

### DNS Integration

When a DHCP client provides a hostname (option 12), the server automatically registers:

- An A record: `<hostname>.lan.<tld>.` → assigned IP (as a scoped record)
- A PTR record: `<reversed-ip>.in-addr.arpa.` → `<hostname>.lan.<tld>.` (as a scoped record)

Both records are scoped to the network scope associated with the DHCP pool. On lease release or expiry, both records are removed.

The DHCP assignment is linked to the network scoping system via `JoinNetwork`, creating a split-horizon DNS overlay unique to the DHCP address. The DNS overlay passes through any records that have changed.

### Per-Scope RBL

Each network scope can opt into additional RBL providers not present in the global configuration. Per-scope providers are checked alongside global providers during DNS resolution for IPs associated with that scope. Managed via `AddScopeRblProvider`, `RemoveScopeRblProvider`, and `ListScopeRblProviders`.

### Certificate Delivery

Certificates can be delivered to DHCP clients via site-specific DHCP options (codes 224-254). Certificate data is stored per scope and included in DHCP OFFER and ACK responses. Managed via `SetDhcpCertOption`, `RemoveDhcpCertOption`, and `ListDhcpCertOptions`.

### Background Lease Sweep

A background task runs at a configurable interval (`sweep_interval`, default 60 seconds) to:

- Expire active leases past their duration
- Remove DNS records and network associations for expired leases
- Reclaim IPs from leases past the `reclaim_timeout` (default 24 hours)

## Proxy Configuration

Upstream DNS forwarding can be routed through a proxy. Supported modes:

- `connect` — HTTP CONNECT proxy (default)
- `socks5` — SOCKS5 proxy
- `doh` — Forward DNS queries as DoH requests through an HTTP proxy

Configuration includes URL (e.g., `"socks5://127.0.0.1:1080"`), optional authentication (`"user:pass"`), and mode. Configurable at runtime via `SetProxyConfig`/`GetProxyConfig`.

## gRPC Management Interface

The management API is defined in `proto/rolodex_dns.proto` under the `RolodexDnsService` service. It can listen on TCP (default `127.0.0.1:50051`) and/or a Unix socket (default `/var/run/rolodex-dns.sock`). Either transport can be disabled by setting its bind address to an empty string.

### Authentication

- **TCP connections** require a shared secret passed as `auth_token` in each request. If the server's shared secret is empty, all connections are allowed without authentication.
- **Unix socket connections** bypass authentication entirely.

### Operations

#### Record Management

| RPC            | Description                                                                                                                                  |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `AddRecord`    | Adds a DNS record to the local database. TTL defaults to 300 if set to 0.                                                                    |
| `RemoveRecord` | Removes records by name, with optional type and value filters. Returns the count of records removed.                                         |
| `ListRecords`  | Queries the local database with optional name filter (supports `*.` wildcard prefix for subdomain matching) and optional record type filter. |

#### Network Scoping

| RPC                      | Description                                                       |
| ------------------------ | ----------------------------------------------------------------- |
| `CreateNetworkScope`     | Creates a new network scope with a reserved `.home` domain.       |
| `DeleteNetworkScope`     | Deletes a scope and all its records and associations.             |
| `ListNetworkScopes`      | Retrieves all configured network scopes.                          |
| `JoinNetwork`            | Associates a client IP with a scope (TTL-based, default 300s).    |
| `LeaveNetwork`           | Removes an IP's association with its scope.                       |
| `GetNetworkAssociations` | Retrieves IP-to-scope associations, optionally filtered by scope. |
| `AddScopedRecord`        | Adds a DNS record within a specific network scope.                |
| `RemoveScopedRecord`     | Removes DNS records from a specific scope.                        |
| `ListScopedRecords`      | Queries DNS records within a scope with optional filters.         |
| `GetSearchDomains`       | Retrieves the search domains for a client IP address.             |

#### Authoritative Zones

| RPC                       | Description                                                      |
| ------------------------- | ---------------------------------------------------------------- |
| `AddAuthoritativeZone`    | Declares a zone as authoritative (prevents upstream forwarding). |
| `RemoveAuthoritativeZone` | Removes a zone from the authoritative list.                      |
| `ListAuthoritativeZones`  | Retrieves all authoritative zone names.                          |

#### Forwarding & RBL

| RPC                   | Description                                                                       |
| --------------------- | --------------------------------------------------------------------------------- |
| `SetForwarders`       | Replaces the upstream DNS forwarder list at runtime without restart.              |
| `SetRblConfig`        | Replaces the RBL configuration (global enable flag and provider list) at runtime. |
| `GetRblConfig`        | Returns the current RBL configuration.                                            |
| `FlushCache`          | Clears the RBL result cache.                                                      |
| `AddLocalRblEntry`    | Adds a local RBL blocklist entry (name/IP and reason).                            |
| `RemoveLocalRblEntry` | Removes a local RBL entry by name.                                                |
| `ListLocalRblEntries` | Retrieves all local RBL entries.                                                  |

#### DNS Cache

| RPC             | Description                                                     |
| --------------- | --------------------------------------------------------------- |
| `GetCacheStats` | Returns cache statistics: total entries, hit count, miss count. |
| `FlushDnsCache` | Clears the DNS response cache.                                  |

#### TTL Drift & Latency

| RPC                    | Description                                                                                  |
| ---------------------- | -------------------------------------------------------------------------------------------- |
| `SetTtlDriftConfig`    | Sets the TTL drift mode, fixed adjustment, and log multiplier.                               |
| `GetTtlDriftConfig`    | Returns the current TTL drift configuration.                                                 |
| `GetQueryLatencyStats` | Returns per-server upstream query latency statistics (server, average latency, query count). |

#### Encrypted Transport Configuration

| RPC                                 | Description                                             |
| ----------------------------------- | ------------------------------------------------------- |
| `SetDotConfig` / `GetDotConfig`     | Configures DNS-over-TLS (bind address, TLS settings).   |
| `SetDohConfig` / `GetDohConfig`     | Configures DNS-over-HTTPS (bind address, TLS settings). |
| `SetDoqConfig` / `GetDoqConfig`     | Configures DNS-over-QUIC (bind address, TLS settings).  |
| `SetProxyConfig` / `GetProxyConfig` | Configures upstream proxy transport (URL, auth, mode).  |

#### DNSSEC

| RPC                 | Description                                                    |
| ------------------- | -------------------------------------------------------------- |
| `GenerateDnssecKey` | Generates a DNSSEC key pair for a zone (algorithm + key type). |
| `ListDnssecKeys`    | Retrieves DNSSEC keys for a zone.                              |
| `DeleteDnssecKey`   | Deletes a DNSSEC key by ID.                                    |
| `GetDsRecords`      | Retrieves DS records for parent-zone delegation.               |
| `SignZone`          | Signs a zone with its DNSSEC keys.                             |

#### DANE & TLSA

| RPC                  | Description                                                                                              |
| -------------------- | -------------------------------------------------------------------------------------------------------- |
| `GenerateTlsaRecord` | Generates a TLSA record from a PEM certificate (domain, port, protocol, usage, selector, matching type). |
| `ListTlsaRecords`    | Retrieves TLSA records for a domain.                                                                     |
| `GenerateDaneRootCa` | Generates a self-signed root CA certificate for DANE.                                                    |

#### ACME

| RPC               | Description                                                              |
| ----------------- | ------------------------------------------------------------------------ |
| `RequestAcmeCert` | Requests a certificate via ACME DNS-01 challenge (domain, provider URL). |
| `GetAcmeStatus`   | Retrieves ACME certificate status (status, expiry, domain).              |

#### DNS64

| RPC              | Description                                           |
| ---------------- | ----------------------------------------------------- |
| `SetDns64Config` | Sets DNS64 synthesis configuration (enabled, prefix). |
| `GetDns64Config` | Returns the current DNS64 configuration.              |

#### DHCP Pool Management

| RPC              | Description                                                                      |
| ---------------- | -------------------------------------------------------------------------------- |
| `AddDhcpPool`    | Adds a DHCP address pool for a scope (range, gateway, subnet mask, DNS servers). |
| `RemoveDhcpPool` | Removes a DHCP pool by ID.                                                       |
| `ListDhcpPools`  | Lists DHCP pools, optionally filtered by scope.                                  |

#### DHCP Lease Management

| RPC               | Description                                      |
| ----------------- | ------------------------------------------------ |
| `ListDhcpLeases`  | Lists DHCP leases, optionally filtered by scope. |
| `DeleteDhcpLease` | Deletes a DHCP lease by MAC address.             |

#### Per-Scope RBL Providers

| RPC                      | Description                                           |
| ------------------------ | ----------------------------------------------------- |
| `AddScopeRblProvider`    | Adds an additional RBL provider for a specific scope. |
| `RemoveScopeRblProvider` | Removes a scope-specific RBL provider.                |
| `ListScopeRblProviders`  | Lists RBL providers for a specific scope.             |

#### DHCP Certificate Options

| RPC                    | Description                                              |
| ---------------------- | -------------------------------------------------------- |
| `SetDhcpCertOption`    | Sets a certificate to be delivered via DHCP for a scope. |
| `RemoveDhcpCertOption` | Removes a DHCP certificate option for a scope.           |
| `ListDhcpCertOptions`  | Lists DHCP certificate options for a scope.              |

All changes made via gRPC take effect immediately and are reflected in subsequent DNS resolution.

## CLI Client

The `rolodex-dns-cli` binary is a command-line client for the gRPC management interface. It supports all gRPC operations as subcommands and can connect over TCP or Unix socket.

### Global Options

| Option          | Short | Default           | Description                                                                 |
| --------------- | ----- | ----------------- | --------------------------------------------------------------------------- |
| `--address`     | `-a`  | `127.0.0.1:50051` | gRPC server address (host:port). Ignored when `--unix-socket` is specified. |
| `--unix-socket` | `-u`  | —                 | Path to Unix domain socket. Overrides `--address`.                          |
| `--auth-token`  | `-t`  | (empty)           | Authentication token for TCP connections. Ignored for Unix socket.          |

### Subcommands

#### Record Management

| Command         | Description                                                                                                                                                             |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `add-record`    | Add a DNS record. Takes `--name` (required), `--record-type` (default `a`), `--value` (required), `--ttl` (default 300), and `--priority` (default 0, used for MX/SRV). |
| `remove-record` | Remove DNS record(s). Takes `--name` (required), with optional `--record-type` and `--value` filters.                                                                   |
| `list-records`  | List DNS records. Takes optional `--name` (supports `*.` wildcard prefix) and `--record-type` filters.                                                                  |

#### Network Scoping

| Command                | Description                                                                                                |
| ---------------------- | ---------------------------------------------------------------------------------------------------------- |
| `create-scope`         | Create a network scope. Takes `--name` (required) and optional `--home-domain`.                            |
| `delete-scope`         | Delete a network scope and all its records/associations. Takes `--name`.                                   |
| `list-scopes`          | List all network scopes.                                                                                   |
| `join-network`         | Associate an IP with a scope. Takes `--ip`, `--scope`, and optional `--ttl` (default 300).                 |
| `leave-network`        | Remove an IP's scope association. Takes `--ip`.                                                            |
| `list-associations`    | List IP-to-scope associations. Takes optional `--scope` filter.                                            |
| `add-scoped-record`    | Add a DNS record to a scope. Takes `--scope`, `--name`, `--record-type`, `--value`, `--ttl`, `--priority`. |
| `remove-scoped-record` | Remove records from a scope. Takes `--scope`, `--name`, optional `--record-type` and `--value`.            |
| `list-scoped-records`  | List records in a scope. Takes `--scope`, optional `--name` and `--record-type`.                           |
| `get-search-domains`   | Get search domains for an IP. Takes `--ip`.                                                                |

#### Authoritative Zones

| Command            | Description                                      |
| ------------------ | ------------------------------------------------ |
| `add-auth-zone`    | Declare a zone as authoritative. Takes `--zone`. |
| `remove-auth-zone` | Remove an authoritative zone. Takes `--zone`.    |
| `list-auth-zones`  | List all authoritative zones.                    |

#### Forwarding & RBL

| Command            | Description                                                                                         |
| ------------------ | --------------------------------------------------------------------------------------------------- |
| `set-forwarders`   | Set upstream DNS forwarders. Takes `--forwarders` (one or more `host:port` addresses).              |
| `set-rbl-config`   | Configure RBL settings. Takes `--enabled` flag and optional `--providers` in `zone:enabled` format. |
| `get-rbl-config`   | Display current RBL configuration.                                                                  |
| `flush-cache`      | Clear the RBL result cache.                                                                         |
| `add-local-rbl`    | Add a local RBL entry. Takes `--name` and optional `--reason`.                                      |
| `remove-local-rbl` | Remove a local RBL entry. Takes `--name`.                                                           |
| `list-local-rbl`   | List all local RBL entries.                                                                         |

#### DNS Cache

| Command           | Description                                           |
| ----------------- | ----------------------------------------------------- |
| `flush-dns-cache` | Clear the DNS response cache.                         |
| `cache-stats`     | Display DNS cache statistics (entries, hits, misses). |

#### TTL Drift & Latency

| Command         | Description                                                                                                                            |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `set-ttl-drift` | Set TTL drift config. Takes `--mode` (`disabled`/`fixed`/`logarithmic`), `--adjustment` (e.g., `"+5m"`, `"-30s"`), `--log-multiplier`. |
| `get-ttl-drift` | Display current TTL drift configuration.                                                                                               |
| `latency-stats` | Display per-server upstream query latency statistics.                                                                                  |

#### DNS64

| Command     | Description                                                               |
| ----------- | ------------------------------------------------------------------------- |
| `set-dns64` | Set DNS64 config. Takes `--enabled` and `--prefix` (default `64:ff9b::`). |
| `get-dns64` | Display current DNS64 configuration.                                      |

#### DNSSEC

| Command               | Description                                                                                                  |
| --------------------- | ------------------------------------------------------------------------------------------------------------ |
| `generate-dnssec-key` | Generate a DNSSEC key pair. Takes `--zone`, `--algorithm` (default `ed25519`), `--key-type` (default `ZSK`). |
| `list-dnssec-keys`    | List DNSSEC keys for a zone. Takes `--zone`.                                                                 |
| `sign-zone`           | Sign a zone with DNSSEC. Takes `--zone`.                                                                     |

#### DANE & ACME

| Command             | Description                                                                                                                                                                           |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `generate-tlsa`     | Generate a DANE TLSA record. Takes `--domain`, `--port`, `--protocol` (default `tcp`), `--cert-path`, `--usage` (default 3), `--selector` (default 0), `--matching-type` (default 1). |
| `request-acme-cert` | Request an ACME certificate. Takes `--domain` and `--provider-url` (default: Let's Encrypt).                                                                                          |
| `acme-status`       | Get ACME certificate status. Takes `--domain`.                                                                                                                                        |

#### DHCP

| Command             | Description                                                                                                                                        |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `add-dhcp-pool`     | Add a DHCP address pool. Takes `--scope`, `--range-start`, `--range-end`, `--gateway`, `--subnet-mask` (default `255.255.255.0`), `--dns-servers`. |
| `remove-dhcp-pool`  | Remove a DHCP pool. Takes `--pool-id`.                                                                                                             |
| `list-dhcp-pools`   | List DHCP pools. Takes optional `--scope` filter.                                                                                                  |
| `list-dhcp-leases`  | List DHCP leases. Takes optional `--scope` filter.                                                                                                 |
| `delete-dhcp-lease` | Delete a DHCP lease. Takes `--mac`.                                                                                                                |
| `add-scope-rbl`     | Add a per-scope RBL provider. Takes `--scope`, `--zone`, `--enabled` (default `true`).                                                             |
| `remove-scope-rbl`  | Remove a per-scope RBL provider. Takes `--scope`, `--zone`.                                                                                        |
| `list-scope-rbl`    | List per-scope RBL providers. Takes `--scope`.                                                                                                     |
| `set-dhcp-cert`     | Set a DHCP certificate option. Takes `--scope`, `--option-code`, `--cert-path`, `--description`.                                                   |
| `remove-dhcp-cert`  | Remove a DHCP certificate option. Takes `--scope`, `--option-code`.                                                                                |
| `list-dhcp-certs`   | List DHCP certificate options. Takes `--scope`.                                                                                                    |

The `list-records` and `list-scoped-records` subcommands display results in a tabular format with columns for name, type, value, TTL, and priority. The `get-rbl-config` subcommand displays the global enabled state and a table of providers.

## Go Client Library

A Go client library is provided in the `go/` directory, importable as `gitea.com/town-os/rolodex-dns/go`. It wraps the gRPC API with idiomatic Go types and supports the same transport and authentication modes as the CLI.

### Connection

The `Dial` function establishes a connection and returns a `Client`:

- **TCP**: `Dial(ctx, "host:port", WithAuthToken("secret"))` — connects via TCP with shared-secret authentication.
- **Unix socket**: `Dial(ctx, "/path/to/socket", WithUnixSocket())` — connects via Unix domain socket, bypassing server-side authentication.

An additional `WithGRPCDialOption` option allows passing custom `grpc.DialOption` values for TLS or interceptor configuration.

### Client Methods

#### Record Management

| Method                          | Description                                                                                                  |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `AddRecord(ctx, record)`        | Adds a DNS record.                                                                                           |
| `RemoveRecord(ctx, name, opts)` | Removes records by name with optional `RemoveRecordOptions` (type and value filters). Returns removed count. |
| `ListRecords(ctx, opts)`        | Queries records with optional `ListRecordsOptions` (name filter with `*.` wildcard support, type filter).    |

#### Network Scoping

| Method                                               | Description                                       |
| ---------------------------------------------------- | ------------------------------------------------- |
| `CreateNetworkScope(ctx, scope)`                     | Creates a network scope.                          |
| `DeleteNetworkScope(ctx, name)`                      | Deletes a scope and all its records/associations. |
| `ListNetworkScopes(ctx)`                             | Retrieves all scopes.                             |
| `JoinNetwork(ctx, ipAddress, scopeName, ttlSeconds)` | Associates an IP with a scope.                    |
| `LeaveNetwork(ctx, ipAddress)`                       | Removes an IP's scope association.                |
| `GetNetworkAssociations(ctx, scopeName)`             | Retrieves IP-to-scope associations.               |
| `AddScopedRecord(ctx, scopeName, record)`            | Adds a record within a scope.                     |
| `RemoveScopedRecord(ctx, scopeName, name, opts)`     | Removes records from a scope.                     |
| `ListScopedRecords(ctx, scopeName, opts)`            | Queries records within a scope.                   |
| `GetSearchDomains(ctx, ipAddress)`                   | Returns search domains for an IP.                 |

#### Authoritative Zones

| Method                               | Description                             |
| ------------------------------------ | --------------------------------------- |
| `AddAuthoritativeZone(ctx, zone)`    | Declares a zone as authoritative.       |
| `RemoveAuthoritativeZone(ctx, zone)` | Removes an authoritative zone.          |
| `ListAuthoritativeZones(ctx)`        | Retrieves all authoritative zone names. |

#### Forwarding & RBL

| Method                                  | Description                                                |
| --------------------------------------- | ---------------------------------------------------------- |
| `SetForwarders(ctx, forwarders)`        | Replaces the upstream forwarder list.                      |
| `SetRblConfig(ctx, enabled, providers)` | Replaces the RBL configuration.                            |
| `GetRblConfig(ctx)`                     | Returns an `RblStatus` with the current RBL configuration. |
| `FlushCache(ctx)`                       | Clears the RBL result cache.                               |
| `AddLocalRblEntry(ctx, entry)`          | Adds a local RBL entry.                                    |
| `RemoveLocalRblEntry(ctx, name)`        | Removes a local RBL entry.                                 |
| `ListLocalRblEntries(ctx)`              | Retrieves all local RBL entries.                           |

#### DNS Cache

| Method               | Description                    |
| -------------------- | ------------------------------ |
| `GetCacheStats(ctx)` | Returns cache statistics.      |
| `FlushDnsCache(ctx)` | Clears the DNS response cache. |

#### TTL Drift & Latency

| Method                           | Description                            |
| -------------------------------- | -------------------------------------- |
| `SetTtlDriftConfig(ctx, config)` | Sets TTL drift configuration.          |
| `GetTtlDriftConfig(ctx)`         | Returns TTL drift configuration.       |
| `GetQueryLatencyStats(ctx)`      | Returns per-server latency statistics. |

#### Encrypted Transport Configuration

| Method                                                | Description                 |
| ----------------------------------------------------- | --------------------------- |
| `SetDotConfig(ctx, config)` / `GetDotConfig(ctx)`     | Configures DNS-over-TLS.    |
| `SetDohConfig(ctx, config)` / `GetDohConfig(ctx)`     | Configures DNS-over-HTTPS.  |
| `SetDoqConfig(ctx, config)` / `GetDoqConfig(ctx)`     | Configures DNS-over-QUIC.   |
| `SetProxyConfig(ctx, config)` / `GetProxyConfig(ctx)` | Configures proxy transport. |

#### DNSSEC

| Method                                             | Description                          |
| -------------------------------------------------- | ------------------------------------ |
| `GenerateDnssecKey(ctx, zone, algorithm, keyType)` | Generates a DNSSEC key pair.         |
| `ListDnssecKeys(ctx, zone)`                        | Lists DNSSEC keys for a zone.        |
| `DeleteDnssecKey(ctx, keyID)`                      | Deletes a DNSSEC key by ID.          |
| `GetDsRecords(ctx, zone)`                          | Retrieves DS records for delegation. |
| `SignZone(ctx, zone)`                              | Signs a zone with its DNSSEC keys.   |

#### DANE, ACME & DNS64

| Method                                                | Description                                 |
| ----------------------------------------------------- | ------------------------------------------- |
| `GenerateTlsaRecord(ctx, opts)`                       | Generates a TLSA record from a certificate. |
| `ListTlsaRecords(ctx, domain)`                        | Retrieves TLSA records for a domain.        |
| `GenerateDaneRootCa(ctx, name)`                       | Generates a DANE root CA certificate.       |
| `RequestAcmeCert(ctx, domain, providerURL)`           | Requests an ACME certificate via DNS-01.    |
| `GetAcmeStatus(ctx, domain)`                          | Retrieves ACME certificate status.          |
| `SetDns64Config(ctx, config)` / `GetDns64Config(ctx)` | Configures DNS64 synthesis.                 |

#### DHCP

| Method                                               | Description                                      |
| ---------------------------------------------------- | ------------------------------------------------ |
| `AddDhcpPool(ctx, pool)`                             | Adds a DHCP address pool for a scope.            |
| `RemoveDhcpPool(ctx, poolID)`                        | Removes a DHCP pool by ID.                       |
| `ListDhcpPools(ctx, scopeName)`                      | Lists DHCP pools, optionally filtered by scope.  |
| `ListDhcpLeases(ctx, scopeName)`                     | Lists DHCP leases, optionally filtered by scope. |
| `DeleteDhcpLease(ctx, mac)`                          | Deletes a DHCP lease by MAC address.             |
| `AddScopeRblProvider(ctx, scopeName, zone, enabled)` | Adds a per-scope RBL provider.                   |
| `RemoveScopeRblProvider(ctx, scopeName, zone)`       | Removes a per-scope RBL provider.                |
| `ListScopeRblProviders(ctx, scopeName)`              | Lists per-scope RBL providers.                   |
| `SetDhcpCertOption(ctx, opt)`                        | Sets a DHCP certificate option for a scope.      |
| `RemoveDhcpCertOption(ctx, scopeName, optionCode)`   | Removes a DHCP certificate option.               |
| `ListDhcpCertOptions(ctx, scopeName)`                | Lists DHCP certificate options for a scope.      |

| Other     | Description                              |
| --------- | ---------------------------------------- |
| `Close()` | Releases the underlying gRPC connection. |

The client automatically includes the auth token in every RPC call. All methods accept `context.Context` for cancellation and deadlines.

### Exported Types

- `RecordType` — DNS record type enum (constants: `RecordTypeA`, `RecordTypeAAAA`, `RecordTypeCNAME`, `RecordTypeMX`, `RecordTypeTXT`, `RecordTypeNS`, `RecordTypeSOA`, `RecordTypeSRV`, `RecordTypePTR`, `RecordTypeURI`, `RecordTypeSSHFP`, `RecordTypeDNAME`, `RecordTypeANAME`, `RecordTypeZONEMD`, `RecordTypeTLSA`, `RecordTypeDNSKEY`, `RecordTypeDS`, `RecordTypeRRSIG`, `RecordTypeNSEC`, `RecordTypeNSEC3`, `RecordTypeNSEC3PARAM`).
- `DnsRecord` — DNS record with name, record type, value, TTL, and priority.
- `RblConfig` — RBL provider configuration (zone and enabled flag).
- `RblStatus` — RBL state returned by `GetRblConfig` (global enabled flag and provider list).
- `RemoveRecordOptions` — Optional filters for `RemoveRecord` (record type, value).
- `ListRecordsOptions` — Optional filters for `ListRecords` (name filter, record type).
- `NetworkScope` — Network scope with name and home domain.
- `NetworkAssociation` — IP-to-scope association with TTL.
- `RemoveScopedRecordOptions` — Optional filters for `RemoveScopedRecord`.
- `ListScopedRecordsOptions` — Optional filters for `ListScopedRecords`.
- `CacheStats` — DNS cache statistics (total entries, hits, misses).
- `TtlDriftConfig` — TTL drift configuration (mode, fixed adjustment, log multiplier).
- `QueryLatencyStats` — Per-server latency statistics.
- `LocalRblEntry` — Local RBL entry (name and reason).
- `DotConfig` / `DohConfig` / `DoqConfig` — Encrypted transport configurations.
- `TlsConfig` — TLS certificate configuration (cert path, key path, auto self-signed).
- `ProxyConfig` — Proxy transport configuration (URL, auth, mode).
- `DnssecKey` — DNSSEC key with zone, algorithm, key type, key tag, timestamps, and active flag.
- `DsRecord` — String representation of a DS record.
- `TlsaRecord` — String representation of a TLSA record.
- `DaneRootCa` — PEM-encoded root CA certificate.
- `AcmeStatus` — ACME certificate status (status, expiry, domain).
- `Dns64Config` — DNS64 configuration (enabled, prefix).
- `DhcpPool` — DHCP address pool (scope, range, gateway, subnet mask, DNS servers).
- `DhcpLease` — DHCP lease (MAC, IP, scope, hostname, lease start/duration, state).
- `ScopeRblProvider` — Per-scope RBL provider (scope, zone, enabled).
- `DhcpCertOption` — DHCP certificate option (scope, option code, cert data, description).
- `GenerateTlsaRecordOptions` — TLSA generation parameters.
- `Option` — Functional option for configuring `Dial`.

### Generated Protobuf Code

Generated Go protobuf and gRPC bindings are in `go/rolodexdnspb/`, produced from `proto/rolodex_dns.proto`. The client library re-exports the key types so consumers do not need to import the generated package directly.

## Configuration

Configuration is loaded from a YAML file (default path `rolodex-dns.yml`, overridable via `-c`/`--config` CLI flag). If the file does not exist, sensible defaults are used.

### Configuration Fields

| Field                               | Default                        | Description                                            |
| ----------------------------------- | ------------------------------ | ------------------------------------------------------ |
| `dns.udp_bind`                      | `0.0.0.0:53`                   | DNS UDP listener address                               |
| `dns.tcp_bind`                      | `0.0.0.0:53`                   | DNS TCP listener address                               |
| `grpc.tcp_bind`                     | `127.0.0.1:50051`              | gRPC TCP listener address (empty to disable)           |
| `grpc.unix_socket`                  | `/var/run/rolodex-dns.sock`    | gRPC Unix socket path (empty to disable)               |
| `grpc.shared_secret`                | (empty)                        | Shared secret for TCP gRPC auth                        |
| `forwarders`                        | `["8.8.8.8:53", "8.8.4.4:53"]` | Upstream DNS resolvers                                 |
| `database_path`                     | `rolodex-dns.db`               | SQLite database file path                              |
| `rbl.enabled`                       | `false`                        | Global RBL enable flag                                 |
| `rbl.providers`                     | 5 default zones (see above)    | RBL provider list                                      |
| `dot.bind`                          | `0.0.0.0:853`                  | DoT listener address (section optional)                |
| `dot.tls.cert_path`                 | (none)                         | TLS certificate path                                   |
| `dot.tls.key_path`                  | (none)                         | TLS private key path                                   |
| `dot.tls.auto_self_signed`          | `true`                         | Auto-generate self-signed certificate                  |
| `doh.bind`                          | `0.0.0.0:443`                  | DoH listener address (section optional)                |
| `doh.tls.*`                         | (same as DoT)                  | TLS settings for DoH                                   |
| `doh.enable_h3`                     | `false`                        | Enable HTTP/3 (QUIC) transport for DoH                 |
| `doq.bind`                          | `0.0.0.0:8853`                 | DoQ listener address (section optional)                |
| `doq.tls.*`                         | (same as DoT)                  | TLS settings for DoQ                                   |
| `proxy.url`                         | (empty)                        | Proxy URL (e.g., `socks5://127.0.0.1:1080`)            |
| `proxy.auth`                        | (none)                         | Proxy authentication (`user:pass`)                     |
| `proxy.mode`                        | `connect`                      | Proxy mode (`connect`, `socks5`, or `doh`)             |
| `ttl_drift.mode`                    | `disabled`                     | TTL drift mode (`disabled`, `fixed`, `logarithmic`)    |
| `ttl_drift.fixed_adjustment`        | `0s`                           | Fixed TTL adjustment duration                          |
| `ttl_drift.log_multiplier`          | `0.1`                          | Logarithmic drift sensitivity                          |
| `dns64.enabled`                     | `false`                        | Enable DNS64 AAAA synthesis                            |
| `dns64.prefix`                      | `64:ff9b::`                    | NAT64 prefix for synthesis                             |
| `security.qname_case_randomization` | `true`                         | 0x20 encoding for cache poisoning resistance           |
| `dhcp.bind`                         | `0.0.0.0:67`                   | DHCP UDP listener address (section optional)           |
| `dhcp.default_lease_duration`       | `3600`                         | Default DHCP lease duration in seconds                 |
| `dhcp.reclaim_timeout`              | `86400`                        | Seconds after expiry before IP is reclaimed            |
| `dhcp.sweep_interval`               | `60`                           | Background lease sweep interval in seconds             |
| `dhcp.tld`                          | (required)                     | TLD for hostname DNS registration (e.g. `example.com`) |

The `dot`, `doh`, `doq`, and `proxy` sections are optional. When omitted, the corresponding transport is not started.

## Build System

The project uses a top-level Makefile with the following targets:

| Target                | Description                                                                                                                                                |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `build`               | Compile the Rust project in debug mode (`cargo build`). Produces the `rolodex-dns` server and `rolodex-dns-cli` client binaries.                           |
| `test`                | Run all tests: Go integration tests, Go unit tests, and Rust tests (`cargo test`).                                                                         |
| `clean`               | Clean build artifacts (`cargo clean`).                                                                                                                     |
| `go-test`             | Run Go unit tests (depends on `go-integration-test`).                                                                                                      |
| `go-integration-test` | Build the Rust binaries, then run Go integration tests with the `integration` build tag, passing the compiled server binary path via `ROLODEX_DNS_BINARY`. |
| `install`             | Install the Rust binaries to the Cargo bin directory (`cargo install --path .`).                                                                           |
| `dev`                 | Build the Rust project in debug mode, then start a development server using `dev.yml`.                                                                     |
| `dev-release`         | Build the Rust project in release mode, then start a development server using `dev.yml`.                                                                   |
| `image`               | Build a container image using `make/build.sh release`.                                                                                                     |
| `push` / `push-rc`    | Build and push a release candidate container image to `gitea.com/town-os/rolodex-dns`.                                                                     |
| `push-release`        | Build and push a release container image.                                                                                                                  |
| `clean-containers`    | Remove locally built container images.                                                                                                                     |

The Makefile is designed to be extended for non-cargo scenarios. Protocol buffer bindings are generated at build time via `build.rs` using `tonic-prost-build`. Container images are built with Podman using unique instance IDs derived from the working directory path.

### Development Server

The `make dev` target starts a local development instance configured via `dev.yml`:

- DNS listeners on `127.0.0.1:5300` (UDP and TCP) — a non-privileged port that does not require root.
- gRPC management via Unix socket at `/tmp/rolodex-dns.sock` only (TCP gRPC disabled).
- Database at `/tmp/rolodex-dns-dev.db`.
- No authentication (empty shared secret).
- RBL disabled.
- Google DNS forwarders (`8.8.8.8:53`, `8.8.4.4:53`).

The `make dev-release` target does the same but builds with `--release` for optimized performance.

## Testing

### Rust Tests

Rust tests (`cargo test`) include unit tests and integration tests covering gRPC operations, DNS resolution (UDP and TCP), split-horizon behavior, authentication enforcement, Unix socket auth bypass, database persistence, configuration serialization, EDNS handling, TTL drift calculations, latency tracking, and IPAM.

### IPAM Unit Tests

IPAM unit tests in `src/db.rs` cover IP address allocation logic: pool exhaustion (allocate all IPs in a range, verify `None` when full), IP reuse after lease deletion, scope isolation (same IP ranges in different scopes don't interfere), sticky MAC binding survival across lease release, single-IP pool behavior, and lease replacement for the same MAC (always reissues the same IP).

### DHCP Integration Tests

DHCP integration tests in `tests/dhcp_integration_test.rs` cover end-to-end DHCP flows: DISCOVER/OFFER/REQUEST/ACK, sticky bindings, pool exhaustion, lease creation with DNS registration, lease release cleanup, lease sweep with DNS removal, certificate option delivery, multiple concurrent clients, and full UDP packet round-trips.

### CLI Integration Tests

The `rolodex-dns-cli` binary has integration tests that spawn a test gRPC server and execute the CLI binary against it. Tests cover all subcommands over both TCP and Unix socket transports, authentication (success, failure, and Unix socket bypass), all record types (A, AAAA, CNAME, MX, TXT, NS, SRV, PTR, and extended types), wildcard filtering, network scoping, authoritative zone management, and help output validation.

### Go Client Tests

The Go client has two test layers:

- **Unit tests** — Use an in-process mock gRPC server via `bufconn` to test all client methods, authentication token propagation, transport modes, error handling, and edge cases (idempotent close, lazy dial, custom dial options).
- **Integration tests** — Gated behind the `integration` build tag. Each test starts a real Rolodex DNS server subprocess with a unique temporary directory, random ports, and isolated database. Tests cover record CRUD, wildcard filtering, forwarder configuration, RBL round-trip, cache flushing, Unix socket transport, authentication failure, default TTL behavior, concurrent clients (5 simultaneous), network scoping, DNS64, and TTL drift.

The `make test` target runs the full test suite: Go integration tests, Go unit tests, Rust integration tests (each test file explicitly: `integration_test`, `new_features_test`, `cli_integration_test`, `dhcp_integration_test`), and then all Rust tests via `cargo test`. Individual targets are available: `make go-integration-test`, `make go-test`, `make rust-integration-test`, `make rust-test`.

## Key Dependencies

### Rust

- **domain** / **hickory-resolver** / **hickory-proto** — DNS protocol parsing, record types, and upstream resolution
- **tonic** / **tonic-prost** / **prost** — gRPC framework and protocol buffer serialization
- **rusqlite** (bundled) — SQLite database with WAL mode
- **tokio** — Async runtime (full feature set)
- **dashmap** — Lock-free concurrent hash map/set for caching
- **arc-swap** — Lock-free atomic swapping of `Arc` pointers for runtime configuration
- **clap** — CLI argument parsing (server and client)
- **tracing** / **tracing-subscriber** — Structured logging (configurable via `RUST_LOG` environment variable)
- **hyper-util** / **tower** — HTTP/2 transport for Unix socket gRPC connections
- **rustls** / **tokio-rustls** — TLS for encrypted DNS transports
- **rcgen** — Self-signed certificate generation
- **axum** / **axum-server** — HTTP framework for DoH
- **quinn** — QUIC protocol for DoQ
- **ring** / **sha2** — Cryptographic operations for DNSSEC and DANE
- **base64** — Base64 encoding for DoH GET requests
- **hex** — Hex encoding for TLSA/DNSSEC records
- **serde** / **serde_yaml_ng** — Configuration serialization
- **fancy_duration** — Compound duration parsing for TTL drift
- **rand** — QNAME case randomization
- **anyhow** / **thiserror** — Error handling

### Go

- **google.golang.org/grpc** — gRPC framework
- **google.golang.org/protobuf** — Protocol buffer runtime

## Concurrency Model

The server runs on the tokio multi-threaded async runtime. DNS UDP queries are handled sequentially on a single task. DNS TCP connections spawn a new task per connection. DoT, DoH, and DoQ connections each spawn a new task per connection. gRPC servers (TCP and Unix socket) run as separate tasks. Upstream forwarder configuration is protected by `ArcSwap` for lock-free reads. RBL state uses lock-free primitives: the enabled flag is an `AtomicBool` and the provider list uses `ArcSwap` for zero-contention reads. The RBL cache and DNS response cache use lock-free `DashMap`. The SQLite database is protected by a `Mutex` with `prepare_cached` for statement reuse.

At boot, in-memory caches are populated from the database: scope count (`AtomicUsize`), local RBL entries (`DashSet`), authoritative zones (`DashSet`), and managed zones (`DashSet`). These caches avoid SQL queries on the hot path and are updated incrementally as records are added or removed via gRPC.

Upstream DNS forwarding uses a pool of 8 UDP sockets, allowing concurrent forwarding without contention on a single socket. Socket selection uses round-robin via `AtomicUsize`.

The in-memory DNS cache is automatically flushed when records are mutated via gRPC (add, remove, or scoped variants) to ensure consistency between the database and cached responses. Local database records are cached with a `local` flag that prevents TTL decay and SQLite persistence, since they are authoritative.

TTL drift configuration uses `ArcSwap` for lock-free reads, matching the pattern used for forwarder configuration.
