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
- never delete, move, or modify git tags unless explicitly told to

## DNS Resolution

Rolodex DNS serves DNS queries over UDP, TCP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), and DNS-over-QUIC (DoQ) on configurable bind addresses (default `0.0.0.0:53` for UDP/TCP). TCP and DoT use the standard 2-byte length prefix framing. Maximum UDP message size is 4096 bytes; maximum TCP message size is 65535 bytes.

### Supported Record Types

**Basic**: A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR.

**Extended**: URI (RFC 7553), SSHFP (RFC 4255), DNAME (RFC 6672), ANAME (alias resolved at query time), ZONEMD (RFC 9156), TLSA (RFC 6698), CERT (RFC 4398).

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

SOA values are stored as `"mname rname serial refresh retry expire minimum"`. SRV values are stored as `"weight port target"`. TLSA values are stored as `"usage selector matching_type hex_data"`. URI values are stored as `"priority weight target_uri"`. SSHFP values are stored as `"algorithm fp_type hex_fingerprint"`. ZONEMD values are stored as `"serial scheme hash_algorithm hex_digest"`. CERT values are stored as `"cert_type key_tag algorithm base64_cert_data"`.

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

## ACME Issuer (Certificate Authority)

Rolodex is itself an **ACME server / certificate authority** (RFC 8555, server side) — not merely an ACME client. Off-the-shelf ACME clients (certbot, lego, acme.sh, Caddy) point at the Rolodex directory URL and obtain certificates issued by a Rolodex-run CA. Because Rolodex is also the DNS server, it serves and self-validates the dns-01 challenge against its own database.

### CA hierarchy

A single self-signed **root CA** signs a **per-zone intermediate CA**; each intermediate signs the leaf certificates issued through ACME. All keys are **Ed25519**. CAs are stored as PEM in the database (`dane_root_cas` reserved name `__rolodex_root__`, and `zone_cas`) and re-materialized at use time via rcgen `from_ca_cert_pem`. See `src/ca.rs` (`ensure_root_ca`, `ensure_zone_intermediate`, `issue_leaf`, `intermediate_tlsa`, `responsible_zone`).

### Protocol flow (`src/acme_server.rs`, `src/acme_jose.rs`)

Endpoints are mounted under `/acme`: `directory`, `new-nonce`, `new-account`, `new-order`, `order/{id}`, `authz/{id}`, `challenge/{id}`, `finalize/{id}`, `cert/{id}`, `revoke-cert`. Every response carries a fresh `Replay-Nonce`. JWS requests are verified with `ring` for `EdDSA`, `ES256`, and `RS256`; nonces are single-use (anti-replay). Account identity uses the RFC 7638 JWK thumbprint.

- **Validation is dns-01 only**, checked against Rolodex's own DNS data. The client provisions `_acme-challenge.<name>` TXT (60s TTL) through the Rolodex control plane — use the bundled hook `scripts/rolodex-dns01-hook.sh` (supports lego `exec` and certbot `--manual-auth-hook`).
- **Authorization**: account registration requires External Account Binding (EAB) by default (`require_eab`); EAB credentials are scoped to a zone and minted by the portal/CLI. Issuance is restricted to names under an intermediate-backed zone unless `issuance_scope` is `any`.
- **Issuance**: `finalize` signs the client CSR with the per-zone intermediate and returns the `leaf + intermediate` chain.

### DANE integration

On issuance, the per-zone intermediate is auto-published as a **DANE-TA** TLSA record — `2 1 1` (intermediate SPKI SHA-256) at `_<port>._<proto>.<name>` (default `_443._tcp`, configurable). The server presents `leaf + intermediate`, so a DANE-TA validator matches the intermediate in the chain. No per-leaf EE records are published.

### CA Distribution over DNS

When a per-zone intermediate CA is created (or re-ensured), `publish_ca_dns_records` in `src/ca.rs` publishes the CA chain into the local DNS database so any client that can resolve the zone can retrieve the root and intermediate certificates — no portal access required:

- **CERT records (RFC 4398)** at `_ca.<zone>.` — one record per certificate, value `"1 0 0 <base64 DER>"` (type 1 = PKIX, key tag 0, algorithm 0). Retrievable with any DNS client (`dig CERT _ca.<zone>`); the root is identified as the self-signed certificate.
- **TXT records** at `_rolodex-ca.<zone>.` — the same base64 DER split into ≤255-byte character-string chunks framed as `rolodex-ca:v1:<root|intermediate>:<i>/<n>:<chunk>`. The unique `rolodex-ca:` prefix distinguishes the chunks from unrelated TXT data; chunks carry explicit sequence numbers because DNS answer order is not guaranteed. This is the fallback for resolver stacks that cannot query CERT.

Publication is idempotent (existing records at both names are replaced) and happens at every `ensure_zone_intermediate` call site: portal account creation, the `EnsureZoneCa`/`CreateEabCredential` RPCs, and ACME account/finalize paths. The DNS response cache is flushed after publication. Consumers prefer CERT and fall back to TXT — the browser extension's `extension/ca_dns.js` retrieves the chain over DoH this way and can verify the intermediate against the DANE-TA TLSA record.

### Enrollment surfaces (trusted-network)

End users do not need a CLI. A built-in **web portal** (`src/portal.rs`, served on `acme.portal_bind`) and a **browser extension** (`extension/`) share one JSON API (`/api/account`, `/api/ca`, `/api/zones`, `/api/certs`); a **JavaScript client library** for the same API plus DANE/TLSA retrieval and a local enrollment UI lives in `js/` (see the JavaScript Client Library section). The extension can additionally retrieve the CA chain from DNS itself over DoH (see CA Distribution over DNS), which works for any client that can resolve the zone — no portal access required. The portal mints an EAB account behind the scenes and returns copy-paste client config; users just trust the root CA and run their client. **Access is trusted-network only** — bind `portal_bind` to an internal address; anyone who can reach it may enroll.

### Legacy stub RPCs

`RequestAcmeCert`/`GetAcmeStatus` remain for backward compatibility (challenge-record plumbing + status), superseded by the ACME endpoint and the admin RPCs below.

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
| `RequestAcmeCert` | Legacy: provisions a dns-01 challenge record (superseded by the issuer). |
| `GetAcmeStatus`   | Retrieves ACME certificate status (status, expiry, domain).              |

#### ACME Issuer Administration

| RPC                    | Description                                                                  |
| ---------------------- | ---------------------------------------------------------------------------- |
| `EnsureZoneCa`         | Creates the per-zone intermediate CA if absent; returns root + intermediate PEM. |
| `CreateEabCredential`  | Mints an EAB credential (kid + base64url HMAC) scoped to a zone.             |
| `RemoveEabCredential`  | Removes an EAB credential by kid.                                            |
| `ListAcmeAccounts`     | Lists registered ACME server accounts.                                      |
| `ListAcmeCertificates` | Lists issued certificates, optionally filtered by zone.                     |

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

#### ACME Issuer Administration

| Command              | Description                                                                |
| -------------------- | -------------------------------------------------------------------------- |
| `ensure-zone-ca`     | Ensure the per-zone intermediate CA exists. Takes `--zone`. Prints root + intermediate PEM. |
| `create-eab`         | Mint an EAB credential scoped to a zone. Takes `--zone`. Prints kid + HMAC key. |
| `remove-eab`         | Remove an EAB credential. Takes `--kid`.                                   |
| `list-acme-accounts` | List registered ACME server accounts.                                     |
| `list-acme-certs`    | List issued certificates. Takes optional `--zone`.                        |

The bundled `scripts/rolodex-dns01-hook.sh` provisions/removes the `_acme-challenge` TXT via `rolodex-dns-cli` for ACME clients doing dns-01 (lego `exec` and certbot `--manual-auth-hook`).

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
| `EnsureZoneCa(ctx, zone)`                             | Ensures the per-zone intermediate CA exists. |
| `CreateEabCredential(ctx, zone)`                      | Mints an EAB credential scoped to a zone.   |
| `RemoveEabCredential(ctx, kid)`                       | Removes an EAB credential by kid.           |
| `ListAcmeAccounts(ctx)`                               | Lists registered ACME server accounts.      |
| `ListAcmeCertificates(ctx, zone)`                     | Lists issued certificates, optionally by zone. |

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

- `RecordType` — DNS record type enum (constants: `RecordTypeA`, `RecordTypeAAAA`, `RecordTypeCNAME`, `RecordTypeMX`, `RecordTypeTXT`, `RecordTypeNS`, `RecordTypeSOA`, `RecordTypeSRV`, `RecordTypePTR`, `RecordTypeURI`, `RecordTypeSSHFP`, `RecordTypeDNAME`, `RecordTypeANAME`, `RecordTypeZONEMD`, `RecordTypeTLSA`, `RecordTypeDNSKEY`, `RecordTypeDS`, `RecordTypeRRSIG`, `RecordTypeNSEC`, `RecordTypeNSEC3`, `RecordTypeNSEC3PARAM`, `RecordTypeCERT`).
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

## JavaScript Client Library

A JavaScript client for the ACME issuer is provided in the `js/` directory (`rolodex-ca-client`, ESM, Node 20+, no runtime dependencies). It targets the issuer's HTTP surfaces rather than gRPC.

### Portal Client (`js/src/portal.js`)

`PortalClient` wraps the trusted-network enrollment portal JSON API (the same API used by the built-in web portal and browser extension):

| Method                   | Endpoint                  | Description                                                       |
| ------------------------ | ------------------------- | ----------------------------------------------------------------- |
| `createAccount(zone)`    | `POST /api/account`       | Mints a zone-scoped EAB credential (creates the intermediate CA). |
| `getCaPem()`             | `GET /api/ca`             | Downloads the root CA PEM.                                        |
| `listZones()`            | `GET /api/zones`          | Lists enrollable (intermediate-backed) zones.                     |
| `listCertificates(zone)` | `GET /api/certs[?zone=]`  | Lists issued certificates.                                        |

The portal listener serves an auto-generated self-signed certificate by default, so the constructor accepts `ca` (PEM to trust) or `insecure: true` (trusted-network only). Non-2xx responses raise `PortalError` with the HTTP status.

### DANE Module (`js/src/dane.js`)

Implements DANE protocol retrieval directly on the DNS wire format (Node's resolver does not expose TLSA):

- `fetchTlsaRecords(domain, {port, protocol, dnsServer, dnsPort, transport})` — queries `_<port>._<protocol>.<domain>.` for TLSA over UDP with automatic TCP fallback on truncation (or forced TCP). NXDOMAIN yields `[]`; other rcodes raise `DnsError`.
- `certAssociationData(certPem, selector, matchingType)` — computes RFC 6698 association data from a PEM certificate via `node:crypto` (selector 0 = full DER cert, 1 = SPKI; matching 0/1/2 = exact/SHA-256/SHA-512), mirroring the Rust `dane::generate_tlsa_record`.
- `verifyCertAgainstTlsa(certPem, record)` / `matchDane(records, chainPem)` — verify retrieved records against a certificate or a `leaf + intermediate` chain (with Rolodex's DANE-TA publication the intermediate is the expected match).
- Wire codec helpers (`encodeQuery`, `decodeMessage`, `encodeResponse`, `parseTlsaRdata`, …) are exported and symmetric, and are reused by the tests' mock DNS servers.

### Local Enrollment UI (`js/bin/rolodex-ca-ui.js`, `js/src/ui_server.js`, `js/ui/`)

`rolodex-ca-ui` serves a local web console (plain HTTP on a loopback bind) that proxies the portal API over its self-signed TLS — so the browser never needs to trust the portal certificate — and adds a `POST /api/dane` endpoint performing live TLSA lookups (something a browser cannot do) with optional verification of a pasted PEM chain. Flags: `--portal`, `--bind`, `--dns`, `--ca`, `--insecure`.

### JavaScript Tests

- **Unit tests** (`js/test/*.test.js`, `node:test`) — DNS wire codec round-trips (including compression pointers and pointer-loop rejection), TLSA retrieval against in-process mock UDP/TCP DNS servers (truncation fallback, NXDOMAIN, SERVFAIL, timeout), portal client against a mock self-signed HTTPS portal, and the UI server's proxy + DANE endpoints. The browser extension's `ca_dns.js` module is tested here too (`extension.test.js`): codec interop against the Node encoder, X.509 DER field extraction cross-checked against `node:crypto`, TXT chunk reassembly (shuffled/incomplete/foreign data), CERT-preferred retrieval with TXT fallback, and DANE-TA verification — all with mocked DoH. Certificate association data is checked against openssl-generated Ed25519 fixtures in `js/test/fixtures/` whose expected SPKI/cert digests were computed with openssl — an oracle independent of `node:crypto`.
- **Integration tests** (`js/test/integration.test.js`, `js/test/ca_dns_integration.test.js`, shared harness in `js/test/server_helper.js`) — gated on `ROLODEX_DNS_BINARY`; spawn a real server with the ACME issuer (and DoH) enabled in an isolated temp dir with random ports. They exercise the portal flow (EAB minting, zone listing, root CA download) and a cross-implementation DANE check: the Rust side publishes a DANE-TA TLSA record for the zone intermediate (via `ensure-zone-ca` + `generate-tlsa` over the Unix socket CLI), and the JS client retrieves it over real UDP and TCP DNS and independently recomputes the SPKI SHA-256 from the intermediate PEM. The two implementations must agree. The CA-over-DNS suite retrieves the published chain via CERT records over DoH and plain UDP, reassembles the TXT fallback, compares both byte-for-byte with `ensure-zone-ca` output and the portal root CA, and runs DANE-TA verification end to end.

## Configuration

Configuration is loaded from a YAML file (default path `rolodex-dns.yml`, overridable via `-c`/`--config` CLI flag). If the file does not exist, sensible defaults are used.

### Bind Address Syntax

Bind address strings (used by `dns.bind`, `dot.bind`, `doh.bind`, `doq.bind`, `grpc.tcp_bind`, `dhcp.bind`) accept four forms:

| Form | Example | Description |
| ---- | ------- | ----------- |
| `ip:port` | `192.168.1.1:53` | Bind to a specific IPv4 address and port |
| `[ipv6]:port` | `[::1]:53` | Bind to a specific IPv6 address and port (brackets required) |
| `primary:port` | `primary:53` | Detect the OS default-route outbound IP and bind to it |
| `interface:port` | `eth0:53` | Resolve all IP addresses on the named network interface and bind to each one |

The `primary` keyword detects which IP address the OS would use to reach the public internet (via a non-sending UDP connect to `8.8.8.8:53`) and binds a single listener on that address. The keyword is case-insensitive.

Interface binding creates one listener per IP address assigned to the interface. For example, if `eth0` has both `192.168.1.5` and `fe80::1`, then `eth0:53` creates two listeners: `192.168.1.5:53` and `[fe80::1]:53`.

The `dns.bind` field is a list of protocol/address pairs. Each entry is a single-key map with `udp` or `tcp` as the key and a bind address as the value:

```yaml
dns:
  bind:
    - udp: "eth0:53"
    - udp: "127.0.0.1:53"
    - tcp: "eth0:53"
    - tcp: "primary:53"
```

### Configuration Fields

| Field                               | Default                        | Description                                            |
| ----------------------------------- | ------------------------------ | ------------------------------------------------------ |
| `dns.bind`                          | `[{udp: "0.0.0.0:53"}, {tcp: "0.0.0.0:53"}]` | DNS listeners; list of `{udp: addr}` / `{tcp: addr}` entries |
| `grpc.tcp_bind`                     | `127.0.0.1:50051`              | gRPC TCP listener; supports interface:port (empty to disable) |
| `grpc.unix_socket`                  | `/var/run/rolodex-dns.sock`    | gRPC Unix socket path (empty to disable)               |
| `grpc.shared_secret`                | (empty)                        | Shared secret for TCP gRPC auth                        |
| `forwarders`                        | `["8.8.8.8:53", "8.8.4.4:53"]` | Upstream DNS resolvers                                 |
| `database_path`                     | `rolodex-dns.db`               | SQLite database file path                              |
| `rbl.enabled`                       | `false`                        | Global RBL enable flag                                 |
| `rbl.providers`                     | 5 default zones (see above)    | RBL provider list                                      |
| `dot.bind`                          | `0.0.0.0:853`                  | DoT listener; supports interface:port (section optional) |
| `dot.tls.cert_path`                 | (none)                         | TLS certificate path                                   |
| `dot.tls.key_path`                  | (none)                         | TLS private key path                                   |
| `dot.tls.auto_self_signed`          | `true`                         | Auto-generate self-signed certificate                  |
| `doh.bind`                          | `0.0.0.0:443`                  | DoH listener; supports interface:port (section optional) |
| `doh.tls.*`                         | (same as DoT)                  | TLS settings for DoH                                   |
| `doh.enable_h3`                     | `false`                        | Enable HTTP/3 (QUIC) transport for DoH                 |
| `doq.bind`                          | `0.0.0.0:8853`                 | DoQ listener; supports interface:port (section optional) |
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
| `dhcp.bind`                         | `0.0.0.0:67`                   | DHCP listener; supports interface:port (section optional) |
| `dhcp.default_lease_duration`       | `3600`                         | Default DHCP lease duration in seconds                 |
| `dhcp.reclaim_timeout`              | `86400`                        | Seconds after expiry before IP is reclaimed            |
| `dhcp.sweep_interval`               | `60`                           | Background lease sweep interval in seconds             |
| `dhcp.tld`                          | (required)                     | TLD for hostname DNS registration (e.g. `example.com`) |
| `acme.bind`                         | `0.0.0.0:8555`                 | Client-facing ACME HTTPS listener; supports interface:port |
| `acme.portal_bind`                  | `127.0.0.1:8500`               | Trusted-network enrollment portal listener (portal + `/api`) |
| `acme.tls.*`                        | (same as DoT)                  | TLS settings for the ACME and portal listeners         |
| `acme.directory_url`                | `https://localhost:8555/acme`  | External ACME directory URL advertised to clients (set this) |
| `acme.root_ca_cn`                   | `Rolodex Root CA`              | Common name for the root CA created at boot             |
| `acme.leaf_validity_days`           | `90`                           | Validity of issued leaf certificates                   |
| `acme.tlsa_port` / `acme.tlsa_proto`| `443` / `tcp`                  | Where the DANE-TA TLSA record is published per name    |
| `acme.require_eab`                  | `true`                         | Require External Account Binding for account registration |
| `acme.issuance_scope`               | `managed_zones`                | `managed_zones` (zone must have a CA) or `any`          |

The `dot`, `doh`, `doq`, `proxy`, and `acme` sections are optional. When omitted, the corresponding transport/service is not started. When `acme` is present, the root CA is created at boot and both the ACME and portal listeners start.

## Build System

The project uses a top-level Makefile with the following targets:

| Target                | Description                                                                                                                                                |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `help`                | Print all targets with their descriptions, grouped by section. The default goal, so bare `make` shows it. Descriptions come from `##` annotations on the target lines; `##@` lines start sections. |
| `build`               | Compile the Rust project in debug mode (`cargo build`). Produces the `rolodex-dns` server and `rolodex-dns-cli` client binaries.                           |
| `test`                | Run all tests: lint, Go integration tests, Go unit tests, Rust tests (`cargo test`), and JavaScript tests.                                                 |
| `lint`                | Run `cargo fmt -- --check` and `cargo clippy -- -D warnings`.                                                                                             |
| `deps`                | Install JavaScript dev dependencies (`npm install` in `js/`).                                                                                              |
| `js-lint`             | Run eslint on the JavaScript package (depends on `deps`).                                                                                                  |
| `js-test`             | Run JavaScript unit tests (depends on `js-integration-test`).                                                                                              |
| `js-integration-test` | Build the Rust binaries, lint, then run JavaScript integration tests with `ROLODEX_DNS_BINARY` pointing at the compiled server.                            |
| `bench`               | Run criterion benchmarks (`cargo bench --bench dns_perf`). Benchmarks cover QNAME randomization, cache key generation, DB lookups, zone matching, and cache operations. |
| `clean`               | Clean build artifacts (`cargo clean`).                                                                                                                     |
| `go-test`             | Run Go unit tests (depends on `go-integration-test`).                                                                                                      |
| `go-integration-test` | Build the Rust binaries, then run Go integration tests with the `integration` build tag, passing the compiled server binary path via `ROLODEX_DNS_BINARY`. |
| `install`             | Install the Rust binaries to the Cargo bin directory (`cargo install --path .`).                                                                           |
| `dev`                 | Build the Rust project in debug mode, then start a development server using `dev.yml`.                                                                     |
| `dev-release`         | Build the Rust project in release mode, then start a development server using `dev.yml`.                                                                   |
| `image`               | Build a container image for the host architecture using `make/build.sh release`. Tags with a `uname -m` arch suffix (`-x86_64`/`-aarch64`). Accepts `IMAGE_TAG` (default `latest`). |
| `push` / `push-rc`    | Build and push the host-arch release candidate image to `quay.io/town/rolodex`. Auto-tags `rc.YYYYMMDD-<arch>` + `` rc.latest-`uname -m` `` (e.g. `rc.latest-x86_64`/`rc.latest-aarch64`) unless `IMAGE_TAG` is set.   |
| `push-arch`           | Build and push ONLY the current host's per-arch tag (`<IMAGE_TAG\|latest>-<arch>`) to `quay.io/town/rolodex`. No date/`rc`/`latest` aliases, no manifest.       |
| `push-release`        | Build and push the host-arch release image to `quay.io/town/rolodex`. Auto-tags `release.YYYYMMDD-<arch>` + `latest-<arch>` unless `IMAGE_TAG` is set.             |
| `image-amd64`         | Build the amd64 image inside the builder VM (`make/amd64-vm.sh`) and import it into host podman. |
| `push-rc-amd64` / `push-release-amd64` | Build and push the amd64 RC/release image from inside the builder VM (pushes straight to the registry). |
| `push-rc-all` / `push-release-all` | Publish **both** arches from a single arm64 host — native arm64 here, amd64 in the VM — then assemble the manifest. |
| `amd64-vm-up` / `-down` / `-destroy` / `-status` / `-ssh` | Manage the amd64 builder VM lifecycle (`make/amd64-vm.sh`). |
| `manifest` / `manifest-rc` | Assemble and push a multi-arch RC manifest list (`rc.YYYYMMDD`, `rc.latest`, or `IMAGE_TAG`) from the per-arch tags already in the registry. The `rc.latest` list is assembled from the `uname -m`-suffixed tags (`rc.latest-x86_64`, `rc.latest-aarch64`). |
| `manifest-release`    | Assemble and push a multi-arch release manifest list (`release.YYYYMMDD`, `latest`, or `IMAGE_TAG`) from the per-arch tags already in the registry.                |
| `quay-login`          | Login to Quay.io using `QUAY_USERNAME` and `QUAY_PASSWORD` from environment or `.env`.                                                                     |
| `clean-containers`    | Remove locally built per-arch container images.                                                                                                            |

The Makefile is designed to be extended for non-cargo scenarios. Protocol buffer bindings are generated at build time via `build.rs` using `tonic-prost-build`. Container images are built with Podman using unique instance IDs derived from the working directory path.

### Multi-Architecture Container Builds

Images are published to `quay.io/town/rolodex` as multi-arch manifest lists covering `linux/amd64` and `linux/arm64` (the OCI platform names embedded in the manifest by podman). Builds are **native**: each architecture is compiled on a host of that architecture (no in-container cross-compilation). `make/build.sh` detects the host arch via `host_arch` in `make/lib.sh`, which echoes the raw `uname -m` machine name (`x86_64`/`aarch64`), and suffixes **every** per-arch image tag with it — including `rc.latest` (`rc.latest-x86_64`/`rc.latest-aarch64`) — so deploy hosts can pull `` <tag>-`uname -m` `` directly without any OCI-name mapping. `ARCHES` in `make/lib.sh` holds the same `x86_64 aarch64` machine names used as manifest suffixes. The `build_manifest` helper assembles a manifest list from the per-arch tags using `podman manifest add docker://…`, so the per-arch images only need to exist in the registry, not locally.

**amd64 builder VM (`make/amd64-vm.sh`).** To build amd64 images from an arm64 host (e.g. Fedora Asahi), in-container user-mode emulation is **not** an option: Fedora Asahi's x86 emulation runs through FEX + `binfmt-dispatcher` + `muvm`, which on a 16k-page kernel executes the emulator inside a 4k-page microVM and is not usable inside a `podman build` sandbox (even a bare `podman run --platform linux/amd64` fails there). Instead, amd64 is built **natively inside a full-system qemu VM**: `make/amd64-vm.sh` boots a Debian cloud image under `qemu-system-x86_64` (TCG — there is no KVM for x86 on arm), provisions podman via cloud-init, `rsync`s the repo in, and runs the ordinary `make image`/push targets inside the guest (where `host_arch` is genuinely `x86_64`). `make image-amd64` builds in the VM and streams the result back to host podman via `podman save | podman load`; `make push-rc-amd64`/`push-release-amd64` push straight to the registry from the guest (forwarding `QUAY_*`). VM state lives under `.cache/amd64-vm/` (gitignored); tunables: `VM_MEM`, `VM_CPUS`, `VM_DISK_SIZE`, `VM_SSH_PORT`, `VM_IMAGE_URL`. TCG builds are slow — expect minutes-to-tens-of-minutes.

**Build network.** `podman build` RUN steps run in their own network namespace, which cannot reach a resolver on the host's loopback (e.g. rolodex on `127.0.0.1`). `build.sh` therefore passes `--network=host` to both `podman build` invocations so RUN steps use the host's `/etc/resolv.conf`. Override with `BUILD_NETWORK=` (empty, to opt out) or `BUILD_NETWORK=<name>` (another podman network).

The end-to-end multi-arch publish flow — either build each arch on its own native host:

1. On an amd64 host: `make push-release` → pushes `…:latest-x86_64` (+ date tag).
2. On an arm64 host: `make push-release` → pushes `…:latest-aarch64` (+ date tag).
3. On any host, once both are pushed: `make manifest-release` → pushes the `…:latest` manifest list.

— or, from a single arm64 host, `make push-release-all` (native arm64 + amd64 in the VM, then the manifest); `push-rc-all` is the RC equivalent.

### Container Image Tagging

Images are published to `quay.io/town/rolodex`. The `IMAGE_TAG` variable controls the tag used for both building and pushing. Per-arch images carry an arch suffix; the manifest targets produce the un-suffixed multi-arch tag.

**Push with auto-generated tags** (default):

```bash
make push-rc          # pushes rc.YYYYMMDD-<arch> and rc.latest-$(uname -m)
make push-release     # pushes release.YYYYMMDD-<arch> and latest-<arch>
make manifest-rc      # pushes rc.YYYYMMDD and rc.latest manifest lists
make manifest-release # pushes release.YYYYMMDD and latest manifest lists
```

**Push a specific tag**:

```bash
make IMAGE_TAG=v1.2.3 push-release      # pushes quay.io/town/rolodex:v1.2.3-<arch>
make IMAGE_TAG=v1.2.3 manifest-release  # pushes quay.io/town/rolodex:v1.2.3 manifest list
make IMAGE_TAG=v1.2.3-rc1 push-rc       # pushes quay.io/town/rolodex:v1.2.3-rc1-<arch>
```

When `IMAGE_TAG` is set, only that exact tag (per-arch, then manifest) is pushed — no date-based or `latest` tags are created.

**Re-tag and push to a different registry**:

```bash
sudo podman tag quay.io/town/rolodex:latest registry.example.com/myorg/rolodex:v1.2.3
sudo podman push quay.io/town/rolodex:latest registry.example.com/myorg/rolodex:v1.2.3
```

### Development Server

The `make dev` target starts a local development instance configured via `dev.yml`:

- DNS listeners on `127.0.0.1:5300` and the primary outbound IP on port `5300` (UDP and TCP) — a non-privileged port that does not require root.
- gRPC management via Unix socket at `/tmp/rolodex-dns.sock` only (TCP gRPC disabled).
- Database at `/tmp/rolodex-dns-dev.db`.
- No authentication (empty shared secret).
- RBL disabled.
- Google DNS forwarders (`8.8.8.8:53`, `8.8.4.4:53`).

The `make dev-release` target does the same but builds with `--release` for optimized performance.

## Testing

### Rust Tests

Rust tests (`cargo test`) include unit tests and integration tests covering gRPC operations, DNS resolution (UDP and TCP), split-horizon behavior, authentication enforcement, Unix socket auth bypass, database persistence, configuration serialization, EDNS handling, TTL drift calculations, latency tracking, and IPAM.

### Performance Unit Tests

Performance-related unit tests cover the optimized hot-path code:

- **QNAME randomization** (`src/dns_server.rs`): Tests for `extract_qname` (simple names, subdomains, single labels, root label, truncated input, empty input) and `randomize_qname_case` (structure preservation, alpha-only changes, round-trip name consistency, short input rejection).
- **Batched DB lookups** (`src/db.rs`): Tests for `lookup_with_fallbacks` covering exact hit, wildcard fallback with qname substitution, CNAME fallback, ANAME fallback, all-at-once mixed results, complete miss, and exact-over-CNAME priority.
- **Zone matching** (`src/db.rs`): Tests for `matches_zone_suffix` (exact match, subdomain, deep subdomain, no match, empty cache, TLD-level), `find_managed_zone` (match and miss), `find_authoritative_zone` (match, exact, miss).
- **Cache key generation** (`src/dns_cache.rs`): Tests for `cache_key` with specific types, wildcard type, various record types, and consistency.
- **Arc-based cache** (`src/dns_cache.rs`): Tests for local insert with no TTL decay, empty-vec no-op, and multiple records under same key.
- **DoH connection pool** (`src/doh_proxy.rs`): Tests for pool cap enforcement (max 8), new connection creation, and pooled connection reuse.

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

The `make test` target runs the full test suite: Go integration tests, Go unit tests, Rust integration tests (each test file explicitly: `integration_test`, `new_features_test`, `cli_integration_test`, `dhcp_integration_test`, `acme_issuer_test`), all Rust tests via `cargo test`, and the JavaScript lint/integration/unit tests. Individual targets are available: `make go-integration-test`, `make go-test`, `make rust-integration-test`, `make rust-test`, `make js-integration-test`, `make js-test`.

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
- **rcgen** (with `x509-parser` feature) — certificate generation and CA signing (root → per-zone intermediate → leaf-from-CSR)
- **x509-parser** — SPKI extraction for TLSA records and CA import
- **time** — certificate validity periods and RFC 3339 timestamps in ACME responses
- **axum** / **axum-server** — HTTP framework for DoH
- **quinn** — QUIC protocol for DoQ
- **ring** / **sha2** — Cryptographic operations for DNSSEC and DANE
- **base64** — Base64 encoding for DoH GET requests
- **hex** — Hex encoding for TLSA/DNSSEC records
- **serde** / **serde_yaml_ng** — Configuration serialization
- **fancy_duration** — Compound duration parsing for TTL drift
- **rand** — QNAME case randomization
- **nix** — Safe Unix interface abstractions (interface address enumeration via `getifaddrs`)
- **anyhow** / **thiserror** — Error handling

### Dev / Benchmarks

- **criterion** — Micro-benchmarking framework for performance regression testing

### Go

- **google.golang.org/grpc** — gRPC framework
- **google.golang.org/protobuf** — Protocol buffer runtime

## Concurrency Model

The server runs on the tokio multi-threaded async runtime. DNS UDP queries are handled sequentially on a single task. DNS TCP connections spawn a new task per connection. DoT, DoH, and DoQ connections each spawn a new task per connection. gRPC servers (TCP and Unix socket) run as separate tasks. Upstream forwarder configuration is protected by `ArcSwap` for lock-free reads. RBL state uses lock-free primitives: the enabled flag is an `AtomicBool` and the provider list uses `ArcSwap` for zero-contention reads. The RBL cache and DNS response cache use lock-free `DashMap`. The SQLite database is protected by a `Mutex` with `prepare_cached` for statement reuse.

At boot, in-memory caches are populated from the database: scope count (`AtomicUsize`), local RBL entries (`DashSet`), authoritative zones (`DashSet`), and managed zones (`DashSet`). These caches avoid SQL queries on the hot path and are updated incrementally as records are added or removed via gRPC.

Upstream DNS forwarding uses a pool of 8 UDP sockets, allowing concurrent forwarding without contention on a single socket. Socket selection uses round-robin via `AtomicUsize`.

The in-memory DNS cache is automatically flushed when records are mutated via gRPC (add, remove, or scoped variants) to ensure consistency between the database and cached responses. Local database records are cached with a `local` flag that prevents TTL decay and SQLite persistence, since they are authoritative.

TTL drift configuration uses `ArcSwap` for lock-free reads, matching the pattern used for forwarder configuration.

### Performance Optimizations

The DNS hot path uses several optimizations to minimize allocations and lock contention:

- **QNAME case randomization** operates directly on DNS wire-format bytes (toggling the 0x20 bit on ASCII alpha bytes) instead of parsing, cloning, rebuilding, and re-serializing the entire DNS message. This avoids ~6 allocations per forwarded query.
- **Batched DB lookups** (`lookup_with_fallbacks`) combine exact, wildcard, CNAME, and ANAME lookups into a single SQL `UNION ALL` query, reducing lock acquisitions from 4+ to 1 per query.
- **Zone matching** uses O(labels) suffix-based `DashSet` lookups (`find_managed_zone`, `find_authoritative_zone`) instead of O(zones) linear iteration with `ends_with()`.
- **DNS cache** stores records as `Arc<Vec<DnsRecord>>` to eliminate cloning on cache insertion and local cache hits. Cache keys use pre-sized `String::with_capacity` without redundant `to_lowercase()` (names are already normalized).
- **Batched cache persistence** uses a bounded `mpsc` channel (capacity 1024) with a single background worker that drains up to 64 writes at a time, replacing per-insert `tokio::spawn`.
- **UDP buffer reuse** allocates the receive buffer once outside the loop and clones only `len` bytes (via `Vec::with_capacity` + `extend_from_slice`) instead of always copying the full 4096-byte buffer.
- **DoH proxy connection pooling** reuses TCP connections via a per-proxy-address `DashMap` pool (max 8 connections per address) with HTTP/1.1 keep-alive instead of `Connection: close`.

### Benchmarks

Criterion benchmarks in `benches/dns_perf.rs` cover the performance-critical paths. Run with `make bench`. Benchmarked operations:

- `qname_randomize` / `qname_randomize_long_name` — Wire-format QNAME case randomization
- `cache_key_with_type` / `cache_key_wildcard` — Cache key generation
- `lookup_with_fallbacks_exact_hit` / `_miss` / `_wildcard` — Batched UNION ALL DB lookups
- `lookup_original_exact_hit` / `_miss` — Original single-query DB lookups (for comparison)
- `find_managed_zone_hit` / `_miss` — O(labels) zone matching
- `find_authoritative_zone_hit` / `_miss` — O(labels) authoritative zone matching
- `is_authoritative_zone_hit` / `_miss` — Combined zone check
- `cache_lookup_local_hit` / `cache_lookup_upstream_hit` / `cache_lookup_miss` — DNS cache lookups
- `cache_insert_local` — DNS cache insertion
- `handle_query_local_hit` / `handle_query_local_nxdomain` — End-to-end query pipeline (parse → resolve → serialize)
- `handle_query_cached_hit` — Query pipeline with DNS cache enabled (cache hit path)
- `handle_query_A` / `_AAAA` / `_TXT` / `_MX` — Query pipeline across record types
- `handle_query_scoped_hit` — Query pipeline with network scoping (split-horizon)
- `udp_round_trip` / `udp_round_trip_reuse_socket` — Full UDP socket round-trip (new vs reused client socket)
- `tcp_round_trip_new_conn` / `tcp_round_trip_reuse_conn` — Full TCP round-trip with 2-byte length framing (new vs reused connection)
