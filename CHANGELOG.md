# Changelog

## v0.2.4 (2026-06-28)

### New Features

- **DNSBL (domain blocklists)** — a domain-name blocklist facility, separate from the IP-based RBL. DNSBL providers (e.g. Spamhaus DBL, SURBL, URIBL) are queried by prepending the looked-up name to the zone (`<name>.<zone>`), as opposed to the reversed-IP form used by RBL. DNSBL listings take **precedence over any externally-resolved answer** — forwarded, iterative-from-roots, or upstream-cached — while local records and managed/authoritative zones always win. Configurable at startup via the `dnsbl` config section and at runtime via the new `SetDnsblConfig`/`GetDnsblConfig` gRPC endpoints, the `set-dnsbl-config`/`get-dnsbl-config` CLI subcommands, and the Go client `SetDnsblConfig`/`GetDnsblConfig` methods (`DnsblConfig`/`DnsblStatus` types).
- **RBL/DNSBL in the resolution caching pipeline** — local-RBL and DNSBL checks now apply to forward domain names after local/zone resolution but before the upstream cache and forwarder, so a blocklisted name is refused with NXDOMAIN even when an upstream answer was previously cached. The DNS cache's "local records first" stage now serves only authoritative local entries (via `lookup_local_only`); upstream-cached entries are served after the blocklist gate.

### Changes

- **RBL and DNSBL provider lists now default to empty.** Previously the RBL shipped five default zones; no external blocklist is queried until the operator configures providers (via config or `Set{Rbl,Dnsbl}Config`). An enabled-but-empty blocklist is a no-op.

### Code Quality

- `make lint` now runs `cargo clippy --all-targets`, linting tests and benches in addition to the library. Fixed the pre-existing findings this surfaced: a `RefCell` borrow held across an `await` in the benchmarks, clone-on-`Copy` in tests, `assert!(true)` placeholders, and `field_reassign_with_default` in config tests.
- New unit, integration, CLI, and Go tests covering DNSBL resolution and precedence (including precedence over upstream-cached answers), empty-blocklist no-op behavior, and the gRPC/CLI/Go programmable endpoints.

## v0.2.3 (2026-06-28)

### New Features

- **Iterative root-based resolution** is now the default upstream mode — queries are resolved recursively starting at the root servers, with the previous `forward` mode still selectable.
- **Automatic reverse PTR records** — opt-in `dns.auto_ptr` makes A/AAAA records added through the gRPC management interface automatically maintain a matching `in-addr.arpa`/`ip6.arpa` PTR record.
- **ACME issuer / certificate authority** (RFC 8555, server side) — Rolodex acts as its own CA: a self-signed root signs per-zone intermediates that issue leaf certificates through ACME, validated dns-01 against Rolodex's own DNS data. Includes External Account Binding, automatic DANE-TA TLSA publication, a trusted-network web enrollment portal, a browser extension, and a JavaScript client library with DANE retrieval.
- **CA distribution over DNS** — the root and intermediate CA chain is published into the DNS database as CERT (RFC 4398) and chunked TXT records, so any client that can resolve the zone can retrieve and trust the CA without portal access.

### Infrastructure

- Native multi-architecture (amd64/arm64) container builds published to `quay.io/town/rolodex`, including an amd64 builder VM for arm64 hosts and per-arch image tags suffixed with `uname -m`.
- Unified DNS bind configuration with the `primary` (auto-detect outbound IP) and `interface:port` (bind every address on a named interface) keywords.
- Added the `repository` field to `Cargo.toml`.

## v0.2.0-alpha (2026-03-27)

### New Features

- **DHCP server** with integrated IPAM, automatic DNS hostname registration (A + PTR scoped records), sticky MAC-to-IP bindings, background lease sweep, and full DISCOVER/OFFER/REQUEST/ACK flow
- **Per-scope RBL providers** — network scopes can opt into additional RBL providers beyond the global configuration
- **DHCP certificate delivery** — certificates delivered to clients via site-specific DHCP options (codes 224-254)
- **SOCKS5 proxy** support for upstream DNS forwarding (RFC 1928), alongside existing HTTP CONNECT and DoH proxy modes
- **HTTP/3 (QUIC) transport** for DNS-over-HTTPS via `enable_h3` configuration flag
- **Criterion benchmarks** (`make bench`) covering QNAME randomization, cache operations, DB lookups, zone matching, query pipeline, and UDP/TCP round-trips

### Performance

- **In-place QNAME case randomization** — operates directly on DNS wire-format bytes (0x20 bit toggle) instead of parsing, cloning, rebuilding, and re-serializing the entire DNS message; eliminates ~6 allocations per forwarded query
- **Batched DB lookups** — `lookup_with_fallbacks()` combines exact, wildcard, CNAME, and ANAME lookups into a single SQL `UNION ALL` query, reducing mutex lock acquisitions from 4+ to 1 per query
- **O(labels) zone matching** — `find_managed_zone()` and `find_authoritative_zone()` walk DNS label suffixes against a `DashSet` instead of O(zones) linear iteration with `ends_with()`
- **Arc-wrapped cache records** — DNS cache stores `Arc<Vec<DnsRecord>>` to eliminate cloning on cache insertion and local cache hits
- **Batched cache persistence** — bounded `mpsc` channel (capacity 1024) with a single background worker replaces per-insert `tokio::spawn`, draining up to 64 writes at a time
- **Optimized cache keys** — pre-sized `String::with_capacity` without redundant `to_lowercase()` (names already normalized)
- **UDP buffer sizing** — receive buffer allocated once outside loop; clone sized to actual packet length via `Vec::with_capacity` + `extend_from_slice`
- **DoH proxy connection pooling** — reusable TCP connections via per-proxy-address `DashMap` pool (max 8 per address) with HTTP/1.1 keep-alive

### Code Quality

- Eliminated all `unwrap()` calls, `let _ = expr;` suppressions, and dead code throughout the codebase
- Added `lint` Makefile target (`cargo fmt --check` + `cargo clippy -D warnings`)
- `#![deny(dead_code)]` and `#![deny(unsafe_code)]` enforced at crate level in both lib.rs and main.rs
- 40 new unit tests covering all performance-optimized code paths
- Comprehensive CLAUDE.md specification updated with all new features, performance patterns, and benchmark documentation

### Infrastructure

- Container image switched to `quay.io/town/rolodex`
- All dependencies updated to latest compatible versions

## v0.1.0

Initial release.
