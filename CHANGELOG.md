# Changelog

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
