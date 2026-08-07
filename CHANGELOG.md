# Changelog

## Unreleased

### Features

- **DNSBL allowlist — specific hosts can be exempted from the blocklist check.** A blocklist provider that false-positives on a name previously left the operator with no recourse short of disabling the provider or the whole DNSBL. Names on the allowlist (stored in the `dnsbl_allowlist` table, with a reason) skip step 7 of resolution entirely.

  An entry is **suffix-matched on label boundaries**, so allowlisting `example.com` also exempts `www.example.com` but not `notexample.com`, and it is stored normalized (lowercase, trailing dot) so any spelling adds or removes the same entry. The check short-circuits the whole name-based step — neither the configured DNSBL providers nor the local RBL blocklist can block an exempt name — and it runs *before* the provider lookup, so an exempt name issues no blocklist query at all. Reverse-DNS IP blocking is unaffected. Lookups are O(labels) against a `DashSet` mirrored from the table and reloaded at boot, so the hot path costs an empty-set check when no allowlist is configured.

  Managed via `AddDnsblAllowlistEntry` / `RemoveDnsblAllowlistEntry` / `ListDnsblAllowlistEntries` (gRPC and Go client), or `add-dnsbl-allow` / `remove-dnsbl-allow` / `list-dnsbl-allow` on the CLI.

## v0.4.2 (2026-08-06)

### Bug Fixes

- **The upstream response cache was a near-total no-op.** Two independent key bugs meant answers were written under keys no lookup could ever reproduce, so nearly every query paid a full upstream round trip no matter how recently the same name had been resolved.

  `cache_answers` keyed each entry on the first *answer record* rather than on the question. That is wrong for any name behind a CNAME: `index.crates.io A` comes back as a chain — `index.crates.io CNAME` → `fastly-index.crates.io CNAME` → A records on a third name — whose first record is a CNAME, so the entry landed under `index.crates.io.:CNAME` while every lookup asked for `index.crates.io.:A`. Those keys never meet, so the name was *permanently* uncacheable. That is most of the CDN-fronted internet (Fastly, CloudFront, S3). It went unnoticed because a name like `example.com` answers with an A record for itself, making the wrong key accidentally correct — and every test used a name of that shape.

  `cache_key` separately trusted its caller to have normalized the name. The two sides of the cache do not see the same case: reads use the case the client sent, writes use the case the question came back in, and with 0x20 encoding (`security.qname_case_randomization`, on by default) a forwarded query goes out as `eXaMpLe.CoM` and the response echoes that back. Every upstream answer was therefore filed under a randomly-cased key, which disabled the cache wholesale — every name, not only chained ones.

  Both paths now key on the question, `question.name()` + the question's type, which is the key the read path looks up and the rule `cache_negative` already followed. The whole answer set, CNAME chain included, is stored under that one key. A response carrying no question cannot be keyed correctly and is no longer cached at all rather than cached somewhere nothing will look. `cache_key` lowercases as it fills the key, which costs no extra allocation because the `String` was being allocated anyway.

### Build

- **Both architectures are cross-compiled on whatever host runs `make`; the builder VM is gone.** Multi-arch images were previously built by spinning up an x86_64 QEMU VM (`make/amd64-vm.sh`) whenever the host could not run the foreign architecture — an entire virtual machine standing in for a toolchain. The two published images now differ only in their target triple rather than in how they were produced.

  `cargo-zigbuild` (`make/cross.sh`) supplies the C cross-compiler that `rusqlite` (bundled SQLite sources) and `ring` require — `rustup target add` alone dies at the `cc` step — and links against a pinned glibc (`GLIBC_VERSION`, default `2.36`, matching `debian:bookworm`) so the binary runs on the runtime base image regardless of the build host's own glibc. The whole toolchain installs without root: `rustup target add`, `cargo install cargo-zigbuild`, and a zig tarball extracted under `.cache/zig/`, so `make deps` provisions it anywhere instead of depending on distro-specific cross-gcc packages.

  The runtime `Containerfile` now only `COPY`s — the cross-compiled binaries and a CA bundle taken from the build host. With zero `RUN` steps, `podman build --platform linux/<arch>` never has to *execute* anything of the target architecture, so a foreign-arch image needs no user-mode emulation at all. That is what removes the VM rather than relocating the problem: on hosts such as Fedora Asahi, x86 emulation runs through FEX + `binfmt-dispatcher` + `muvm` and is unusable inside a `podman build` sandbox. `Containerfile.build` is removed along with it, and `--network=host` is no longer passed by default since nothing in the image build resolves DNS.

- `TARGET` now selects the architecture for **every** container target (`image`, `push-arch`, `push-rc`, `push-release`), mirroring the model used by the `install` repo so one `TARGET=` value passes across the town-os repos. Board flavors (`rpi`, `rg35xxpro`, `anbernic`, …) resolve to their architecture; an unrecognized value is a hard error at parse time. Any host can build any architecture — `CROSS` is derived, not a user knob. `push-rc-all` / `push-release-all` publish both arches and assemble the manifest from a single host of either architecture.

## v0.4.1 (2026-08-06)

### Performance

- **The UDP listener is sharded across `SO_REUSEPORT` sockets.** A single UDP socket serialised the entire listener: one task drained it with `recv_from` and every reply went back out through that same socket, so receive was single-threaded and the kernel took a per-socket lock in both directions. Spawning a task per query fanned the *handling* across cores but never the socket, so throughput flattened while the machine sat idle — on a 16-core host the server plateaued at ~104k qps while burning under one core, and past that point additional client concurrency only inflated latency (p99 1.70ms at 32 concurrent clients) instead of adding throughput. Each UDP listen address now binds `dns.udp_shards` sockets to the same `addr:port`, each with its own receive loop and its own socket for replies, and the kernel hashes arriving datagrams across them. Measured on 16 cores against a local record, before → after: 68k → 101k qps at 4 concurrent clients, 99k → 168k at 16, and 104k → 257k at 32 (p99 1.70ms → 432µs). The old path had already flattened by 32 clients; the sharded one is still climbing at 128 (477k qps) with the server at 2.87 of 16 cores, so the remaining ceiling is the load generator rather than the server.

  `SO_REUSEPORT` is set **only** when more than one shard is requested. Linux shares a port only when every socket bound to it carries the option, so a single-shard listener still collides on a busy port — which is what the ingress bind-failure handling depends on. Setting it unconditionally would have made a failed ingress bind start "succeeding" against a port owned by another process and silently take a share of its traffic. Shards are owned by the `serve_udp` future (in a `JoinSet`) rather than by the caller, so `stop_ingress_listener` still tears all of them down through its single abort handle; and a port-`0` bind is forced to one shard, because the kernel hands each socket a *different* ephemeral port and there is nothing coherent to share.

### Configuration

- `dns.udp_shards` (default `0`) — number of `SO_REUSEPORT` sockets bound per UDP listen address. `0` means one shard per available core; `1` restores the previous single-socket listener.

### Documentation

- The Concurrency Model section described DNS UDP queries as "handled sequentially on a single task", which had been stale since queries were moved to a task each; it now describes the shard fan-out and the three constraints above.

## v0.4.0 (2026-08-05)

### Changes

- **An ingress DNS listener now resolves the whole namespace, not just its own TLD.** Scope selection was keyed on the queried *name*: `ingress_target` started from `find_tld_owner(qname)`, so a name under no owned TLD returned `None` and the query lost its association with the listener it arrived on. It then fell through to the source-IP branch, where a WireGuard peer sits inside `security.overlay_cidrs` but was never `JoinNetwork`'d (only the box's own ingress address is joined, never the peers) — and was REFUSED as an unassociated overlay peer. The listener therefore answered its own TLD and nothing else: a client on the network resolved `gitea.default.fart` but got REFUSED for `google.com`, so the network's DNS server could not resolve the internet it is the resolver for.

  The scope is now selected from the **listener** (`db::scope_for_ingress_ip`, the reverse of the per-TLD ingress mapping), not from the name. A query arriving on an ingress listener belongs to that listener's owning scope whatever the name is: owned TLDs stay partitioned (a sibling network's TLD is still an authoritative NXDOMAIN), and every other name falls through to global resolution and upstream forwarding. The answer **rewrite** to the ingress IP remains name-gated, so a pass-through name keeps its resolved value. Scope enforcement off the ingress listeners is unchanged.

### Documentation

- `CLAUDE.md` and `README.md` brought up to date with the resolver work landed in v0.3.x: the `auto` tier chain, the iterative resolver's server selection/backoff/bounds, the delegation and record caches (including what `flush_cache` versus `flush_upstream_state` clears), TTL semantics, and the ingress-listener scope rules above.

## v0.3.3 (2026-07-14)

### Bug Fixes

- **A failed ingress bind no longer poisons its IP for the life of the process.** `spawn_ingress_listener` recorded the UDP+TCP abort handles unconditionally, before either task had tried to bind, so a listener that failed to bind left behind an entry claiming the address was served while nothing listened on it — and the presence-only guard made every later re-add early-return on that corpse. This bit the common case: a network TLD's ingress IP is a WireGuard overlay address that `sync_ingress_listeners` replays from the database at startup, *before* the tunnel interface exists, so both tasks failed `EADDRNOTAVAIL` and exited; a box that rebooted with a network configured could never serve DNS on that overlay again. An entry whose tasks have all finished is now treated as absent — dropped and respawned — so a re-add actually retries the bind once the interface is up.

## v0.3.2 (2026-07-11)

### Performance

- **Delegation caching for the iterative resolver** — the zone → nameserver delegations learned while walking down from the root servers are now cached, so a cold name no longer re-walks root → TLD on every lookup. Long-lived delegations (root and TLD NS sets carry multi-day TTLs) are persisted to a new `delegation_cache` table, gated by `resolution.delegation_persist_min_ttl` (default 300s), so a restart comes back warm.
- **The whole recursion is cached, not just the delegation** — glue, glue-less NS-name lookups, and CNAME hops arrive with TTLs and were previously discarded after a single use. They are now kept keyed by `(name, type)` and handed back with their *remaining* lifetime, so a served record is never re-cached upstream at full TTL. Authoritative NXDOMAIN/NODATA answers are cached in a separate negatives map, leaving the positive paths free to treat "no records" as a miss.
- **Load spread across the root servers** — server selection now scores by `hits * ema_latency` instead of pure sort-by-RTT, which drove every query to a single fastest root. The product drives toward equality across the group, allocating queries as `hits ∝ 1/latency`: fast servers carry more, every healthy server carries some. An unqueried server scores 0, is tried first, and learns its latency from a query that had to happen anyway — no pre-measurement and no explore-probability branch.
- **Root priming** — the live root NS set is fetched once at startup and cached as the `.` delegation with its real TTL. The hardcoded `ROOT_HINTS` become what they should be: a bootstrap, and the fallback when priming fails.

### Bug Fixes

- **Failed upstream servers now actually recover.** Failures are tracked as an explicit exponential backoff (2s, doubling, capped at 300s, cleared on the first success) rather than folded into the latency EMA as a synthetic 10s RTT. Folding them in tied recovery to how fast the healthy peers happened to be — against a 0.3ms peer, a 10s penalty gave a dead server a 1-in-33,000 share, so it was never retried and never came back. Backed-off servers sort behind healthy ones within their address family but are never removed, so resolution continues even if everything is failing.
- **The DNS cache boot load always loaded 0 entries** — it called `cache_lookup` with an empty name; a new `cache_load_all` performs the query it should have been making.
- **Duplicate `dns_cache` rows** — re-caching a response appended a row instead of updating it. Existing duplicates are collapsed and a unique index makes `cache_insert` upsert.
- **`flush_cache` no longer discards delegations.** Every gRPC record mutation calls it, which was throwing away the upstream state on every local record change; tier switches use a separate `flush_upstream_state`.

### Configuration

- `resolution.delegation_persist_min_ttl` (default 300) — minimum TTL for a delegation to be persisted across restarts.
- `resolution.default_ttl` (default 300) — TTL applied wherever a record or response supplies none of its own (an NXDOMAIN/NODATA with no SOA, a zero-TTL delegation or glue record). A TTL that *is* present is always honoured exactly as sent, including an SOA's negative TTL, which is never clamped.

## v0.3.1 (2026-07-10)

### New Features

- **LAN → owning-scope resolution fallback** — a trusted local source (loopback / LAN, associated with no scope) now resolves **every** owned network TLD from its owning scope, so all network TLDs are visible on the LAN even though records are stored scoped. The fallback runs after the global lookup (a dual-homed name's LAN-facing global record still wins) and before upstream forwarding: scoped-only names (e.g. a network's zone apex) are served from the owning scope at their stored value, the TLD's peer forwarders are consulted next, and failing everything an **authoritative NXDOMAIN** is returned — a privately-owned TLD is never forwarded upstream from the LAN. Overlay peers are unaffected and remain strictly partitioned (a peer joined to one network sees only its own TLD and gets NXDOMAIN for a sibling network's TLD), which lets a scope be created purely to *own* a TLD (partitioned-from-peers, LAN-resolvable) without binding any WireGuard overlay to it.

### Build

- **Live `go test` output** — the `go-test` and `go-integration-test` Makefile targets now run `go test` in local-directory mode (dropping the `./...` package pattern) so verbose (`-v`) output streams as tests run instead of being buffered per-package until completion. All Go tests live in the root `go/` package, so coverage is unchanged.

## v0.3.0 (2026-07-02)

### New Features

- **Resilient `auto` upstream resolution with a DoH-preferred secure tier** — the resolver now follows a tiered fallback chain (roots → DoH/DoT → local forwarder → public :53) instead of roots-only, so it keeps resolving on networks that filter outbound :53 (and DoT's :853). DoH on :443 is preferred. A sticky active tier avoids per-query timeouts on dead tiers, a periodic recovery probe reclaims a tier once it comes back, tier switches are gated behind a failure grace period, and every committed switch flushes the DNS cache as a cross-tier cache-poisoning guard. Configured via the `resolution` section (`mode = auto`, `secure_upstreams`, `public_fallback`, `switch_grace_failures`, `recovery_probe_secs`).
- **Address-family routability probe** — a new `address_family` config section and background probe periodically TCP-connect to public v4/v6 targets on :443 to test real internet reachability. In `auto` mode (default) the server stops returning A or AAAA answers for a family the host cannot reach, so clients fall back to the working stack instead of stalling on a dead-family address. `off` always answers both families (legacy); `force4`/`force6` pin one family without probing. A failure threshold debounces flaps, recovery is immediate on the first success, and the first probe at boot is decisive (no grace) so a boot onto a dead-family link suppresses it from the first query.

### Bug Fixes

- **RBL/DNSBL lookups no longer loop through the local stub.** Blocklist queries (`<name>.<zone>`) previously went out via the system resolver, which on a typical host pointed back at rolodex itself — re-entering the query handler, getting DNSBL-checked again, appending the zone once more, and looping forever (`<name>.<zone>.<zone>…`), wedging all resolution. The `RecursiveRblResolver` now resolves blocklist names the same way rolodex resolves everything else: recursively from the roots on its own sockets (never the local stub), falling back to the configured forwarder over UDP when the roots aren't reachable. Total failure fails open (treated as not-listed).
- **RBL/DNSBL checks skip resolver-backed providers when outbound :53 is filtered** (detected by a background probe), so a filtered network doesn't stall resolution; local database-backed RBL entries are unaffected.

### Performance

- **Fire-and-forget async cache filling for RBL/DNSBL checks** — blocklist cache population no longer blocks the resolution path.

### Infrastructure

- **Reproducible-image guarantees** — `make/build.sh` computes `SOURCE_REV` (git short HEAD, `+dirty` when the tree is modified) and threads it into both image builds: the builder stage references it right before `cargo build` so a changed commit always invalidates the compile layer (no stale binary shipped from a reused cache layer), and the runtime image stamps `org.opencontainers.image.revision` so a pushed image self-identifies via `skopeo inspect`.

### Code Quality

- The live DoH/DoT upstream test is now reachability-gated instead of unconditionally ignored, so it actually exercises the secure tier where the network allows it.

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
