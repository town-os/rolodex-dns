# Rolodex DNS Functional Specification

Rolodex DNS is a split-horizon DNS server and recursive/forwarding resolver with remote management via gRPC. It resolves iteratively from the root servers by default, falling back through encrypted and plaintext upstreams. It is written in Rust and licensed under AGPL-3.0-only.

## Rules

- please do not run make tasks unless told to
- ensure deny(dead_code) and deny(unsafe) are at the top and honored
- handle all std::result::Result in an appropriate way
- do not use unwrap
- do not use unsafe code
- never run tests yourself
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

### Stream Transport Limits

TCP and DoT connections are bounded, because `dns.bind` defaults to `0.0.0.0:53` and an unbounded listener on a routable interface is a pre-auth resource exhaustion: a client that connects and sends nothing holds a task and a file descriptor, and once descriptors run out `accept` fails for everyone.

| Bound | Value | Applies to |
| ----- | ----- | ---------- |
| `TCP_IDLE_TIMEOUT` | 10s | Waiting for the next message's length prefix |
| `TCP_MESSAGE_TIMEOUT` | 5s | The body of a message whose length was already announced |
| `TLS_HANDSHAKE_TIMEOUT` | 10s | DoT only: waiting for the ClientHello and the rest of the handshake |
| `MAX_TCP_CONNECTIONS` | 1024 | Concurrent connections per listener; a connection over the cap is dropped at accept |

The idle timeout is measured from the **last activity**, not from the connection opening, so RFC 7766 connection reuse works — a client may hold one connection open and send many queries down it. That matters more on DoT, where reconnecting costs a fresh handshake. Idle and message timeouts are separate because they are different claims: "I have nothing to say yet" is legitimate between queries, while a half-delivered message is a client that announced 65535 bytes and stopped.

The DoT handshake timeout is the bound plain TCP does not need. `acceptor.accept()` waits for a ClientHello, so without it a bare `connect()` — no TLS implementation required — parks a task before any DNS is exchanged, where a timeout on the DNS read loop never applies. DoQ sets `max_idle_timeout` (30s) through Quinn and needs no equivalent.

### Supported Record Types

**Basic**: A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR.

**Extended**: URI (RFC 7553), SSHFP (RFC 4255), DNAME (RFC 6672), ANAME (alias resolved at query time), ZONEMD (RFC 9156), TLSA (RFC 6698), CERT (RFC 4398).

**DNSSEC**: DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM.

### Split-Horizon Behavior

DNS queries are resolved in the following order:

0. **Scope selection** — The query's scope is chosen from the listener it arrived on and its source IP (see Source Classification and Scope Enforcement): a query on a per-TLD ingress listener belongs to that listener's owning scope for **every** name; otherwise only source IPs inside `security.overlay_cidrs` are scope-enforced (unjoined ⇒ REFUSED) and every other source resolves the global namespace unscoped.
1. **Network scope check** — If a scope was selected, scoped records for that scope are checked first.
2. **RBL check** — If the query is a reverse DNS lookup (`in-addr.arpa` or `ip6.arpa`), the extracted IP is checked against enabled RBL providers and local RBL entries. If listed, NXDOMAIN is returned.
3. **Local database lookup** — The local database is queried for the requested name and type. If records exist, they are returned immediately.
4. **CNAME chain** — If no exact type match is found locally, a CNAME lookup is attempted for the queried name. If a CNAME exists, it is returned.
5. **LAN → owning-scope fallback** (non-scoped sources only) — For a trusted local source (loopback / LAN, `scope_name == None`) whose name matched no global record, if the name falls under a TLD owned by *some* network scope (`db::find_tld_owner`), it is resolved from that owning scope's records so **every network TLD is visible on the LAN**. This runs *after* the global lookup, so a dual-homed name (a global LAN-IP record plus a scoped overlay-IP record) still returns its LAN-facing global value; only scoped-only names (e.g. a network's zone apex) are served from the scope, at their stored value. If the owning scope has no record, the TLD's peer forwarders are consulted, and failing that an **authoritative NXDOMAIN** is returned — a privately-owned TLD is never forwarded upstream from the LAN. (Overlay peers are unaffected: they take the scoped path at step 1, which partitions owned TLDs — a peer joined to one network sees only its own TLD and gets NXDOMAIN for a sibling network's or another scope's TLD.)
6. **Managed zone authority** — If the queried name falls under a zone that has records in the local database (determined by the last two labels of any stored FQDN), but the specific name was not found, an authoritative NXDOMAIN is returned. This prevents forwarding queries for names that should be resolved internally. Zones can also be explicitly declared authoritative via `AddAuthoritativeZone`.
7. **DNSBL / local blocklist check** — Before any external resolution, the queried name (forward names only; reverse names are handled by step 2) is checked against the local RBL blocklist and, if DNSBL is enabled, against the configured DNSBL (domain blocklist) providers. If listed, an NXDOMAIN is returned. Names on the **DNSBL allowlist** (and everything under them) skip this step entirely — see DNSBL Allowlist. Because this runs after the local/managed-zone checks but before the upstream cache and forwarder, DNSBLs take precedence over any externally-resolved answer (forwarded, iterative, or upstream-cached) while local records always win.
8. **DNS64 synthesis** — If DNS64 is enabled and the query is for AAAA but only A records exist upstream, AAAA records are synthesized using the configured NAT64 prefix.
8.5. **Recursion access control** — Before anything reaches outside this server (the upstream cache, a blocklist provider, a forwarder, the roots), the source must be inside `security.recursion_cidrs`; otherwise the query is REFUSED. Steps 1–6 are unaffected, so a stranger is still served data this server is authoritative for. See Recursion Access Control.
9. **Upstream resolution** — Unmatched queries go to the upstream path selected by `resolution.mode` (see Upstream Resolution): the `auto` tier chain by default, iterative-from-the-roots under `recursive`, or plain forwarding under `forward`. If every tier/forwarder fails, SERVFAIL is returned.
10. **Address-family filter** — Before the response goes out, A/AAAA records of an address family the host cannot route are dropped (see Address-Family Answer Filtering). This applies to every answer, local or upstream.

This ordering ensures the inside representation always takes priority over external DNS, allowing TLD-level and domain-level overlays that update in real time as the gRPC control plane modifies records.

### EDNS Support

EDNS (RFC 6891) context is extracted from incoming queries. The server respects client maximum payload size, supports the DNSSEC-OK (DO) bit, and includes OPT records in responses. Only EDNS version 0 is supported.

### QNAME Case Randomization

0x20 encoding is used on forwarded queries for DNS cache poisoning resistance. This is enabled by default and configurable via `security.qname_case_randomization`.

## Upstream Resolution

Names not satisfied locally are resolved by the strategy in the `resolution` config section (`ResolutionMode` in `src/dns_server.rs`):

| Mode | Behavior |
| ---- | -------- |
| `auto` (default) | The tiered fallback chain below. |
| `recursive` | Iterative from the root servers only; no upstream resolver is ever contacted. |
| `forward` | Forward to the configured `forwarders` only (the legacy behavior). |

### The `auto` Tier Chain

Four tiers, ordered most-preferred/most-trusted first. The numeric order is also the trust order, so moving to a *smaller* index is a recovery and a *larger* index is a degrade:

| Tier | Name | Transport |
| ---- | ---- | --------- |
| 0 | roots | Iterative resolution from the root servers (`src/resolver.rs`) |
| 1 | secure | DoH (`:443`, preferred) or DoT (`:853`) to `resolution.secure_upstreams` (`src/secure_client.rs`) |
| 2 | local | Plaintext Do53 to the configured `forwarders` (the local/DHCP resolver) |
| 3 | public | Plaintext Do53 to `resolution.public_fallback`, as a last resort |

The chain exists so resolution survives networks that filter outbound `:53`. DoH is preferred over DoT because `:443` looks like ordinary HTTPS and survives DPI that lets the DoT TCP connect through but drops the TLS session. Secure upstreams are dialed **by IP** (`addr`) with the TLS certificate validated against the configured `hostname`, so the tier needs no prior DNS; the per-upstream timeout is 1.5s.

- **Definitive answers only.** A tier "wins" only if the transport succeeded and the rcode is NoError or NXDOMAIN. SERVFAIL, REFUSED, and unparseable responses fall through to the next tier.
- **Sticky active tier.** The winning tier is remembered, so queries do not pay a timeout on a dead tier every time.
- **Grace-gated degrades, immediate recoveries.** A more-preferred tier winning switches immediately; a degrade commits only after `resolution.switch_grace_failures` (default 3) consecutive deviating queries, so one flaky query cannot thrash the tier.
- **Recovery probe.** While degraded, one query per `resolution.recovery_probe_secs` (default 60) restarts at tier 0 to reclaim a recovered tier. A compare-exchange ensures only one concurrent query probes per interval.
- **Cache flush on switch.** Every committed tier change calls `flush_upstream_state()` first, so answers from one tier cannot linger after a switch to another (a cross-tier cache-poisoning guard).
- **Startup pre-warm.** In `auto` mode, `prewarm_auto` runs canary queries at boot so the first *client* query does not pay for discovering that `:53` is filtered.

### Iterative Resolver (`src/resolver.rs`)

Walks the delegation chain from the roots: query a root, follow the NS referral to the TLD servers, then to the zone's authoritative servers. Queries are sent with recursion-desired cleared; responses are validated by transaction ID and question name against off-path spoofing; UDP first with automatic TCP fallback on truncation.

- **Root hints.** The 13 IANA root addresses, IPv4 only (one address family avoids stalling on IPv6 roots from a v4-only host; glue may still yield IPv6 authoritative servers, which are tried opportunistically). Overridable via `resolution.root_hints`.
- **Root priming.** At startup (never on the query path) the roots are asked who the roots are, and the live `.` NS set is cached as a delegation with its real TTL. The hardcoded hints become a bootstrap and the fallback when priming fails.
- **Server selection.** Lowest `hits * ema_latency` — this drives the product toward equality across the server set, allocating queries as `hits ∝ 1/latency`, so fast servers carry more and every healthy server carries some (rather than one "fastest" root absorbing everything and earning a rate-limit). An unqueried server scores 0, is tried first, and learns its latency from a query that had to happen anyway. Latency is an EMA (α = 0.3).
- **Failure backoff.** Tracked separately from latency as an explicit exponential backoff (2s, doubling, capped at 300s, cleared on the first success). Backed-off servers sort behind healthy ones within their address family but are never removed, so resolution still proceeds when everything is failing.
- **Bailiwick.** A referral is followed and cached only if it moves **strictly down** from the zone that answered *and* covers the name being resolved (`referral_in_bailiwick`). Without it, any nameserver the resolver ever talks to can return `AUTHORITY: com. NS <attacker>` for a query about its own zone and have it cached — and since `best_match` walks suffixes and long-TTL delegations are persisted to SQLite, that is a resolver takeover that survives a restart. A violating referral fails the lookup rather than being silently skipped, so a hostile delegation cannot masquerade as progress. Glue is filtered to names inside the **answering** zone rather than the delegated one, because a root referral for `com.` legitimately carries glue for `a.gtld-servers.net.` — outside `com.`, inside `.`. Discards are counted by `rolodex_dns_resolver_out_of_bailiwick_total`.
- **Bounds.** 1.5s per-nameserver timeout (short so a black-holed `:53` fails over to the secure tier quickly), max 30 referrals, 16 CNAME hops, depth 16, 4 nameservers tried per glue-less delegation, and a hard cap of **64 upstream queries per client lookup**. The per-axis limits multiply — a zone that keeps referring without glue costs `O(4^16)` queries — so the total is bounded outright to prevent a self-inflicted DoS/amplifier.

### Resolver Caches

Two caches sit *inside* the resolver, below the answer-level `DnsCache`, holding what a recursion learns on the way down instead of discarding it:

- **Delegation cache** (`src/delegation_cache.rs`) — zone → nameserver addresses, populated from every referral seen. Consulted before falling back to the root hints, so a warm `.com` lookup skips the root hop entirely (without it, every cache-cold name re-walked root → TLD → authoritative, hammering one root into rate-limiting). TTLs are honoured as published, capped at 7 days as an absurdity bound, with no floor; max 10,000 zones in memory. Entries whose TTL exceeds `resolution.delegation_persist_min_ttl` (default 300s) are persisted to the `delegation_cache` table by a background write worker and reloaded at boot, so a restart comes back warm — root and TLD NS sets carry multi-day TTLs, so in practice exactly the entries worth keeping survive.
- **Record cache** (`src/record_cache.rs`) — `(name, type)` → records, in memory, for glue, glue-less NS-name lookups, and CNAME hops. Records are handed back with their **remaining** lifetime (without that decay a served record would be re-cached upstream at full TTL and a 1h record would never expire). Capped at 50,000 keys and a 7-day TTL ceiling.

Both are flushed by `flush_upstream_state()` (tier switches) and **not** by `flush_cache()`, which is called from every gRPC record mutation — hanging upstream state off record mutations would mean every package add wipes the delegations and recreates the cold-start outage.

### TTL Semantics

A TTL that is present is honoured exactly as sent. A negative answer's TTL is the RFC 2308 `min(SOA MINIMUM, SOA TTL)`, unclamped — clamping would override what the zone actually published. `resolution.default_ttl` (default 300s) is the single fallback used only where nothing carries a usable TTL: a negative response with no SOA, or a delegation/glue record with a zero TTL.

## Address-Family Answer Filtering

Networks routinely advertise an IPv6 default route yet silently drop all v6 traffic (and the mirror case happens on v4-only NAT). Handing a client an address in a family the host cannot route makes the client stall on the dead family instead of falling back — the failure that wedges container image pulls on a broken-v6 link.

The probe in `src/probe.rs` therefore tests *actual* per-family internet reachability with a plain TCP connect to public anycast resolvers on `:443` (`:443` because it is the port real traffic uses and survives `:53`/`:853` filtering; TCP-connect because it needs no raw-socket privilege). A family the host cannot reach is suppressed in the answer filter, which drops A/AAAA records of that family and turns them into NODATA.

- `address_family.mode`: `auto` (probe and suppress, the default), `off` (always answer both), `force4`, `force6`.
- In `auto` the first probe runs **synchronously at startup** and is decisive with no grace, so a boot onto a dead-family link suppresses that family from the very first query; the recurring probe then runs detached every `probe_interval_secs`.
- A previously-up family is marked unreachable only after `fail_threshold` (default 2) consecutive failed cycles (flap debounce); recovery is immediate on the first success.

## Local Record Database

Records are stored in SQLite with WAL mode enabled for concurrent read performance. The database path is configurable (default `rolodex-dns.db`). An in-memory mode is available for testing.

The database file is created **`0600`**, and so are its `-wal`/`-shm` sidecars. It is the keystore — the root CA private key, every per-zone intermediate key, the DNSSEC private keys, and the EAB HMAC secrets are plain rows in it, so a local user who can read the file holds the root key and can forge a certificate for any name every enrolled client trusts. The mode is set explicitly by `Database::open` (via `db::restrict_to_owner`) *before* the WAL pragma runs, because SQLite copies the main file's mode onto the sidecars it creates; leaving it to the umask would produce `0644` under the common default.

Domain names are normalized to lowercase with a trailing dot on storage and lookup, providing case-insensitive matching. The database has indices on `name` and `(name, record_type)`.

Records consist of: name, record type, value, TTL (default 300 seconds), and priority (used by MX and SRV).

SOA values are stored as `"mname rname serial refresh retry expire minimum"`. SRV values are stored as `"weight port target"`. TLSA values are stored as `"usage selector matching_type hex_data"`. URI values are stored as `"priority weight target_uri"`. SSHFP values are stored as `"algorithm fp_type hex_fingerprint"`. ZONEMD values are stored as `"serial scheme hash_algorithm hex_digest"`. CERT values are stored as `"cert_type key_tag algorithm base64_cert_data"`.

### Automatic Reverse PTR Records

When `dns.auto_ptr` is enabled (disabled by default), A and AAAA records added or removed through the gRPC management interface (`AddRecord`/`RemoveRecord` and the scoped `AddScopedRecord`/`RemoveScopedRecord`) automatically maintain a matching reverse PTR record. Adding an A record creates the `<reversed-octets>.in-addr.arpa.` PTR; adding an AAAA record creates the 32-nibble `<reversed-nibbles>.ip6.arpa.` PTR. The PTR carries the forward record's TTL and points back to the (normalized) forward name. Removing the forward record removes the corresponding PTR; scoped records create/remove the PTR within the same scope. A and AAAA are handled equivalently — the only difference is the reverse zone (`in-addr.arpa` vs `ip6.arpa`). The reverse name is built by `db::reverse_ptr_name`, the inverse of the reverse-name parser used for RBL lookups. This is independent of the DHCP server's own A/PTR registration, which remains IPv4-only.

## DNS Response Cache

Rolodex DNS caches DNS responses in memory backed by SQLite for persistence across restarts. Once cached, queries are answered without contacting upstream resolvers. This is a deliberate privacy-first design to prevent DNS query leakage to upstream providers.

- **Local records** are cached with a `local` flag — TTL is returned as-is (no decay) and entries are not persisted to the SQLite cache table.
- **Upstream records** have TTL adjusted based on remaining cache time (TTL decay).
- Expired entries are evicted on access.
- The cache tracks hit and miss counters, retrievable via `GetCacheStats`.
- Cache keys use `"name:type"` or `"name:*"` format.
- **Negative answers** (authoritative NXDOMAIN/NODATA) are held in a separate `negatives` map, so the positive paths keep treating "no records" as a miss. Their lifetime is the RFC 2308 negative TTL computed by `Resolution::negative_ttl`. Adding a local record for a name invalidates any cached negative for it (`invalidate_negative`), so a newly-added name is not shadowed until the negative TTL runs out.
- Persistence upserts on a unique index over the cache key, so re-caching a name updates its row instead of appending a duplicate. The on-disk cache is loaded at boot via `cache_load_all`.
- The cache is automatically flushed when records are mutated via gRPC (add, remove, or scoped variants) to ensure consistency. This is `flush_cache()`, which clears answers and negatives but deliberately **not** the resolver's delegation/record caches — those are flushed only by `flush_upstream_state()` on an `auto`-mode tier switch.
- The cache can be explicitly flushed via `FlushDnsCache`.
- Set `forwarders: []` and `resolution.mode: forward` to operate as a purely authoritative server with no upstream resolution.

## Realtime Blackhole Lists (RBL)

Rolodex DNS checks IPs against DNS-based blackhole lists using the standard reversed-IP lookup format:

- **IPv4**: Octets are reversed and appended to the RBL zone (e.g., `192.168.1.100` becomes `100.1.168.192.zen.spamhaus.org`).
- **IPv6**: Nibbles are expanded, reversed, and appended to the RBL zone.

RBL checking is globally togglable and disabled by default, **with an empty provider list** — no external blocklist is queried until the operator adds providers via the `rbl` config section or `SetRblConfig`. Individual providers can also be enabled or disabled independently.

### Commonly Used Providers

The provider list ships empty; these are the standard IP DNSBL zones (as used by unbound) an operator typically adds:

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
- **Refusals**: Not cached either, and the provider is rotated out — see Refusal Codes and Provider Rotation.

The cache can be flushed via gRPC. A flush also returns every rotated-out provider to rotation.

### Refusal Codes and Provider Rotation

A DNSxL answers a listing and a complaint about the *querier* the same way: an `A` record under `127.0.0.0/8`. `zen.spamhaus.org` says "listed" with `127.0.0.2` and "you are querying via a public resolver" with `127.255.255.254`, and **only the address distinguishes them**. Reading any `A` record as a listing therefore turns the moment a blocklist decides to stop answering us into NXDOMAIN for *every* name checked against that provider — and it starts when query volume crosses the provider's threshold, hours or weeks after a deployment that looked fine. Spamhaus states it directly: those codes "should NOT be interpreted as any sort of reputation".

So each provider carries a set of **refusal codes**. A returned code matching one is `Refused`: not a listing, not a negative, nothing cached — we learned nothing about the queried name. A refusal anywhere in an answer wins over a listing in the same answer, because a provider that is complaining is not simultaneously reporting reputation, and erring this way fails *open* where the other order fails closed on every name.

**The built-in set**, used when a provider configures none — so an existing deployment gets the safe reading without being edited:

| Code | Meaning |
| ---- | ------- |
| `127.255.255.0/24` | Spamhaus error range: `.252` typo in the zone name, `.254` query via a public/open resolver, `.255` excessive queries. A whole range rather than the three codes, because Spamhaus reserves it and adds to it — enumerating today's three would silently start reading tomorrow's fourth as a listing |
| `127.0.1.255` | Spamhaus DBL answering an IP query — "IP queries not supported" |
| `127.0.2.255` | Spamhaus ZRD answering an IP query — same |
| `127.0.0.1` | URIBL/SURBL "query blocked" (public resolver / over quota). RFC 5782 §5 also forbids a DNSxL from listing `127.0.0.1`, so it is never a legitimate listing |
| `127.0.0.255` | URIBL "query blocked" (over quota) |

Each entry is an IPv4 address or `address/prefix`. **Empty means the built-in set** — it cannot mean "no codes", because empty is what every configuration written before this feature existed has. The single entry `none` disables refusal detection for that provider, for a private blocklist whose real listings collide with one of the above. An explicit list is exactly that list; the defaults are **not** merged in, so an operator who spells it out can also narrow it.

An unparseable code is **rejected** — at startup, or with `InvalidArgument` from the RPC — rather than skipped. A code that silently does not apply is a refusal that reads as a listing, and it would do so with the configuration having reported success.

**Rotation.** A refusal takes the provider out of the lookup rotation for a configurable cooldown (`refusal_cooldown_secs`, default 3600s, per-provider override available), so a blocklist that has just told us to stop is backed off instead of queried on every request. Rotation:

- Skips **new lookups** only. Already-cached verdicts still count: rotation says "this provider will not answer new questions", not "the answers it already gave were wrong", and dropping those would unblock genuinely-listed names for the whole cooldown.
- **Lapses on its own**, so a transient over-quota period heals with no operator action.
- Is **cleared** by `FlushCache` and by any `SetRblConfig`/`SetDnsblConfig` — a flush is "re-check everything", and a reconfiguration is often the fix for the refusal (a typo in the zone name is both a cause of `127.255.255.252` and the thing being corrected).
- Is **reported** over the management API: `GetRblConfig`/`GetDnsblConfig` return the rotated-out providers with the code that removed them and the seconds remaining, and `rolodex_dns_blocklist_refusals_total{kind}` / `rolodex_dns_blocklist_rotated_out` expose the same to Prometheus. Without them, "the blocklist went quiet" and "the blocklist is clean" look identical from outside, and the second is what an operator assumes.

Setting the cooldown to `0` means "use the default", not "no cooldown" — a zero cooldown re-asks the provider that just told us to stop, which is the behaviour rotation exists to prevent.

The RBL and DNSBL lists carry independent cooldown defaults, matching their independent configuration sections. Per-scope RBL providers carry their own refusal codes and cooldown, stored alongside the provider row.

### Local RBL Entries

In addition to DNS-based providers, Rolodex DNS supports a local RBL blocklist stored in the database. Local entries are checked alongside external providers and can block specific names or IPs with a human-readable reason. Entries are managed via `AddLocalRblEntry`, `RemoveLocalRblEntry`, and `ListLocalRblEntries`. Local entries are matched against both reverse-DNS IP lookups (step 2) and forward domain names (step 7), tolerating trailing-dot and case differences in the stored entry. A forward name on the DNSBL allowlist is exempt from the local blocklist too (see DNSBL Allowlist).

## Domain Blocklists (DNSBL)

While RBL providers block by **IP address** (queried with a reversed IP on reverse-DNS lookups), DNSBL providers block by **domain name**. A DNSBL lookup prepends the queried name's labels to the provider zone — e.g. `googleadservices.com` against `dbl.spamhaus.org` is queried as `googleadservices.com.dbl.spamhaus.org` — mirroring how domain blocklists such as Spamhaus DBL, SURBL, and URIBL operate.

DNSBL gives blocklists **precedence over external DNS**: the check runs after local records and managed/authoritative zones (so internal data always wins) but **before** the upstream response cache and the forwarder/iterative resolver. A listed name therefore returns NXDOMAIN even if a forwarded answer was previously cached. For example, with DNSBL enabled, `googleadservices.com` is refused while a locally-defined `gitea.default.home` (e.g. planted by a package) continues to resolve.

DNSBL checking is globally togglable and **disabled by default, with an empty provider list**; providers are independently enable-able. The standard domain blocklists an operator typically adds are `dbl.spamhaus.org`, `multi.surbl.org`, and `multi.uribl.com`. An enabled-but-empty DNSBL is a no-op (nothing is queried and nothing is blocked). DNSBL configuration is independent of the IP-based RBL configuration and shares the same in-memory result cache (positive results cached for the provider TTL, negatives for 5 minutes) and the same refusal-code handling — `dbl.spamhaus.org` answers an IP query with `127.0.1.255`, which is an error and not a listing (see Refusal Codes and Provider Rotation). It is configured at startup via the `dnsbl` config section and at runtime via `SetDnsblConfig`/`GetDnsblConfig`.

### DNSBL Allowlist

Specific hosts can be exempted from the blocklist check entirely. Allowlist entries are stored in the database (`dnsbl_allowlist` table) with a human-readable reason and managed via `AddDnsblAllowlistEntry`, `RemoveDnsblAllowlistEntry`, and `ListDnsblAllowlistEntries` (CLI: `add-dnsbl-allow`, `remove-dnsbl-allow`, `list-dnsbl-allow`).

- **Suffix-matched.** An entry covers the name itself *and* every name beneath it, so allowlisting `example.com` also exempts `www.example.com`. Matching is on label boundaries — `notexample.com` is not exempt. Lookups are O(labels) against an in-memory `DashSet` mirrored from the table (loaded at boot), the same technique used for zone matching.
- **Normalized on storage.** Entries are lowercased with a trailing dot, so `Example.COM`, `example.com`, and `example.com.` are one entry and any spelling removes it. An empty or root (`.`) entry is rejected — it would exempt the whole namespace.
- **The allowlist wins.** The check short-circuits step 7 in full: an exempt name is checked against neither the configured DNSBL providers nor the local RBL blocklist, so an allowlist entry is the operator's escape hatch from a false positive on either. It runs *before* the provider lookup, so an exempt name never issues a blocklist query at all.
- **Forward names only.** The allowlist gates the forward-name check (step 7). Reverse-DNS IP blocking (step 2, `in-addr.arpa`/`ip6.arpa` against IP-based RBL providers) is unaffected.
- Adding or removing an entry takes effect on the next query with no cache flush needed, because the blocklist step runs ahead of the DNS response cache lookup.

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

Rolodex DNS signs its own zones. It performs **no validation** of DNSSEC data received from upstream — see Upstream DNSSEC (Not Validated) below.

Supported algorithms (strongest first):

1. **Ed25519** (RFC 8080, algorithm 15) — preferred
2. **ECDSA P-384/SHA-384** (RFC 6605, algorithm 14)
3. **ECDSA P-256/SHA-256** (RFC 6605, algorithm 13)

**RSA/SHA-256 (algorithm 8) is not supported** and `GenerateDnssecKey` refuses it: `ring` cannot generate RSA keys. Every algorithm on the list is one whose keys are actually generated and whose signatures are actually produced — an algorithm that cannot be honoured end to end is refused at key generation rather than substituted, because a DNSKEY advertising algorithm 13 over Ed25519 key material yields a DS, a DNSKEY and a set of RRSIGs that all disagree, and that failure surfaces at a validating resolver rather than locally.

### Key Management

Two key types are supported:

- **ZSK** (Zone Signing Key, flag 256) — signs zone data records.
- **KSK** (Key Signing Key, flag 257) — signs the DNSKEY RRset.

Keys are generated, stored in the database, and managed via gRPC: `GenerateDnssecKey`, `ListDnssecKeys`, `DeleteDnssecKey`. The stored algorithm name round-trips through `DnssecAlgorithm::parse`, and a key whose stored bytes do not load as the algorithm it is filed under is skipped at signing time with a warning rather than signed with.

### Zone Signing

`SignZone` republishes the apex DNSKEY RRset and signs every RRset in the zone, storing the resulting RRSIG records in the local database.

- **RRset grouping.** Records are grouped by owner name and type; one RRSIG covers the whole set. Zone membership is matched on label boundaries, so `notexample.com.` is not signed as part of `example.com.`
- **Canonical form.** The signed bytes are RFC 4034 §3.1.8.1: the RRSIG RDATA up to the signature, then each RR with a canonical owner name (lowercased, uncompressed), its type, class IN, the **original** TTL, and canonical RDATA — sorted into RFC 4034 §6.3 canonical order with duplicates dropped, so the order records come out of SQLite in cannot change the signature.
- **Key roles.** The DNSKEY RRset is signed by the KSK and other RRsets by the ZSK (RFC 4035 §2.1). With only one key type present, that key signs both. RRSIG RRsets are never themselves signed.
- **Validity.** Inception is backdated one hour for clock skew; signatures expire 30 days out. The RRSIG's original TTL is the RRset's own TTL.
- **Unsignable types are skipped, not approximated.** NSEC, NSEC3, NSEC3PARAM and ANAME have no stored wire format here, and a malformed value has no canonical encoding; those RRsets are skipped and named in the response message. A signature computed over an invented encoding is worse than none — it fails closed at every validator instead of leaving the name unsigned.
- **Re-signing replaces.** Existing RRSIGs in the zone are cleared first, including at names whose records were deleted since the last run, so signatures never accumulate or outlive their data. The DNSKEY RRset is likewise republished rather than appended to. The response cache is flushed afterwards.

RRSIG values are stored as `"type_covered algorithm labels original_ttl expiration inception key_tag signer_name base64_signature"`. Expiration and inception are raw seconds since the Unix epoch rather than presentation-format `YYYYMMDDHHmmSS`, matching how every other record type here stores its numeric fields.

DS records for parent-zone delegation are computed using SHA-256 and retrievable via `GetDsRecords`. Key tags are calculated per RFC 4034 Appendix B. Cryptographic operations use the `ring` crate.

`dnssec::verify_rrsig` is the inverse of the signer and exists so signatures can be checked against something other than the code that produced them. It is deliberately **not** wired into the resolution path.

### Wire Serving of DNSSEC Types

DNSKEY, DS and RRSIG are served under their own type codes, with RDATA encoded by the same canonical encoder the signer hashes — so what goes on the wire is byte-for-byte what was signed. URI and ZONEMD are encoded the same way. (These were previously served as TXT records carrying the stored string, which answers a DNSKEY query with a TXT and makes any published signature unusable.) NSEC, NSEC3 and NSEC3PARAM are never generated and are not served.

### Upstream DNSSEC (Not Validated)

Rolodex does **not** validate DNSSEC on answers it resolves. There is no root trust anchor, the iterative resolver sets no DO bit on its outbound queries (so RRSIG/DNSKEY/NSEC are never even requested), and no signature verification runs on the resolution path.

What does happen: a client that sets the DO bit gets the raw upstream response passed through untouched (`src/dns_server.rs`), so a client validating for itself is not interfered with. Two consequences follow, and neither is a promise of authenticity:

- The **AD bit is relayed from upstream unverified**. On the `local` and `public` tiers that is plaintext Do53, where a relayed AD is worth nothing; on the `secure` tier it is at least channel-authenticated to the configured upstream.
- In `recursive` mode a DO client receives no RRSIGs at all, since the iterative resolver never asks for them.

Responses built locally never set AD, so answers this server generates make no authentication claim.

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

Two limits sit alongside that, because "may enroll" is not "may become a CA for the entire namespace", and reaching the portal must mean *the user* reached it:

- **Enrollment is confined to zones the server manages.** `POST /api/account` accepts a zone only if a scope owns it as a TLD (which covers a scope's implicit `.home` domain), it has records in the local database, it is a declared authoritative zone, or it already has an intermediate CA from `EnsureZoneCa`. All four are suffix-matched, so a subzone of a managed zone enrolls too. `acme.issuance_scope: any` lifts the restriction, as it does for the issuer.
- **Cross-site requests are refused.** The endpoint requires a `application/json` content-type — the three types a cross-origin form POST can send without a preflight are rejected, and the portal answers no preflight — and refuses any `Origin` that is not this server (compared on authority, so a TLS-terminating proxy works). Browser-extension origins are exempt; non-browser clients send no `Origin` and are unaffected.

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

### Source Classification and Scope Enforcement

Scope enforcement is not applied to every source — it is confined to network-overlay (WireGuard) peers, listed in `security.overlay_cidrs` (default `10.64.0.0/10`, Town OS's overlay range; parsed by `src/cidr.rs`). A query's scope is chosen in this order:

1. **Arrived on a per-TLD ingress listener** → the listener's owning scope, for **every** name, whatever the query is. The listener is bound to the network's overlay address and is that network's dedicated resolver, so owned TLDs stay partitioned (a sibling network's TLD is still an authoritative NXDOMAIN) while everything else falls through to global resolution and forwarding. Keying the scope off the queried *name* instead would drop a public name like `google.com` into the source-IP branch, where an overlay peer that never called `JoinNetwork` is REFUSED — the listener would then answer its own TLD and nothing else, so the network's own resolver could not resolve the internet it is the resolver for.
2. **Source IP joined to a scope** (only overlay addresses are ever joined) → that scope, partitioned.
3. **Source IP inside `overlay_cidrs` but joined to nothing** → REFUSED: an overlay peer that is not a member of any network.
4. **Everything else** — loopback (the box's own resolver), the LAN, container bridges — is a **trusted local source**: never refused, resolving the global namespace. This is the split-horizon: global records carry the box's LAN-reachable address while scoped overlay records carry the overlay address, so each side gets an address it can actually route to.

The source address (and the local listener IP) is **canonicalized in `handle_query_on` before any of this runs**, so an IPv4 peer arriving on a dual-stack listener as `::ffff:10.64.0.1` is the same address as `10.64.0.1` to the CIDR test, the association lookup, and the ingress-listener match. Without it, `IpCidr::contains` — which deliberately does not match across address families — classifies every IPv4 overlay peer on a `[::]` bind as a trusted local source, so whether a WireGuard peer is scope-enforced at all would depend on how the listener happened to be bound. IPv4-compatible addresses (`::1.2.3.4`, deprecated) are not folded; only true IPv4-mapped ones.

### Recursion Access Control

Scope enforcement decides *which view* a source gets. A separate axis decides whether a source gets **upstream resolution** at all: `security.recursion_cidrs`.

`dns.bind` defaults to `0.0.0.0:53`, so on a routable interface the listener is reachable from the entire internet, and every source outside `overlay_cidrs` is classified as a trusted local client. Without a second check that makes a default deployment an **open recursive resolver** — the classic reflection/amplification asset: a small spoofed query returns a large answer aimed at the spoofed victim, and the outbound resolution traffic is billed to this box.

The default list is every range that is unroutable from the internet — `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `::1/128`, `fe80::/10`, `fc00::/7` — which covers loopback, the LAN, container bridges, and the WireGuard overlay (`10.64.0.0/10` sits inside `10.0.0.0/8`). An empty list closes recursion to everyone, leaving a purely authoritative server.

- **The check sits at the local/remote boundary** (resolution step 8.5): after every path that answers from data this server holds, before every path that reaches for data it does not. A stranger therefore still receives this server's authoritative answers and authoritative NXDOMAINs — closing recursion must not turn the box into a black hole for its own zones — but cannot make it go and ask someone else.
- **It runs before the response cache**, because a cached answer amplifies exactly as well as a freshly-resolved one, and warming the cache is how the attack is staged.
- **The refusal is REFUSED with an empty answer section**, the smallest reply available: the response is never larger than the question that provoked it, so a spoofed query gains an attacker nothing.
- **Every transport is gated.** UDP, TCP, DoT, and DoQ pass the peer address already; DoH serves with connect info (`into_make_service_with_connect_info`) so its peer reaches classification too — otherwise `:443` would reopen what `:53` closes.

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

### Per-Network Owned TLDs

Beyond its implicit `.home` domain, a scope can own additional TLDs (zones) that partition the DNS namespace across networks. Each owned TLD is **globally unique** to a single scope. Names under an owned TLD are resolved only within the owning network and are never forwarded upstream — an unmatched name yields an authoritative NXDOMAIN (after optionally consulting the TLD's peer forwarders, the overlay addresses of other rolodex members of the same network). Owned TLDs are managed via `AddScopeTld`, `RemoveScopeTld`, and `ListScopeTlds`; peer forwarders via `SetScopeTldForwarders`/`ListScopeTldForwarders`. Ownership is enforced by a `scope_tlds` table with a globally-unique index and mirrored into an in-memory `tld_owner_cache` for O(labels) suffix lookup on the hot path (`db::find_tld_owner`).

**Partitioning across WireGuard endpoints vs. LAN visibility.** For an *overlay peer* (source IP joined to a scope), owned TLDs are strictly partitioned: the peer resolves only its own network's TLD and gets an authoritative NXDOMAIN for any other scope's TLD — so `.fart` and `.fart2` are never both resolvable from a single WireGuard endpoint. For a *trusted local source* (loopback / LAN, associated with no scope), the LAN → owning-scope fallback (resolution step 5) resolves **every** owned TLD from its owning scope, so all network TLDs are visible on the LAN. A scope can therefore be created purely to *own* a TLD (marking it partitioned-from-overlay-peers and LAN-resolvable) without ever binding a WireGuard overlay to it — this is how Town OS keeps `.home` LAN-only and hidden from every WireGuard peer while giving it no overlay transport.

### Ingress DNS Listeners

An owned TLD can be given a local **ingress IP** when registered (`AddScopeTld` with a `listen_ip`). This does three things:

1. **Binds a DNS listener** (UDP + TCP) on that local IP, on the server-configured `dns.ingress_listen_port` (default 53). Listeners are tracked in an abort-handle registry so removing the TLD (`RemoveScopeTld`) tears the listener down once no remaining TLD references that IP; they are re-created at boot from the database by `sync_ingress_listeners`.
2. **Serves the owning scope's full view.** A query arriving on the listener is resolved within that TLD's owning scope for **every** name, not only names under the owned TLD — see Source Classification and Scope Enforcement. Owned TLDs remain partitioned (a sibling network's TLD is an authoritative NXDOMAIN), and everything else falls through to global resolution and upstream forwarding, so a peer can use the listener as its general-purpose resolver.
3. **Rewrites answers to the ingress IP.** A query for a **programmed** name under the TLD (one that has a stored A/AAAA record — packages, pages, etc.), *when it arrives on that ingress listener*, has its A/AAAA answer rewritten to the ingress IP so the network's ingress controller receives the traffic and routes by Host/SNI. The rewrite is a full override of the stored value, matching the queried address family. Unlike scope selection, the rewrite stays **name-gated**: a pass-through name (not under the listener's TLD) keeps its resolved value, the same name on the main `:53` listener resolves to its stored value, and a name with no stored record still returns NXDOMAIN (no wildcard synthesis). The listener's local IP is threaded through the query handler (`handle_query_on`); the main wildcard (`0.0.0.0`) listeners carry no concrete local IP, so they never rewrite and never take the ingress scope.

**Failed binds do not poison the IP.** The registry records both abort handles at spawn time, before either task has tried to bind, so a listener that failed to bind would otherwise leave an entry claiming the address is served while nothing listens on it. That is the normal case at boot: a TLD's ingress IP is a WireGuard overlay address, and `sync_ingress_listeners` replays it from the database before the tunnel interface exists, so both tasks fail `EADDRNOTAVAIL` and exit. An entry whose tasks have all finished is therefore treated as **absent** — dropped and respawned — so a later `AddScopeTld` re-add actually retries the bind once the interface is up. `has_ingress_listener`/`ingress_listener_count` likewise report only live listeners.

The per-TLD ingress mapping is stored in a `tld_listeners` table and mirrored into an in-memory `tld_ingress_cache`. Listeners are listed via `ListScopeTldListeners`.

## Authoritative Zone Declarations

Zones can be explicitly declared authoritative via `AddAuthoritativeZone`. Queries for names within authoritative zones are never forwarded upstream — if the specific name is not found locally, an authoritative NXDOMAIN is returned. Zones are managed via `AddAuthoritativeZone`, `RemoveAuthoritativeZone`, and `ListAuthoritativeZones`.

## DHCP Server

Rolodex DNS includes an integrated DHCPv4 server that provides IP address allocation (IPAM) with automatic DNS hostname registration. The DHCP service is disabled by default and enabled via the `dhcp` configuration section.

### IPAM (IP Address Management)

DHCP address pools are configured per network scope. Each pool defines an IP range, gateway, subnet mask, and DNS servers. There is no cross-pool aggregation: each pool is a single contiguous range, and when the pool is exhausted, allocation fails (returns `None`). MAC-to-IP bindings are persistent (sticky): once a MAC address is assigned an IP, subsequent requests from the same MAC receive the same IP.

Lease states: `active` (in use), `expired` (past duration), `released` (client released), `reclaimable` (past reclaim timeout, IP available for reuse).

### DNS Integration

When a DHCP client provides a hostname (option 12), the server automatically registers the records below — **provided the hostname is a valid DNS label**. Option 12 arrives verbatim from an unauthenticated device on the LAN and is interpolated straight into a record name, so `valid_hostname_label` requires a single LDH label per RFC 1123 §2.1 (1–63 bytes, letters/digits/hyphen, no leading or trailing hyphen) and lowercases it. A hostname that fails is **rejected, not sanitized** — registration is skipped with a warning rather than a different name being silently assigned — and deregistration applies the same rule so the name removed is the name that was added. The check matters most for `*`: `*.lan.<tld>.` is a real wildcard to `lookup_scoped`, so without it a client naming itself `*` answers for every unregistered name in its scope.

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

- **TCP connections** require a shared secret passed as `auth_token` in each request. The token is compared in **constant time** (`subtle::ConstantTimeEq`); `==` on `String` defers to `memcmp`, which returns at the first differing byte and so leaks how many leading bytes were guessed right, turning a search over the whole secret into a byte-at-a-time one. If the server's shared secret is empty, all connections are allowed without authentication — so an empty `grpc.shared_secret` combined with a `grpc.tcp_bind` that resolves to any non-loopback address is **refused at startup** (`config::check_grpc_exposure`).
- **Failed authentications are throttled per source address.** A shared secret is a password, and an online guessing oracle with no backoff is what makes a weak one fatal. After 5 consecutive failures a source is locked out for 30s, doubling per consecutive lockout to a 15-minute ceiling; while locked out every attempt is refused with `ResourceExhausted` **without the token being compared at all**, so the lockout is not itself an oracle. A successful authentication clears the source's history, and a run of failures that goes quiet for 5 minutes resets — so legitimate automation is never throttled (the counter is on failures, not requests) and an occasional mistyped token never accumulates. Keying by source address rather than globally means one attacker cannot lock the operator out of their own management plane. The table is capped at 65536 sources: over the cap, idle-and-unlocked entries are pruned, and if that does not suffice new sources go untracked rather than the table growing without bound. That combination is an unauthenticated management plane on a routable port; on loopback it remains the documented development configuration. `0.0.0.0` and `::` are not loopback, and an `interface:port` bind is condemned by a single routable address on the interface.
- **Unix socket connections** bypass authentication entirely, so the socket's file mode *is* the access control. It is created `0660` rather than under the umask (which would leave it `0755` and hand every local user unauthenticated administrative control). The listener is bound at a temporary sibling path, restricted, then renamed into place — an atomic rename keeps the same inode, so the published path never exists in a permissive mode. `0660` rather than `0600` so a deployment can grant a dedicated admin group access by chgrp'ing the socket.

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
| `SetRblConfig`        | Replaces the RBL configuration (global enable flag, provider list, per-provider refusal codes/cooldown, and the list-wide refusal cooldown) at runtime. Rejects a malformed refusal code with `InvalidArgument`. |
| `GetRblConfig`        | Returns the current RBL configuration, with refusal codes resolved to what is in effect, plus the providers currently rotated out. |
| `SetDnsblConfig`      | Replaces the DNSBL (domain blocklist) configuration (global enable flag, provider list, and refusal handling) at runtime. |
| `GetDnsblConfig`      | Returns the current DNSBL configuration, with resolved refusal codes and the rotated-out providers. |
| `FlushCache`          | Clears the RBL result cache and returns every rotated-out provider to rotation.   |
| `AddLocalRblEntry`    | Adds a local RBL blocklist entry (name/IP and reason).                            |
| `RemoveLocalRblEntry` | Removes a local RBL entry by name.                                                |
| `ListLocalRblEntries` | Retrieves all local RBL entries.                                                  |
| `AddDnsblAllowlistEntry`     | Exempts a name (and its subdomains) from the name-based blocklist check.   |
| `RemoveDnsblAllowlistEntry`  | Removes a DNSBL allowlist entry by name.                                   |
| `ListDnsblAllowlistEntries`  | Retrieves all DNSBL allowlist entries.                                     |

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

#### Per-Network Owned TLDs

| RPC                       | Description                                                                                                |
| ------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `AddScopeTld`             | Registers a globally-unique TLD as owned by a scope. An optional `listen_ip` also starts an ingress DNS listener on that IP. |
| `RemoveScopeTld`          | Removes a TLD ownership from a scope (the implicit `home_domain` cannot be removed this way) and tears down its ingress listener once no remaining TLD uses that IP. |
| `ListScopeTlds`           | Lists the TLDs owned by a scope.                                                                           |
| `SetScopeTldForwarders`   | Replaces the peer forwarders for a scope's TLD (the overlay addresses of other rolodex members of the network). |
| `ListScopeTldForwarders`  | Lists the peer forwarders for a scope's TLD.                                                               |
| `ListScopeTldListeners`   | Lists the ingress DNS listeners bound to a scope's TLDs.                                                    |

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
| `set-rbl-config`   | Configure RBL settings. Takes `--enabled` flag, optional `--providers` in `zone:enabled` format, and the refusal knobs: `--refusal-codes zone=code,code` (repeatable; `none` disables detection for that zone), `--provider-cooldown zone=secs` (repeatable), `--refusal-cooldown secs` (list-wide). A `zone=` entry naming a zone absent from `--providers` is an error, not a dropped flag. |
| `get-rbl-config`   | Display current RBL configuration, including each provider's effective refusal codes and cooldown and any providers currently rotated out. |
| `set-dnsbl-config` | Configure DNSBL (domain blocklist) settings. Same flags as `set-rbl-config`.                        |
| `get-dnsbl-config` | Display current DNSBL configuration, including refusal codes and rotated-out providers.             |
| `flush-cache`      | Clear the RBL result cache.                                                                         |
| `add-local-rbl`    | Add a local RBL entry. Takes `--name` and optional `--reason`.                                      |
| `remove-local-rbl` | Remove a local RBL entry. Takes `--name`.                                                           |
| `list-local-rbl`   | List all local RBL entries.                                                                         |
| `add-dnsbl-allow`    | Exempt a name (and its subdomains) from the DNSBL/blocklist check. Takes `--name` and optional `--reason`. |
| `remove-dnsbl-allow` | Remove a DNSBL allowlist entry. Takes `--name`.                                                   |
| `list-dnsbl-allow`   | List all DNSBL allowlist entries.                                                                 |

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
| `add-scope-tld`     | Register an owned TLD for a scope. Takes `--scope`, `--tld`, and optional `--listen-ip` (starts an ingress DNS listener on that IP).                |
| `remove-scope-tld`  | Remove an owned TLD from a scope. Takes `--scope`, `--tld`.                                                                                         |
| `list-scope-tlds`   | List the TLDs owned by a scope (home domain first). Takes `--scope`.                                                                                |
| `set-scope-tld-forwarders`  | Replace the peer forwarders for a scope's TLD. Takes `--scope`, `--tld`, repeatable `--forwarder host:port` (omit to clear).                |
| `list-scope-tld-forwarders` | List the peer forwarders for a scope's TLD. Takes `--scope`, `--tld`.                                                                       |
| `list-scope-tld-listeners`  | List the ingress DNS listeners bound to a scope's TLDs. Takes `--scope`.                                                                    |
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
| `SetRblConfigWithRefusalCooldown(ctx, enabled, providers, secs)` | The same, with the list-wide rotate-out duration for refusing providers. |
| `GetRblConfig(ctx)`                     | Returns an `RblStatus` with the current RBL configuration, effective refusal codes, and rotated-out providers. |
| `SetDnsblConfig(ctx, enabled, providers)` | Replaces the DNSBL (domain blocklist) configuration.     |
| `SetDnsblConfigWithRefusalCooldown(ctx, enabled, providers, secs)` | The same, with the DNSBL rotate-out duration. |
| `GetDnsblConfig(ctx)`                   | Returns a `DnsblStatus` with the current DNSBL configuration. |
| `FlushCache(ctx)`                       | Clears the RBL result cache.                               |
| `AddLocalRblEntry(ctx, entry)`          | Adds a local RBL entry.                                    |
| `RemoveLocalRblEntry(ctx, name)`        | Removes a local RBL entry.                                 |
| `ListLocalRblEntries(ctx)`              | Retrieves all local RBL entries.                           |
| `AddDnsblAllowlistEntry(ctx, entry)`    | Exempts a name (and its subdomains) from the blocklist check. |
| `RemoveDnsblAllowlistEntry(ctx, name)`  | Removes a DNSBL allowlist entry.                           |
| `ListDnsblAllowlistEntries(ctx)`        | Retrieves all DNSBL allowlist entries.                     |

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
| `AddScopeRblProviderWithRefusal(ctx, scopeName, zone, enabled, codes, secs)` | The same, with the provider's refusal codes and rotate-out duration. |
| `RemoveScopeRblProvider(ctx, scopeName, zone)`       | Removes a per-scope RBL provider.                |
| `ListScopeRblProviders(ctx, scopeName)`              | Lists per-scope RBL providers.                   |
| `AddScopeTld(ctx, scopeName, tld)`                   | Registers a globally-unique owned TLD for a scope. |
| `AddScopeTldWithListener(ctx, scopeName, tld, listenIP)` | Registers an owned TLD and binds an ingress DNS listener on `listenIP`. |
| `RemoveScopeTld(ctx, scopeName, tld)`                | Removes an owned TLD from a scope.               |
| `ListScopeTlds(ctx, scopeName)`                      | Lists the TLDs owned by a scope.                 |
| `SetScopeTldForwarders(ctx, scopeName, tld, forwarders)` | Replaces the peer forwarders for a scope's TLD. |
| `ListScopeTldForwarders(ctx, scopeName, tld)`        | Lists the peer forwarders for a scope's TLD.     |
| `ListScopeTldListeners(ctx, scopeName)`              | Lists the ingress DNS listeners for a scope's TLDs. |
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
- `RblConfig` — RBL provider configuration (zone, enabled flag, refusal codes, per-provider refusal cooldown).
- `RblStatus` — RBL state returned by `GetRblConfig` (global enabled flag, provider list, list-wide refusal cooldown, rotated-out providers).
- `DnsblConfig` — DNSBL (domain blocklist) provider configuration (same fields as `RblConfig`).
- `DnsblStatus` — DNSBL state returned by `GetDnsblConfig` (same shape as `RblStatus`).
- `RotatedProvider` — A blocklist provider currently out of the lookup rotation (zone, refusal code, seconds remaining).
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
- `DnsblAllowlistEntry` — DNSBL allowlist entry (name and reason); covers the name and everything beneath it.
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
- `ScopeRblProvider` — Per-scope RBL provider (scope, zone, enabled, refusal codes, refusal cooldown).
- `DhcpCertOption` — DHCP certificate option (scope, option code, cert data, description).
- `TldListener` — Per-TLD ingress DNS listener (scope, TLD, listen IP).
- `ZoneCa` — Root + intermediate PEM returned by `EnsureZoneCa`.
- `EabCredential` — EAB credential (kid, HMAC key, zone) returned by `CreateEabCredential`.
- `AcmeAccount` / `AcmeCertificate` — Registered ACME accounts and issued certificates.
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

## Prometheus Metrics

An optional `metrics` config section starts a plain-HTTP scrape endpoint at `/metrics` (default `127.0.0.1:9153`; `/` serves a link to it). The section is **absent by default**, so no listener is started and an upgrade opens no new port.

**Plain HTTP, loopback by default.** The endpoint is unauthenticated and carries only aggregate counts — no query names, no record values, no certificate material. TLS here would mean shipping the self-signed certificate to every scraper for an endpoint that should be bound to a private address regardless, so the default bind is loopback instead.

### Implementation (`src/metrics.rs`)

The registry is hand-rolled on the same lock-free primitives as the rest of the server — `AtomicU64` counters/gauges, `DashMap` for label dimensions known only at runtime — and renders the text exposition format directly. **No metrics crate dependency.** A hot-path counter bump is one relaxed `fetch_add` into a pre-allocated series: no hashing, no allocation, no lock.

- **Global registry.** Instrumentation calls `metrics()`, a `LazyLock<Metrics>`. Threading an `Arc<Metrics>` through the query path, both caches, the resolver, the blocklists, DHCP, the ACME issuer and the gRPC service would have meant changing every constructor and every test call site. Consequence for tests: counters accumulate across a test binary, so assertions are deltas taken under a serializing lock (`tests/metrics_test.rs`).
- **Bounded cardinality.** Every label is a fixed enum (`Proto`, `RCODES`, `ANSWER_SOURCES`, `TIERS`, `FAMILIES`, …) or bounded by configuration (upstream server addresses, gRPC method names). Query *type* — the one dimension a client controls — folds unrecognized types into `OTHER`, so a flood of `TYPE4242` queries cannot mint series. Query **names are never labels**.
- **Push vs. pull.** Counters are pushed where the work happens. Gauges with no natural push point (row counts, cache sizes, active tier, per-nameserver latency) are pulled once per scrape by `metrics::collect`, which reads every database count in a single `Database::metrics_counts` call under one lock acquisition rather than a dozen `list_*` calls that would materialize whole zones to take a `.len()`.
- **Histograms** store observations in an integer native unit (nanoseconds, bytes) so the running sum needs no float CAS, dividing by a scale at render time; bucket counts accumulate into the cumulative `le` form at render.

### Query attribution

`rolodex_dns_answers_total{source}` reports which stage of the resolution order produced each answer — `cache`, `local`, `scoped`, `scope_fallback`, `tld_peer`, `blocklist`, `rbl`, `dns64`, `upstream`, `authoritative_nxdomain`, `refused`, `error`. This is what makes the split-horizon pipeline legible from outside, and its total equals the query total.

`resolve_query` has roughly thirty exits. Rather than instrument each — where a new early return would silently escape the metrics — a `QueryTag` is threaded through and each non-upstream exit tags itself; the initial value is `upstream`, which is what the function's fall-through ending is. The observation is then recorded at **one** instrumented exit, `DnsServer::handle_query_proto`, which every transport funnels through, *after* the address-family filter, so the recorded rcode and response size are what the client actually receives. The `proto` label (`udp`/`tcp`/`dot`/`doh`/`doq`) only labels metrics and never affects resolution; the pre-existing `handle_query`/`handle_query_from`/`handle_query_on` wrappers keep their signatures and report `udp`.

### What is exposed

68 metric families, all prefixed `rolodex_dns_`:

| Area | Metrics |
| ---- | ------- |
| Process | `build_info{version}`, `start_time_seconds`, `uptime_seconds`, `metrics_scrapes_total` |
| Queries | `queries_total{proto,rcode}`, `queries_by_type_total{qtype}`, `answers_total{source}`, `query_duration_seconds{proto}` (histogram), `query_size_bytes`, `response_size_bytes`, `responses_truncated_total`, `malformed_queries_total`, `edns_unsupported_version_total`, `edns_do_queries_total`, `ingress_rewrites_total`, `answers_family_filtered_total{family}` |
| Response cache | `cache_hits_total`, `cache_misses_total`, `cache_negative_hits_total`, `cache_expired_total`, `cache_flushes_total{reason}` (`mutation`/`explicit`/`tier_switch`), `cache_entries`, `cache_negative_entries` |
| Blocklists | `blocklist_blocks_total{kind}`, `blocklist_allowlisted_total`, `blocklist_lookups_total{kind,result}` (`listed`/`not_listed`/`error`/`refused`), `blocklist_skipped_total`, `blocklist_cache_entries`, `blocklist_refusals_total{kind}`, `blocklist_rotated_out` |
| Upstream | `upstream_active_tier`, `upstream_tier_attempts_total{tier}`, `_wins_total{tier}`, `_failures_total{tier}`, `upstream_tier_switches_total{direction}`, `upstream_recovery_probes_total`, `upstream_duration_seconds{tier}`, `upstream_queries_total{server}`, `upstream_exhausted_total` |
| Resolver | `resolver_lookups_total`, `_referrals_total`, `_cname_hops_total`, `_budget_exhausted_total`, `_tcp_retries_total`, `resolver_priming_total{result}`, `resolver_nameserver_latency_milliseconds{server}`, `delegation_cache_entries`, `record_cache_entries` |
| Split-horizon | `records`, `scoped_records`, `scopes`, `scope_associations`, `authoritative_zones`, `managed_zones`, `owned_tlds`, `ingress_listeners`, `address_family_reachable{family}` |
| DHCP | `dhcp_messages_total{type}`, `dhcp_leases{state}`, `dhcp_pools`, `dhcp_allocation_failures_total`, `dhcp_sweeps_total` |
| ACME | `acme_accounts`, `acme_certificates`, `acme_issued_total`, `acme_validations_total{result}` |
| gRPC | `grpc_requests_total{method}`, `grpc_auth_failures_total` |

`dhcp_messages_total` deliberately has no `nak` label: the server never sends one, and a series pinned at zero forever reads like a signal when it is only an unimplemented branch.

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
| `dns.auto_ptr`                      | `false`                        | Auto-maintain reverse PTR records for A/AAAA added via gRPC (see Automatic Reverse PTR Records) |
| `dns.ingress_listen_port`           | `53`                           | UDP/TCP port for per-TLD ingress listeners (bind IP is per-TLD; see Ingress DNS Listeners) |
| `dns.udp_shards`                    | `0` (one per core)             | `SO_REUSEPORT` sockets bound per UDP listen address; `1` restores the single-socket listener (see Concurrency Model) |
| `grpc.tcp_bind`                     | `127.0.0.1:50051`              | gRPC TCP listener; supports interface:port (empty to disable) |
| `grpc.unix_socket`                  | `/var/run/rolodex-dns.sock`    | gRPC Unix socket path (empty to disable)               |
| `grpc.shared_secret`                | (empty)                        | Shared secret for TCP gRPC auth                        |
| `forwarders`                        | `["8.8.8.8:53", "8.8.4.4:53"]` | Upstream DNS resolvers (the `local` tier in `auto` mode; the only upstream in `forward` mode) |
| `resolution.mode`                   | `auto`                         | Upstream strategy: `auto` (tier chain), `recursive` (roots only), `forward` (forwarders only) |
| `resolution.root_hints`             | `[]` (built-in IANA roots)     | Override the root server hints used in `recursive`/`auto` mode |
| `resolution.secure_upstreams`       | Cloudflare + Google over DoH   | Encrypted upstreams for the `secure` tier; each entry is `{transport: https\|tls, addr, hostname, path}` |
| `resolution.public_fallback`        | `["1.1.1.1:53", "8.8.8.8:53"]` | Plaintext public resolvers, tried last in `auto` mode   |
| `resolution.switch_grace_failures`  | `3`                            | Consecutive deviating queries before an `auto` tier degrade commits |
| `resolution.recovery_probe_secs`    | `60`                           | How often a degraded `auto` chain retries from the top   |
| `resolution.delegation_persist_min_ttl` | `300`                      | Minimum TTL for a learned delegation to be persisted to SQLite |
| `resolution.default_ttl`            | `300`                          | Fallback TTL where a record/response carries none; a present TTL is always honoured |
| `database_path`                     | `rolodex-dns.db`               | SQLite database file path                              |
| `rbl.enabled`                       | `false`                        | Global RBL enable flag                                 |
| `rbl.providers`                     | `[]` (empty)                   | RBL provider list; each entry takes `zone`, `enabled`, and optionally `refusal_codes` / `refusal_cooldown_secs` |
| `rbl.refusal_cooldown_secs`         | `3600`                         | Seconds a refusing RBL provider stays rotated out, for providers that set none (see Refusal Codes and Provider Rotation) |
| `rbl.providers[].refusal_codes`     | `[]` (built-in set)            | Codes meaning "query refused" rather than "listed"; `none` disables detection for that provider |
| `rbl.providers[].refusal_cooldown_secs` | (list default)             | Per-provider rotate-out duration                       |
| `dnsbl.enabled`                     | `false`                        | Global DNSBL (domain blocklist) enable flag            |
| `dnsbl.providers`                   | `[]` (empty)                   | DNSBL provider list; same per-provider refusal fields as `rbl.providers` |
| `dnsbl.refusal_cooldown_secs`       | `3600`                         | DNSBL rotate-out default, independent of the RBL one   |
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
| `security.overlay_cidrs`            | `["10.64.0.0/10"]`             | Source ranges treated as untrusted overlay peers and scope-enforced; every other source is trusted |
| `security.recursion_cidrs`          | loopback, RFC 1918, link-local, ULA, CGNAT | Source ranges allowed to drive **upstream** resolution; others get local data only and are REFUSED for anything else (see Recursion Access Control) |
| `address_family.mode`               | `auto`                         | `auto` (probe and suppress an unroutable family), `off`, `force4`, `force6` |
| `address_family.probe_interval_secs`| `30`                           | Seconds between routability probes in `auto` mode      |
| `address_family.fail_threshold`     | `2`                            | Consecutive failed probe cycles before a family is marked down (recovery is immediate) |
| `address_family.probe_timeout_secs` | `2`                            | Per-target TCP-connect timeout for each probe          |
| `address_family.targets_v4` / `targets_v6` | Cloudflare/Google on `:443` | Probe targets per family (literal IPs)              |
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
| `metrics.bind`                      | `127.0.0.1:9153`               | Prometheus `/metrics` HTTP listener; supports interface:port (section optional) |

The `dot`, `doh`, `doq`, `proxy`, `acme`, and `metrics` sections are optional. When omitted, the corresponding transport/service is not started. When `acme` is present, the root CA is created at boot and both the ACME and portal listeners start.

## Build System

The project uses a top-level Makefile with the following targets:

| Target                | Description                                                                                                                                                |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `help`                | Print all targets with their descriptions, grouped by section. The default goal, so bare `make` shows it. Descriptions come from `##` annotations on the target lines; `##@` lines start sections. |
| `build`               | Compile the binaries for `TARGET`: a debug `cargo build` natively, or a cross-compiled release build when `TARGET` is a foreign architecture.              |
| `test`                | Run all tests: lint, Go integration tests, Go unit tests, Rust tests (`cargo test`), and JavaScript tests.                                                 |
| `test-log`            | Same as `test`, tee'd into a timestamped log file under `/tmp/rolodex-dns/log` (override with `LOG_DIR`). The log path is printed at the end even when the run fails. |
| `rust-test`           | Run the Rust integration test files, then `cargo test`.                                                                                                     |
| `rust-integration-test` | Build, then run each Rust integration test file explicitly (`integration_test`, `new_features_test`, `cli_integration_test`, `dhcp_integration_test`, `acme_issuer_test`, `auto_resolution_test`, `metrics_test`, `rbl_refusal_test`, `dnssec_signing_test`). |
| `lint`                | Run `cargo fmt -- --check` and `cargo clippy --all-targets -- -D warnings`.                                                                                |
| `deps`                | Install build dependencies: the Rust cross-compilation toolchain (`cross-deps`) and the JavaScript dev dependencies (`npm install` in `js/`).              |
| `cross-deps`          | Install the Rust cross toolchain: `rustup target add` for both triples, `cargo-zigbuild`, and zig. Rootless — see Cross-Compilation.                       |
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
| `image`               | Build a container image for `TARGET` (default: the host architecture) using `make/build.sh release`: cross-compile, stage, then `podman build --platform`. Tags with the `BUILD_ARCH` suffix (`-x86_64`/`-aarch64`). Accepts `IMAGE_TAG` (default `latest`). |
| `push` / `push-rc`    | Build and push the `TARGET`-arch release candidate image to `quay.io/town/rolodex`. Auto-tags `rc.YYYYMMDD-<arch>` + `rc.latest-<arch>` (e.g. `rc.latest-x86_64`/`rc.latest-aarch64`) unless `IMAGE_TAG` is set.   |
| `push-arch`           | Build and push ONLY the `TARGET` arch's per-arch tag (`<IMAGE_TAG\|latest>-<arch>`) to `quay.io/town/rolodex`. No date/`rc`/`latest` aliases, no manifest.       |
| `push-release`        | Build and push the `TARGET`-arch release image to `quay.io/town/rolodex`. Auto-tags `release.YYYYMMDD-<arch>` + `latest-<arch>` unless `IMAGE_TAG` is set.             |
| `image-amd64`         | Alias for `make image TARGET=x86_64`. |
| `push-rc-amd64` / `push-release-amd64` | Aliases for `make push-rc TARGET=x86_64` / `make push-release TARGET=x86_64`. |
| `push-rc-all` / `push-release-all` | Publish **both** arches from a single host of either architecture (both cross-compiled), then assemble the manifest. |
| `manifest` / `manifest-rc` | Assemble and push a multi-arch RC manifest list (`rc.YYYYMMDD`, `rc.latest`, or `IMAGE_TAG`) from the per-arch tags already in the registry. The `rc.latest` list is assembled from the `uname -m`-suffixed tags (`rc.latest-x86_64`, `rc.latest-aarch64`). |
| `manifest-release`    | Assemble and push a multi-arch release manifest list (`release.YYYYMMDD`, `latest`, or `IMAGE_TAG`) from the per-arch tags already in the registry.                |
| `quay-login`          | Login to Quay.io using `QUAY_USERNAME` and `QUAY_PASSWORD` from environment or `.env`.                                                                     |
| `clean-containers`    | Remove locally built per-arch container images.                                                                                                            |

The Makefile is designed to be extended for non-cargo scenarios. Protocol buffer bindings are generated at build time via `build.rs` using `tonic-prost-build`. Container images are built with Podman using unique instance IDs derived from the working directory path.

### Multi-Architecture Container Builds

Images are published to `quay.io/town/rolodex` as multi-arch manifest lists covering `linux/amd64` and `linux/arm64` (the OCI platform names embedded in the manifest by podman). Builds are **native**: each architecture is compiled on a host of that architecture (no in-container cross-compilation).

#### `TARGET` — selecting the architecture

`TARGET` selects the architecture for **every** container target (`image`, `push-arch`, `push-rc`, `push-release`), mirroring the model used by the `install` repo so one `TARGET=` value can be passed across the town-os repos. Empty (the default) is a native build for the host arch. Recognized values:

| `TARGET` | Resolves to |
| -------- | ----------- |
| *(empty)* | the host arch (`uname -m`, normalized) |
| `x86_64`, `x86`, `amd64` | `x86_64` |
| `aarch64`, `arm64` | `aarch64` |
| `rpi` | `aarch64` |
| `rg35xxpro`, `rg35xx-pro`, `rg35xx`, `anbernic` | `aarch64` |

Anything else is a hard `$(error)` at parse time listing the valid values. The board flavors (`rpi`, `rg35xxpro`, …) carry no image differences here — rolodex-dns ships one container image per architecture, not per board. They are accepted so that a `TARGET=rg35xxpro` that builds a board-specific disk image in `install` resolves to the aarch64 container image here instead of failing on a value that is valid one repo over.

Two derived variables follow from it, neither of which is a user knob:

- **`BUILD_ARCH`** — the image's architecture, and therefore the suffix on every arch-suffixed tag (`latest-<arch>`, `rc.latest-<arch>`, `release.YYYYMMDD-<arch>`). The Makefile exports it and `make/build.sh` reads it, falling back to `host_arch` when invoked directly. Deploy hosts can still pull `` <tag>-`uname -m` `` with no OCI-name mapping.
- **`CROSS`** — set when `BUILD_ARCH` differs from `HOST_ARCH`. Every architecture is cross-compiled either way, so this only decides whether `make build` runs a plain debug `cargo build` or the cross toolchain. **Any host can build any architecture** — there is no rejected combination. Set `TARGET`, not `CROSS`.

`ARCHES` in `make/lib.sh` holds the `x86_64 aarch64` machine names used as manifest suffixes (note: it is assigned unconditionally, so it is not overridable from the environment). The `build_manifest` helper assembles a manifest list from the per-arch tags using `podman manifest add docker://…`, so the per-arch images only need to exist in the registry, not locally.

#### Cross-Compilation (`make/cross.sh`)

Both architectures are **cross-compiled on whatever host runs `make`** — there is no builder VM and no emulation. The native and the foreign arch take the identical code path, so the two published images differ only in their target triple rather than in how they were produced.

**Why a real cross toolchain is required.** `rustup target add` on its own is not enough: `rusqlite` is built with the `bundled` feature (it compiles SQLite's C sources) and `ring` compiles C and assembly, so the build dies at the `cc` step without a cross **C** compiler. `cargo-zigbuild` supplies one by using zig as the C cross-compiler and linker.

**Why zig rather than a distro cross-gcc.** The entire toolchain installs without root — `rustup target add`, `cargo install cargo-zigbuild`, and a zig tarball extracted under `.cache/zig/` — so `make deps` can provision it on any machine instead of depending on distro-specific packages (`gcc-aarch64-linux-gnu` and friends differ per distro and need root). zig also links against a **pinned glibc**: the target triple is suffixed with `GLIBC_VERSION` (default `2.36`, matching `debian:bookworm`), so the binary runs on the runtime base image regardless of the build host's own glibc. Pins: `ZIG_VERSION`, `ZIGBUILD_VERSION`, `GLIBC_VERSION`.

**The runtime image has no `RUN` steps.** This is the constraint that removes the VM rather than relocating the problem. `podman build --platform linux/<arch>` only needs to *execute* something of the target architecture if a `RUN` instruction exists; a foreign `RUN` requires user-mode emulation, which is exactly what is unavailable on hosts like Fedora Asahi (its x86 emulation runs through FEX + `binfmt-dispatcher` + `muvm`, unusable inside a `podman build` sandbox — even a bare `podman run --platform linux/amd64` fails there). `Containerfile` therefore only `COPY`s: the cross-compiled binaries, and a CA bundle taken from the build host (certificates are architecture-independent data, so they need no `apt-get`). With zero `RUN` steps, a foreign-arch image is pure assembly of files and needs no emulation at all.

`make/cross.sh` has three subcommands: `deps` (provision the toolchain), `build ARCH` (cross-compile and strip the release binaries into `target/<triple>/release`), and `stage ARCH` (assemble `.cache/stage/<arch>` — the binaries plus the CA bundle — as the container build context).

**Build network.** Nothing in the image build resolves DNS any more, so `--network=host` is no longer passed by default. `BUILD_NETWORK=<name>` is still honoured if you need a specific podman network.

The end-to-end multi-arch publish flow, from **one host of either architecture**:

```bash
make push-release-all   # cross-compiles both arches, pushes both, then the manifest
```

Or step by step, which is also how you split it across hosts if you prefer:

1. `make push-release TARGET=x86_64` → pushes `…:latest-x86_64` (+ date tag).
2. `make push-release TARGET=aarch64` → pushes `…:latest-aarch64` (+ date tag).
3. `make manifest-release` → pushes the `…:latest` manifest list.

`push-rc-all` is the RC equivalent.

### Container Image Tagging

Images are published to `quay.io/town/rolodex`. Two variables control the tag: `IMAGE_TAG` picks the tag itself, and `TARGET` picks the architecture suffix appended to it (via `BUILD_ARCH`). Per-arch images carry the arch suffix; the manifest targets produce the un-suffixed multi-arch tag.

**Push with auto-generated tags** (default):

```bash
make push-rc          # pushes rc.YYYYMMDD-<arch> and rc.latest-<arch>
make push-release     # pushes release.YYYYMMDD-<arch> and latest-<arch>
make manifest-rc      # pushes rc.YYYYMMDD and rc.latest manifest lists
make manifest-release # pushes release.YYYYMMDD and latest manifest lists
```

**Pick the architecture** with `TARGET` (default: the host arch). Any host builds any arch by cross-compiling:

```bash
make push-release TARGET=x86_64     # pushes release.YYYYMMDD-x86_64 and latest-x86_64
make push-release TARGET=aarch64    # pushes release.YYYYMMDD-aarch64 and latest-aarch64
make image TARGET=rg35xxpro         # board flavor -> aarch64 container image
```

**Push a specific tag**:

```bash
make IMAGE_TAG=v1.2.3 push-release      # pushes quay.io/town/rolodex:v1.2.3-<arch>
make IMAGE_TAG=v1.2.3 manifest-release  # pushes quay.io/town/rolodex:v1.2.3 manifest list
make IMAGE_TAG=v1.2.3-rc1 push-rc       # pushes quay.io/town/rolodex:v1.2.3-rc1-<arch>

# IMAGE_TAG and TARGET compose: the tag, with that arch's suffix.
make IMAGE_TAG=v1.2.3 TARGET=x86_64 push-release   # -> quay.io/town/rolodex:v1.2.3-x86_64
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

### Metrics Tests

- **Registry unit tests** (`src/metrics.rs`): counter/gauge/vec semantics including out-of-range label indices (which must never panic on the query path), cumulative histogram bucketing, nanosecond→seconds and byte rendering, dynamic series creation, label-value escaping, float formatting that avoids scientific notation, rcode/qtype folding of unknowns, and a guard that every emitted series is preceded by its own `# HELP`/`# TYPE`.
- **Endpoint and attribution tests** (`tests/metrics_test.rs`): the router is served on an ephemeral port and scraped over a real TCP socket with a hand-written HTTP/1.1 request — status, content type, and that every non-comment line parses as `name[{labels}] value` with a numeric value, since one malformed line makes Prometheus reject the whole scrape. Query-path tests assert that a local hit, a cache hit, an authoritative NXDOMAIN, a malformed query and an unknown query type each land in the right series, that gauges are sampled at scrape time (a row added after the listener started shows up), that the three cache-flush reasons stay distinct, and that a blocklist refusal advances `blocklist_refusals_total` and the `refused` lookup outcome **without** also advancing `listed`. Because the registry is a process-global, each test holds a shared lock and asserts exact deltas — serializing rather than loosening to `>=` is what catches an observation being recorded *twice*.

### Resolver Tests

The iterative resolver has a dedicated suite built on a **mock delegation hierarchy** (`tests/mock_hierarchy/mod.rs`) — real in-process nameservers whose queries are counted, because query counts (not returned records) are what distinguish these bugs from their fixes:

| Test file | What it pins |
| --------- | ------------ |
| `tests/auto_resolution_test.rs` | The `auto` tier chain: root recursion pointed at loopback so it fails fast, empty secure tier, mock UDP upstreams for the plaintext tiers — exercising definitive-answer/fall-through logic as on a network that filters outbound `:53`. |
| `tests/delegation_cache_test.rs` | N cold names must cost **one** root query, not N. |
| `tests/delegation_flush_test.rs` | `flush_cache()` (called from 15+ gRPC mutation sites) must **not** wipe delegations; only `flush_upstream_state()` may. Adding one package must not send every name back to the roots. |
| `tests/delegation_persist_test.rs` | Delegation persistence across restart, and the answer cache's boot load. |
| `tests/record_cache_test.rs` | Glue, glue-less NS lookups, and CNAME hops are cached and not re-queried. |
| `tests/negative_ttl_test.rs` | RFC 2308 negative TTL honoured as sent (no floor, no ceiling); `default_ttl` only when there is no SOA. |
| `tests/resolver_selection_test.rs` | A slow server is demoted, a dead server is demoted, IPv4 is always tried before IPv6. |
| `tests/root_balance_test.rs` | `hits * latency` selection spreads load across the roots instead of pinning the fastest one. |
| `tests/root_priming_test.rs` | Priming happens at startup (never on the query path) and the hints are a bootstrap/fallback. |
| `tests/query_budget_test.rs` | One client lookup costs a bounded number of upstream queries (the pathological glue-less zone that produced 65,536 queries in 42s). |

### DNSSEC Signing Tests

`tests/dnssec_signing_test.rs` pins that a signature is *checkable*, not merely present. Asserting that RRSIG rows appeared would pass just as happily for a signature computed over the wrong bytes, the wrong owner name, or with a key that is not the one advertised — and each of those fails at a validating resolver rather than in the suite. So the central test re-derives the signing input from the **published DNSKEY RRset** (never from the private key rows, since a validator has only the DNSKEY) and verifies every RRSIG in the zone, across all three algorithms and both key types, over a zone containing multi-record RRsets, embedded names and out-of-band MX/SRV priorities.

The rest covers: one RRSIG per multi-record RRset and its failure to verify over a subset, the KSK/ZSK role split and the single-key fallback, label-boundary zone confinement, re-signing replacing rather than accumulating signatures (including at names whose records were deleted), validity windows and original-TTL agreement, unsignable types being skipped and reported, DNSKEY/RRSIG being served under their own type codes, served RDATA being byte-identical to what was signed, generated keys carrying the algorithm they claim, RSA being refused, and the DS record matching the published DNSKEY.

Unit tests in `src/dnssec.rs` cover the canonical form itself: name lowercasing and qualification, RFC 4034 §3.1.3 label counts, character-string chunking, per-type RDATA encoding, RRset order-independence, per-algorithm sign/verify round-trips, tamper detection, refusal to load key material that contradicts its label, and that stored algorithm names round-trip through `parse`.

### Blocklist Refusal Tests

`tests/rbl_refusal_test.rs` drives refusal codes and provider rotation over **real UDP DNS** — a mock blocklist zone answering with real `A` records, through `RecursiveRblResolver`'s forwarder fallback, through classification, into `DnsServer::handle_query` — because every layer in between is somewhere the listing/refusal distinction could be lost, and asserting on `classify` alone would pass just as happily with a query path that never calls it. Root recursion points at a dead loopback address so the roots tier fails instantly and the test never touches the network.

Every test is paired with a **control**: a genuine `127.0.0.2` listing travelling the identical path must still return NXDOMAIN. Without it, a checker that had simply stopped blocking anything would pass the whole file.

It covers each documented refusal code failing to block while rotating its provider out, rotation suppressing further lookups for distinct names (the query *count* is the only way "out of rotation" is observable), the cooldown lapsing on its own, `none` restoring the old reading, an explicit list replacing rather than extending the defaults, the gRPC round trip of codes/cooldowns/rotated-out state, `InvalidArgument` for a malformed code and for `none` mixed with real codes, and the per-scope provider's database round trip.

Unit tests in `src/rbl.rs` cover the pieces: prefix parsing and masking, that every entry of `DEFAULT_REFUSAL_CODES` parses (they are resolved with `filter_map`, so a typo in the constant would otherwise silently drop a code) and that no Spamhaus *listing* code falls inside them, `resolve_refusal_codes`' empty/`none`/explicit rules, a refusal winning over a listing in the same answer, refusals caching nothing, cached listings surviving rotation, and `flush_cache`/`set_config` returning providers to rotation. `src/config.rs` pins that a provider written before the fields existed still parses and lands on the built-in codes; `src/db.rs` pins the column migration onto a database created without them.

### Security Regression Suites

The `tests/security_*.rs` files each pin the behaviour one security finding requires, stated in observable terms and paired with a control that must stay green. They cover: the Do53 forwarder and iterative resolver response validation (`security_forwarder_test`, `security_resolver_test`), referral and glue bailiwick (`security_bailiwick_test`), the ACME issuer's CSR confinement, authorization, replay and expiry handling (`security_acme_test`), the enrollment portal's zone scoping and CSRF defences (`security_portal_test`), IPv4-mapped source classification (`security_scope_test`), open recursion and amplification (`security_open_resolver_test`), DHCP-supplied hostname validation (`security_dhcp_hostname_test`), stream-transport connection limits (`security_tcp_limits_test`, `security_dot_limits_test`), filesystem permissions and startup refusal of an unauthenticated routable gRPC bind (`security_local_access_test`), and constant-time secret comparison plus brute-force throttling (`security_auth_hardening_test`).

A failure in one of these is the finding, not a broken test — the module docs at the top of each file state the invariant and why it is written the way it is. Never weaken an assertion to make one pass.

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

The `make test` target runs the full test suite: lint, Go integration tests, Go unit tests, Rust integration tests (each test file explicitly: `integration_test`, `new_features_test`, `cli_integration_test`, `dhcp_integration_test`, `acme_issuer_test`, `auto_resolution_test`, `metrics_test`, `rbl_refusal_test`, `dnssec_signing_test`), all Rust tests via `cargo test` (which also covers the resolver suite above), and the JavaScript lint/integration/unit tests. Individual targets are available: `make go-integration-test`, `make go-test`, `make rust-integration-test`, `make rust-test`, `make js-integration-test`, `make js-test`. Use `make test-log` to capture the whole run to a timestamped log file.

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
- **subtle** — Constant-time comparison of the gRPC shared secret (ring's own `verify_slices_are_equal` is deprecated and documented as internal-only with no side-channel promises)
- **base64** — Base64 encoding for DoH GET requests
- **hex** — Hex encoding for TLSA/DNSSEC records
- **serde** / **serde_yaml_ng** — Configuration serialization
- **fancy_duration** — Compound duration parsing for TTL drift
- **rand** — QNAME case randomization, nameserver selection jitter
- **nix** — Safe Unix interface abstractions (interface address enumeration via `getifaddrs`)
- **webpki-roots** / **rustls-pemfile** — Trust anchors for the encrypted (DoH/DoT) upstream clients; PEM loading
- **dhcproto** — DHCPv4 message parsing and serialization
- **anyhow** / **thiserror** — Error handling

### Dev / Benchmarks

- **criterion** — Micro-benchmarking framework for performance regression testing

### Go

- **google.golang.org/grpc** — gRPC framework
- **google.golang.org/protobuf** — Protocol buffer runtime

## Concurrency Model

The server runs on the tokio multi-threaded async runtime. Each UDP listen address is **sharded across `SO_REUSEPORT` sockets** (`dns.udp_shards`, default one per core): a single socket serialises the listener — one task drains it with `recv_from` and every reply contends on it — which caps throughput far below CPU saturation no matter how many cores are idle. Each shard runs its own receive loop and replies on its own socket, so the kernel hashes arriving datagrams across cores in both directions. `SO_REUSEPORT` is set only when more than one shard is requested, so a single-shard listener still fails loudly on an occupied port (which the ingress bind-failure handling depends on) instead of silently sharing it; a port-`0` (ephemeral) bind is forced to one shard, since the kernel would otherwise hand each shard a different port. Shards live in a `JoinSet` owned by the `serve_udp` future, so aborting the driving task — as `stop_ingress_listener` does — tears every shard down with it. Within a shard, a task is spawned per received query. DNS TCP connections spawn a new task per connection. DoT, DoH, and DoQ connections each spawn a new task per connection. gRPC servers (TCP and Unix socket) run as separate tasks. Upstream forwarder configuration is protected by `ArcSwap` for lock-free reads. RBL state uses lock-free primitives: the enabled flag is an `AtomicBool` and the provider list uses `ArcSwap` for zero-contention reads. The RBL cache and DNS response cache use lock-free `DashMap`. The SQLite database is protected by a `Mutex` with `prepare_cached` for statement reuse.

At boot, in-memory caches are populated from the database: scope count (`AtomicUsize`), local RBL entries (`DashSet`), DNSBL allowlist entries (`DashSet`), authoritative zones (`DashSet`), managed zones (`DashSet`), TLD ownership (`tld_owner_cache`), per-TLD ingress IPs (`tld_ingress_cache`), and the persisted delegation cache. These caches avoid SQL queries on the hot path and are updated incrementally as records are added or removed via gRPC.

The `auto` resolution state machine is entirely lock-free: the active tier, deviation streak, last-probe timestamp, and grace/probe parameters are atomics, and the recovery probe is gated by a compare-exchange so only one concurrent query probes per interval. The secure upstream list, public fallback list, resolution mode, and overlay CIDR list use `ArcSwap`. Answer-family suppression is a pair of `AtomicBool`s written by the background probe task. Ingress listeners are tracked in a `DashMap<IpAddr, Vec<AbortHandle>>`; the delegation cache persists through a background SQLite write worker fed by an `mpsc` channel, and the delegation/record caches are `DashMap`.

The Prometheus registry is lock-free by the same means: counters and gauges are `AtomicU64`, fixed-label families are pre-allocated arrays indexed directly (so an increment is an index plus one relaxed `fetch_add`, with no hashing and no allocation), histograms are per-bucket atomics accumulated into cumulative form only at render, and the runtime-labelled families are `DashMap`. Nothing on the query path takes a lock to record a metric. The scrape path pulls its gauges through a single `Database::metrics_counts` call so it holds the SQLite mutex once per scrape rather than a dozen times.

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
