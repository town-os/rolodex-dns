# Changelog

## Unreleased

### Security

- **The Do53 forwarder accepted any datagram that arrived.** `forward_udp` sent a query and returned whatever came back: the transaction id was never compared, the pooled sockets are unconnected so the kernel delivered datagrams from *any* source, the response question was never matched against the query, and the one check that did exist — 0x20 QNAME case — only emitted `warn!` and then returned the response anyway. `security.qname_case_randomization` is on by default and documented as cache-poisoning resistance; it enforced nothing. Because the 8 pooled sockets are bound once and reused for the process lifetime, their source ports are stable after a single observation, so off-path poisoning needed no guessing at all — and `cache_from_wire` then persisted the forgery.

  A reply is now accepted only if it comes from the address that was queried, carries the transaction id that was sent, and answers the same question — name, type, and class, compared **case-sensitively**, which is what finally makes 0x20 do its job. Rejected datagrams are discarded and the real answer is still awaited until the deadline, rather than the first packet deciding the query: that keeps a single injected packet from denying the lookup, and drains late replies to earlier queries off the pooled socket.

  Operationally: an upstream resolver that does not echo the question verbatim will now fail instead of silently resolving. Well-behaved resolvers echo it as required, but if you point at one that normalizes case, turn off `security.qname_case_randomization` for it. The proxied (`proxy.mode`) forwarding path is unchanged — its responses arrive over a TCP connection to a known proxy.

- **The iterative resolver accepted replies from any source, answering any question.** `query_one` bound its UDP socket and never connected it, so the kernel delivered a datagram from *any* peer — the source-address check that normally forces an off-path attacker to spoof the authoritative server's IP was simply absent, leaving only the transaction id and the ephemeral port. Separately, `validate_question` compared the response question's *name* and nothing else, so a reply answering a question the resolver never asked — a different record type, or a different DNS class — passed validation and its records were taken, cached, and served.

  The query socket is now connected to the nameserver before the query goes out, which restores the source check in the kernel at no per-packet cost, and `validate_question` compares the full question: name (case-insensitively, as the resolver does not 0x20-randomize), type, and class. This path was already the better-defended of the two upstream paths — it did check the transaction id — but both gaps are now closed on UDP and TCP alike.

- **The iterative resolver accepted out-of-bailiwick referrals and glue.** `classify` took the referral zone from the owner name of whatever NS record came first in the authority section and never checked it against the name being resolved or the zone that answered, and `walk` wrote it straight into the delegation cache. Any nameserver the resolver ever talked to — one ad domain, one link — could answer a query about its own zone with `AUTHORITY: com. NS ns.attacker.example` plus glue, and `best_match` walks suffixes, so every later `.com` lookup started at the attacker's server. A referral whose TTL cleared `resolution.delegation_persist_min_ttl` was written to the `delegation_cache` table and reloaded at boot, so the hijack outlived a restart. `.` worked identically. Separately, `cache_glue` cached additional-section addresses under their own owner names, so the same response could plant an address for a foreign nameserver hostname.

  A referral is now followed and cached only if it moves **strictly down** from the zone that answered *and* covers the name being resolved (`referral_in_bailiwick`); anything else fails the lookup rather than being quietly ignored, so a hostile delegation cannot masquerade as progress. Glue is filtered to names inside the **answering** zone — deliberately not the delegated one, because a root referral for `com.` legitimately carries glue for `a.gtld-servers.net.`, which is outside `com.` but well inside `.`. Discards are counted by `rolodex_dns_resolver_out_of_bailiwick_total`.

- **DHCP hostnames were interpolated into DNS names unvalidated.** `register_dns_hostname` built the record name with `format!("{}.lan.{}.", hostname, tld)` from DHCP option 12 — supplied verbatim by any unauthenticated device on the LAN. A client that named itself `*` got `*.lan.<tld>.` registered, and `make_wildcard_name` makes that a real wildcard: `lookup_scoped` falls back to it whenever an exact match misses, so one laptop answered for every unregistered name in its scope. Dots let a client place itself at a depth it was never allocated, and nothing checked length, so labels over the 63-byte wire limit reached the database and failed later at serialization instead of once, on arrival.

  Hostnames are now validated as a single LDH label (RFC 1123 §2.1) — 1–63 bytes, letters/digits/hyphen, no leading or trailing hyphen — lowercased, and **rejected rather than sanitized**, so a client sending a name the rule refuses is not silently assigned a different one. Registration is skipped with a warning; deregistration runs the same validation so the name removed is the name that was added.

- **DNS-over-TCP and DoT connections were unbounded and untimed.** `serve_tcp` and `serve_dot` spawned a task per connection with no cap, and both read loops awaited `read_exact` with no timeout, so a client that connected and sent nothing — or half a length prefix, or a 65535-byte announcement it never delivered — parked a task and a file descriptor indefinitely. `dns.bind` defaults to `0.0.0.0:53`: on a routable interface that is a pre-auth remote resource exhaustion, and once descriptors run out `accept` fails for every legitimate client too. DoT was worse: `acceptor.accept()` was untimed as well, so a bare `connect()` with no TLS implementation at all parked a task before any DNS was exchanged, somewhere no fix aimed at the DNS read loop would reach.

  Both listeners now apply a 10s idle timeout between messages, a 5s deadline for the body of an announced message, and a 1024-connection cap per listener; DoT adds a 10s TLS handshake timeout. The idle timeout is measured from the last activity, so RFC 7766 connection reuse still works — which matters more on DoT, where reconnecting costs a fresh handshake. DoQ already had `max_idle_timeout` and is unchanged.

- **The gRPC shared secret was compared with `==`, and failures were unthrottled.** `String: PartialEq` compares lengths and then defers to `memcmp`, which returns at the first differing byte — so the time taken leaks how many leading bytes of the secret the caller guessed correctly, turning a search over the whole secret into a byte-at-a-time one. Separately, nothing limited failed attempts: a client that could reach the gRPC port could guess as fast as it could open connections, which is what makes a weak shared secret fatal rather than merely unwise.

  The comparison now uses `subtle::ConstantTimeEq`. (`ring`'s `verify_slices_are_equal` is deprecated and documented as internal-only with no side-channel promises, so `subtle` — already in the tree transitively — is now a direct dependency.) Failed authentications are throttled **per source address**: 5 consecutive failures lock a source out for 30s, doubling per consecutive lockout to a 15-minute ceiling, and while locked out every attempt is refused with `ResourceExhausted` *without the token being compared at all*, so the lockout is not itself an oracle for "was that guess right?".

  Keyed per source rather than globally, so one attacker cannot lock the operator out of their own management plane; the counter is on *failures*, not requests, and a success clears the source's history, so legitimate automation calling in a loop is never throttled; a run that goes quiet for 5 minutes resets, so an occasional mistyped token never accumulates. The table is capped at 65536 sources — over the cap, idle-and-unlocked entries are pruned and further new sources go untracked, rather than a distributed flood growing it without bound.

- **The gRPC Unix socket was world-connectable.** A Unix connection bypasses authentication entirely — that is deliberate, and it makes the socket's file mode the *only* access control on the management plane. `main.rs` did a bare `UnixListener::bind` and never chmodded the result, so it landed under the umask, typically `0755`, and every local user on the box had unauthenticated administrative control: rewrite any DNS record, mint EAB credentials, ensure zone CAs. The socket is now created `0660` — bound at a temporary sibling path, restricted, then renamed into place, because chmod-after-bind at the published path leaves a window in which the socket exists and is world-connectable, and an atomic rename keeps the same inode so the listener is unaffected. `0660` rather than `0600` so a deployment can grant a dedicated admin group access by chgrp'ing the socket.

- **The database was world-readable.** It is the keystore: the root CA private key, every per-zone intermediate key, the DNSSEC private keys, and the EAB HMAC secrets are plain rows in it. Nothing called `set_permissions`, so SQLite created it under the bare umask — `0644` under the common default — and any local user could read the root CA key and forge a certificate for any name that every enrolled client trusts. `Database::open` now restricts it to `0600`, and does so *before* enabling WAL, since SQLite copies the main file's mode onto the `-wal`/`-shm` sidecars it creates; pre-existing sidecars are tightened too.

- **A routable gRPC bind with no shared secret started silently.** An empty `grpc.shared_secret` makes `check_auth` early-return `Ok(())` for every TCP RPC. That is the documented development configuration on loopback and a total exposure of the management plane on anything else — and the server came up looking healthy, logging nothing unusual. The combination is now refused at startup (`config::check_grpc_exposure`): the loopback case still starts, `0.0.0.0` and `::` are correctly not loopback, and an `interface:port` bind is condemned by a single routable address on the interface.

- **A default deployment was an open recursive resolver.** `dns.bind` defaults to `0.0.0.0:53` and source classification treats everything outside `security.overlay_cidrs` as a trusted local client, so on a routable interface every host on the internet got full recursive service. That is the classic reflection/amplification asset — a small spoofed query returns a large answer aimed at the spoofed victim, and the outbound resolution traffic is billed to this box — and nothing rate-limited it, so a flood was serviced as fast as it arrived.

  A new `security.recursion_cidrs` decides who may drive **upstream** resolution, defaulting to every range that is unroutable from the internet: loopback, RFC 1918, link-local, ULA, and CGNAT. That covers the LAN, container bridges, and the WireGuard overlay (`10.64.0.0/10` is inside `10.0.0.0/8`), so nothing that legitimately used this server loses service. It is a separate axis from `overlay_cidrs`, which decides who is scope-*enforced*.

  The check sits at the local/remote boundary — after everything that answers from data this server holds, before everything that reaches for data it does not — so a stranger still gets this server's authoritative answers and NXDOMAINs but cannot make it resolve the internet on their behalf. It runs *before* the response cache, because a cached answer amplifies as well as a fresh one and warming the cache is how the attack is staged, and the refusal is REFUSED with an empty answer section, which is never larger than the question that provoked it. DoH now serves with connect info so its peer address reaches classification; without that, `:443` would have reopened what `:53` closes.

- **An IPv4-mapped source address bypassed scope enforcement.** Source classification tested the address exactly as the socket reported it, and `IpCidr::contains` deliberately does not match across address families. On a dual-stack listener — `[::]:53`, a documented bind form and the default on Linux with `net.ipv6.bindv6only=0` — an IPv4 overlay peer arrives as `::ffff:10.64.0.1`, which is an `IpAddr::V6`, so `is_overlay_peer` returned false and the peer was classified as a *trusted local source*. Both halves of the split-horizon broke: an overlay peer joined to no network was no longer REFUSED and reached the global namespace it was meant to be partitioned away from, and a peer that *had* called `JoinNetwork` silently lost its scope, because the association was stored under the plain IPv4 form. Whether a WireGuard peer was scope-enforced at all came down to how the listener happened to be bound.

  `handle_query_on` now canonicalizes the source address (and the local listener IP) once, before anything classifies it, so the mapped and plain spellings of an address are the same address everywhere downstream — the CIDR test, the association lookup, and the ingress-listener match. IPv4-compatible addresses (`::1.2.3.4`, deprecated) are deliberately not folded; only true IPv4-mapped addresses are.

- **The enrollment portal would become a CA for any zone on the internet.** `create_account_inner` took the `zone` string verbatim, called `ensure_zone_intermediate` on it, and minted an EAB scoped to it. Nothing tied the zone to anything the server actually manages, so a reachable client could create an intermediate for `windowsupdate.com` — published as DANE-TA records in the local DNS, chaining to the root every enrolled client trusts — and then issue against it. "Anyone who can reach it may enroll" is a deliberate design decision and is unchanged; it was never meant to mean "may become a CA for the entire namespace". Enrollment is now confined to zones this server has a relationship with: a scope owns it as a TLD (which covers a scope's implicit `.home` domain), it has records in the local database, it is a declared authoritative zone, or it already has an intermediate CA because an operator ran `EnsureZoneCa`. Each is suffix-matched, so a subzone of a managed zone enrolls too, and `acme.issuance_scope: any` lifts the restriction entirely — the same thing that setting already means for the issuer.

- **The portal was open to drive-by CSRF.** `POST /api/account` read the body as bytes and parsed JSON without requiring a JSON content-type or checking `Origin`. A cross-origin form POST with `Content-Type: text/plain` is a CORS *simple request* — no preflight, so the browser sends it and the side effect lands. The attacker could not read the minted EAB back, but the CA creation and the DNS publication happened anyway: a page in any LAN user's browser could reshape the local PKI. The endpoint now requires `application/json` (which forces a preflight the portal does not answer) and refuses any `Origin` that is not this server, compared on authority so a TLS-terminating proxy still works. Browser-extension origins are exempt — the bundled extension is a first-class client, and its origin is only attached after the user grants host permission. Non-browser clients (the CLI, the `js/` portal client, the local UI proxy) send no `Origin` and are unaffected.

- **The ACME issuer signed whatever names the CSR asked for.** `ca::issue_leaf` handed the client's CSR straight to rcgen, which copies its `dNSName` SANs and subject into the issued certificate. Nothing compared them to the identifiers the order had actually validated, so proof of control over one name bought a certificate for *any* name — including names in another tenant's zone — signed by an intermediate that chains to the Rolodex root every enrolled client trusts, and published as a DANE-TA anchor. `issue_leaf` now takes the order's validated identifiers and rejects a CSR requesting anything outside them (`badCSR`). The subject common name is checked too, but only when it reads as a hostname, since rcgen stamps `"rcgen self signed cert"` into any CSR built without an explicit DN.

- **ACME endpoints authenticated the caller but never authorized them.** `order`, `authz`, `challenge`, `finalize`, and `cert` looked their object up by id and never checked it belonged to the requesting account (RFC 8555 §7.4). Finalizing another account's ready order yielded a certificate for the victim's name under an attacker-held key; certificates are addressed by a sequential rowid, so any account could enumerate and download every certificate the CA had issued. All five now verify ownership, the certificate path via the issuing order.

- **`url` binding was optional.** `verify_request` checked the JWS protected header's `url` only when present, so omitting it bound the request to no endpoint and allowed cross-endpoint replay. It is now mandatory (RFC 8555 §6.4).

- **EAB credentials were reusable forever.** The `used` column was written by `mark_eab_used` and never read, so one leaked enrollment credential registered unlimited accounts against its zone. It is now enforced.

- **Order and authorization expiry was never checked.** `expires_at` was stored and ignored, so a validation performed once was good indefinitely — long after the operator removed the challenge record or lost the name. `finalize` and the challenge-response path now enforce it.

- **Anti-replay nonces accumulated without bound.** A nonce was minted and persisted on every response, including unauthenticated `GET /acme/directory`, and only spent ones were removed — an unauthenticated remote client could grow the table until the disk filled, contending on the mutex the DNS hot path uses. Nonces now expire after an hour *and* the table is capped at 1024 outstanding entries, evicted oldest-first. A TTL alone would not have bounded it: a flood inside one second is entirely within the window.

- **`revoke-cert` reported success without revoking.** It returned `200 OK` after verifying the JWS, telling clients a compromised certificate was dead when nothing had changed. It now returns `501` until revocation is implemented.

### Features

- **Prometheus metrics.** An optional `metrics` config section starts a plain-HTTP `/metrics` endpoint (default `127.0.0.1:9153`) exposing 66 metric families across the whole server: queries by transport/rcode/type, an end-to-end latency histogram per transport, message-size histograms, response-cache hit/miss/expiry/flush accounting, blocklist blocks and provider-lookup outcomes, the `auto` tier chain (active tier, per-tier attempts/wins/failures, committed switches, recovery probes, per-upstream exchange counts), iterative-resolver internals (referrals, CNAME hops, budget exhaustion, TCP retries, root priming, per-nameserver EMA latency), split-horizon state (records, scopes, associations, owned TLDs, ingress listeners), address-family suppression, DHCP messages and leases by state, ACME issuance and dns-01 validations, and per-method gRPC call counts.

  The section is **absent by default**, so an upgrade opens no new port; the default bind is loopback because the endpoint is unauthenticated. It carries only aggregate counts — no query names, no record values.

  The registry is hand-rolled (`src/metrics.rs`) on the same lock-free primitives the rest of the server already uses, adding **no dependencies**: a counter bump on the hot path is one relaxed `fetch_add` against a pre-allocated series, and the text exposition format is written directly. Every label dimension is a fixed enum or bounded by configuration — the one a client could otherwise blow up, the query type, folds unrecognized types into `OTHER`, so a flood of `TYPE4242` queries cannot mint unbounded series.

  The `rolodex_dns_answers_total{source}` metric reports which stage of the resolution order answered — cache, local record, scope, LAN→scope fallback, TLD peer, blocklist, RBL, DNS64, upstream, authoritative NXDOMAIN, refused — which is what makes the split-horizon pipeline legible from outside. It is threaded through `resolve_query`'s ~30 exits by a tag whose default is the upstream path, and recorded at a single instrumented exit shared by every transport, so a new early return cannot silently escape the metrics.

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
