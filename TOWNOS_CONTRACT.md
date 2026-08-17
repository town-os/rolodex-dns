# The Town OS contract

> Languages: **English** | [繁體中文](TOWNOS_CONTRACT.zh-TW.md) | [简体中文](TOWNOS_CONTRACT.zh-CN.md) | [Español (España)](TOWNOS_CONTRACT.es-ES.md) | [Español (México)](TOWNOS_CONTRACT.es-MX.md) | [日本語](TOWNOS_CONTRACT.ja-JP.md)

This is the authoritative list of everything that crosses the boundary between rolodex and Town OS, in both directions.

**The direction is the opposite of gfeh's.** gfeh is a client of Town OS; rolodex is a thing Town OS drives. Town OS's systemcontroller is rolodex's gRPC client, the `../install` image writes rolodex's bootstrap config file, and ttyforce writes the network configuration that decides what rolodex can discover. So most of what follows is **what those three may assume about rolodex**, and a short section of what rolodex requires back.

**Nothing here is pinned to a revision.** `make check-townos-sync` resolves whatever checkouts are on the machine at the moment it runs. A recorded revision that no script reads is a claim nobody is maintaining, and a pin would fail loudly on Town OS commits that changed nothing rolodex depends on — the worst of both.

| Command | Checks against | Skips? |
|---|---|---|
| `make check-townos-sync` | local checkouts (`TOWNOS_DIR=`, `INSTALL_DIR=`) | yes, if absent |

It runs as part of `make lint`, so ordinary development gets it for free and still works on a machine that has only this repository.

### What the check actually verifies

Names alone are not enough — a constant that still exists but moved is exactly the failure that stays green here and breaks on the box. The check compares:

- **Every method Town OS's `Client` interface declares exists on rolodex's own Go client (`go/client.go`).** That, not the proto, is the surface Town OS binds to — its `client` struct delegates straight through to this repository's Go package. Some of those methods are convenience wrappers rather than distinct rpcs (`AddScopeTldWithListener` is `AddScopeTld` with `listen_ip` set), so a proto-only check reports drift that is not there while missing a removed wrapper, which is drift that is.
- **The forwarder scheme sets in the two parsers are identical** — `src/forwarder.rs` here and `src/rolodex/forwarder.go` there. Two hand-written parsers of the same grammar in repositories that cannot see each other is the newest and least defended thing in this document.
- **The fixed addresses agree across all three repositories**: the DoH backend, the metrics listener, the loopback rolodex binds, and the TLS directory, as a Go constant, a literal in the install script, and a default here.

## Scope

Three counterparties, and they are not interchangeable:

1. **Town OS (`../town-os`)** — the systemcontroller. Programs rolodex's *settings* over gRPC and scrapes its metrics. It writes no configuration file.
2. **The install image (`../install`)** — `scripts/rolodex-config.sh` writes `rolodex.yml` and nothing else does. It carries only what cannot be set on a running rolodex.
3. **ttyforce (`~/src/github.com/erikh/ttyforce`)** — writes the networkd units. It appears here only because one of its choices (`UseDNS=no`) decides what Town OS's forwarder discovery can find, which is not obvious from either side.

Nothing else crosses the boundary. In particular:

- **rolodex never calls Town OS.** There is no HTTP client, no account lookup, no storage call. Everything flows in.
- **rolodex writes no file Town OS reads.** Its database is its own; the gRPC socket and the metrics endpoint are the whole outward surface.

## `rolodex.yml` is bootstrap-only, and the two repositories move together

`scripts/rolodex-config.sh` in `../install` is the only writer. It carries exactly what cannot be set on a running server:

| Key | Why it cannot be programmed |
|---|---|
| `dns.bind` | The listeners must exist before any API call can reach them |
| `metrics.bind` | rolodex opens that listener once at startup, from the section's presence |
| `doh` / `dot` / `doq` | Opened once at startup from each section's presence |
| `database_path`, `grpc` | Read before the server exists |
| `forwarders`, `resolution.mode` | Boot **defaults** only — the systemcontroller programs the operator's real choices over gRPC |

**Serde rejects an unknown or missing field outright.** A field required at the image's revision and absent from the file — or present in the file and unknown to the image — is a hard `failed to parse config file` at startup, and under `Restart=always` that is a crash loop with DNS down for everything on the box. It has already happened once, on the `rbl` → `dnsbl` rename.

The rule that follows: **the install repo's `rolodex-config.sh` and the published rolodex image move together.** A config key renamed here without a matching change there is a broken box, not a failed test. `TestRolodexDohBackendMatchesTheInstallScript` in Town OS catches exactly one direction of this, and only where `../install` is checked out.

## Settings live in memory only

rolodex persists **nothing** set over gRPC. It seeds from `rolodex.yml` at startup and holds the rest in memory, so a crash under `Restart=always`, a DHCP lease change bouncing the unit, or an operator restarting it by hand drops every setting Town OS pushed back to boot defaults.

Town OS's obligation, therefore: **re-push after every restart.** `ProgramRolodex` runs on a 15-second tick and notices a restart through `Manager.Generation` — the identity of the gRPC socket rolodex binds at startup (device, inode, mtime). Nothing in rolodex announces a restart; the socket's identity is the signal.

Two consequences worth stating plainly:

- **An identical re-push must be free.** `SetForwarders` and the blocklist setters are plain stores — no cache flush, no upstream reconnection — precisely so the tick can push unconditionally rather than diff. `SetResolutionMode` is *not* free (switching into `auto` restarts tier discovery), which is why Town OS diffs that one against `GetResolutionMode` and pushes only on a change.
- **Per-forwarder health must survive the tick.** A circuit breaker owned by the pushed list would be reset every 15 seconds — faster than three failures can trip it — so `forwarder::carry_health` moves health onto the replacement list by label. This is a rolodex-side obligation created entirely by Town OS's push cadence, and it is the reason the label of a forwarder is stable rather than cosmetic.

## The forwarder spec grammar

**Two hand-written parsers, one grammar, and no generated code between them.** `src/forwarder.rs` here and `src/rolodex/forwarder.go` in Town OS accept the same strings; the repositories cannot see each other and nothing at build time ties them together. `make check-townos-sync` compares the scheme sets, and each side's unit tests deliberately pin the same cases. Treat that as the only guard there is.

`SetForwarders` takes `repeated string`, unchanged, so the grammar rides on the existing wire type:

| Spec | Transport |
|---|---|
| `8.8.8.8:53` | Plaintext UDP (Do53) |
| `tcp://8.8.8.8:53` | Plaintext TCP (RFC 7766) |
| `tls://cloudflare-dns.com@1.1.1.1:853` | DoT (RFC 7858) |
| `https://cloudflare-dns.com@1.1.1.1/dns-query` | DoH (RFC 8484) |
| `quic://dns.adguard.com@94.140.14.14:853` | DoQ (RFC 9250) |

Properties Town OS's side depends on exactly:

- **A bare `ip:port` is plaintext UDP.** Every caller written before transports were nameable keeps working, and the scheme is what a caller adds to ask for something else. Both `udp://` and the bare form parse to the same forwarder and carry the same metrics label.
- **The address is always a literal, never a hostname.** `name@ip` carries the address to dial and the name to validate the certificate against, in one string. This is the bootstrapping property: an encrypted upstream that had to be resolved first could not be the thing that fixes a box with no working DNS.
- **Which tier a forwarder lands in is rolodex's decision, not Town OS's.** It is derived from the forwarder — encrypted, then plaintext-private, then plaintext-public — so Town OS must not order the list to express preference, and must not assume the order it sent is the order tried.
- **Validation is all-or-nothing.** `SetForwarders` replaces the list, so rolodex parses every entry before applying any of it, and Town OS validates before pushing. A list accepted with one entry dropped leaves the resolver holding something nobody asked for.

**Encrypted upstreams are programmable only through this list.** `resolution.secure_upstreams` in `rolodex.yml` has no gRPC setter and is read once at startup. Before the list was typed, that meant the one tier that works on a network filtering outbound `:53` was also the one tier nothing could reconfigure without restarting the box's only resolver — while the tier that *was* programmable could only carry the plaintext addresses such a network drops.

## Fixed addresses

Each of these is written in more than one repository, and each pair has been wrong at least once:

| Value | rolodex | Town OS | `../install` |
|---|---|---|---|
| `127.0.0.2` | `dns.bind` first entry | `rolodex.DNSLoopback` | `add_bind 127.0.0.2` |
| `127.0.0.2:9153` | `metrics.bind` | `rolodex.DefaultMetricsPort` | `metrics.bind` literal |
| `127.0.0.2:4443` | `doh.bind` | `systemcontroller.RolodexDohBackend` | `doh.bind` literal |
| `/data/tls/dot` | `dot`/`doq` `cert_path` | `systemcontroller.RolodexTLSSubdir` | `ENC_CERT` / `ENC_KEY` |
| `/data/rolodex.sock` | `grpc.unix_socket` | `Config.UnixSocketPath` | `unix_socket` literal |

`4443` rather than `443` is load-bearing: the ingress is published on `0.0.0.0:443` and rolodex runs `--net host`, so a wildcard `:443` and a specific `127.0.0.2:443` in one namespace is `EADDRINUSE` for whichever binds second — DNS or the ingress goes down, depending on boot order.

`127.0.0.2` rather than `127.0.0.1` avoids systemd-resolved's stub on `127.0.0.53` and anything else on `127.0.0.1`; it is also the address `bootstrap-dns.sh` points resolved at, so it is the one bind the box's own resolution cannot work without.

### What the ingress serves while the DoH backend is down

Town OS fronts `127.0.0.2:4443` as a path backend on an ordinary ingress vhost, and that ingress answers a backend which is unreachable — or which answered `5xx` — with a retry page of its own: a `503` that says the service is unavailable and reloads itself every five seconds, instead of Caddy's bare `502`. rolodex restarts are exactly when it fires.

**It is gated on the request, and a DoH client never matches the gate.** The page is served only to `GET`/`HEAD` requests whose `Accept` carries `text/html`. An RFC 8484 client sends `application/dns-message`, and as often as not sends `POST`, so:

- a `5xx` from rolodex reaches the client verbatim — status, body and headers copied through,
- a rolodex that is not listening yields `503` with `Retry-After` from the ingress rather than `502`.

The second is the only observable change on this path, and it is one rolodex cannot see from its own side, because it happens when rolodex is not running. It is recorded here because "what a DoH client gets while the resolver is restarting" is a Town OS decision that surfaces as a rolodex bug report.

**The gate is the part that is contractual**, not the page behind it: a change on the Town OS side that dropped the `Accept` test would start answering `/dns-query` with an HTML page, and every DoH client on the box would fail to parse a DNS message it was never sent.

## Metrics

rolodex serves Prometheus text exposition on `127.0.0.2:9153`, opened once at startup from the presence of the `metrics` section. Town OS configures the scrape target from `rolodex.Manager.MetricsAddr()` rather than recomposing it from a default, so the target and the bind cannot drift.

Two properties Town OS's monitoring depends on:

- **Every label dimension is bounded.** A fixed enum, or bounded by configuration. Anything a client controls folds into a catch-all (`OTHER` for query types, `other` for TLDs). **Query names are never labels.** `upstream_queries_total{server}` and `upstream_skipped_total{server}` are bounded by the configured forwarder list.
- **New label values are appended, never inserted.** The `BLOCK_*`-style constants are positions in a pre-allocated array; an insertion silently relabels every existing counter.

Adding or renaming a metric means updating the family count and the affected queries in `README.md` and `DESIGN.md` — `tests/promql_docs_test.rs` pins the documented count against what the registry emits.

## Required of Town OS: do not reorder, and do not assume Do53

Two things Town OS must *not* do, both of which used to be safe:

- **Do not sort or reorder the forwarder list to express preference.** Order within a tier is honoured — it is the sequence rolodex tries — but the tier itself is derived. A list sorted "encrypted first" by Town OS is redundant at best and, if the sort disagrees with rolodex's derivation, misleading in the logs.
- **Do not assume a forwarder is `ip:port`.** `Manager.Forwarders` may return a spec with a scheme. Anything splitting a forwarder on `:` to recover a host and port is wrong for `tls://name@ip:853` and catastrophically wrong for an IPv6 literal.

## Required of Town OS: the DHCP resolver is not discoverable from resolv.conf

This is the one place where a Town OS/ttyforce choice silently disables a rolodex-facing feature, and it is recorded here because neither side is wrong on its own.

- ttyforce writes `[DHCPv4] UseDNS=no` (and the v6 equivalent) on its networkd units, so the DHCP-offered resolvers never become a per-link resolver that would outrank rolodex.
- `bootstrap-dns.sh` in `../install` points systemd-resolved at `127.0.0.2` whenever rolodex is up.
- `/etc/resolv.conf` is resolved's own `127.0.0.53` stub.

All three are loopback or absent, and all three are correctly discarded as query loops. So Town OS's `HostResolversFrom` finds **nothing** on a running box, and its local-forwarder discovery has to read the **default gateway** from `/proc/net/route` to find anything at all. The gateway survives because it comes from the DHCP lease's *router* option rather than its DNS option.

Anything that changes one of those three choices changes what discovery can find. Change them together or not at all.

## Known divergences

Recorded so nobody discovers them by debugging:

- **rolodex's gRPC surface is much larger than what Town OS uses.** The proto declares the full management API; Town OS's `Client` interface is a subset. The check verifies that everything Town OS declares exists here, not the reverse — an rpc no Town OS client calls is not a drift.
- **`shared_secret` is empty and auth is filesystem permission.** The install script writes `grpc.tcp_bind: ""` and a Unix socket, so the socket's mode is the whole access control. A TCP bind would need the secret, and nothing in Town OS sets one.
- **`GetForwarders` does not exist.** Town OS pushes unconditionally and cannot read back what rolodex holds. This is why `GET /dns/status` reports what Town OS *would* program rather than what rolodex has.
- **Scope/TLD forwarders are a separate list.** `SetScopeTldForwarders` is per-scope peer forwarding and is not the global forwarder list; it is plain `ip:port` and does not take the transport grammar above.

## Staying in sync

Town OS ships as per-architecture container images with no semantic version, so a commit revision is the only precise unit of synchronization — and there is deliberately **no pin**.

**On every change touching the gRPC surface, the forwarder grammar, or any fixed address:**

1. Run `make check-townos-sync` with `TOWNOS_DIR` and `INSTALL_DIR` pointing at the checkouts.
2. Reconcile any failure by updating the other side **and** this document together — never one without the other.
3. If the change renames or removes a `rolodex.yml` key, the install script and the published image must ship together. There is no version handshake to catch it.
