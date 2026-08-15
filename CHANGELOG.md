# Changelog

> Languages: **English** | [繁體中文](CHANGELOG.zh-TW.md) | [简体中文](CHANGELOG.zh-CN.md) | [Español (España)](CHANGELOG.es-ES.md) | [Español (México)](CHANGELOG.es-MX.md) | [日本語](CHANGELOG.ja-JP.md)

## v0.6.0 (2026-08-15)

### Breaking changes

- **RBL is removed. DNSBL remains, and is now the blocklist.** The reverse-IP provider lookup — a reversed address queried against a provider zone on every reverse-DNS query — is gone, along with per-scope RBL providers, the `rbl:` config section, `SetRblConfig`/`GetRblConfig`, `AddScopeRblProvider`/`RemoveScopeRblProvider`/`ListScopeRblProviders`, and the `set-rbl-config`/`get-rbl-config`/`*-scope-rbl` CLI commands. `src/rbl.rs` is now `src/dnsbl.rs`, and the machinery both lists shared — providers, refusal codes, rotation, the result cache, the recursive resolver — survives under `DnsblChecker`/`DnsblProvider`/`DnsblResolver`. With one list left, `set_dnsbl_config` and friends are simply `set_config`.

  **Addresses are still blockable**, by the local list rather than by a provider: an operator names the address (or the reverse name `dig -x` prints) and both spellings are NXDOMAIN. That is what a provider could never do well here anyway — it is asked about the *name* being resolved, which on a reverse lookup is a name nobody publishes reputation for.

  **The local list is renamed, and its rows are migrated**: `local_rbl_entries` becomes `local_blocklist_entries` and the entries are moved onto it at startup. They are an operator's own list, and a box whose blocklist silently emptied on upgrade would look exactly like the blocklist not working. `scope_rbl_providers` is dropped outright — the lookups it configured no longer exist. Over gRPC, `LocalRblEntry` and its Add/Remove/List methods are now `LocalBlocklistEntry` / `AddLocalBlocklistEntry` / `RemoveLocalBlocklistEntry` / `ListLocalBlocklistEntries`; the HTTP paths Town OS serves them on (`/dns/rbl/local*`) keep their historical spelling, because they are a published contract with the UI.

  proto3 can reserve a *field* number but not a message or method **name**, and every retired piece was a whole message or method — so the proto carries an explicit retired-names block instead, and none of those names may be reused.

- **Blocklist metric labels changed.** `blocklist_blocks_total{kind}` is now `local` or `dnsbl_provider`; `rbl_provider`, `rbl_local` and `rbl_scope_provider` are gone. `answers_total{source}` reports `reverse_blocklist` where it reported `rbl`. Dashboards that name the old label values need updating; anything summing by `kind` keeps working.

### Features

- **ACME publishes its DANE-TA record at every endpoint a certificate serves, not just one.** `acme.tlsa_port`/`acme.tlsa_proto` are a single scalar pair, so issuance placed exactly one TLSA record — `_443._tcp.<name>` by default. A TLSA record names a *service endpoint* rather than a certificate, and encrypted DNS is two of them on one certificate: DoT at `853/tcp` and DoQ at `853/udp`. The unpublished half fails closed for any client that checks DANE, which is indistinguishable from a server that never had DANE at all. `acme.tlsa_endpoints` is a list of `"<port>/<proto>"` entries published alongside the scalar pair, deduplicated against it, with the protocol normalized to lower case so `853/UDP` is a working record rather than an unqueried `_853._UDP.` name. A malformed entry is refused at startup instead of skipped, for the same reason: a record that silently never appears is the failure this mechanism exists to prevent.

- **The encrypted transports are configurable at runtime, and `Set*Config` stops lying.** `SetDotConfig`, `SetDohConfig` and `SetDoqConfig` logged their request and returned `success: true` having stored nothing — accepted and dropped. An orchestrator could not tell that apart from working, so the only way to configure encrypted DNS was to write the config file and restart the process, which on a box where rolodex is the only resolver is a DNS outage for everything on it.

  A new `TransportSupervisor` (`src/transports.rs`) owns the DoT/DoH/DoQ listeners for the life of the process, and **the startup path and the RPCs are now one code path**: `main.rs` brings each transport up through the same `apply()` an RPC calls, so a configuration that works at boot is applied by exactly the code that applies one arriving later, and neither can drift into doing something the other does not. `:53` is never touched — these are independent listeners, and reconfiguring one costs nothing outside itself.

  A listener cannot be started before the old one on its port is stopped, so there is no way to prove a new configuration binds before giving up the old one. What is done instead: everything that can be checked *without* the port is checked first (the bind list resolves, the TLS material loads or generates), so a typo'd address or an unreadable certificate is refused with the old listener still serving; then the old listeners are stopped **and awaited**, because aborting without awaiting races the new bind against the old socket's close; and if the bind fails anyway, the previous configuration is restored and the caller is told the transport is down. An empty bind list is a shutdown rather than an error — it is what an omitted config section already means.

  `Get*Config` reports the addresses actually **bound**, which differ from the ones requested whenever the request named port 0. The messages grew a `binds` list and `TlsConfig` grew `self_signed_sans`; the old single `bind` string is still honoured, so a caller that predates the list keeps working. `doh.bind` accepts a list too, on the same terms as `dot.bind`. A server built without transport supervision — the in-process test harnesses — answers `FailedPrecondition` rather than claiming to have configured a listener it does not have.

- **SVCB and HTTPS records (RFC 9460), and with them DDR (RFC 9462).** There was no SVCB record type, so a resolver had nothing to answer `_dns.resolver.arpa. SVCB` with — which is how a client discovers its own resolver's encrypted endpoints. Encrypted DNS therefore had to be typed into every device by hand, if the operator knew it existed at all.

  Values are one line of RFC 9460 §2.1 presentation format (`1 dns.home. alpn=dot port=853`), with `alpn`, `no-default-alpn`, `port`, `dohpath` (RFC 9461) and the `keyNNNNN=` escape hatch. Parameters are sorted into the strictly-increasing key order the wire format requires, so an operator can write them in any order and still get a record clients accept rather than one every validating client discards. Parsing is **strict and happens on the way in**: an unparseable value is refused by `AddRecord` rather than stored and then skipped at serve time, because a record that exists in every listing and answers nothing is the failure this codebase keeps finding. DNSSEC canonicalisation encodes the same rdata the serve path emits, so the bytes signed and the bytes on the wire cannot disagree.

  `arpa.` is still never resolved off-box — but that refusal sits *below* every local lookup, so a designation this server holds is answered from its own records and never leaves the box. That is exactly the property DDR needs: the resolver, and only the resolver, answers for its own designation.

- **A certificate that has not been issued yet can be named.** `cert_path`/`key_path` pointing at a file that does not exist was a hard startup failure, so the paths could only be written once the files were there — and on a box whose CA is created *after* the resolver starts, getting there meant rewriting the config and restarting the box's only resolver. With `auto_self_signed: true` alongside them, a named-but-absent certificate now starts on generated material and the existing 30-second poller adopts the real pair the moment it appears, with no restart and nothing to coordinate. With `auto_self_signed: false` it is still a hard failure: that is an operator saying "serve this certificate or nothing", and quietly serving a generated one instead would be worse than refusing to start.

- **The upstream resolution mode is switchable at runtime.** `resolution.mode` was read once at startup and never again, which made it the one piece of upstream behaviour an orchestrator could not change without rewriting the config file and restarting the process — and restarting the box's only resolver is a DNS outage for everything on it. `SetResolutionMode` / `GetResolutionMode` (proto, `src/grpc_service.rs`, the Go client, and the `set-resolution-mode` / `get-resolution-mode` CLI verbs) now change and read it live. The file is the **startup seed**; the getter reports the mode actually resolving queries, so the two can disagree and the running server is the authority.

  The RPC **rejects** an unrecognized mode with `InvalidArgument` rather than warning and falling back to `auto` the way the file path does. A file is read once at startup by an operator who can see the warning; an RPC has a caller waiting on an answer, and telling it "success" while resolving in a mode it did not ask for is how a box ends up in `recursive` on a `:53`-filtering network with nothing in the logs to say why every name fails.

  Switching **into** `auto` spawns the same tier warm-up the startup path runs, so the first queries after the switch do not pay the cold-tier cost, and `recovery_probe_loop` is now spawned unconditionally (it no-ops outside `auto`) so a mode switched into `auto` at runtime can still reclaim a recovered tier.

- **`dot.bind` and `doq.bind` accept a list of addresses, so DoT and DoQ can cover both address families.** Each took a single bind string, which cannot name both: `0.0.0.0` is IPv4-only, and `[::]` is not a portable substitute — with `net.ipv6.bindv6only=0`, the Linux default, a `[::]` socket also accepts v4-mapped traffic and therefore collides with the `0.0.0.0` socket on the same port, so whichever binds second fails with `EADDRINUSE`. Both fields now take **either a bare string or a list**, each entry resolved independently through the usual four forms (`ip:port`, `[ipv6]:port`, `primary:port`, `interface:port`), with duplicates dropped rather than bound twice. A bare string is still accepted, so every configuration written before the list form existed parses unchanged.

- **A renewed TLS certificate is served without restarting the server.** Every TLS listener — DoT, DoH, DoQ, the ACME issuer and the enrollment portal — took a one-time snapshot of its `rustls::ServerConfig` at startup, and `TlsManager::reload()`, which existed and was tested, was called by nothing. A certificate renewal was therefore a DNS outage: the listener served the expired one until the process was restarted, and on a box where rolodex *is* the resolver, restarting it to renew the certificate that the ACME listener itself issues is a circle worth breaking.

  Listeners now follow a `watch` channel rather than a snapshot, and each manager polls its certificate files every 30 seconds and rebuilds when their contents change. A connection already established finishes under the certificate it handshook with; the next one to arrive gets the new one. Nothing rebinds, so the port is never closed. DoT builds its acceptor per connection, DoQ applies the swap with `set_server_config` in its accept loop, and the three HTTPS listeners store into the `RustlsConfig` axum-server reloads per connection.

  Detection is a poll of the file **contents**, hashed in the same pass that parses them. An inotify watch would miss the two shapes a real renewal usually takes — a rename over the old path, or a moved symlink into a versioned directory — because neither writes to the inode being watched. A poll that fails keeps the previous certificate serving and retries, since the fingerprint is recorded only after a successful load: an ACME client writes two files and a thirty-second timer will eventually land between them, `rustls` rejects the mismatched pair, and the finished pair is picked up on the next tick. Managers serving generated (`auto_self_signed`) material are not polled — regenerating on a timer would hand every client a different certificate twice a minute.

### Fixes

- **A blocklist enabled over gRPC now gets the outbound `:53` reachability probe.** Provider lookups go out over plaintext `:53`, so on a network that filters it they only time out and add latency; the probe exists to notice that and skip them, logging a prominent flag. It was spawned only when `dnsbl.enabled` was true **in the config file** — but the orchestrator that drives this (Town OS) programs the blocklist over `SetDnsblConfig` and writes no config file at all, so on those boxes the probe never ran: `resolver_available` stayed at its `true` default and every provider lookup timed out, with nothing logged to say why. The loop is now spawned unconditionally and reads the checker's *runtime* enabled flag, the same shape `recovery_probe_loop` already had. While the blocklist is off it skips the network probe entirely — there is nothing to probe for — and only re-reads the flag, which is an atomic load and so runs often enough that a blocklist enabled at runtime does not wait out a whole probe interval.

- **The DoT listener advertises the `dot` ALPN token.** It advertised nothing: `main.rs` built the DoT listener's TLS config with an empty ALPN list, so a client that offered `dot` — the token IANA assigns DNS-over-TLS, and what a stub resolver sends to distinguish a DoT listener from any other TLS service on the port — got no answer to the question and was left to guess. The token is now offered, and offered *only*: a client asking for `dot` negotiates it, a client offering only some other protocol is refused rather than quietly served, and a client that sends no ALPN extension at all (Android's Private DNS, systemd-resolved in opportunistic mode) is served exactly as before, because TLS fails a handshake only when the client offers protocols and none match.

- **A generated TLS certificate now names the address its listener is bound to.** `auto_self_signed` produced a certificate covering `localhost`, `127.0.0.1` and `::1` and nothing else, on every transport. On a LAN-facing DoT listener that certificate cannot be used by any client that checks the name it dialled — which is every client configured with an authentication name, and the only validation a self-signed certificate admits short of raw public-key pinning. Each listener's own bind addresses are now folded into the certificate automatically, and `<transport>.tls.self_signed_sans` (new, on `dot`, `doh`, `doq` and `acme`) carries the identities a bind address cannot name: the box's hostname, its `.local` name, a LAN alias. Wildcard binds (`0.0.0.0`, `::`) contribute nothing, since they are not identities anyone dials — a listener on the wildcard needs the list. Duplicate spellings fold together (`[::1]` and `::1`, `DNS.Home.` and `dns.home`), and none of it applies when `cert_path`/`key_path` are set. This is a name check and it fails first; trusting the certificate is still a separate act.

- **A zone cut that no referral announces is now crossed instead of rejected.** When one nameserver is authoritative for a parent *and* a signed child of it, a query for a name in the child is answered from the child zone directly — no referral is ever sent — so a resolver that picks its keys from the last delegation it followed validated the child's signatures against the parent's keys and called a good answer bogus:

  ```
  answer for cdnjs.cloudflare.com. A is bogus: RRSIG over cdnjs.cloudflare.com. A
  is signed by cdnjs.cloudflare.com., which is not the zone cloudflare.com.
  ```

  This is the validator defect v0.5.1 named and left open. RFC 4035 §5.3.1 decides it: the RRSIG's signer name says which keys apply. Before validating an answer, a CNAME hop, or a negative's denial, the resolver now checks whether the signatures name a zone below the current one and extends the chain of trust down to it, one cut at a time, fetching the DS the referral never delivered. Each cut is established exactly as a referral's is — the DS validates under the parent's keys, the child's DNSKEY RRset matches it, an absent DS must be *proven* absent — and a cut that cannot be established still withholds the answer.

  Every name behind a provider that hosts a subzone on the same infrastructure was affected. The one that found it was `cdnjs.cloudflare.com`, whose SERVFAIL leaves pages that load assets from it rendering blank.

  The descent is not steerable by the response: the signer is chased only when every RRSIG in the section names it, it lies strictly inside the current zone, and it contains every owner it signed. Without that last condition a forged answer could nominate a genuinely-unsigned sibling zone as its signer, have the parent truthfully prove that delegation carries no DS, and get data the real zone signs accepted as insecure — `a_signer_below_the_zone_that_does_not_enclose_its_owner_is_refused` is that attack, and it fails the suite if the check is removed.

- **An *unsigned* child on its parent's nameservers is now visible.** It is the same hidden cut with nothing to chase: the response carries no signatures, so there is no signer name for the descent above to follow, and it stays refused — that packet is also exactly what stripping every RRSIG in flight produces, and the two cannot be told apart from the resolver's side. `dnssec_unsigned_responses_total{evidence}` now counts each one, labelled `child_apex_soa` when the authority section's SOA names a zone below the current one (what an unsigned child's negative answer carries) and `none` otherwise. The SOA is unsigned and therefore forgeable, so it is diagnostic only and decides nothing; before this the case left no trace but a SERVFAIL indistinguishable from any other.

- **Two new metrics**, bringing the exposed families to 80: `rolodex_dns_dnssec_hidden_zone_cuts_total`, counting responses signed by a zone below the one queried (i.e. how often the DS lookup above is paid), and `rolodex_dns_dnssec_unsigned_responses_total{evidence}` described above.

### Testing

- **The resolver-availability probe loop is covered.** Two cases in `src/dnsbl.rs`, driven with an injected probe and millisecond intervals so nothing touches the network: a disabled blocklist must never probe (it would be traffic to a public resolver for no reason), and a blocklist enabled the way `SetDnsblConfig` enables it — no config file involved — must start being probed and must have the probe's verdict actually reach the checker. A probe that is called but whose answer is dropped is the same outage.

- **`BindList` is covered where a regression would be silent.** In `src/config.rs`: a bare-string `bind:` still parses (every configuration written before the list form uses it, so dropping that would break them on upgrade), a list parses and resolves both families, a one-entry list serializes back as a bare string rather than churning every scalar `bind:` in the wild into a one-element list, a repeated address resolves once, an empty entry is skipped, and a bad entry names itself in the error.

- **The certificate-reload path is covered end to end.** `tests/tls_reload_test.rs` gains the polling half: an unchanged pair is not reloaded (the poller runs 2,880 times a day, so a version that reloaded unconditionally would republish that often), a rotated pair is detected and served, a self-signed manager has nothing to poll and is given no polling task, and the task itself picks up a rotation with nothing else called. The case with teeth is the renewal caught **mid-write** — it must fail, leave the old certificate serving, and then pick up the finished pair; a poller that recorded what it saw rather than what it loaded would treat the torn state as the new normal and serve the old certificate until restart, which is the exact failure the mechanism exists to remove and would look like it was working. `tests/dot_test.rs` pins the listener side: a certificate rotated under a running `serve_dot` reaches the next connection while a connection already open is undisturbed, and the listener still answers.

- **`tests/dot_test.rs` covers what DoT must *do*.** `src/dot_server.rs` carried one compilation smoke test, and `tests/security_dot_limits_test.rs` covers only what the listener must refuse; nothing exercised negotiating the transport, framing a message, answering, or keeping the session open for the next query. Two halves, because they answer different questions. In-process, a real `tokio-rustls` client against `serve_dot`: the three ALPN outcomes above, the 2-byte length prefix against the body that followed it, a programmed name answered and an unprogrammed one NXDOMAIN, and one connection carrying four queries with their IDs and questions matched back. Out-of-process, the real `rolodex-dns` binary against a config file with a `dot:` section, which is the only thing that could have caught either fix above — an in-process harness builds its own `rustls::ServerConfig` and so cannot see a `main.rs` that never asks for the ALPN token or never names its bind address. That half programs a record over the management socket and queries it back over DoT, then decodes the subject alternative names out of the certificate the server actually presented. It binds `127.0.0.2` deliberately: the loopback set is baked into every generated certificate, so only an address outside that set proves the bind address was derived rather than defaulted.

### Documentation

- **The document set is complete in every locale.** `README.md`, `DESIGN.md` and `CHANGELOG.md` gained European Spanish, Mexican Spanish and Japanese translations, so all five documents now exist in all six languages and no language nav line points at a file that does not exist. English remains the source of truth: it is changed first, and a translation is a follow-up rather than a second place to edit. Nothing verifies that they agree — `tests/promql_docs_test.rs` reads only the English `README.md` and `DESIGN.md`, so a PromQL block or a family count inside a translation is documentation, not a checked assertion.

  The Japanese suffix is now `.ja-JP.md` rather than `.ja.md`, so every locale in the set is a region code and the suffix is read the same way everywhere. Nothing but the filenames and the nav lines changed.

  The Chinese translations were also brought back level with English, where they had drifted a release behind: the `arpa.` subtree rule, the roots-tier rejection and root-server blame from v0.5.1, and the metric family count.

## v0.5.1 (2026-08-12)

### Breaking changes

- **`arpa.` is never resolved off this box.** Every name under it is answered from local data — a stored PTR, a scoped record, a managed or authoritative reverse zone — or **REFUSED**, in every resolution mode. Nothing in the subtree reaches a root server, a forwarder or an encrypted upstream. REFUSED rather than NXDOMAIN because the server is declining to answer for a namespace, not claiming the name does not exist.

  The gate sits at both layers: the query path refuses at the boundary between data this box holds and data it must go and get — before the upstream response cache, so nothing cached under the old policy is served — and the iterative resolver refuses without sending a packet, which also covers a CNAME target or a glue-less NS hostname pointing into the subtree. Membership is the last *label*, never a string suffix, so `notarpa.` and `arpa.example.com` are ordinary names and resolve normally.

  This removes the SERVFAILs for `ipv4only.arpa` (the RFC 7050 NAT64 probe) that prompted the work: the co-served root/`arpa.` zone cut, where one query crosses two cuts and the referral's NSEC is signed by `arpa.` while the walk is still checking against the root's keys, can no longer be reached at all. The underlying validator defect — checking a referral's proof against the assumed parent rather than the RRSIG signer's zone — is untouched and still open.

  Two consequences worth stating rather than discovering later: a reverse lookup for an address this box holds no data for is refused rather than answered from the internet (`dig -x 8.8.8.8`), and `ipv4only.arpa` is refused, which a NAT64-discovering client reads as "no NAT64 here". Serving the reverse tree properly from local data is separate, deferred work.

- **A root zone that will not validate is now an outage rather than a silent degrade.** `fetch_dnskeys` distinguishes `Unreachable` (transport) from `Invalid` (cryptographic). At the root, `Invalid` withholds and the chain stops; `Unreachable` still falls through, deliberately, because unreachable is not invalid. Flattening the two let anyone who could reliably break root DNSKEY retrieval take validation out of the path without ever producing a bogus verdict — the fallback chain read the error as "the roots are unreachable" and answered from an upstream that does not validate.

  The trade-off is real: a trust anchor this build does not know about (a KSK rollover) becomes a DNS outage rather than a quiet degrade to DoH. `dnssec.validate: false` is the escape hatch while the anchor is fixed.

### Features

- **A root server that serves invalid DNSSEC is dropped from the root set** for 15 minutes, doubling per offence to a 24-hour cap, on the one claim checkable without asking anyone else: its root DNSKEY against the local anchor. Blame survives the server answering promptly (`note_success` clears only the transport fields), is cleared only by an answer that *validates* — never by waiting — and is never applied to the last remaining root, because every root failing at once is the zone or the anchor, not thirteen rogue servers. Root servers only: below the root a validation failure is usually the zone's own signing error, and those already fail closed. Blame is in memory, so a restart re-trusts every root.

- **One new metric, `rolodex_dns_dnssec_blamed_roots`**, bringing the exposed families to 78. A long-lived silent exclusion of part of the root set is the one part of this that no existing counter reports. The family count and the PromQL cookbook are updated in `README.md` and `DESIGN.md`.

### Bug fixes

- **A DNSSEC walk that ends Bogus no longer leaves anything behind.** The delegation and its glue are now cached only after `extend_trust` returns a usable trust state. They were written first, so a referral whose DS/NSEC proof failed had already had its NS set committed — and persisted to disk, where it survived a restart.

### Documentation

- **The functional specification moved out of `CLAUDE.md` into `DESIGN.md`.** `CLAUDE.md` is now development rules only; what the software does lives in the specification, which is the document behaviour changes are required to land in.

- **Translations are keyed by region locale code.** The Chinese translations moved from the BCP 47 script subtags `zh-Hant`/`zh-Hans` to `zh-TW`/`zh-CN`, so every locale suffix in the document set answers the same question now that Spanish is split by region. `CLAUDE.md` and `CONFIGURATION.md` gained European Spanish (`.es-ES.md`), Mexican Spanish (`.es-MX.md`) and Japanese (`.ja.md`) translations, and `Cargo.toml`'s `include` list ships them.

  `README.md`, `DESIGN.md` and `CHANGELOG.md` are **not yet translated** into the three new locales, so their language nav lines currently link to files that do not exist. English remains the source of truth, and nothing verifies that the translations agree — `tests/promql_docs_test.rs` reads only the English `README.md` and `DESIGN.md`.

### Testing

- **`tests/arpa_refusal_test.rs`** (new, and named in the Makefile's `rust-integration-test` recipe) asserts on *packets* rather than rcodes, with the label boundary and the local-data path as its controls, swept across all three resolution modes. An `arpa.` gate that refuses everything satisfies "the subtree is refused"; one that refuses nothing satisfies "`notarpa.` still resolves" — only the pair says anything.

- **`tests/security_dnssec_test.rs`** gains the rejection rules, driven through a real `DnsServer` with a working counting forwarder, because "the client got SERVFAIL" and "the forwarder was never consulted" are different properties and only the second one is the finding.

## v0.5.0 (2026-08-10)

### Bug fixes

- **A client query is never spent probing a degraded tier again.** In `auto` mode the query path elected one lookup per `resolution.recovery_probe_secs` (default 60) to restart the tier chain at the roots, so a recovered, more-preferred tier could be spotted. That is a fine thing to want and a terrible thing to charge a caller for: on a network that filters outbound `:53` the roots tier cannot answer, so the elected query paid the entire iterative walk — up to `MAX_QUERIES_PER_RESOLUTION` upstream queries at the per-nameserver timeout each — before falling through to the tier that was going to answer all along. Once a minute one unlucky lookup stalled for tens of seconds and the client usually gave up first, which reads to a user as "DNS hangs", not as a probe.

  `auto_start_tier` is now always the committed tier, full stop, and the compare-exchange that elected the probing query is gone with it — there is only ever one prober now, so no election is needed.

### Features

- **Asynchronous tier recovery.** Recovery moved to `recovery_probe_loop`, a background task that retests the tiers above the committed one every `resolution.recovery_probe_secs` on its own throwaway canary. Its results are discarded — the probe exists to move the committed tier and never to answer anything — so an overrun costs no client an answer, which is precisely what let the timing bound below be chosen for correctness rather than for the patience of whoever was waiting. The interval is measured from the last probe rather than from the end of the last pass, so a slow probe does not turn into a busy one, and it is re-read every pass so a runtime change takes effect without a restart.

- **Reclaiming the roots tier requires a DNSSEC-validated answer.** Tier 0 is promoted only on a `Verdict::Secure` resolution of the root zone's own `DNSKEY`, not on mere reachability. An intercepting middlebox or captive portal on `:53` is reachable and answers promptly — it simply answers with whatever it likes — so without the gate any network that hijacks port 53 could install itself as the most-trusted tier, silently and automatically displacing the encrypted upstream the box had correctly fallen back to. A validated answer is the one thing such a middlebox cannot forge, and the root's own DNSKEY is the narrowest form of the question actually being asked: can this box reach a root server and build a chain of trust from it.

  With `dnssec.validate: false` there is no verdict to gate on — the resolver reports `Insecure` for everything by design — so a definitive answer is required instead. Demanding `Secure` there would strand a deliberately non-validating box on a fallback tier forever, unable to ever use the recursive resolution that is the default and preferred mode.

- **The roots tier is bounded by wall clock, not only by query count.** The iterative resolver budgets itself by *query count*, which answers "how much work is this name worth?" and cannot answer "how long may a caller be kept waiting?" — and only the second question matters to whoever is waiting. A black-holed `:53` times out every one of those queries, so the count budget alone permits a single lookup to run for over a minute. The tier now carries an 8s ceiling on the query path and 2s for the recovery probe.

  8s rather than the 1.5s the other tiers use, deliberately: a cold iterative resolution is several sequential round trips (root, TLD, zone, plus the DNSKEY fetches validation needs) where the secure and forwarding tiers are one round trip to one server. Measured cold lookups run 0.6–1.9s for a public name and about 2.7s for an RFC 1918 PTR, so a ceiling near those figures would not bound a pathology — it would break healthy recursion, failing every slow-but-fine lookup and degrading a working resolver onto DoH. The probe's 2s is much tighter because it is a much smaller question: one query to one server, no delegation to walk.

### Testing

- **`tests/recovery_probe_test.rs`**, against the DNSSEC-signed mock hierarchy, covers both directions on purpose: validated roots *are* reclaimed, while roots that are reachable but unsigned, foreign-signed, or serving expired signatures are *not*. A gate that never opens passes every negative test and a gate that always opens passes every positive one — only the pair says anything. It also pins the guard that no client query is ever spent probing, and unit tests cover the wall-clock bounds and the probe's no-op cases (already at the top tier, or not in `auto` mode).

## v0.4.6 (2026-08-09)

### Bug fixes

- **The DoH connection-pool tests no longer race each other.** `DOH_POOL` is a process-global `DashMap` and the four pool tests run concurrently in one binary, yet each called the **global** `DOH_POOL.clear()` at both ends. Any one of them wiped whatever the others had just pooled, so `test_get_doh_connection_reuses_pooled` could find `None` one line after inserting an entry — an occasional unexplained panic rather than a reproducible failure, which is why it survived several green runs.

  Each test now removes only its own key. No serializing lock is needed: every test binds its own ephemeral port, so two running at once cannot hold the same address, and a port recycled between tests was already removed by whoever used it. The two bare `unwrap()`s on pool lookups were replaced with forms that report what was actually found, so the next failure here names the problem instead of panicking anonymously.

## v0.4.5 (2026-08-09)

### Features

- **Blocklist attribution split by which list actually matched.** `blocklist_allowlisted_total` gained a `kind` label — `forward_name`, `reverse_name`, `ip_literal` — and `rbl_scope_provider` joined the block kinds.

  The allowlist label names the *match path*, not the list, and that is forced by where the check sits: the exemption short-circuits before any provider lookup is issued, so at the moment it fires nothing has been asked and there is no "which list would have matched" to record. Naming the gate instead is both knowable and the more useful axis, separating an exemption on a forward name (step 7) from one on a reverse lookup (step 2), and within the latter the `in-addr.arpa` spelling from the IP literal — matched by different rules, suffix versus exact.

  `rbl_scope_provider` exists because a provider one network opted into and the box-wide list are different operator decisions with different blast radii. Folded together, "this network's own blocklist broke this network" was indistinguishable from "the global list broke everyone", which is the first thing worth knowing when a network reports that reverse DNS stopped working. The split costs nothing: the two checks cover disjoint provider sets and the result cache is keyed per `<ip>/<zone>`. New kinds are appended, never inserted — the `BLOCK_*` constants are positions in the array, so an insertion silently relabels every existing counter.

- **Traffic volume.** `traffic_bytes_total{direction=rx|tx}` and `records_served_total`, both recorded at the single instrumented exit every transport funnels through, so a query cannot be counted without its bytes also being counted. Record counts are read off the response header's ANCOUNT field rather than by re-parsing a message the server just serialized. The query count alone cannot show this: a million NXDOMAINs and a million populated answers are the same number of queries and very different amounts of work, and the tx/rx ratio is the amplification factor worth watching on any listener reachable from outside.

- **Per-TLD isolation.** `queries_by_tld_total{tld}` separates the query stream by TLD, which is what makes a split-horizon deployment's networks distinguishable from each other and from the public internet.

  The dimension is bounded by an operator-owned set, because the queried name is chosen by the client: an unbounded `tld` label would let a scanner sweeping `a.zzz1`, `a.zzz2`, … mint series until the registry ate the process. Three sources feed it, unioned — every TLD a network scope owns (including each scope's implicit `.home` domain) tracked **automatically**, since requiring a network's own namespace to be named twice is a footgun that surfaces as a silently missing series; the new `metrics.tracked_tlds` config list, pinned so it survives restarts and cannot be removed over the API; and a stored list managed by the new `SetTrackedTlds`/`ListTrackedTlds` RPCs, with `set-tracked-tlds`/`list-tracked-tlds` CLI subcommands and matching Go client methods. Everything untracked folds into `other`.

  The entry `common` expands to a built-in common-TLD set, so the usual public TLDs are one config line rather than twenty, and it is stored **unexpanded** — a read-back reports what the operator asked for, and a later change to the built-in list takes effect without every deployment re-issuing the call, the same shape as `none` in `refusal_codes`. Matching walks the name's suffixes most-specific-first and returns a slice of the name, so a deployment tracking both `home.` and `lab.home.` attributes `box.lab.home.` to the more specific one and an untracked name allocates nothing. The root zone is refused with `InvalidArgument`: `.` is a suffix of every name, so tracking it would collapse every series into one and make the catch-all unreachable.

### Breaking changes

- **DHCP metric labels are now subsystem-qualified.** `rolodex_dns_dhcp_messages_total{type}` is `{message_type}` and `rolodex_dns_dhcp_leases{state}` is `{lease_state}`. A generic label name is what lets an aggregation spanning both subsystems — a `sum by (type)` in a recording rule — silently blend a DHCP ACK count into a DNS one. Dashboards and alerts selecting on the old names need updating. The DNS rollups (`queries_total`, `traffic_bytes_total`, `records_served_total`, `queries_by_tld_total`) likewise count DNS only: DHCP's `:67` traffic is never DNS traffic, and a DHCP-registered name reaches these metrics only when somebody actually resolves it.

### Testing

- **The documented PromQL is tested, in two layers.** `tests/promql_docs_test.rs` parses every ```promql block out of `README.md` and `CLAUDE.md`, extracts the metric names and label matchers, and resolves each against live exposition output. Documentation is the one part of a metrics change that nothing else verifies: the DHCP rename above leaves the code compiling and every other test green while silently turning each documented dashboard query into one that returns no data, and an operator finds out when a panel goes blank mid-incident. It also pins the documented family count against what the registry emits — that had already drifted, 73 documented against 74 emitted — and guards the fence itself, since a block relabelled ` ```bash ` would make the whole file quietly stop checking anything.

  `tests/prometheus_integration_test.rs` runs the same queries through a real Prometheus scraping a live server, catching what a substring scanner cannot: a query malformed *as PromQL* rather than merely naming a missing series. `rate(sum(x)[5m])` names only real series and is rejected the moment it is pasted. It runs from `make prometheus-test`, which `make test` now depends on; a missing podman skips loudly rather than failing, so a machine without a container runtime still gets a green run while never pretending the queries were checked, and `ROLODEX_PROMETHEUS_REQUIRED=1` promotes that skip to a failure for CI.

- Unit and integration coverage for each new dimension, each paired with its control — notably that an untracked TLD mints **no** series, since a test asserting only the positive would pass with the cardinality bound removed entirely.

### Packaging

- **The crate is publishable, and ships its documentation.** `readme` and `homepage` are declared, and an explicit `include` list replaces packaging-by-omission: a published package now carries `README.md`, `CONFIGURATION.md`, `CHANGELOG.md`, `CLAUDE.md` and `LICENSE` alongside the sources, protos, benches and tests.

  An `include` rather than an `exclude` because the working tree also holds a Go client, a JavaScript client, a browser extension and container tooling that a crate consumer has no use for — and an exclude list would silently start shipping each new one of those. `proto/` and `build.rs` are load-bearing (the gRPC bindings are generated at build time, so a package without them does not compile), and `benches/` ships because `[[bench]]` names a target — cargo fails on a declared target whose file is missing, so omitting it would break the package rather than merely shrink it.

  `tests/` ships so the published crate can be verified by whoever receives it, which for an AGPL network service is the point. That is also why `CLAUDE.md` is included rather than treated as repo-only tooling: `tests/promql_docs_test.rs` reads it alongside `README.md`, and a package carrying a test but not its input is a test that cannot run. With every documentation file guaranteed present in both a checkout and a published package, that test insists on finding each one rather than skipping what it cannot load — skipping is how a check quietly starts verifying nothing.

### Documentation

- **`CONFIGURATION.md` — a configuration guide.** The README's configuration section is a field reference, which answers "what does this option do" and not "what should my config look like". The guide is task-oriented: how the file is loaded (and that a missing one is not an error), the smallest working config, four worked deployment shapes (home resolver, purely authoritative, split-horizon overlay node, resolver on a network that filters `:53`), then one section per subsystem. It states plainly which settings are *not* configuration at all — records, scopes, zones, blocklist entries, DNSSEC keys and ACME CAs are runtime state in SQLite — with a table of what needs a restart, the four conditions the server deliberately refuses to start under, and a troubleshooting table keyed by symptom.

  The two CIDR lists get a side-by-side comparison, because `overlay_cidrs` (who is scope-*enforced*) and `recursion_cidrs` (who may make this server ask upstream) are different questions that read alike.

- **README brought up to v0.4.4.** DNSSEC now documents both halves — the signer and the upstream validator, with the four verdicts and why Insecure-vs-Bogus is the distinction carrying the security. Blocklist refusal codes and provider rotation, the allowlist's reach across every list and both gates, and recursion access control (previously shipped but never written down) each have a section. The configuration example and options table gained `dnssec.*`, `security.recursion_cidrs`, `metrics.bind` and the per-provider refusal fields; the CLI docs gained the refusal flags and the current `get-rbl-config` output; and the RFC table gained the DNSSEC family (4033/4034/4035, 5155, 6605/8080, 6840, 9276) and 7766.

## v0.4.4 (2026-08-08)

### Features

- **Upstream DNSSEC validation.** Rolodex signed its own zones and validated nothing it resolved: no trust anchor, no DO bit on outbound iterative queries, and `verify_rrsig` deliberately unwired. `src/dnssec_validate.rs` is the verifying half, and it shares no code with the signer — the signer works on database rows we wrote and controls every byte, a validator works on whatever arrives from a party whose honesty is the thing in question, and the two must be able to disagree.

  The chain is built **top-down alongside the delegation walk the resolver already performs**, so a DS costs no extra query — it rides in the referral, signed by the parent whose keys are already held. Validated key sets (and proven-insecure delegations) are cached per zone in `src/key_cache.rs`; re-deriving the chain on every query would reintroduce the delegation cache's cold-start problem one layer up. Lookups there are exact-name, never suffix: a parent's keys say nothing about a child's, which is what the DS record is for.

  All four RFC 4033 §5 states are distinguished. The one carrying the security is Insecure vs. Bogus: "no signature present" is *not* Insecure, since an on-path attacker strips signatures from any response — it is Insecure only when a signed NSEC/NSEC3 proves the missing DS at the delegation above, which an attacker cannot forge without the parent's key. That is why the NSEC/NSEC3 denial machinery exists at all; skipping it leaves a validator any attacker downgrades to no validator.

  Bogus and Indeterminate data is never served and never cached, positively or negatively — a cached bogus negative would suppress the real name for its whole TTL. In `auto` mode a failed validation is a **definitive** answer rather than a tier failure, so a broken signature cannot be laundered through an upstream that does not validate. AD is set only for Secure, and only for a client that asked (DO or AD in the query); RRSIG/NSEC/NSEC3 are stripped for a client that did not set DO, since a signed A record roughly triples in size and a large answer to a small question is the amplification shape `security.recursion_cidrs` exists to close.

  Validation applies to the **iterative path only** — `recursive` mode and the roots tier of `auto`. A forwarded response is somebody else's recursive summary, and validating it would mean re-resolving the chain ourselves, which is what the roots tier already is; a chain degraded past tier 0 is therefore unvalidated and says so by leaving AD clear.

  Configured by `dnssec.validate` (default `true`) and `dnssec.trust_anchors` (default: the IANA root keys). An anchor override **replaces** the IANA keys rather than adding to them, and every field of every anchor is validated at startup — a malformed anchor is a hard failure rather than a silent fallback. Outbound iterative queries now carry EDNS0 with DO set and a 1232-byte payload size when validating (previously no OPT at all, so a server was entitled to cap responses at 512 bytes, which a signed answer essentially never fits inside). The per-lookup query budget gains `VALIDATION_QUERY_BUDGET` (32 on top of the base 64), so enabling validation does not silently shorten how deep a name may be. NSEC3 iteration counts above 100 are treated as insecure rather than computed (RFC 9276) — the hashing is attacker-chosen work on our side of the wire. Records validated only against algorithms this build cannot verify are Insecure, not Bogus (RFC 6840 §5.11): our missing algorithm is not the zone's outage.

  Enables hickory's `dnssec-ring` feature for typed DNSSEC RDATA and RSA verification. `ring` cannot *generate* RSA keys, which is why signing refuses algorithm 8 — but verifying is a different question, and a validator that cannot check RSA cannot check the root.

- **Blocklist refusal codes and provider rotation.** A DNSxL answers a listing and a complaint about the *querier* the same way — an `A` record under `127.0.0.0/8` — and only the address distinguishes them: `zen.spamhaus.org` says "listed" with `127.0.0.2` and "you are querying via a public resolver" with `127.255.255.254`. Reading any `A` record as a listing therefore turned the moment a blocklist decided to stop answering us into NXDOMAIN for *every* name checked against that provider, starting whenever query volume crossed the provider's threshold — hours or weeks after a deployment that looked fine. Spamhaus states it directly: those codes "should NOT be interpreted as any sort of reputation".

  Refusal codes are now recognized, and a refusal is neither a listing nor a negative — nothing is cached, because we learned nothing about the queried name. A refusal anywhere in an answer wins over a listing in the same answer: a provider that is complaining is not simultaneously reporting reputation, and erring this way fails *open* where the other order fails closed on every name. The provider is then rotated out of the lookup rotation for a cooldown (`refusal_cooldown_secs`, default 3600s, per-provider override available) instead of being asked again on every request; rotation skips new lookups only, leaving already-cached verdicts intact, lapses on its own so a transient over-quota period heals with no operator action, and is cleared by `FlushCache` or any `SetRblConfig`/`SetDnsblConfig` — a reconfiguration is often the fix for the refusal.

  The built-in set covers the documented codes of the common providers: `127.255.255.0/24` (the whole Spamhaus error range, rather than today's three codes, so tomorrow's fourth is not silently read as a listing), `127.0.1.255` and `127.0.2.255` (Spamhaus DBL/ZRD "IP queries not supported"), and `127.0.0.1` / `127.0.0.255` (URIBL/SURBL "query blocked"). Empty means the built-in set — it cannot mean "no codes", because empty is what every configuration written before this feature existed has — and the single entry `none` disables detection for a private blocklist whose real listings collide with one of them. An explicit list replaces rather than extends the defaults, so an operator who spells it out can also narrow it. An unparseable code is rejected at startup or with `InvalidArgument` from the RPC, never skipped: a code that silently does not apply is a refusal that reads as a listing, with the configuration having reported success.

  Configurable per provider and list-wide over the proto, the CLI, the Go client and the config file, with the RBL and DNSBL lists carrying independent cooldown defaults. `GetRblConfig`/`GetDnsblConfig` report the codes **in effect** resolved (an empty configured list reads back as the built-in set, not as empty) plus which providers are currently out of rotation and for how long; `rolodex_dns_blocklist_refusals_total{kind}` and `rolodex_dns_blocklist_rotated_out` expose the same to Prometheus. Without those, "the blocklist went quiet" and "the blocklist is clean" look identical from outside, and the second is what an operator assumes. Setting a cooldown to `0` means "use the default", not "no cooldown" — a zero cooldown re-asks the provider that just told us to stop.

### Bug Fixes

- **Every blocklist positive is now NXDOMAIN, and an allowlist entry is the only thing that suppresses one.** Three holes, each a case where a list said "listed" and the query resolved anyway, or where the operator's escape hatch did not reach:

  - The DNSBL allowlist only gated the forward-name check (step 7), so a false positive on an *address* was unliftable — a wrongly-listed IP broke `dig -x` for a host that was running fine, with no recourse short of disabling the provider. It now gates the reverse/IP path (step 2) too, under either spelling: the `in-addr.arpa`/`ip6.arpa` name, suffix-matched like any DNS name so one entry lifts a whole /24, or the IP literal, matched **exactly** — octets run most-significant-first, so `1.100` is not a parent of `192.168.1.100` and treating it as one would exempt addresses nobody named.
  - Per-scope RBL providers were stored, listed back by the API, and never consulted. The query path called plain `is_listed`, so a positive from a scope's own list resolved normally.
  - A local RBL entry written as the reverse name matched nothing — the IP gate only looked up `ip.to_string()`. `dig -x` prints the reverse name, so it is what an operator pastes in, and an entry that reads as a block while silently matching nothing is worse than one that is rejected. Either spelling matches now.

  Both reverse call sites funnel through one gate (`ip_blocklist_kind`) and every gate through one exemption (`blocklist_exempt`), so a future exit cannot drift. Per-scope providers are skipped when outbound plaintext `:53` is unreachable — that flag is not a policy switch, it says the lookup can only time out. Local records still beat blocklists, deliberately: inverting that lets a third-party listing take out an internal service, and a test pins it.

- **Zone signing produced signatures that could not be verified, and published keys that could not be read.** DNSKEY, DS and RRSIG were served as **TXT records** carrying the stored string, so a DNSKEY query got a TXT back and every published signature was unusable. They are now served under their own type codes, with RDATA from the same canonical encoder the signer hashes, so what goes on the wire is byte-for-byte what was signed; URI and ZONEMD are encoded the same way. The signed bytes themselves are now RFC 4034 §3.1.8.1 canonical form — canonical owner names, original TTLs, RFC 4034 §6.3 ordering with duplicates dropped, so the order records come out of SQLite in cannot change the signature — with the KSK/ZSK role split of RFC 4035 §2.1, label-boundary zone confinement, and re-signing that replaces rather than accumulates (including at names whose records were deleted since the last run). Unsignable types (NSEC, NSEC3, NSEC3PARAM, ANAME, and malformed values) are skipped and named in the response rather than signed over an invented encoding — a signature over bytes nobody else will reproduce fails closed at every validator, which is worse than leaving the name unsigned.

- **RSA/SHA-256 (algorithm 8) is refused at key generation** instead of being accepted and then substituted. `ring` cannot generate RSA keys; a DNSKEY advertising algorithm 13 over Ed25519 key material yields a DS, a DNSKEY and a set of RRSIGs that all disagree, and that failure surfaces at a validating resolver rather than locally. Relatedly, a stored key whose bytes do not load as the algorithm it is filed under is skipped at signing time with a warning rather than signed with.

- **Managed-zone authority required a record at the zone *apex*.** A zone whose records all sit at subdomains — `www.example.com` with nothing at `example.com`, which is the normal shape of a zone — never became authoritative, so its misses were forwarded upstream and the inside representation stopped taking priority. Any record in the zone counts now, and `remove_records` prunes the `managed_zones` cache once nothing is left at or beneath the zone, so trusting the cache is safe (a stale entry is not inert — it would keep answering NXDOMAIN for a zone that no longer exists). The reverse trees are excluded: the last-two-labels heuristic always derives `in-addr.arpa.` itself, so one stored PTR would have claimed the entire global reverse tree — and with `dns.auto_ptr` on, a single A record creates that PTR. `home.arpa` (RFC 8375) is deliberately *not* excluded, since the heuristic gets it right there and forwarding a miss is what RFC 8375 §4 forbids.

- **Zone suffix matching used bare `ends_with` in three places**, putting `notexample.com` inside `example.com` — for certificate listings, scoped authority, and zone signing. Hoisted to `db::name_in_zone`, which matches on label boundaries.

- **`SetDns64Config` was a stub** that logged its argument, stored nothing, and reported success; `GetDns64Config` returned hardcoded defaults. The enable flag and the prefix are now stored independently, so disabling synthesis does not discard the configured prefix, and a prefix that does not parse is refused rather than substituted.

- **`GetTtlDriftConfig` did not round-trip.** An adjustment set as `1h30m` read back as `5400s`. The reply is what an operator reads to confirm what they configured, and read-modify-write automation needs it to round-trip, so it is now formatted in the same compound spelling it was set with (`ttl_drift::format_duration_secs`, the inverse of the parser).

- **`add-scope-rbl --enabled` was decorative.** As a bare `bool` with `default_value = "true"`, clap gives the field the `SetTrue` action; clap 4.6 applies the default, so the flag could never express `false` and a disabled per-scope provider was unreachable. It takes a value now (`--enabled false`), pinned in both directions since the flag has been wrong in both.

### Changes

- `dnsbl.sorbs.net` removed from the documentation and examples — SORBS has shut down.

### Tests

- **`tests/signed_hierarchy/mod.rs`** — a DNSSEC-signed mock hierarchy over real UDP sockets: signed root → signed TLD → signed zone, each holding its own Ed25519 key, publishing a DNSKEY RRset and handing out a DS for each signed child. Where `tests/mock_hierarchy` proves query *counts*, this proves *verdicts*, because almost every way of getting DNSSEC wrong still returns the right records — a validator that skips the expiry check, or believes an unsigned NSEC, or accepts any signer name resolves the whole internet correctly right up until someone attacks it. Its `Tamper` enum applies each attack when the response is **serialized**, after the zone has been correctly constructed, so every test is "a valid deployment, attacked" rather than "an invalid deployment, rejected".

  `tests/dnssec_validation_test.rs` covers the paths that must keep working (a full chain validating Secure, an NSEC-proven insecure delegation, proven NXDOMAIN and NODATA, the key cache sparing the root a second query, a non-validating resolver reporting Insecure rather than Secure); `tests/security_dnssec_test.rs` covers the attacks (stripped signatures, a delegation with neither a DS nor a proof of its absence, expired and premature signatures, a signature from an unpublished key, a foreign signer name, data mutated after signing, an unproven negative, a trust anchor matching no root key, malformed anchors). Both matter equally and for the same reason: a validator that rejects everything passes every attack test, and one that accepts everything passes every happy-path test.

- **`tests/dnssec_signing_test.rs`** pins that a signature is *checkable*, not merely present — the central test re-derives the signing input from the **published DNSKEY RRset**, never from the private key rows, since a validator has only the DNSKEY.

- **`tests/blocklist_nxdomain_test.rs`** drives the blocklist contract the way an operator does: a gRPC mutation, then a query over a real UDP or TCP socket. Five lists, two gates, two code paths, each with its own control — a gate that blocks everything satisfies half the contract and a gate that blocks nothing satisfies the other half.

- **`tests/rbl_refusal_test.rs`** drives refusal codes over real UDP DNS against a mock blocklist zone, through the forwarder fallback and classification into `handle_query`, because every layer in between is somewhere the listing/refusal distinction could be lost. Every test is paired with a control in which a genuine `127.0.0.2` listing travelling the identical path still returns NXDOMAIN.

- **`tests/doq_test.rs`, `tests/proxy_test.rs`, `tests/tls_reload_test.rs`** cover three surfaces that previously had only a compilation smoke test or a config-parsing unit test: a real `quinn` client against `serve_doq`; mock HTTP CONNECT, SOCKS5 and DoH proxies that **parse** what the server sends rather than replying with a canned response (with an unreachable proxy pinned *not* to fall back to a direct connection); and `TlsManager::reload()` observed through real TLS handshakes.

- **`tests/zonemd_test.rs`** pins the RFC 8976 RDATA layout field by field, written longhand rather than taken from the encoder — comparing the encoder to itself would ratify a bug.

- **`tests/acme_admin_test.rs`** covers the five admin RPCs by their properties rather than their `success` flags: `EnsureZoneCa` idempotency (a re-mint would break every certificate already chaining to the old intermediate, and the published DANE-TA record with it), per-zone intermediates under one shared root, EAB scoping and key round-trip, honest removal, and label-boundary certificate listing.

- **`tests/cli_integration_test.rs`** now walks every subcommand's `--help`. clap validates short options at parser construction and **panics** on a duplicate, so a subcommand reusing a letter taken by a global option aborts before reading a single argument — which is how `generate-dnssec-key` (`-a`/`--algorithm`) and `set-ttl-drift` (`-a`/`--adjustment`) both collided with the global `--address` and became impossible to run at all. Both are long-form only now.

## v0.4.3 (2026-08-07)

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
