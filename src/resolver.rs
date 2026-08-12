//! Iterative DNS resolver.
//!
//! Resolves names by walking the delegation chain starting at the root
//! name servers — querying a root, following the NS referral to the TLD
//! servers, then to the authoritative servers for the zone, until an
//! answer (or an authoritative negative response) is obtained. This is an
//! alternative to forwarding queries to a recursive upstream resolver and
//! is the default resolution mode.
//!
//! Queries are sent with the recursion-desired bit cleared (iterative
//! mode). Responses are validated by transaction id and by the full
//! question (name, type, and class) to resist off-path spoofing, and the
//! UDP query socket is connected to the nameserver so the kernel drops
//! datagrams from any other source. UDP is used first, with automatic TCP
//! fallback when a response is truncated.
//!
//! One namespace is never resolved here at all: `arpa.` and everything under
//! it is this server's to answer from local data, so a lookup that reaches this
//! module for such a name is REFUSED without a packet being sent. See
//! [`is_arpa_subtree`].

use anyhow::{Context, Result, bail};
use dashmap::DashMap;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rand::Rng;
use rand::seq::SliceRandom;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, warn};

use crate::delegation_cache::DelegationCache;
use crate::dnssec_validate::{self as validate, Anchors, Denial, Denied, KeySource, Verdict};
use crate::key_cache::{KeyCache, TrustState};
use crate::record_cache::RecordCache;
use crate::ttl_drift::LatencyTracker;

/// Maximum UDP DNS message size we are willing to receive.
const MAX_UDP_SIZE: usize = 4096;
/// Per-nameserver query timeout. Deliberately short: a black-holed :53 (e.g. a
/// network that filters outbound plaintext DNS) must fail fast so the `auto`
/// chain falls through to the DoH/DoT tier instead of hanging seconds per hop.
/// Healthy root/TLD/authoritative servers answer well under this.
const DEFAULT_QUERY_TIMEOUT_MS: u64 = 1500;
/// Maximum number of delegation hops within a single name resolution.
const MAX_REFERRALS: usize = 30;

/// Outcome indices for [`crate::metrics::Metrics::resolver_priming`].
const PRIMING_SUCCESS: usize = 0;
const PRIMING_FAILURE: usize = 1;

/// Maximum number of CNAME indirections we will follow.
const MAX_CNAME_CHAIN: usize = 16;
/// Maximum recursion depth (CNAME chasing + glue-less NS resolution).
const MAX_RESOLUTION_DEPTH: u32 = 16;
/// Maximum number of NS targets to try when resolving a glue-less delegation.
const MAX_GLUELESS_NS: usize = 4;

/// Hard cap on the number of upstream queries a **single** client lookup may cost.
///
/// The depth/referral/CNAME limits bound each dimension separately, but they
/// multiply: glue-less NS resolution recurses, and every level of that recursion
/// may fan out across [`MAX_GLUELESS_NS`] nameservers, each of which can hit another
/// glue-less delegation. A chain that keeps referring without glue therefore costs
/// `O(MAX_GLUELESS_NS ^ MAX_RESOLUTION_DEPTH)` queries — 2^16 was observed in a
/// test with a pathological zone. That is a self-inflicted DoS (and an amplifier
/// pointed at whoever the delegation names), so total work is bounded outright.
///
/// Real recursors do the same; this is deliberately generous next to the ~10 queries
/// a healthy deep lookup actually needs.
const MAX_QUERIES_PER_RESOLUTION: usize = 64;

/// Extra query allowance granted when DNSSEC validation is on.
///
/// Validating costs roughly one extra query per zone on the path — the child's
/// DNSKEY RRset; the DS arrives inside the referral for free — plus the root's
/// DNSKEY once. Those are queries a non-validating lookup never makes, so
/// charging them against the same 64 would mean turning validation on silently
/// shortens how deep a name may be before the budget kills it. The cap still
/// exists, it is just sized for the work actually being done.
const VALIDATION_QUERY_BUDGET: usize = 32;

/// TTL used when a record or a negative response does not carry a usable one of
/// its own. A present TTL is **always** honoured as sent — this is only the
/// fallback. Overridable via `resolution.default_ttl`.
pub const DEFAULT_TTL: u32 = 300;

/// EMA smoothing factor for nameserver latency.
const LATENCY_EMA_ALPHA: f64 = 0.3;

/// How long a nameserver sits out after its first failure. Doubles per consecutive
/// failure up to [`MAX_FAILURE_BACKOFF`], and resets the moment it answers.
const DEFAULT_FAILURE_BACKOFF: Duration = Duration::from_secs(2);
/// Ceiling on the backoff, so a server that has been down a long time is still
/// retried regularly rather than written off forever.
const MAX_FAILURE_BACKOFF: Duration = Duration::from_secs(300);

/// How long a root server that served DNSSEC we could not validate is *omitted*
/// from the root set. Doubles per consecutive offence up to
/// [`MAX_BLAME_BACKOFF`], and is cleared only by an answer that validates.
///
/// Deliberately not [`DEFAULT_FAILURE_BACKOFF`], because the two claims differ.
/// A timeout says "this server was busy, try again shortly"; a signature that
/// does not check out against our own trust anchor says "this server told me
/// something untrue", and the second has no business recovering on a 2s curve.
const DEFAULT_BLAME_BACKOFF: Duration = Duration::from_secs(15 * 60);
/// Ceiling on the blame backoff: a persistent liar earns its way to a day and
/// stays there, rather than being written off forever.
const MAX_BLAME_BACKOFF: Duration = Duration::from_secs(24 * 60 * 60);

/// The IANA root server IPv4 addresses (the "root hints").
///
/// IPv4 only: every host that can reach the internet can reach these, and
/// using a single address family avoids stalling on IPv6 servers from a
/// host without IPv6 connectivity. Glue and glue-less resolution may still
/// yield IPv6 authoritative servers, which are tried opportunistically.
pub const ROOT_HINTS: [IpAddr; 13] = [
    IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), // a.root-servers.net
    IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)), // b.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 33, 4, 12)), // c.root-servers.net
    IpAddr::V4(Ipv4Addr::new(199, 7, 91, 13)), // d.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 203, 230, 10)), // e.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 5, 5, 241)), // f.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 112, 36, 4)), // g.root-servers.net
    IpAddr::V4(Ipv4Addr::new(198, 97, 190, 53)), // h.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 36, 148, 17)), // i.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 58, 128, 30)), // j.root-servers.net
    IpAddr::V4(Ipv4Addr::new(193, 0, 14, 129)), // k.root-servers.net
    IpAddr::V4(Ipv4Addr::new(199, 7, 83, 42)), // l.root-servers.net
    IpAddr::V4(Ipv4Addr::new(202, 12, 27, 33)), // m.root-servers.net
];

/// The result of an iterative resolution: the final response code and the
/// accumulated answer records (including any CNAME chain that was followed).
#[derive(Debug, Clone)]
pub struct Resolution {
    pub rcode: ResponseCode,
    pub answers: Vec<Record>,
    /// The authority-section SOA of a negative (NXDOMAIN/NODATA) response, kept
    /// so the caller can derive an RFC 2308 negative-cache TTL. `None` for
    /// positive answers.
    pub soa: Option<Record>,
    /// What DNSSEC validation concluded about these records.
    ///
    /// [`Verdict::Insecure`] when validation is switched off, because that is
    /// the honest reading: an unvalidated answer makes no authentication claim,
    /// which is exactly what `Insecure` means. It is deliberately not `Secure` —
    /// `Secure` is what sets the AD bit, and a resolver that never checked
    /// anything must never claim it did.
    pub verdict: Verdict,
}

impl Resolution {
    /// An answer (or any response carrying records).
    fn answer(rcode: ResponseCode, answers: Vec<Record>) -> Self {
        Self {
            rcode,
            answers,
            soa: None,
            verdict: Verdict::Insecure,
        }
    }

    /// The same resolution, carrying `verdict`.
    fn with_verdict(mut self, verdict: Verdict) -> Self {
        self.verdict = verdict;
        self
    }

    /// The negative-cache TTL for this resolution.
    ///
    /// When the zone supplied an SOA, its TTL is **authoritative and honoured as
    /// sent** — `min(SOA MINIMUM, SOA record TTL)` per RFC 2308, with no floor and
    /// no ceiling. A zone that asks for a 30s negative TTL gets 30s; one that asks
    /// for a day gets a day. Clamping it would override what the zone actually
    /// said, which is the whole point of publishing an SOA.
    ///
    /// `default_ttl` is used only when the response is a negative that carries no
    /// SOA at all — there is nothing to honour, so we fall back rather than
    /// declining to cache it (which would send every lookup of a nonexistent name
    /// back to the root servers, forever).
    ///
    /// `None` when this is not a negative at all.
    pub fn negative_ttl(&self, default_ttl: u32) -> Option<u32> {
        if !self.answers.is_empty() {
            return None;
        }
        let Some(soa) = self.soa.as_ref() else {
            return Some(default_ttl);
        };
        let RData::SOA(data) = soa.data() else {
            return Some(default_ttl);
        };
        Some(data.minimum().min(soa.ttl()))
    }
}

/// A nameserver that is currently failing, and when it may be tried again.
///
/// Failures are tracked *separately* from latency rather than being folded into it
/// as a huge synthetic RTT. Folding them in couples recovery to how fast the healthy
/// peers happen to be: against a loopback peer at 0.3ms, a 10s failure penalty gives
/// a dead server a 1-in-33,000 share, so it is never retried and never recovers.
/// An explicit backoff recovers in bounded time no matter what the peers' absolute
/// speeds are.
///
/// Blame lives here too, alongside the transport fields rather than in a parallel
/// map, because it is another fact about the same server — but it is cleared by
/// completely different events. See [`IterativeResolver::note_success`].
#[derive(Debug, Clone)]
struct ServerHealth {
    consecutive_failures: u32,
    retry_after: Instant,
    /// Consecutive answers from this root server whose DNSSEC did not validate
    /// against our trust anchor. Cleared **only** by an answer that validates —
    /// not by expiry, and not by a prompt reply — so a root that has lied three
    /// times and served nothing since returns at the fourth step of the curve
    /// rather than the first.
    blame_count: u32,
    /// When this server's omission from the root set ends, if it is omitted.
    blamed_until: Option<Instant>,
}

impl ServerHealth {
    /// A fresh entry, with nothing held against the server.
    fn clean() -> Self {
        Self {
            consecutive_failures: 0,
            retry_after: Instant::now(),
            blame_count: 0,
            blamed_until: None,
        }
    }

    /// Whether anything is still recorded about this server. An entry that says
    /// nothing is dropped rather than kept forever.
    fn is_empty(&self) -> bool {
        self.consecutive_failures == 0 && self.blame_count == 0 && self.blamed_until.is_none()
    }
}

/// Marker error: every nameserver we were handed for a zone failed to answer.
///
/// This is the **only** failure that says anything about the cached delegation
/// itself, and therefore the only one that may invalidate it. Everything else — a
/// depth limit, a delegation loop, an exhausted query budget, a broken chain
/// *below* the delegation — is a fact about the name being looked up, not about the
/// nameservers. Invalidating on those would let one bad name evict a perfectly good
/// delegation (a nested glue-less sub-recursion failing deep in the chain would wipe
/// the `com.` entry that got it there), sending every subsequent lookup in that zone
/// back to the root servers.
#[derive(Debug)]
struct NameserversUnreachable;

impl std::fmt::Display for NameserversUnreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "all nameservers failed")
    }
}

impl std::error::Error for NameserversUnreachable {}

/// Remaining upstream-query allowance for one client lookup.
///
/// Shared across every branch of a resolution — the CNAME chase, each glue-less NS
/// sub-recursion — so the *total* cost is bounded rather than each dimension being
/// bounded on its own while their product runs away.
/// Atomic rather than a `Cell` because the resolution future is held across `await`
/// points inside `tokio::spawn`ed request handlers, which requires it to be `Send`.
#[derive(Debug)]
struct QueryBudget {
    remaining: AtomicUsize,
}

impl QueryBudget {
    fn new(limit: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(limit),
        }
    }

    /// Claims one query. `false` once the budget is spent.
    fn claim(&self) -> bool {
        self.remaining
            .fetch_update(AtomicOrdering::SeqCst, AtomicOrdering::SeqCst, |left| {
                if left == 0 { None } else { Some(left - 1) }
            })
            .is_ok()
    }
}

/// What extending the chain of trust across one delegation produced.
///
/// A failure here is not an ordinary resolution error, and returning it as one
/// would lose the distinction the whole module is built on: `Failed` carries the
/// [`Verdict`] so a broken chain is reported as *bogus* — an attack or a
/// misconfigured zone — rather than disappearing into a generic "lookup failed"
/// that reads identically to a timeout.
#[derive(Debug)]
enum TrustOutcome {
    /// Trust for the child zone, or `None` when validation is off.
    Trust(Option<TrustState>),
    /// The chain is broken; the answer must be withheld.
    Failed(Verdict),
}

/// What establishing the *root* zone's keys produced.
///
/// The two failures at the top of the chain are not the same failure, and
/// flattening them into one `Err` is what let an attacker take validation out of
/// the path: an `Err` reads to the tier chain as "the roots are unreachable" and
/// sends the query to an upstream that does not validate. So a *cryptographic*
/// failure is a verdict — the answer is withheld and the chain stops — while a
/// *transport* failure stays an error and falls through, or an unplugged network
/// would hard-fail every lookup on the box.
#[derive(Debug)]
enum RootTrust {
    /// The root's DNSKEY RRset is anchored.
    Trust(TrustState),
    /// The RRset arrived and could not be anchored. Withhold.
    Failed(Verdict),
}

/// Why a zone's DNSKEY RRset could not be established.
///
/// The split is the whole point of the type: `Unreachable` is a fact about the
/// network, `Invalid` is a fact about what a server said. They are the same
/// `anyhow::Error` at every call site below the root, and they must not be at
/// the root.
#[derive(Debug)]
enum DnskeyError {
    /// The RRset could not be obtained at all.
    Unreachable(anyhow::Error),
    /// The RRset arrived and did not validate against the key source, together
    /// with the address that served it — which is who blame attaches to.
    Invalid { from: IpAddr, reason: String },
}

impl std::fmt::Display for DnskeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(e) => write!(f, "{e:#}"),
            Self::Invalid { reason, .. } => write!(f, "{reason}"),
        }
    }
}

/// A validated DNSKEY RRset, and where it came from.
#[derive(Debug)]
struct ValidatedKeys {
    keys: Vec<hickory_proto::dnssec::rdata::DNSKEY>,
    ttl: u32,
    /// The server that produced it. At the root this is the address whose blame
    /// a validating answer clears.
    from: IpAddr,
}

/// A nameserver's response, together with the address that produced it.
///
/// Without the address a bogus verdict cannot be blamed on anyone: "some server
/// for this zone lied" is not a statement any policy can act on.
#[derive(Debug)]
struct Answered {
    message: Message,
    from: IpAddr,
}

/// Classification of a single nameserver response relative to the query.
#[derive(Debug)]
enum Step {
    /// A usable answer (the requested type, or terminal records).
    Answer(Vec<Record>),
    /// A CNAME pointing elsewhere; resolution must continue at `target`.
    Cname { target: Name, records: Vec<Record> },
    /// A delegation to a more specific zone.
    Referral {
        zone: Name,
        /// The additional-section glue records, TTLs intact. Addresses are derived
        /// from these *after* the bailiwick filter, so an out-of-bailiwick glue
        /// record cannot be used even transiently.
        glue_records: Vec<Record>,
        ns_targets: Vec<Name>,
        /// Shortest TTL across the delegation's NS (and glue) records — how long
        /// the delegation may be cached for.
        ttl: u32,
    },
    /// An authoritative negative response (NXDOMAIN or NODATA), with the
    /// authority-section SOA when the server supplied one.
    Negative {
        rcode: ResponseCode,
        soa: Option<Record>,
    },
}

/// An iterative resolver that resolves names from the root servers down.
///
/// Consults a [`DelegationCache`] before falling back to the root hints, so a
/// warm zone is entered as far down the delegation chain as possible, and orders
/// candidate nameservers by measured RTT so a slow or rate-limiting server is
/// demoted rather than retried first on every query.
#[derive(Debug, Clone)]
pub struct IterativeResolver {
    root_hints: Vec<IpAddr>,
    timeout: Duration,
    /// Port used to reach nameservers (always 53 in production; overridable
    /// for tests).
    port: u16,
    /// Zone -> nameservers, so cold names do not re-walk from the root every time.
    delegations: Arc<DelegationCache>,
    /// Glue, glueless NS-name lookups and CNAME hops seen mid-recursion — the
    /// parts of a walk that used to be discarded despite carrying TTLs.
    records: Arc<RecordCache>,
    /// Per-nameserver EMA latency and hit counts, used to balance candidates.
    /// Only *successful* queries are recorded here, so it stays a measure of speed
    /// rather than a mixture of speed and failure.
    latency: Arc<LatencyTracker>,
    /// Currently-failing nameservers and when each may be retried.
    health: Arc<DashMap<SocketAddr, ServerHealth>>,
    /// First-failure backoff (doubles per consecutive failure).
    backoff_base: Duration,
    /// First-offence omission for a root server that serves invalid DNSSEC
    /// (doubles per consecutive offence).
    blame_base: Duration,
    /// Ceiling on that omission.
    blame_cap: Duration,
    /// TTL applied where a record or negative carries none of its own.
    default_ttl: u32,
    /// Whether root priming has been *attempted*.
    ///
    /// Tracks the attempt rather than the success on purpose: a failed prime caches
    /// nothing, so keying off the cache alone would re-fire the `. NS` query on
    /// every single lookup for the rest of time on any network where priming does
    /// not work. One attempt, then fall back to the hints and get on with it.
    primed: Arc<AtomicBool>,
    /// The DNSSEC trust anchors, or `None` when validation is switched off.
    ///
    /// This one field decides everything: whether outbound queries carry the DO
    /// bit, whether the walk derives a chain of trust as it descends, and
    /// whether a bogus answer becomes SERVFAIL. `Option` rather than an empty
    /// anchor set because "validate against nothing" and "do not validate" are
    /// different things — the former would make every signed zone bogus.
    anchors: Option<Anchors>,
    /// Zone -> validated DNSKEY set (or proven-insecure), so the chain is not
    /// re-derived from the root on every query.
    keys: Arc<KeyCache>,
}

impl IterativeResolver {
    /// Creates a resolver using the given root hints, falling back to the
    /// built-in [`ROOT_HINTS`] when the list is empty, with a fresh in-memory
    /// delegation cache.
    pub fn new(root_hints: Vec<IpAddr>) -> Self {
        Self::with_delegations(root_hints, Arc::new(DelegationCache::in_memory()))
    }

    /// Creates a resolver backed by an existing (possibly persistent) delegation
    /// cache.
    pub fn with_delegations(root_hints: Vec<IpAddr>, delegations: Arc<DelegationCache>) -> Self {
        let root_hints = if root_hints.is_empty() {
            ROOT_HINTS.to_vec()
        } else {
            root_hints
        };
        Self {
            root_hints,
            timeout: Duration::from_millis(DEFAULT_QUERY_TIMEOUT_MS),
            port: 53,
            delegations,
            records: Arc::new(RecordCache::new(DEFAULT_TTL)),
            latency: Arc::new(LatencyTracker::new(LATENCY_EMA_ALPHA)),
            health: Arc::new(DashMap::new()),
            backoff_base: DEFAULT_FAILURE_BACKOFF,
            blame_base: DEFAULT_BLAME_BACKOFF,
            blame_cap: MAX_BLAME_BACKOFF,
            default_ttl: DEFAULT_TTL,
            primed: Arc::new(AtomicBool::new(false)),
            anchors: None,
            keys: Arc::new(KeyCache::new()),
        }
    }

    /// Creates a resolver using the built-in root hints.
    pub fn with_defaults() -> Self {
        Self::new(Vec::new())
    }

    /// Sets the TTL applied where a record or negative response carries none of
    /// its own. A TTL that *is* present is always honoured as sent.
    pub fn with_default_ttl(mut self, default_ttl: u32) -> Self {
        self.default_ttl = default_ttl;
        self.records = Arc::new(RecordCache::new(default_ttl));
        self
    }

    /// Returns a resolver identical to this one but with different root hints,
    /// **keeping** the delegation cache, the record cache and the latency stats.
    ///
    /// `DnsServer::set_root_hints` swaps the whole resolver behind an `ArcSwap`;
    /// building a fresh one there would silently throw away everything learned so
    /// far and put us right back to walking from the roots on every query.
    pub fn with_root_hints(&self, root_hints: Vec<IpAddr>) -> Self {
        let root_hints = if root_hints.is_empty() {
            ROOT_HINTS.to_vec()
        } else {
            root_hints
        };
        Self {
            root_hints,
            timeout: self.timeout,
            port: self.port,
            delegations: Arc::clone(&self.delegations),
            records: Arc::clone(&self.records),
            latency: Arc::clone(&self.latency),
            // Health travels too, and with it blame: a root server that lied is
            // the same lying server after the hints are swapped.
            health: Arc::clone(&self.health),
            backoff_base: self.backoff_base,
            blame_base: self.blame_base,
            blame_cap: self.blame_cap,
            default_ttl: self.default_ttl,
            primed: Arc::clone(&self.primed),
            anchors: self.anchors.clone(),
            // The key cache travels with the delegation cache for the same
            // reason: changing the root hints does not invalidate what we
            // already proved about `com.` or anything under it.
            keys: Arc::clone(&self.keys),
        }
    }

    /// Turns on DNSSEC validation against `anchors`.
    ///
    /// Everything downstream keys off this: outbound queries start carrying the
    /// DO bit, the walk derives a chain of trust as it descends, and
    /// [`Resolution::verdict`] stops being unconditionally `Insecure`.
    pub fn with_validation(mut self, anchors: Anchors) -> Self {
        self.anchors = Some(anchors);
        self
    }

    /// Turns validation on or off in place. `None` switches it off.
    pub fn set_anchors(&mut self, anchors: Option<Anchors>) {
        self.anchors = anchors;
    }

    /// Whether DNSSEC validation is switched on.
    pub fn validating(&self) -> bool {
        self.anchors.is_some()
    }

    /// The validated-key cache backing this resolver.
    pub fn keys(&self) -> &Arc<KeyCache> {
        &self.keys
    }

    /// The delegation cache backing this resolver.
    pub fn delegations(&self) -> &Arc<DelegationCache> {
        &self.delegations
    }

    /// The port used to reach nameservers (53 in production; tests override it).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The mid-recursion record cache (glue, glueless NS lookups, CNAME hops).
    pub fn records(&self) -> &Arc<RecordCache> {
        &self.records
    }

    /// Per-nameserver `(address, EMA latency ms, queries sent)` — the same
    /// figures server selection balances on, exposed for metrics.
    pub fn latency_stats(&self) -> Vec<(SocketAddr, f64, u64)> {
        self.latency.all_stats()
    }

    /// The TTL applied where a record or negative carries none of its own.
    pub fn default_ttl(&self) -> u32 {
        self.default_ttl
    }

    /// The root hints this resolver falls back to.
    pub fn root_hints(&self) -> &[IpAddr] {
        &self.root_hints
    }

    /// Overrides the per-nameserver query timeout.
    ///
    /// Public so integration tests can drive failover without waiting out the
    /// production timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Overrides the port used to reach nameservers (always 53 in production).
    ///
    /// Public so integration tests can stand a delegation hierarchy up on an
    /// unprivileged port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Overrides the first-failure backoff (doubling per consecutive failure, capped
    /// at [`MAX_FAILURE_BACKOFF`]).
    ///
    /// Public so integration tests can watch a killed server get shed and a revived
    /// one earn its traffic back without sitting out the production backoff.
    pub fn with_failure_backoff(mut self, backoff: Duration) -> Self {
        self.backoff_base = backoff;
        self
    }

    /// Overrides the omission applied to a root server that serves invalid
    /// DNSSEC: the first offence's duration and the ceiling it doubles up to.
    ///
    /// Public for the same reason as [`Self::with_failure_backoff`], and more
    /// urgently: with a 15-minute base and a 24-hour cap, a test that had to sit
    /// out the production curve is not a slow test, it is a test that cannot be
    /// written. Both ends are overridable because the escalation stopping at the
    /// cap is itself a property worth pinning.
    pub fn with_blame_backoff(mut self, base: Duration, cap: Duration) -> Self {
        self.blame_base = base;
        self.blame_cap = cap;
        self
    }

    /// Whether `server` is currently omitted from the root set for serving
    /// DNSSEC that did not validate against our trust anchor.
    ///
    /// Public so a test can tell "omitted" apart from "merely slow" — the two
    /// look identical from the outside on any single query, and conflating them
    /// is how a blame bug hides.
    pub fn blamed_root(&self, server: IpAddr) -> bool {
        let addr = SocketAddr::new(server, self.port);
        self.health
            .get(&addr)
            .and_then(|h| h.blamed_until)
            .is_some_and(|until| until > Instant::now())
    }

    /// How many root servers are currently omitted. Sampled by the metrics
    /// collector: a long-lived silent exclusion of part of the root set is
    /// exactly the state an operator needs to see, and nothing else reports it.
    pub fn blamed_root_count(&self) -> usize {
        let now = Instant::now();
        self.health
            .iter()
            .filter(|entry| entry.blamed_until.is_some_and(|until| until > now))
            .count()
    }

    /// Resolves `name`/`qtype` iteratively from the root servers.
    pub async fn resolve(
        &self,
        name: &Name,
        qtype: RecordType,
        qclass: DNSClass,
    ) -> Result<Resolution> {
        crate::metrics::metrics().resolver_lookups.inc();
        let mut cname_seen: Vec<Name> = Vec::new();
        let budget = QueryBudget::new(if self.validating() {
            MAX_QUERIES_PER_RESOLUTION + VALIDATION_QUERY_BUDGET
        } else {
            MAX_QUERIES_PER_RESOLUTION
        });
        let resolution = self
            .resolve_inner(name, qtype, qclass, 0, &mut cname_seen, &budget)
            .await?;
        crate::metrics::metrics()
            .dnssec_verdicts
            .inc(resolution.verdict.index());
        if let Some(reason) = resolution.verdict.reason() {
            debug!(
                "DNSSEC {} for {} {}: {}",
                resolution.verdict.label(),
                name,
                qtype,
                reason
            );
        }
        Ok(resolution)
    }

    /// Primes the root zone: asks the roots who the roots are, and caches the
    /// answer as the `.` delegation with the TTL they gave it (~6 days).
    ///
    /// Without this the compiled-in [`ROOT_HINTS`] are the only root servers we
    /// ever know about — a hardcoded list, never refreshed, with no TTL. Priming
    /// makes the hints what they are supposed to be: a *bootstrap*, used to find
    /// the live root NS set and as the fallback if that lookup fails.
    ///
    /// Called **once at startup**, not from the query path: priming is a
    /// bootstrap concern, and doing it inside `resolve()` would put an extra round
    /// trip in front of a user's first lookup for no benefit to that lookup.
    ///
    /// No-op once a live `.` delegation is cached; on failure we simply keep using
    /// the hints, because failing to prime must never fail a lookup.
    pub async fn prime_roots(&self, qclass: DNSClass) {
        if self.delegations.best_match(&Name::root()).is_some() {
            return;
        }
        // Attempt-once. A failed prime caches nothing, so without this the `. NS`
        // query would re-fire ahead of every lookup forever on any network where
        // priming does not work — a wasted round trip on every single query.
        if self.primed.swap(true, AtomicOrdering::SeqCst) {
            return;
        }

        // Query the hints directly rather than going through `resolve_inner`/`walk`.
        // Two reasons: `resolve_inner` would consult the delegation cache for `.` and
        // recurse straight back into this path; and `walk` only harvests glue from a
        // *referral* — a priming answer is an ordinary answer (the NS set in the
        // answer section, the addresses in the additional section), so its glue would
        // be thrown away before we ever saw it. Priming needs the raw response.
        let budget = QueryBudget::new(MAX_QUERIES_PER_RESOLUTION);
        let hints = self.usable_roots(self.root_hints.clone());
        let response = match self
            .query_servers(&hints, &Name::root(), RecordType::NS, qclass, &budget)
            .await
        {
            Ok(answered) => answered.message,
            Err(e) => {
                debug!("root priming failed ({e}); continuing with the static root hints");
                return;
            }
        };

        // The NS names come back in the answer section...
        let ns_names: Vec<Name> = response
            .answers()
            .iter()
            .filter_map(|rec| match rec.data() {
                RData::NS(rdata::NS(ns)) => Some(ns.clone()),
                _ => None,
            })
            .collect();
        if ns_names.is_empty() {
            debug!("root priming returned no NS set; keeping the static hints");
            return;
        }
        let ttl = response
            .answers()
            .iter()
            .map(|r| r.ttl())
            .min()
            .unwrap_or(self.default_ttl);

        // ...and their addresses as glue in the additional section.
        // `collect_glue_records` keeps only records whose owner is one of the NS
        // names we just asked about, so an off-topic additional record cannot slip
        // in; `glue_addresses` orders v4 first.
        let addrs = glue_addresses(&collect_glue_records(&response, &ns_names));
        if addrs.is_empty() {
            debug!("root priming returned no usable glue; keeping the static hints");
            crate::metrics::metrics()
                .resolver_priming
                .inc(PRIMING_FAILURE);
            return;
        }

        // Cache the glue under the NS hostnames too, so a later lookup of a root
        // server's name is served from cache rather than re-resolved.
        self.cache_glue(&collect_glue_records(&response, &ns_names));

        debug!("primed root zone: {} servers, ttl {}", addrs.len(), ttl);
        crate::metrics::metrics()
            .resolver_priming
            .inc(PRIMING_SUCCESS);
        self.delegations.insert(&Name::root(), addrs, ttl);
    }

    /// Resolves `name`, entering the delegation chain as deep as the cache allows.
    ///
    /// Tries the deepest cached delegation covering `name` first; a warm `.com`
    /// lookup therefore starts at the TLD servers and never touches a root. If
    /// that cached delegation turns out to be unusable (stale glue, dead servers)
    /// the entry is invalidated and the walk is retried from the root hints, so a
    /// bad cache entry costs one retry rather than wedging the name permanently.
    ///
    /// A `Negative` (NXDOMAIN/NODATA) answer is a *successful* resolution and must
    /// not trigger the retry — only a hard failure does.
    async fn resolve_inner(
        &self,
        name: &Name,
        qtype: RecordType,
        qclass: DNSClass,
        depth: u32,
        cname_seen: &mut Vec<Name>,
        budget: &QueryBudget,
    ) -> Result<Resolution> {
        if depth > MAX_RESOLUTION_DEPTH {
            bail!("maximum resolution depth exceeded resolving {}", name);
        }

        // `arpa.` is never resolved off-box (see [`is_arpa_subtree`]). This
        // resolver's whole job is to send queries to somebody else, so for that
        // subtree it declines outright — no packet, no root, no forwarder. It is
        // checked here rather than in `resolve` so that it also covers a CNAME
        // target and a glue-less NS hostname that point into the subtree.
        //
        // REFUSED, not NXDOMAIN: we are declining to answer for a namespace, not
        // asserting the name does not exist. Whoever holds local data for it —
        // the query path above — has already had its turn.
        if is_arpa_subtree(name) {
            debug!("refusing {name} {qtype}: the arpa. subtree is never resolved externally");
            return Ok(Resolution::answer(ResponseCode::Refused, Vec::new()));
        }

        // Anything we already learned for this exact (name, type) — a CNAME target
        // chased earlier, an NS hostname resolved for a glueless delegation, a
        // previous answer — is still good for as long as its TTL says.
        if let Some((records, secure)) = self.records.get_with_proof(name, qtype) {
            debug!("record cache hit for {} {}", name, qtype);
            let verdict = if secure {
                Verdict::Secure
            } else {
                Verdict::Insecure
            };
            return Ok(Resolution::answer(ResponseCode::NoError, records).with_verdict(verdict));
        }

        if let Some((zone, servers, trust)) = self.warm_start(name) {
            let start_zone = Name::from_ascii(&zone).unwrap_or_else(|_| Name::root());
            // A cached `.` delegation is the primed root NS set, and blamed roots
            // are omitted from it exactly as they are from the hints.
            let servers = if start_zone.is_root() {
                self.usable_roots(servers)
            } else {
                servers
            };
            // Work on a copy of the CNAME trail: a failed attempt must not leave
            // partial state that makes the retry look like a CNAME loop.
            let mut attempt_seen = cname_seen.clone();
            match Box::pin(self.walk(
                name,
                qtype,
                qclass,
                depth,
                &mut attempt_seen,
                budget,
                servers,
                start_zone,
                trust,
            ))
            .await
            {
                Ok(resolution) => {
                    *cname_seen = attempt_seen;
                    return Ok(resolution);
                }
                Err(e) => {
                    // Only "the nameservers didn't answer" implicates the cached
                    // delegation. Any other failure is about this *name* — a broken
                    // chain below the delegation, a depth limit, a spent budget — and
                    // a re-walk from the roots would fail identically while
                    // needlessly evicting a good entry.
                    if e.downcast_ref::<NameserversUnreachable>().is_none() {
                        debug!(
                            "resolving {} via cached delegation {} failed ({}); \
                             keeping the delegation, the fault is not with its servers",
                            name, zone, e
                        );
                        return Err(e);
                    }
                    debug!(
                        "cached delegation {} unreachable for {} ({}); re-walking from the roots",
                        zone, name, e
                    );
                    self.delegations.invalidate(&zone);
                }
            }
        }

        // From the root hints. When validating, the root's own DNSKEY RRset has to
        // be fetched and anchored before anything it says can be believed; a
        // failure there is fatal to the lookup rather than a downgrade, because
        // "we could not establish the root's keys" and "the root is unsigned" are
        // not the same statement and only one of them is ever true.
        //
        // *Which* kind of failure it was decides everything downstream: a root
        // zone that will not validate is a withholding verdict (SERVFAIL, chain
        // stops), while a root we could not reach stays an error and falls
        // through to the next tier.
        let trust = match self.anchors.as_ref() {
            Some(anchors) => match self
                .root_trust(anchors, qclass, budget)
                .await
                .context("could not establish the root zone's DNSSEC keys")?
            {
                RootTrust::Trust(state) => Some(state),
                RootTrust::Failed(verdict) => {
                    return Ok(Resolution::answer(ResponseCode::ServFail, Vec::new())
                        .with_verdict(verdict));
                }
            },
            None => None,
        };

        Box::pin(self.walk(
            name,
            qtype,
            qclass,
            depth,
            cname_seen,
            budget,
            self.usable_roots(self.root_hints.clone()),
            Name::root(),
            trust,
        ))
        .await
    }

    /// The deepest cached delegation covering `name` that we may actually start
    /// from, together with the trust state for its zone.
    ///
    /// With validation off this is just [`DelegationCache::best_match`]. With
    /// validation on there is an extra condition: entering the chain part-way
    /// means skipping every DS and DNSKEY check above the entry point, so a
    /// delegation is only a usable shortcut if the trust state for its zone is
    /// *also* still cached. When it is not, the walk restarts at the root and
    /// re-derives the chain — which repopulates the key cache on the way down,
    /// so the cost is paid once per zone rather than once per query.
    fn warm_start(&self, name: &Name) -> Option<(String, Vec<IpAddr>, Option<TrustState>)> {
        let (zone, servers) = self.delegations.best_match(name)?;
        if !self.validating() {
            return Some((zone, servers, None));
        }
        let zone_name = Name::from_ascii(&zone).ok()?;
        let trust = self.keys.get(&zone_name)?;
        Some((zone, servers, Some(trust)))
    }

    /// Walks the delegation chain for `name`, starting at `servers`, caching each
    /// delegation it learns along the way.
    // The parameters are the resolution state, and every one of them has to thread
    // through the mutual recursion with `resolve_inner`. Boxing them into a context
    // struct would just move the same fields behind another name.
    #[allow(clippy::too_many_arguments)]
    async fn walk(
        &self,
        name: &Name,
        qtype: RecordType,
        qclass: DNSClass,
        depth: u32,
        cname_seen: &mut Vec<Name>,
        budget: &QueryBudget,
        mut servers: Vec<IpAddr>,
        start_zone: Name,
        start_trust: Option<TrustState>,
    ) -> Result<Resolution> {
        let mut visited_zones: HashSet<String> = HashSet::new();
        // The zone whose servers we are currently talking to. A referral is only
        // usable if it moves strictly *down* from here — see `referral_in_bailiwick`.
        let mut current_zone = start_zone;
        // The trust state of `current_zone`, moving down the chain alongside it.
        // `None` means validation is off; `Some(Insecure)` means the chain
        // provably ended above here, which is a different and much stronger
        // statement than "we are not checking".
        let mut trust = start_trust;

        for _hop in 0..MAX_REFERRALS {
            let response = self
                .query_servers(&servers, name, qtype, qclass, budget)
                .await?
                .message;

            match classify(&response, qtype) {
                Step::Answer(records) => {
                    let verdict = self.validate_answer(
                        name,
                        qtype,
                        &records,
                        &response,
                        &current_zone,
                        &trust,
                    );
                    if verdict.withholds_answer() {
                        return Ok(Resolution::answer(ResponseCode::ServFail, Vec::new())
                            .with_verdict(verdict));
                    }
                    // Hold onto it: a CNAME chain or a glueless NS lookup that lands
                    // here again must not re-run the whole walk.
                    if response.response_code() == ResponseCode::NoError {
                        self.records.insert_with_proof(
                            name,
                            qtype,
                            records.clone(),
                            verdict == Verdict::Secure,
                        );
                    }
                    return Ok(
                        Resolution::answer(response.response_code(), records).with_verdict(verdict)
                    );
                }
                Step::Cname { target, records } => {
                    if cname_seen.iter().any(|n| n == &target) {
                        bail!("CNAME loop detected at {}", target);
                    }
                    if cname_seen.len() >= MAX_CNAME_CHAIN {
                        bail!("CNAME chain too long resolving {}", name);
                    }
                    // The CNAME itself lives in this zone and is signed by it; the
                    // target lives wherever it lives and is validated separately by
                    // the sub-resolution. Validating the hop here rather than
                    // trusting the whole answer section is what stops a server from
                    // stapling unsigned records for the target onto a signed CNAME.
                    let hop_verdict = self.validate_answer(
                        name,
                        RecordType::CNAME,
                        &records,
                        &response,
                        &current_zone,
                        &trust,
                    );
                    if hop_verdict.withholds_answer() {
                        return Ok(Resolution::answer(ResponseCode::ServFail, Vec::new())
                            .with_verdict(hop_verdict));
                    }
                    cname_seen.push(target.clone());
                    crate::metrics::metrics().resolver_cname_hops.inc();
                    let mut accumulated = records;
                    let sub = Box::pin(self.resolve_inner(
                        &target,
                        qtype,
                        qclass,
                        depth + 1,
                        cname_seen,
                        budget,
                    ))
                    .await?;
                    // The chain is only as trustworthy as its weakest hop: a
                    // securely-signed CNAME into an unsigned zone yields an
                    // Insecure answer, not a Secure one.
                    let verdict = hop_verdict.merge(sub.verdict);
                    if verdict.withholds_answer() {
                        return Ok(Resolution::answer(ResponseCode::ServFail, Vec::new())
                            .with_verdict(verdict));
                    }
                    accumulated.extend(sub.answers);
                    return Ok(Resolution::answer(sub.rcode, accumulated).with_verdict(verdict));
                }
                Step::Negative { rcode, soa } => {
                    let verdict = self.validate_negative(
                        name,
                        qtype,
                        rcode,
                        &response,
                        &current_zone,
                        &trust,
                    );
                    if verdict.withholds_answer() {
                        return Ok(Resolution::answer(ResponseCode::ServFail, Vec::new())
                            .with_verdict(verdict));
                    }
                    return Ok(Resolution {
                        rcode,
                        answers: Vec::new(),
                        soa,
                        verdict,
                    });
                }
                Step::Referral {
                    zone,
                    glue_records,
                    ns_targets,
                    ttl,
                } => {
                    let glue_count = glue_records.len();
                    crate::metrics::metrics().resolver_referrals.inc();
                    if !referral_in_bailiwick(&current_zone, &zone, name) {
                        crate::metrics::metrics().resolver_out_of_bailiwick.inc();
                        bail!(
                            "out-of-bailiwick referral: a server for {} delegated {} \
                             while resolving {}",
                            current_zone,
                            zone,
                            name
                        );
                    }
                    let zone_key = zone.to_ascii().to_lowercase();
                    if !visited_zones.insert(zone_key) {
                        bail!("delegation loop at zone {} resolving {}", zone, name);
                    }

                    // Glue arrives with TTLs. Cache it, keyed by the NS hostname it
                    // describes, instead of reducing it to bare addresses and
                    // dropping it — that is what forced a fresh sub-recursion every
                    // time a glueless delegation came round again.
                    // Glue is only this server's to give for names inside the zone
                    // it is authoritative for. Note the test is against
                    // `current_zone`, the *answering* zone, not the delegated one:
                    // a root referral for `com.` legitimately carries glue for
                    // `a.gtld-servers.net.`, which is outside `com.` but well
                    // inside `.`. Anything further out is unverifiable, and caching
                    // it would let any zone dictate where a foreign nameserver
                    // lives for every later glue-less lookup.
                    let in_bailiwick: Vec<Record> = glue_records
                        .into_iter()
                        .filter(|rec| current_zone.zone_of(rec.name()))
                        .collect();
                    if in_bailiwick.len() != glue_count {
                        crate::metrics::metrics().resolver_out_of_bailiwick.inc();
                        debug!(
                            "discarded {} out-of-bailiwick glue record(s) from the {} delegation",
                            glue_count - in_bailiwick.len(),
                            zone
                        );
                    }
                    let glue = glue_addresses(&in_bailiwick);

                    servers = if !glue.is_empty() {
                        glue
                    } else {
                        self.resolve_ns_addresses(&ns_targets, qclass, depth + 1, budget)
                            .await?
                    };
                    if servers.is_empty() {
                        bail!("no reachable nameservers for delegation of {}", zone);
                    }

                    // Extend the chain of trust across the delegation *before*
                    // descending, so that whatever the child's servers say next is
                    // already checkable. This is also the point where an insecure
                    // delegation has to be proven rather than assumed.
                    let outcome = self
                        .extend_trust(
                            &current_zone,
                            &zone,
                            &trust,
                            response.name_servers(),
                            &servers,
                            qclass,
                            budget,
                        )
                        .await;
                    trust = match outcome {
                        TrustOutcome::Trust(state) => state,
                        TrustOutcome::Failed(verdict) => {
                            // Nothing learned from a referral we just refused to
                            // verify may survive the rejection. No bogus data
                            // reaches a client either way, but a delegation
                            // cached here is an NS set we would keep using — and
                            // it is written through to disk, so it would outlive
                            // the restart as well.
                            return Ok(Resolution::answer(ResponseCode::ServFail, Vec::new())
                                .with_verdict(verdict));
                        }
                    };

                    // Past the gate: remember the delegation, so the next name in
                    // this zone starts here instead of back at the root, and keep
                    // the glue that got us here.
                    //
                    // The glue was already safe on its own — `RecordCache::insert`
                    // flags it unproven, so it could never be mistaken for
                    // validated data — and it is cached here rather than earlier
                    // so that one rule covers both: a walk that ends Bogus leaves
                    // nothing behind.
                    self.delegations.insert(&zone, servers.clone(), ttl);
                    self.cache_glue(&in_bailiwick);
                    current_zone = zone;
                }
            }
        }

        bail!("too many referrals resolving {}", name)
    }

    /// Fetches and anchors the root zone's DNSKEY RRset.
    ///
    /// This is the top of every chain, so it fails closed: if the root's keys
    /// cannot be obtained and matched to a configured anchor, no answer derived
    /// from a walk that starts here can be validated, and returning one anyway
    /// would be validation in name only.
    async fn root_trust(
        &self,
        anchors: &Anchors,
        qclass: DNSClass,
        budget: &QueryBudget,
    ) -> Result<RootTrust> {
        let root = Name::root();
        if let Some(state) = self.keys.get(&root) {
            return Ok(RootTrust::Trust(state));
        }

        // Prefer the primed root NS set over the compiled-in hints, for the same
        // reason `resolve_inner` does: the hints are a bootstrap. Either way a
        // root currently omitted for serving invalid DNSSEC is not in the set.
        let servers = self
            .delegations
            .best_match(&root)
            .map(|(_, servers)| servers)
            .filter(|servers| !servers.is_empty())
            .unwrap_or_else(|| self.root_hints.clone());
        let servers = self.usable_roots(servers);

        match self
            .fetch_dnskeys(
                &root,
                &servers,
                &KeySource::Anchors(anchors.get()),
                qclass,
                budget,
            )
            .await
        {
            Ok(validated) => {
                // The only claim a root server makes that we can check without
                // asking anybody else, and it checked out: this server is
                // restored outright, escalation counter and all.
                self.clear_blame(validated.from);
                let state = TrustState::Secure(Arc::new(validated.keys));
                self.keys.insert(&root, state.clone(), validated.ttl);
                Ok(RootTrust::Trust(state))
            }
            // A root server told us something untrue. That is a verdict about the
            // root zone *and* a fact about that server, so it withholds the
            // answer and costs the responder its place in the root set.
            Err(DnskeyError::Invalid { from, reason }) => {
                self.blame_root(from, &reason);
                Ok(RootTrust::Failed(Verdict::Bogus(format!(
                    "the root zone's DNSKEY RRset did not validate against the configured \
                     trust anchors: {reason}"
                ))))
            }
            // Unreachable is not invalid: this stays an error, so the query falls
            // through to the next tier rather than hard-failing.
            Err(DnskeyError::Unreachable(e)) => Err(e),
        }
    }

    /// Queries a zone's DNSKEY RRset and validates it against `source` — the
    /// trust anchors at the root, the parent's DS RRset everywhere else.
    async fn fetch_dnskeys(
        &self,
        zone: &Name,
        servers: &[IpAddr],
        source: &KeySource<'_>,
        qclass: DNSClass,
        budget: &QueryBudget,
    ) -> std::result::Result<ValidatedKeys, DnskeyError> {
        crate::metrics::metrics().dnssec_dnskey_lookups.inc();
        let answered = self
            .query_servers(servers, zone, RecordType::DNSKEY, qclass, budget)
            .await
            .with_context(|| format!("could not fetch the DNSKEY RRset for {zone}"))
            .map_err(DnskeyError::Unreachable)?;
        let answers = answered.message.answers();
        // No clock is a failure to *decide*, not a claim that the server lied —
        // blaming somebody for our own broken clock would be absurd.
        let now = crate::dnssec::now_secs().map_err(DnskeyError::Unreachable)?;
        // The answer section is passed as both the records and the signatures:
        // `validate_dnskey_rrset` filters each out by type, and a DNSKEY response
        // legitimately carries both in the one section.
        let keys =
            validate::validate_dnskey_rrset(zone, answers, answers, source, now).map_err(|e| {
                DnskeyError::Invalid {
                    from: answered.from,
                    reason: e.to_string(),
                }
            })?;
        Ok(ValidatedKeys {
            ttl: validate::min_ttl(answers, self.default_ttl),
            keys,
            from: answered.from,
        })
    }

    /// Extends the chain of trust across a delegation from `parent` to `child`.
    ///
    /// Three outcomes, and the middle one is where DNSSEC actually earns its
    /// keep:
    ///
    /// - The parent published a DS that validates, so the child's DNSKEY RRset is
    ///   fetched and anchored to it: the chain continues, Secure.
    /// - The parent published **no** DS and a signed NSEC/NSEC3 proves it: the
    ///   chain legitimately ends here and everything below is Insecure. The proof
    ///   is what makes this safe — without it "no DS arrived" is a claim any
    ///   on-path attacker can make by deleting records, and believing it is how a
    ///   validating resolver gets downgraded into a non-validating one.
    /// - Neither: the delegation is unverifiable and the answer is withheld.
    #[allow(clippy::too_many_arguments)]
    async fn extend_trust(
        &self,
        parent: &Name,
        child: &Name,
        parent_trust: &Option<TrustState>,
        authority: &[Record],
        child_servers: &[IpAddr],
        qclass: DNSClass,
        budget: &QueryBudget,
    ) -> TrustOutcome {
        // Validation is off entirely.
        let Some(parent_trust) = parent_trust.as_ref() else {
            return TrustOutcome::Trust(None);
        };

        // Below a proven-insecure delegation there is nothing left to check: an
        // unsigned zone cannot sign a DS for its children, so every zone under it
        // is insecure too, and re-testing that at every level would just be an
        // NSEC round trip per hop for a foregone conclusion.
        let Some(parent_keys) = parent_trust.keys() else {
            self.keys
                .insert(child, TrustState::Insecure, self.default_ttl);
            return TrustOutcome::Trust(Some(TrustState::Insecure));
        };

        if let Some(state) = self.keys.get(child) {
            return TrustOutcome::Trust(Some(state));
        }

        let now = match crate::dnssec::now_secs() {
            Ok(now) => now,
            Err(e) => return TrustOutcome::Failed(Verdict::Indeterminate(e.to_string())),
        };

        // The DS RRset rides in the referral's authority section alongside the NS
        // records, and unlike them it is signed — by the parent, which is exactly
        // the key we already hold.
        let ds_rrset = validate::records_at(authority, child, RecordType::DS);
        if !ds_rrset.is_empty() {
            if let Err(e) = validate::verify_rrset(
                child,
                RecordType::DS,
                &ds_rrset,
                authority,
                parent_keys,
                parent,
                now,
            ) {
                return TrustOutcome::Failed(Verdict::Bogus(format!(
                    "the DS RRset for {child} published by {parent} did not validate: {e}"
                )));
            }

            let ds = validate::ds_records(&ds_rrset, child);
            if !validate::ds_algorithms_supported(&ds) {
                // RFC 6840 §5.11: a delegation we have no implementation for is
                // insecure, not broken. Refusing to serve it would turn our own
                // missing algorithm into the zone's outage.
                debug!(
                    "{child} is signed only with algorithms this build cannot verify; \
                     treating the delegation as insecure"
                );
                let ttl = validate::min_ttl(&ds_rrset, self.default_ttl);
                self.keys.insert(child, TrustState::Insecure, ttl);
                return TrustOutcome::Trust(Some(TrustState::Insecure));
            }

            return match self
                .fetch_dnskeys(child, child_servers, &KeySource::Ds(&ds), qclass, budget)
                .await
            {
                Ok(validated) => {
                    let state = TrustState::Secure(Arc::new(validated.keys));
                    self.keys.insert(child, state.clone(), validated.ttl);
                    TrustOutcome::Trust(Some(state))
                }
                // A DS exists, so the zone claims to be signed; failing to get a
                // matching DNSKEY set is a broken chain, not an unsigned zone.
                Err(e) => TrustOutcome::Failed(Verdict::Bogus(format!(
                    "{child} has a DS in {parent} but its DNSKEY RRset did not validate: {e}"
                ))),
            };
        }

        // No DS. The absence must be signed by the parent to mean anything.
        let denial = self.verified_denial(authority, parent, parent_keys, now);
        match validate::prove_no_ds(child, &denial) {
            Ok(_) => {
                crate::metrics::metrics().dnssec_insecure_delegations.inc();
                let ttl = validate::min_ttl(authority, self.default_ttl);
                self.keys.insert(child, TrustState::Insecure, ttl);
                TrustOutcome::Trust(Some(TrustState::Insecure))
            }
            Err(e) => TrustOutcome::Failed(Verdict::Bogus(format!(
                "the delegation from {parent} to {child} cannot be shown to be unsigned: {e}"
            ))),
        }
    }

    /// The NSEC/NSEC3 records from an authority section whose signatures check
    /// out against `keys`.
    ///
    /// Filtering here rather than in the proofs is the point: an NSEC record is a
    /// zone's signed assertion that something does not exist, and an *unsigned*
    /// NSEC record is an attacker's unsigned assertion of the same thing. Only
    /// the former may be reasoned from, so unverified ones are dropped before any
    /// proof ever sees them.
    fn verified_denial(
        &self,
        authority: &[Record],
        zone: &Name,
        keys: &[hickory_proto::dnssec::rdata::DNSKEY],
        now: u32,
    ) -> Denial {
        let (sets, sigs) = validate::group_rrsets(authority);
        let mut verified: Vec<Record> = Vec::new();
        for (owner, rtype, records) in sets {
            if !matches!(rtype, RecordType::NSEC | RecordType::NSEC3) {
                continue;
            }
            match validate::verify_rrset(&owner, rtype, &records, &sigs, keys, zone, now) {
                Ok(_) => verified.extend(records),
                Err(e) => debug!("discarding an unvalidated {rtype} record at {owner}: {e}"),
            }
        }
        Denial::from_records(&verified)
    }

    /// Validates an answer section against the current zone's keys.
    fn validate_answer(
        &self,
        qname: &Name,
        qtype: RecordType,
        records: &[Record],
        response: &Message,
        zone: &Name,
        trust: &Option<TrustState>,
    ) -> Verdict {
        let Some(trust) = trust.as_ref() else {
            return Verdict::Insecure;
        };
        let Some(keys) = trust.keys() else {
            return Verdict::Insecure;
        };
        let now = match crate::dnssec::now_secs() {
            Ok(now) => now,
            Err(e) => return Verdict::Indeterminate(e.to_string()),
        };

        let (sets, sigs) = validate::group_rrsets(records);
        if sets.is_empty() {
            return Verdict::Secure;
        }

        // Every RRset in the answer section must verify, not just the one that
        // answers the question. A server authoritative for this zone has no
        // business returning an RRset here that it cannot sign, and the records
        // it staples on are precisely the ones an injection would add.
        let mut wildcards: Vec<(Name, Name)> = Vec::new();
        for (owner, rtype, rrset) in &sets {
            match validate::verify_rrset(owner, *rtype, rrset, &sigs, keys, zone, now) {
                Ok(facts) => {
                    if let Some(encloser) = facts.wildcard_closest_encloser {
                        wildcards.push((owner.clone(), encloser));
                    }
                }
                Err(e) => {
                    return Verdict::Bogus(format!("answer for {qname} {qtype} is bogus: {e}"));
                }
            }
        }

        if wildcards.is_empty() {
            return Verdict::Secure;
        }

        // A wildcard signature is valid for every name under the closest
        // encloser, so on its own it says nothing about *this* name. RFC 4035
        // §5.3.4: the zone must also prove the queried name has no records of its
        // own, or the answer could be replayed onto a name that does.
        let denial = self.verified_denial(response.name_servers(), zone, keys, now);
        for (owner, encloser) in wildcards {
            match validate::prove_wildcard_expansion(&owner, &encloser, &denial) {
                Ok(Denied::Proven) => {}
                Ok(Denied::OptedOut) => return Verdict::Insecure,
                Err(e) => {
                    return Verdict::Bogus(format!(
                        "wildcard answer for {qname} {qtype} is unsubstantiated: {e}"
                    ));
                }
            }
        }
        Verdict::Secure
    }

    /// Validates a negative (NXDOMAIN/NODATA) response against the current zone's
    /// keys.
    fn validate_negative(
        &self,
        qname: &Name,
        qtype: RecordType,
        rcode: ResponseCode,
        response: &Message,
        zone: &Name,
        trust: &Option<TrustState>,
    ) -> Verdict {
        let Some(trust) = trust.as_ref() else {
            return Verdict::Insecure;
        };
        let Some(keys) = trust.keys() else {
            return Verdict::Insecure;
        };
        let now = match crate::dnssec::now_secs() {
            Ok(now) => now,
            Err(e) => return Verdict::Indeterminate(e.to_string()),
        };

        let denial = self.verified_denial(response.name_servers(), zone, keys, now);
        if denial.is_empty() {
            // A signed zone that answers "no" without proving it is either broken
            // or being spoken for. Either way there is nothing here to believe:
            // an unproven negative is the cheapest forgery in DNS.
            return Verdict::Bogus(format!(
                "{rcode} for {qname} {qtype} from the signed zone {zone} carries no validated \
                 NSEC or NSEC3 proof"
            ));
        }

        let proof = if rcode == ResponseCode::NXDomain {
            validate::prove_nxdomain(qname, zone, &denial)
        } else {
            validate::prove_nodata(qname, qtype, zone, &denial)
        };
        match proof {
            Ok(Denied::Proven) => Verdict::Secure,
            Ok(Denied::OptedOut) => Verdict::Insecure,
            Err(e) => Verdict::Bogus(format!("{rcode} for {qname} {qtype} is unproven: {e}")),
        }
    }

    /// Caches the additional-section glue, grouped by the NS hostname it belongs
    /// to, honouring each record's TTL.
    fn cache_glue(&self, glue_records: &[Record]) {
        if glue_records.is_empty() {
            return;
        }
        // Group by (owner name, type): a hostname may have several A records, and
        // both an A and a AAAA set.
        let mut grouped: Vec<(Name, RecordType, Vec<Record>)> = Vec::new();
        for rec in glue_records {
            let rtype = rec.record_type();
            match grouped
                .iter_mut()
                .find(|(n, t, _)| *t == rtype && names_equal(n, rec.name()))
            {
                Some((_, _, recs)) => recs.push(rec.clone()),
                None => grouped.push((rec.name().clone(), rtype, vec![rec.clone()])),
            }
        }
        for (owner, rtype, recs) in grouped {
            self.records.insert(&owner, rtype, recs);
        }
    }

    /// Resolves the addresses of glue-less delegation nameservers.
    ///
    /// Checks the record cache first: an NS hostname we resolved earlier (or saw as
    /// glue in some other referral) is still good for as long as its TTL says, and
    /// re-running a full sub-recursion for it every time is exactly the waste this
    /// cache exists to stop.
    async fn resolve_ns_addresses(
        &self,
        ns_targets: &[Name],
        qclass: DNSClass,
        depth: u32,
        budget: &QueryBudget,
    ) -> Result<Vec<IpAddr>> {
        let mut addrs = Vec::new();
        for ns in ns_targets.iter().take(MAX_GLUELESS_NS) {
            if let Some(records) = self.records.get(ns, RecordType::A) {
                for record in &records {
                    if let RData::A(rdata::A(ip)) = record.data() {
                        addrs.push(IpAddr::V4(*ip));
                    }
                }
                if !addrs.is_empty() {
                    debug!("glue cache hit for nameserver {}", ns);
                    break;
                }
            }

            let mut seen = Vec::new();
            if let Ok(res) =
                Box::pin(self.resolve_inner(ns, RecordType::A, qclass, depth, &mut seen, budget))
                    .await
            {
                for record in &res.answers {
                    if let RData::A(rdata::A(ip)) = record.data() {
                        addrs.push(IpAddr::V4(*ip));
                    }
                }
            }
            if !addrs.is_empty() {
                break;
            }
        }
        Ok(addrs)
    }

    /// Sends the query to each server in turn, returning the first valid response.
    ///
    /// Servers are tried in RTT order (see [`Self::order_servers`]) and every
    /// attempt is timed, so a slow or black-holed nameserver is demoted for
    /// subsequent queries instead of being retried first every time.
    async fn query_servers(
        &self,
        servers: &[IpAddr],
        name: &Name,
        qtype: RecordType,
        qclass: DNSClass,
        budget: &QueryBudget,
    ) -> Result<Answered> {
        let (query, id) = build_query(name, qtype, qclass, self.validating())?;
        for server in self.order_servers(servers) {
            // Every packet counts against the lookup's total allowance, so a
            // pathological delegation chain cannot fan out into thousands of queries.
            if !budget.claim() {
                crate::metrics::metrics().resolver_budget_exhausted.inc();
                bail!(
                    "query budget ({}) exhausted resolving {}",
                    MAX_QUERIES_PER_RESOLUTION,
                    name
                );
            }
            let started = Instant::now();
            match self
                .query_one(server, &query, id, name, qtype, qclass)
                .await
            {
                Ok(msg) => {
                    self.note_success(server, started.elapsed().as_secs_f64() * 1000.0);
                    return Ok(Answered {
                        message: msg,
                        from: server,
                    });
                }
                Err(e) => {
                    self.note_failure(server);
                    debug!("query for {} to {} failed: {}", name, server, e);
                    continue;
                }
            }
        }
        // Tagged, so `resolve_inner` can tell "these servers are dead" (invalidate
        // the cached delegation) from "this name is broken" (keep it).
        Err(anyhow::Error::new(NameserversUnreachable)
            .context(format!("all nameservers failed for {name}")))
    }

    /// A server answered: record its real latency and clear any *transport*
    /// failure state.
    ///
    /// Deliberately narrower than dropping the whole entry. Blame is a statement
    /// about what a server said, not about how fast it said it, and a hijacked
    /// root answers promptly by construction — so removing the entry here would
    /// let the very server we distrust clear its own record by returning a
    /// packet. The entry is dropped only once nothing at all is left in it.
    fn note_success(&self, server: IpAddr, latency_ms: f64) {
        let addr = SocketAddr::new(server, self.port);
        self.latency.record(addr, latency_ms);
        if let Some(mut entry) = self.health.get_mut(&addr) {
            entry.consecutive_failures = 0;
            entry.retry_after = Instant::now();
        }
        self.health.remove_if(&addr, |_, h| h.is_empty());
    }

    /// A root server answered with DNSSEC that does not validate against our
    /// trust anchor: omit it from the root set, for longer each time.
    ///
    /// Only ever called for the root zone's own DNSKEY RRset checked against the
    /// anchor. That is the one thing a root server tells us that we can verify
    /// without asking anybody else, which is what makes "this root server is
    /// lying" a statement we can stand behind rather than an inference from
    /// somebody else's mistake.
    ///
    /// In memory only: a restarted box re-trusts every root until one misbehaves
    /// again.
    fn blame_root(&self, server: IpAddr, reason: &str) {
        let addr = SocketAddr::new(server, self.port);
        let mut entry = self.health.entry(addr).or_insert_with(ServerHealth::clean);
        entry.blame_count = entry.blame_count.saturating_add(1);

        let shift = entry.blame_count.saturating_sub(1).min(16);
        let penalty = self
            .blame_base
            .saturating_mul(1u32 << shift)
            .min(self.blame_cap);
        entry.blamed_until = Some(Instant::now() + penalty);
        warn!(
            "root server {} served DNSSEC that does not validate ({} in a row); \
             omitting it for {:?}: {}",
            addr, entry.blame_count, penalty, reason
        );
    }

    /// A root server produced an answer that validates: it is fully restored.
    ///
    /// The escalation counter is cleared here and **nowhere else** — not by
    /// expiry, not by a prompt reply. A root that has lied three times and served
    /// nothing since therefore returns at the fourth step of the curve rather
    /// than the first, which is what stops a persistent liar from resetting
    /// itself simply by waiting.
    fn clear_blame(&self, server: IpAddr) {
        let addr = SocketAddr::new(server, self.port);
        let mut cleared = false;
        if let Some(mut entry) = self.health.get_mut(&addr) {
            cleared = entry.blame_count > 0 || entry.blamed_until.is_some();
            entry.blame_count = 0;
            entry.blamed_until = None;
        }
        self.health.remove_if(&addr, |_, h| h.is_empty());
        if cleared {
            debug!("root server {addr} produced a validating answer; blame cleared");
        }
    }

    /// The root candidate set with blamed servers removed.
    ///
    /// Omission is real removal — a blamed root is filtered out *before*
    /// [`Self::order_servers`] ranks anything, so no ordering rule can bring it
    /// back as a last resort.
    ///
    /// **It never empties.** If every root is blamed the filter is not applied at
    /// all: thirteen rogue servers is not what that state means — it is the zone
    /// or our own trust anchor, a different fault with a different owner — and an
    /// empty candidate set yields "no nameservers", which reads as *unreachable*
    /// and falls through to an upstream that does not validate. That is exactly
    /// the hole the withholding root verdict closes, and blame must not reopen
    /// it. In that state blame stops being the deciding input: the root zone
    /// fails to validate, the answer is withheld, and the tier machinery governs.
    fn usable_roots(&self, servers: Vec<IpAddr>) -> Vec<IpAddr> {
        if servers.is_empty() {
            return servers;
        }
        let usable: Vec<IpAddr> = servers
            .iter()
            .copied()
            .filter(|s| !self.blamed_root(*s))
            .collect();
        if usable.is_empty() {
            warn!(
                "every root server is blamed for serving invalid DNSSEC; \
                 deferring to auto mode"
            );
            return servers;
        }
        usable
    }

    /// A server failed: back it off, doubling per consecutive failure.
    ///
    /// The failure is deliberately **not** written into the latency EMA. A synthetic
    /// multi-second "penalty latency" makes recovery depend on how fast the healthy
    /// peers happen to be — against a 0.3ms peer, a 10s penalty gives the failed
    /// server a 1-in-33,000 share and it never gets retried at all. A backoff
    /// recovers in bounded time regardless of the peers' absolute speed.
    fn note_failure(&self, server: IpAddr) {
        let addr = SocketAddr::new(server, self.port);
        let mut entry = self.health.entry(addr).or_insert_with(ServerHealth::clean);
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);

        let shift = entry.consecutive_failures.saturating_sub(1).min(16);
        let backoff = self
            .backoff_base
            .saturating_mul(1u32 << shift)
            .min(MAX_FAILURE_BACKOFF);
        entry.retry_after = Instant::now() + backoff;
        debug!(
            "nameserver {} failed ({} in a row); backing off {:?}",
            addr, entry.consecutive_failures, backoff
        );
    }

    /// Whether a server is currently backed off.
    fn backed_off(&self, server: IpAddr) -> bool {
        let addr = SocketAddr::new(server, self.port);
        self.health
            .get(&addr)
            .map(|h| h.retry_after > Instant::now())
            .unwrap_or(false)
    }

    /// Orders candidate nameservers by load-balancing score, **IPv4 before IPv6
    /// always**.
    ///
    /// The v4/v6 split is not a preference, it is a correctness constraint —
    /// [`collect_glue`] deliberately puts IPv4 first because a host with no
    /// routable IPv6 would otherwise burn the full query timeout on every v6
    /// nameserver it picked. Scoring therefore happens strictly *within* each
    /// family, never across.
    fn order_servers(&self, servers: &[IpAddr]) -> Vec<IpAddr> {
        let mut v4: Vec<IpAddr> = servers.iter().copied().filter(|s| s.is_ipv4()).collect();
        let mut v6: Vec<IpAddr> = servers.iter().copied().filter(|s| s.is_ipv6()).collect();

        self.rank(&mut v4);
        self.rank(&mut v6);

        v4.extend(v6);
        v4
    }

    /// Orders a same-family group by ascending `hits * latency`, lowest first.
    ///
    /// **Why the product.** We want each server to carry queries in inverse
    /// proportion to how slow it is — a 50ms server should take more than a 200ms
    /// one, but the 200ms one must still take *some*, or we are right back to
    /// pinning every query on a single server and getting rate-limited for it.
    /// Always selecting the minimum of `hits * latency` drives that product toward
    /// equality across the group, and `hits_i * lat_i = k` is exactly
    /// `hits_i ∝ 1 / lat_i`. (The inverse ratio, `hits / latency`, would do the
    /// opposite and favour the *slowest* server, since large latency shrinks it.)
    /// Read it as "hits per unit of speed".
    ///
    /// It self-balances with no timer: every query a server answers raises its own
    /// score and hands the next one to somebody else, while the EMA keeps
    /// re-measuring latency from live traffic.
    ///
    /// **Nothing is pre-measured.** A server we have never queried has `hits == 0`,
    /// so its score is `0 * anything == 0` — the minimum — and it gets tried first,
    /// learning its latency from a query that had to happen anyway. There is no
    /// probe and no invented default latency.
    ///
    /// **Failing servers are shed, and recover on a bounded clock.** A server that
    /// fails is backed off (see [`Self::note_failure`]) and sorted behind every
    /// healthy peer — but never removed, so if *everything* is failing we still try
    /// it rather than refusing to resolve. Once its backoff expires it re-enters the
    /// rotation on equal terms and is re-measured by a real query.
    fn rank(&self, group: &mut [IpAddr]) {
        // Shuffle first so equal scores — notably an all-unmeasured set, where
        // every score is 0 — are broken randomly rather than by declaration order.
        // Without this a cold start still leads with ROOT_HINTS[0] every time.
        group.shuffle(&mut rand::rng());
        group.sort_by(|a, b| {
            // Backed-off servers go last, whatever their score.
            match self.backed_off(*a).cmp(&self.backed_off(*b)) {
                Ordering::Equal => self
                    .score_of(*a)
                    .partial_cmp(&self.score_of(*b))
                    .unwrap_or(Ordering::Equal),
                other => other,
            }
        });
    }

    /// `hits * ema_latency_ms` for a server. Zero when we have never queried it.
    ///
    /// Only successful queries are counted, so this is purely a measure of speed —
    /// failures are handled by the backoff, not by poisoning the latency.
    fn score_of(&self, server: IpAddr) -> f64 {
        let addr = SocketAddr::new(server, self.port);
        let hits = self.latency.get_count(&addr) as f64;
        if hits == 0.0 {
            // Never answered: the minimum possible score, so it is tried first and
            // measured for real. This is what "do not pre-measure" means — and it is
            // also how a server whose backoff has just expired gets re-probed.
            return 0.0;
        }
        let latency = self.latency.get_latency(&addr).unwrap_or(0.0);
        hits * latency.max(1.0)
    }

    /// Sends a single query over UDP (falling back to TCP on truncation) and
    /// validates the response transaction id and question.
    async fn query_one(
        &self,
        server: IpAddr,
        query: &[u8],
        id: u16,
        qname: &Name,
        qtype: RecordType,
        qclass: DNSClass,
    ) -> Result<Message> {
        let target = SocketAddr::new(server, self.port);
        let bind = if server.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        // Connecting filters the receive queue to `target` in the kernel: a datagram
        // from any other source is dropped before this task ever sees it, so an
        // off-path injector must also spoof the nameserver's address. Free, and it
        // costs nothing per packet.
        socket.connect(target).await?;
        socket.send(query).await?;

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let len = tokio::time::timeout(self.timeout, socket.recv(&mut buf))
            .await
            .context("nameserver timeout")?
            .context("nameserver recv error")?;
        buf.truncate(len);

        let msg = Message::from_bytes(&buf)?;
        if msg.id() != id {
            bail!("response id mismatch from {}", server);
        }
        if msg.truncated() {
            crate::metrics::metrics().resolver_tcp_retries.inc();
            return self
                .query_tcp(target, query, id, qname, qtype, qclass)
                .await;
        }
        validate_question(&msg, qname, qtype, qclass)?;
        Ok(msg)
    }

    /// Sends a single query over TCP with the standard 2-byte length prefix.
    async fn query_tcp(
        &self,
        target: SocketAddr,
        query: &[u8],
        id: u16,
        qname: &Name,
        qtype: RecordType,
        qclass: DNSClass,
    ) -> Result<Message> {
        let mut stream = tokio::time::timeout(self.timeout, TcpStream::connect(target))
            .await
            .context("nameserver TCP connect timeout")??;

        let len = u16::try_from(query.len()).context("query too large for TCP framing")?;
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(query);
        tokio::time::timeout(self.timeout, stream.write_all(&framed))
            .await
            .context("nameserver TCP write timeout")??;

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut len_buf))
            .await
            .context("nameserver TCP length read timeout")??;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut resp_buf))
            .await
            .context("nameserver TCP body read timeout")??;

        let msg = Message::from_bytes(&resp_buf)?;
        if msg.id() != id {
            bail!("TCP response id mismatch from {}", target);
        }
        validate_question(&msg, qname, qtype, qclass)?;
        Ok(msg)
    }
}

/// The EDNS UDP payload size advertised on outbound iterative queries.
///
/// 1232 rather than [`MAX_UDP_SIZE`]: it is the largest payload that fits in the
/// minimum IPv6 MTU without fragmentation, and a fragmented DNS response is both
/// a reassembly-based spoofing vector and a packet many middleboxes silently
/// drop. Anything larger comes back truncated and is refetched over TCP, which
/// the query path already handles. Without any OPT record at all — the previous
/// behaviour — a server is entitled to cap the response at 512 bytes, which a
/// signed answer essentially never fits inside.
const EDNS_UDP_PAYLOAD: u16 = 1232;

/// Builds an iterative query (recursion desired cleared) for `name`/`qtype`,
/// returning the wire bytes and the random transaction id.
///
/// `dnssec_ok` sets the EDNS DO bit. It is off unless validation is enabled,
/// because DO is a request for RRSIG/NSEC/NSEC3 records that a non-validating
/// resolver would pay for on every response and then discard.
fn build_query(
    name: &Name,
    qtype: RecordType,
    qclass: DNSClass,
    dnssec_ok: bool,
) -> Result<(Vec<u8>, u16)> {
    let id: u16 = rand::rng().random();
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false);

    let mut query = Query::new();
    query.set_name(name.clone());
    query.set_query_type(qtype);
    query.set_query_class(qclass);
    msg.add_query(query);

    if dnssec_ok {
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(EDNS_UDP_PAYLOAD);
        edns.set_dnssec_ok(true);
        msg.set_edns(edns);
    }

    Ok((msg.to_bytes()?, id))
}

/// Verifies the response answers the question we actually asked — name
/// (case-insensitive), type, and class.
///
/// The name alone is not enough: a response echoing the right name but a question
/// about some other type or class is answering something that was never asked, and
/// accepting it lets forged records in under a name the resolver did request.
fn validate_question(
    msg: &Message,
    qname: &Name,
    qtype: RecordType,
    qclass: DNSClass,
) -> Result<()> {
    match msg.queries().first() {
        Some(q)
            if names_equal(q.name(), qname)
                && q.query_type() == qtype
                && q.query_class() == qclass =>
        {
            Ok(())
        }
        Some(q) => bail!(
            "response question {} {} {} does not match query {} {} {}",
            q.name(),
            q.query_class(),
            q.query_type(),
            qname,
            qclass,
            qtype
        ),
        None => bail!("response has no question section"),
    }
}

/// Case-insensitive DNS name comparison.
fn names_equal(a: &Name, b: &Name) -> bool {
    a.to_ascii().eq_ignore_ascii_case(&b.to_ascii())
}

/// Whether `name` is `arpa.` or lives beneath it — the subtree this server
/// never resolves off-box.
///
/// `arpa.` is answered from local data or not at all: a stored PTR, a managed
/// reverse zone, and otherwise REFUSED. Nothing under it is ever sent to an
/// upstream, a forwarder or a root server, so this predicate is the policy and
/// both gates ([`IterativeResolver::resolve_inner`] and the query path in
/// `dns_server`) ask it the same question.
///
/// Matched on the **label boundary**, never as a string suffix: a rooted name is
/// in the subtree if and only if its final label is exactly `arpa`, so
/// `notarpa.` and `arpa.example.com.` fall outside for free, which a
/// `ends_with("arpa.")` test would get wrong in the first case and a `contains`
/// in both. Comparing the last label costs no allocation and needs no table.
pub fn is_arpa_subtree(name: &Name) -> bool {
    name.iter()
        .next_back()
        .is_some_and(|label| label.eq_ignore_ascii_case(b"arpa"))
}

/// Classifies a nameserver response relative to the requested type.
fn classify(response: &Message, qtype: RecordType) -> Step {
    let answers = response.answers();

    if !answers.is_empty() {
        let has_requested = answers.iter().any(|r| r.record_type() == qtype);
        if has_requested || qtype == RecordType::CNAME || qtype == RecordType::ANY {
            return Step::Answer(answers.to_vec());
        }
        if let Some(target) = answers.iter().find_map(|r| match r.data() {
            RData::CNAME(rdata::CNAME(t)) => Some(t.clone()),
            _ => None,
        }) {
            return Step::Cname {
                target,
                records: answers.to_vec(),
            };
        }
        // Answers present but neither the requested type nor a CNAME: return as-is.
        return Step::Answer(answers.to_vec());
    }

    if response.response_code() == ResponseCode::NXDomain {
        return Step::Negative {
            rcode: ResponseCode::NXDomain,
            soa: find_soa(response),
        };
    }

    // No answers, NoError: a delegation (NS in authority) or NODATA.
    let ns_records: Vec<&Record> = response
        .name_servers()
        .iter()
        .filter(|r| matches!(r.data(), RData::NS(_)))
        .collect();

    if ns_records.is_empty() {
        return Step::Negative {
            rcode: response.response_code(),
            soa: find_soa(response),
        };
    }

    let zone = ns_records
        .first()
        .map(|r| r.name().clone())
        .unwrap_or_else(Name::root);
    let ns_targets: Vec<Name> = ns_records
        .iter()
        .filter_map(|r| match r.data() {
            RData::NS(rdata::NS(t)) => Some(t.clone()),
            _ => None,
        })
        .collect();
    // Keep the glue records themselves, not just the addresses: they carry TTLs,
    // the caller caches them instead of throwing them away, and the bailiwick
    // filter needs their owner names.
    let glue_records = collect_glue_records(response, &ns_targets);

    // The delegation may only be cached for as long as its shortest component
    // lives: the NS records, and any glue we are about to rely on.
    let ns_ttl = ns_records.iter().map(|r| r.ttl()).min().unwrap_or(0);
    let glue_ttl = glue_records.iter().map(|rec| rec.ttl()).min();
    let ttl = match glue_ttl {
        Some(g) => ns_ttl.min(g),
        None => ns_ttl,
    };

    Step::Referral {
        zone,
        glue_records,
        ns_targets,
        ttl,
    }
}

/// Whether a referral may be followed and cached.
///
/// Two conditions, and both are load-bearing:
///
/// - **It must move strictly down from the zone that answered.** A server
///   authoritative for `current` may delegate a zone beneath it and nothing else.
///   Without this, any nameserver the resolver ever talks to — one ad domain, one
///   link — can hand back `NS com.` or `NS .` and have it cached, and
///   `best_match` walks suffixes, so every later lookup in that zone starts at
///   the attacker's server. A delegation whose TTL clears
///   `delegation_persist_min_ttl` is written to SQLite too, so the hijack
///   outlives a restart. "Strictly" also rules out the lame referral that
///   delegates the zone back to itself.
/// - **It must cover the name being resolved.** A delegation for a zone the
///   qname does not sit under is not on the path to an answer; following it is
///   how a referral for an unrelated branch gets treated as progress.
fn referral_in_bailiwick(current: &Name, zone: &Name, qname: &Name) -> bool {
    current.zone_of(zone) && zone != current && zone.zone_of(qname)
}

/// Reduces glue records to addresses, IPv4 before IPv6 for reachability.
fn glue_addresses(glue_records: &[Record]) -> Vec<IpAddr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for rec in glue_records {
        match rec.data() {
            RData::A(rdata::A(ip)) => v4.push(IpAddr::V4(*ip)),
            RData::AAAA(rdata::AAAA(ip)) => v6.push(IpAddr::V6(*ip)),
            _ => {}
        }
    }
    v4.extend(v6);
    v4
}

/// Extracts the authority-section SOA of a negative response, used to derive the
/// negative-cache TTL (RFC 2308).
fn find_soa(response: &Message) -> Option<Record> {
    response
        .name_servers()
        .iter()
        .find(|r| matches!(r.data(), RData::SOA(_)))
        .cloned()
}

/// The additional-section A/AAAA records belonging to the given NS targets, TTLs
/// and all.
///
/// Owner-name filtered against `ns_targets`, so an unrelated additional record
/// cannot ride in on a response and end up cached.
fn collect_glue_records(response: &Message, ns_targets: &[Name]) -> Vec<Record> {
    response
        .additionals()
        .iter()
        .filter(|rec| ns_targets.iter().any(|t| names_equal(t, rec.name())))
        .filter(|rec| matches!(rec.data(), RData::A(_) | RData::AAAA(_)))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, SOA};
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    fn a_record(owner: &str, ip: Ipv4Addr) -> Record {
        Record::from_rdata(name(owner), 300, RData::A(A(ip)))
    }

    fn ns_record(zone: &str, target: &str) -> Record {
        Record::from_rdata(name(zone), 300, RData::NS(NS(name(target))))
    }

    fn cname_record(owner: &str, target: &str) -> Record {
        Record::from_rdata(name(owner), 300, RData::CNAME(CNAME(name(target))))
    }

    #[test]
    fn root_hints_count() {
        assert_eq!(ROOT_HINTS.len(), 13);
        assert!(ROOT_HINTS.iter().all(|h| h.is_ipv4()));
    }

    #[test]
    fn resolver_defaults_to_root_hints() {
        let r = IterativeResolver::new(Vec::new());
        assert_eq!(r.root_hints.len(), 13);
        let custom = IterativeResolver::new(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        assert_eq!(
            custom.root_hints,
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]
        );
    }

    #[test]
    fn build_query_roundtrips_with_rd_clear() {
        let (bytes, id) = build_query(&name("example.com."), RecordType::A, DNSClass::IN, false)
            .expect("build query");
        let msg = Message::from_bytes(&bytes).expect("parse");
        assert_eq!(msg.id(), id);
        assert!(!msg.recursion_desired());
        assert_eq!(msg.message_type(), MessageType::Query);
        let q = msg.queries().first().expect("question");
        assert!(names_equal(q.name(), &name("example.com.")));
        assert_eq!(q.query_type(), RecordType::A);
    }

    /// Without an OPT record a server may cap the response at 512 bytes, which a
    /// signed answer essentially never fits inside — so a validating query that
    /// forgot the OPT would fail on truncation rather than on anything DNSSEC.
    #[test]
    fn validating_queries_carry_the_do_bit_and_a_payload_size() {
        let (bytes, _) = build_query(&name("example.com."), RecordType::A, DNSClass::IN, true)
            .expect("build query");
        let msg = Message::from_bytes(&bytes).expect("parse");
        let edns = msg.extensions().as_ref().expect("OPT record present");
        assert_eq!(edns.version(), 0);
        assert!(edns.flags().dnssec_ok, "DO must be set when validating");
        assert_eq!(edns.max_payload(), EDNS_UDP_PAYLOAD);
    }

    /// The converse: with validation off there is no reason to ask for records
    /// we would only throw away, so no OPT record is sent at all.
    #[test]
    fn non_validating_queries_send_no_opt_record() {
        let (bytes, _) = build_query(&name("example.com."), RecordType::A, DNSClass::IN, false)
            .expect("build query");
        let msg = Message::from_bytes(&bytes).expect("parse");
        assert!(msg.extensions().is_none());
    }

    #[test]
    fn names_equal_is_case_insensitive() {
        assert!(names_equal(&name("Example.COM."), &name("example.com.")));
        assert!(!names_equal(&name("example.com."), &name("example.org.")));
    }

    #[test]
    fn classify_direct_answer() {
        let mut msg = Message::new();
        msg.add_answer(a_record("example.com.", Ipv4Addr::new(93, 184, 216, 34)));
        match classify(&msg, RecordType::A) {
            Step::Answer(records) => assert_eq!(records.len(), 1),
            other => panic!("expected answer, got {:?}", other),
        }
    }

    #[test]
    fn classify_cname_indirection() {
        let mut msg = Message::new();
        msg.add_answer(cname_record("www.example.com.", "example.com."));
        match classify(&msg, RecordType::A) {
            Step::Cname { target, records } => {
                assert!(names_equal(&target, &name("example.com.")));
                assert_eq!(records.len(), 1);
            }
            other => panic!("expected cname, got {:?}", other),
        }
    }

    #[test]
    fn classify_cname_when_cname_requested_is_answer() {
        let mut msg = Message::new();
        msg.add_answer(cname_record("www.example.com.", "example.com."));
        match classify(&msg, RecordType::CNAME) {
            Step::Answer(records) => assert_eq!(records.len(), 1),
            other => panic!("expected answer, got {:?}", other),
        }
    }

    #[test]
    fn classify_referral_with_glue() {
        let mut msg = Message::new();
        msg.add_name_server(ns_record("com.", "a.gtld-servers.net."));
        msg.add_additional(a_record(
            "a.gtld-servers.net.",
            Ipv4Addr::new(192, 5, 6, 30),
        ));
        match classify(&msg, RecordType::A) {
            Step::Referral {
                zone,
                glue_records,
                ns_targets,
                ttl,
            } => {
                assert!(names_equal(&zone, &name("com.")));
                assert_eq!(
                    glue_addresses(&glue_records),
                    vec![IpAddr::V4(Ipv4Addr::new(192, 5, 6, 30))]
                );
                assert_eq!(ns_targets.len(), 1);
                // Shortest of the NS record TTL and the glue TTL — both 300 here.
                assert_eq!(ttl, 300);
                // The glue records themselves survive classification, TTLs intact,
                // so they can be cached instead of discarded.
                assert_eq!(glue_records.len(), 1);
                assert_eq!(glue_records[0].ttl(), 300);
            }
            other => panic!("expected referral, got {:?}", other),
        }
    }

    #[test]
    fn referral_bailiwick_requires_downward_progress() {
        // The root may delegate a TLD.
        assert!(referral_in_bailiwick(
            &Name::root(),
            &name("com."),
            &name("www.example.com.")
        ));
        // A TLD may delegate a zone under it.
        assert!(referral_in_bailiwick(
            &name("com."),
            &name("example.com."),
            &name("www.example.com.")
        ));
        // A leaf zone may not redelegate its parent...
        assert!(!referral_in_bailiwick(
            &name("attacker.test."),
            &name("test."),
            &name("victim.attacker.test.")
        ));
        // ...nor an unrelated TLD, which is the cache-poisoning case.
        assert!(!referral_in_bailiwick(
            &name("attacker.test."),
            &name("com."),
            &name("www.example.com.")
        ));
        // ...nor the root, from anywhere below it.
        assert!(!referral_in_bailiwick(
            &name("attacker.test."),
            &Name::root(),
            &name("victim.attacker.test.")
        ));
        // A lame referral back to the same zone is not progress.
        assert!(!referral_in_bailiwick(
            &name("example.com."),
            &name("example.com."),
            &name("www.example.com.")
        ));
    }

    #[test]
    fn referral_bailiwick_requires_covering_the_qname() {
        // A delegation the queried name does not sit under is not on the path to
        // an answer, however well-formed it looks.
        assert!(!referral_in_bailiwick(
            &name("com."),
            &name("example.com."),
            &name("www.other.com.")
        ));
        // The zone apex itself counts as covered.
        assert!(referral_in_bailiwick(
            &name("com."),
            &name("example.com."),
            &name("example.com.")
        ));
    }

    #[test]
    fn referral_bailiwick_is_case_insensitive() {
        assert!(referral_in_bailiwick(
            &name("COM."),
            &name("Example.com."),
            &name("WWW.example.COM.")
        ));
    }

    #[test]
    fn classify_referral_glueless() {
        let mut msg = Message::new();
        msg.add_name_server(ns_record("example.com.", "ns1.example.net."));
        match classify(&msg, RecordType::A) {
            Step::Referral {
                glue_records,
                ns_targets,
                ..
            } => {
                assert!(glue_addresses(&glue_records).is_empty());
                assert_eq!(ns_targets.len(), 1);
            }
            other => panic!("expected glueless referral, got {:?}", other),
        }
    }

    #[test]
    fn classify_nxdomain() {
        let mut msg = Message::new();
        msg.set_response_code(ResponseCode::NXDomain);
        msg.add_name_server(Record::from_rdata(
            name("com."),
            300,
            RData::SOA(SOA::new(
                name("a.gtld-servers.net."),
                name("nstld.verisign-grs.com."),
                1,
                7200,
                3600,
                1_209_600,
                3600,
            )),
        ));
        match classify(&msg, RecordType::A) {
            Step::Negative { rcode, soa } => {
                assert_eq!(rcode, ResponseCode::NXDomain);
                // The authority SOA must be carried out so a negative TTL can be
                // derived (RFC 2308) instead of the negative being thrown away.
                assert!(soa.is_some(), "NXDOMAIN must retain its authority SOA");
            }
            other => panic!("expected negative, got {:?}", other),
        }
    }

    #[test]
    fn classify_nodata_soa_only() {
        let mut msg = Message::new();
        msg.add_name_server(Record::from_rdata(
            name("example.com."),
            300,
            RData::SOA(SOA::new(
                name("ns1.example.com."),
                name("hostmaster.example.com."),
                1,
                7200,
                3600,
                1_209_600,
                3600,
            )),
        ));
        match classify(&msg, RecordType::AAAA) {
            Step::Negative { rcode, soa } => {
                assert_eq!(rcode, ResponseCode::NoError);
                assert!(soa.is_some(), "NODATA must retain its authority SOA");
            }
            other => panic!("expected nodata negative, got {:?}", other),
        }
    }

    #[test]
    fn collect_glue_orders_v4_before_v6() {
        let mut msg = Message::new();
        msg.add_additional(Record::from_rdata(
            name("ns1.example.net."),
            300,
            RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        ));
        msg.add_additional(a_record("ns1.example.net.", Ipv4Addr::new(203, 0, 113, 1)));
        // Unrelated additional record must be ignored.
        msg.add_additional(a_record(
            "other.example.net.",
            Ipv4Addr::new(203, 0, 113, 9),
        ));
        let glue = glue_addresses(&collect_glue_records(&msg, &[name("ns1.example.net.")]));
        assert_eq!(glue.len(), 2);
        assert!(glue[0].is_ipv4());
        assert!(glue[1].is_ipv6());
    }

    /// Drives a full delegation chain from a single mock UDP nameserver: the
    /// first query gets a referral to `com.`, the second a referral to
    /// `example.com.`, and the third the final A answer. Each referral's glue
    /// points back at the same server (127.0.0.1), so the resolver walks the
    /// chain without any real network access.
    #[tokio::test]
    async fn iterative_resolution_follows_full_chain() {
        // Bind the mock nameserver socket.
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock ns");
        let port = server.local_addr().expect("local addr").port();
        let self_ip = Ipv4Addr::new(127, 0, 0, 1);

        // Drive three staged responses from the single socket. Root priming is a
        // startup call, not part of `resolve()`, so no stray query lands here.
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_SIZE];
            for stage in 0..3u8 {
                let (len, peer) = server.recv_from(&mut buf).await.expect("recv");
                let query = Message::from_bytes(&buf[..len]).expect("parse query");
                let mut resp = Message::new();
                resp.set_id(query.id());
                resp.set_message_type(MessageType::Response);
                resp.set_op_code(OpCode::Query);
                if let Some(q) = query.queries().first() {
                    resp.add_query(q.clone());
                }
                match stage {
                    0 => {
                        // Referral to com.
                        resp.add_name_server(Record::from_rdata(
                            Name::from_str("com.").unwrap(),
                            172_800,
                            RData::NS(NS(Name::from_str("a.gtld.").unwrap())),
                        ));
                        resp.add_additional(Record::from_rdata(
                            Name::from_str("a.gtld.").unwrap(),
                            172_800,
                            RData::A(A(self_ip)),
                        ));
                    }
                    1 => {
                        // Referral to example.com.
                        resp.add_name_server(Record::from_rdata(
                            Name::from_str("example.com.").unwrap(),
                            172_800,
                            RData::NS(NS(Name::from_str("ns1.example.com.").unwrap())),
                        ));
                        resp.add_additional(Record::from_rdata(
                            Name::from_str("ns1.example.com.").unwrap(),
                            172_800,
                            RData::A(A(self_ip)),
                        ));
                    }
                    _ => {
                        // Final authoritative answer.
                        resp.set_authoritative(true);
                        resp.add_answer(Record::from_rdata(
                            Name::from_str("example.com.").unwrap(),
                            300,
                            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                        ));
                    }
                }
                let bytes = resp.to_bytes().expect("encode response");
                server.send_to(&bytes, peer).await.expect("send");
            }
        });

        let resolver = IterativeResolver::new(vec![IpAddr::V4(self_ip)])
            .with_port(port)
            .with_timeout(Duration::from_secs(2));

        let result = resolver
            .resolve(&name("example.com."), RecordType::A, DNSClass::IN)
            .await
            .expect("resolution succeeds");

        handle.await.expect("mock ns task");

        assert_eq!(result.rcode, ResponseCode::NoError);
        assert_eq!(result.answers.len(), 1);
        match result.answers[0].data() {
            RData::A(A(ip)) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn iterative_resolution_returns_nxdomain() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock ns");
        let port = server.local_addr().expect("local addr").port();
        let self_ip = Ipv4Addr::new(127, 0, 0, 1);

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_SIZE];
            let (len, peer) = server.recv_from(&mut buf).await.expect("recv");
            let query = Message::from_bytes(&buf[..len]).expect("parse query");
            let mut resp = Message::new();
            resp.set_id(query.id());
            resp.set_message_type(MessageType::Response);
            resp.set_response_code(ResponseCode::NXDomain);
            resp.set_authoritative(true);
            if let Some(q) = query.queries().first() {
                resp.add_query(q.clone());
            }
            let bytes = resp.to_bytes().expect("encode");
            server.send_to(&bytes, peer).await.expect("send");
        });

        let resolver = IterativeResolver::new(vec![IpAddr::V4(self_ip)])
            .with_port(port)
            .with_timeout(Duration::from_secs(2));

        let result = resolver
            .resolve(&name("nope.invalid."), RecordType::A, DNSClass::IN)
            .await
            .expect("resolution returns");

        handle.await.expect("mock ns task");
        assert_eq!(result.rcode, ResponseCode::NXDomain);
        assert!(result.answers.is_empty());
    }

    #[test]
    fn validate_question_rejects_mismatch() {
        let mut msg = Message::new();
        let mut q = Query::new();
        q.set_name(name("evil.example.com."));
        q.set_query_type(RecordType::A);
        q.set_query_class(DNSClass::IN);
        msg.add_query(q);
        assert!(
            validate_question(&msg, &name("example.com."), RecordType::A, DNSClass::IN).is_err()
        );
        assert!(
            validate_question(
                &msg,
                &name("evil.example.com."),
                RecordType::A,
                DNSClass::IN
            )
            .is_ok()
        );
        // A matching name is not enough: the type and class must match too.
        assert!(
            validate_question(
                &msg,
                &name("evil.example.com."),
                RecordType::AAAA,
                DNSClass::IN
            )
            .is_err()
        );
        assert!(
            validate_question(
                &msg,
                &name("evil.example.com."),
                RecordType::A,
                DNSClass::CH
            )
            .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // The `arpa.` subtree
    // -----------------------------------------------------------------------

    /// The rule is a *label* test, and both halves matter: a suffix match would
    /// silently swallow `notarpa.` and anything else ending in those four
    /// letters, refusing to resolve somebody's perfectly ordinary domain, and a
    /// `contains` would do it for `arpa.example.com.` as well.
    #[test]
    fn the_arpa_rule_matches_on_the_label_boundary() {
        for inside in [
            "arpa.",
            "ipv4only.arpa.",
            "in-addr.arpa.",
            "1.0.0.127.in-addr.arpa.",
            "home.arpa.",
            // Case is not significant in DNS names, and an attacker picks the
            // spelling. This must not be a way in or out of the subtree.
            "IPV4ONLY.ARPA.",
            "ArPa.",
        ] {
            assert!(
                is_arpa_subtree(&name(inside)),
                "{inside} is in the arpa. subtree"
            );
        }

        for outside in [
            ".",
            "notarpa.",
            "sharpa.",
            "arpa.example.com.",
            "arpa.test.",
            "arpanet.",
            "com.",
        ] {
            assert!(
                !is_arpa_subtree(&name(outside)),
                "{outside} is NOT in the arpa. subtree"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Blame
    // -----------------------------------------------------------------------

    fn blaming_resolver() -> IterativeResolver {
        IterativeResolver::with_defaults()
            .with_blame_backoff(Duration::from_millis(50), Duration::from_millis(120))
    }

    /// One lie omits a root; each further lie omits it for longer, and the
    /// growth stops at the cap rather than running away.
    #[test]
    fn blame_omits_a_root_and_escalates_to_the_cap() {
        let r = blaming_resolver();
        let root = ROOT_HINTS[0];
        assert!(!r.blamed_root(root), "nothing is held against it yet");

        r.blame_root(root, "test");
        assert!(r.blamed_root(root));
        assert_eq!(r.blamed_root_count(), 1);

        // 50ms, then 100ms, then 200ms — except the cap is 120ms.
        let penalty = |r: &IterativeResolver| {
            let addr = SocketAddr::new(root, r.port());
            r.health
                .get(&addr)
                .and_then(|h| h.blamed_until)
                .map(|until| until.saturating_duration_since(Instant::now()))
                .unwrap_or_default()
        };
        let first = penalty(&r);
        r.blame_root(root, "test");
        let second = penalty(&r);
        assert!(
            second > first,
            "the second offence must cost more than the first ({second:?} vs {first:?})"
        );
        r.blame_root(root, "test");
        let third = penalty(&r);
        assert!(
            third <= Duration::from_millis(120),
            "the escalation must stop at the cap, got {third:?}"
        );
    }

    /// A prompt reply is not an apology. `note_success` clearing the whole
    /// health entry would let the very server we distrust wipe its own record by
    /// answering a packet — which a hijacked root does by definition.
    #[test]
    fn blame_survives_a_transport_success() {
        let r = blaming_resolver();
        let root = ROOT_HINTS[0];
        r.blame_root(root, "test");
        r.note_success(root, 0.2);
        assert!(
            r.blamed_root(root),
            "a successful exchange must not clear blame"
        );

        // The transport half *is* cleared, or an ordinary backoff would become
        // permanent.
        r.note_failure(root);
        assert!(r.backed_off(root));
        r.note_success(root, 0.2);
        assert!(!r.backed_off(root), "transport health recovers on success");
        assert!(r.blamed_root(root), "and blame is still there");
    }

    /// Only a validating answer clears the escalation counter. A root that lied
    /// twice and then waited out its penalty must come back at the third step of
    /// the curve, not the first.
    #[test]
    fn time_alone_does_not_forgive() {
        let r = IterativeResolver::with_defaults()
            .with_blame_backoff(Duration::from_millis(1), Duration::from_secs(60));
        let root = ROOT_HINTS[0];
        r.blame_root(root, "test");
        r.blame_root(root, "test");
        std::thread::sleep(Duration::from_millis(10));
        assert!(!r.blamed_root(root), "the penalty has expired");

        // Expiry did not reset the counter, so the next offence is the *third*
        // step (4ms), not the first (1ms).
        let r = r.with_blame_backoff(Duration::from_secs(1), Duration::from_secs(60));
        r.blame_root(root, "test");
        let addr = SocketAddr::new(root, r.port());
        let count = r.health.get(&addr).map(|h| h.blame_count).unwrap_or(0);
        assert_eq!(count, 3, "the escalation counter survived the expiry");

        r.clear_blame(root);
        assert!(!r.blamed_root(root), "a validating answer restores it");
        r.blame_root(root, "test");
        let count = r.health.get(&addr).map(|h| h.blame_count).unwrap_or(0);
        assert_eq!(count, 1, "and it starts again from the first step");
    }

    /// Omission must never empty the root set: an empty candidate list is
    /// "unreachable", which falls through to an upstream that does not validate,
    /// and that is the hole the withholding root verdict exists to close.
    #[test]
    fn the_root_filter_never_empties() {
        let r = blaming_resolver();
        let roots = vec![ROOT_HINTS[0], ROOT_HINTS[1], ROOT_HINTS[2]];

        r.blame_root(ROOT_HINTS[0], "test");
        let usable = r.usable_roots(roots.clone());
        assert_eq!(usable.len(), 2, "the blamed root is really removed");
        assert!(!usable.contains(&ROOT_HINTS[0]));

        for root in &roots {
            r.blame_root(*root, "test");
        }
        assert_eq!(
            r.usable_roots(roots.clone()),
            roots,
            "with every root blamed the filter is not applied at all"
        );
    }
}
