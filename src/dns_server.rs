use crate::db::{Database, RecordKind};
use crate::dns_cache::DnsCache;
use crate::metrics::{AnswerSource, Proto, QueryObservation, metrics};
use crate::rbl::RblChecker;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use hickory_proto::op::{MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::AbortHandle;
use tracing::{debug, error, info, warn};

const FORWARD_POOL_SIZE: usize = 8;

/// Indices into [`crate::metrics::BLOCK_KINDS`].
const BLOCK_RBL_PROVIDER: usize = 0;
const BLOCK_RBL_LOCAL: usize = 1;
const BLOCK_DNSBL_PROVIDER: usize = 2;

/// Indices into [`crate::metrics::FAMILIES`].
const FAMILY_V4: usize = 0;
const FAMILY_V6: usize = 1;

/// Indices into the `direction` label of
/// [`crate::metrics::Metrics::tier_switches`].
const TIER_SWITCH_RECOVER: usize = 0;
const TIER_SWITCH_DEGRADE: usize = 1;

/// Indices into [`crate::metrics::FLUSH_REASONS`].
const FLUSH_MUTATION: usize = 0;
const FLUSH_EXPLICIT: usize = 1;
const FLUSH_TIER_SWITCH: usize = 2;

/// Carries what only `resolve_query` knows out to the metrics wrapper: which
/// stage of the resolution order answered, and — where the wire form is
/// ambiguous — the response code.
///
/// `resolve_query` has around thirty exits. Rather than instrument each one,
/// each exit that is *not* plain upstream resolution tags itself here and the
/// single wrapper records the observation. The initial value is therefore
/// [`AnswerSource::Upstream`]: the function's fall-through ending is the upstream
/// path, so an exit that sets nothing is already labelled correctly.
///
/// Atomics rather than `Cell` because a `Cell` borrow held across an `await`
/// would make the query future `!Send`, and every listener spawns its queries.
struct QueryTag {
    /// An [`AnswerSource::index`].
    source: AtomicUsize,
    /// An index into [`crate::metrics::RCODES`], or [`RCODE_FROM_WIRE`] to read
    /// it off the response header instead.
    rcode: AtomicUsize,
}

/// Sentinel for [`QueryTag::rcode`]: derive the response code from the response
/// bytes. This is the normal case — the header nibble is authoritative for every
/// code the server actually returns except the EDNS extended ones, whose low
/// nibble is zero and would otherwise be misreported as NOERROR.
const RCODE_FROM_WIRE: usize = usize::MAX;

impl QueryTag {
    fn new() -> Self {
        Self {
            source: AtomicUsize::new(AnswerSource::Upstream.index()),
            rcode: AtomicUsize::new(RCODE_FROM_WIRE),
        }
    }

    /// Declares which stage produced the answer.
    fn set(&self, source: AnswerSource) {
        self.source.store(source.index(), Ordering::Relaxed);
    }

    /// Declares both the stage and an explicit response-code label, for the
    /// extended rcodes that the header nibble cannot express.
    fn set_with_rcode(&self, source: AnswerSource, rcode_index: usize) {
        self.set(source);
        self.rcode.store(rcode_index, Ordering::Relaxed);
    }

    fn source(&self) -> AnswerSource {
        AnswerSource::from_index(self.source.load(Ordering::Relaxed))
    }

    fn rcode_index(&self, response: &[u8]) -> usize {
        match self.rcode.load(Ordering::Relaxed) {
            RCODE_FROM_WIRE => crate::metrics::rcode_index_from_wire(wire_rcode(response)),
            explicit => explicit,
        }
    }
}

/// Upstream resolution strategy for queries not satisfied locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionMode {
    /// Resolve iteratively starting at the root servers.
    Recursive,
    /// Forward to the configured upstream resolvers.
    Forward,
    /// Resilient fallback chain (default): roots → DoH/DoT → local forwarder →
    /// public :53, with a sticky active tier (see the auto-resolution methods).
    Auto,
}

/// Ordered resolution tiers used by [`ResolutionMode::Auto`]. Lower index = more
/// preferred. The numeric order is also the trust order, so a *smaller* winning
/// index than the active tier is a recovery (safe) and a *larger* one is a
/// degrade (gated behind the failure grace period).
const TIER_ROOTS: usize = 0;
const TIER_SECURE: usize = 1;
const TIER_LOCAL: usize = 2;
const TIER_PUBLIC: usize = 3;
const TIER_COUNT: usize = 4;

/// Per-upstream timeout for the secure (DoH/DoT) tier. Short so a wedged/slow
/// encrypted upstream fails over to the next upstream (and then the next tier)
/// quickly; a Cloudflare/Google :443 handshake+query completes well within this
/// even on poor WiFi.
const SECURE_TIER_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1500);

/// Maximum UDP DNS message size.
const MAX_UDP_SIZE: usize = 4096;
/// Maximum TCP DNS message size (with 2-byte length prefix).
const MAX_TCP_SIZE: usize = 65535;

/// How long a stream-transport connection may sit idle between messages before
/// the server closes it.
///
/// Without a bound, a client that connects and sends nothing parks a task and a
/// file descriptor indefinitely: `dns.bind` defaults to `0.0.0.0:53`, so on a
/// routable interface that is a pre-auth remote resource exhaustion — hold
/// enough connections open and `accept` starts failing for everyone. RFC 7766
/// §6.2.1 leaves the value to the server; this is at the short end of the range
/// it describes, which suits a resolver whose clients are on the same network.
pub const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the body of an *announced* message may take to arrive.
///
/// Separate from the idle timeout because the two are different claims: idle is
/// "I have nothing to say yet", which is legitimate between queries on a reused
/// connection, while a half-delivered message is a client that said it was
/// sending 65535 bytes and then stopped. Tighter, since the data is supposedly
/// already in flight.
pub const TCP_MESSAGE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum concurrent stream-transport connections per listener.
///
/// The idle timeout bounds how long one connection can be held; this bounds how
/// many can be held at once, which is the other half — without it an attacker
/// simply opens them faster than they time out. Generous next to real load: a
/// resolver serving a network sees tens of concurrent TCP connections, not
/// hundreds.
pub const MAX_TCP_CONNECTIONS: usize = 1024;

/// The DNS server handles both UDP and TCP DNS queries.
/// It performs split-horizon resolution: local database records are preferred,
/// and unmatched queries are forwarded to upstream resolvers.
///
/// When network scoping is active, DNS queries are resolved within the context
/// of the network scope associated with the source IP. Unassociated IPs receive
/// REFUSED responses. RBL checks are also scoped to the network.
pub struct DnsServer {
    db: Database,
    rbl: Arc<RblChecker>,
    forwarders: Arc<ArcSwap<Vec<SocketAddr>>>,
    /// Optional DNS response cache for privacy-first resolution.
    dns_cache: Option<Arc<DnsCache>>,
    /// Optional DNS64 prefix for synthesizing AAAA records from A records.
    dns64_prefix: Option<Ipv6Addr>,
    /// Whether to randomize QNAME case in forwarded queries (0x20 encoding).
    qname_randomization: bool,
    /// TTL drift configuration for adjusting cached record TTLs.
    ttl_drift_config: Arc<ArcSwap<crate::ttl_drift::TtlDriftConfig>>,
    /// Optional proxy configuration for upstream forwarding.
    proxy_config: Arc<ArcSwap<Option<crate::doh_proxy::ProxyConfig>>>,
    /// Pool of pre-bound UDP sockets for forwarding queries.
    forward_sockets: Vec<Arc<tokio::sync::Mutex<Option<UdpSocket>>>>,
    /// Round-robin index for the forward socket pool.
    forward_socket_idx: AtomicUsize,
    /// Upstream resolution strategy (recursive-from-roots, forward, or auto).
    resolution_mode: Arc<ArcSwap<ResolutionMode>>,
    /// Iterative resolver used in recursive/auto mode.
    resolver: Arc<ArcSwap<crate::resolver::IterativeResolver>>,
    /// Encrypted (DoH/DoT) upstreams for the auto-mode secure tier.
    secure_upstreams: Arc<ArcSwap<Vec<crate::secure_client::SecureUpstream>>>,
    /// Plaintext public resolvers for the auto-mode last-resort tier.
    public_fallback: Arc<ArcSwap<Vec<SocketAddr>>>,
    /// Auto mode: index of the currently committed resolution tier.
    active_tier: AtomicUsize,
    /// Auto mode: consecutive deciding queries whose winner deviated from the
    /// active tier (drives the sticky switch — see `note_auto_winner`).
    deviation_streak: AtomicUsize,
    /// Auto mode: unix-seconds timestamp of the last top-of-chain recovery probe.
    last_probe: AtomicU64,
    /// Auto mode: consecutive-failure grace before committing a downward switch.
    switch_grace_failures: AtomicU32,
    /// Auto mode: how often (seconds) to probe the full chain from the top.
    recovery_probe_secs: AtomicU64,
    /// Whether to return IPv4 (A) answers. Cleared by the routability probe when
    /// the host cannot reach the IPv4 internet, so clients aren't handed
    /// addresses in a family that would stall (see `probe.rs`). Default true.
    answer_v4: AtomicBool,
    /// Whether to return IPv6 (AAAA) answers. Cleared by the routability probe
    /// when the host cannot reach the IPv6 internet. Default true.
    answer_v6: AtomicBool,
    /// Source ranges treated as untrusted network-overlay peers (WireGuard
    /// links). Scope enforcement (REFUSED-if-unassociated + partitioned TLDs)
    /// applies only to these; every other source is a trusted local client that
    /// resolves the full view. Defaults to the overlay range `10.64.0.0/10`.
    overlay_cidrs: Arc<ArcSwap<Vec<crate::cidr::IpCidr>>>,
    /// Source ranges permitted to drive *upstream* resolution. A source outside
    /// these ranges is still served local/authoritative data but is REFUSED
    /// rather than recursed for — see `may_recurse`. Defaults to the loopback,
    /// RFC 1918, link-local, ULA, and CGNAT ranges.
    recursion_cidrs: Arc<ArcSwap<Vec<crate::cidr::IpCidr>>>,
    /// Active per-TLD ingress DNS listeners, keyed by their bound local IP. Each
    /// entry holds the abort handles for the UDP+TCP tasks so the listener can be
    /// torn down when its last TLD is removed. Started via `spawn_ingress_listener`.
    ingress_listeners: Arc<DashMap<IpAddr, Vec<AbortHandle>>>,
    /// UDP/TCP port that ingress listeners bind (the ingress IP is per-TLD).
    /// Defaults to 53; overridable via `set_ingress_port` (e.g. dev/tests).
    ingress_port: AtomicU16,
    /// `SO_REUSEPORT` sockets to bind per UDP listen address. `0` means one per
    /// available core; see `DnsConfig::udp_shards` and `serve_udp`.
    udp_shards: AtomicUsize,
}

/// The default WireGuard-overlay range: only source IPs here are subject to
/// network-scope enforcement (see `overlay_cidrs`).
fn default_overlay_cidrs() -> Vec<crate::cidr::IpCidr> {
    vec![crate::cidr::IpCidr::parse("10.64.0.0/10").expect("valid default overlay CIDR")]
}

/// The source ranges allowed to drive upstream resolution by default: loopback,
/// the RFC 1918 private ranges, link-local, IPv6 ULA, and the CGNAT range.
///
/// Every one of these is unroutable on the public internet, so the default is
/// "recurse for the networks physically attached to this box, and for nobody
/// else". The Town OS WireGuard overlay (`10.64.0.0/10`) falls inside
/// `10.0.0.0/8`, so overlay peers keep full service — they are scope-*enforced*
/// by `overlay_cidrs`, which is a separate axis from whether recursion is
/// offered at all.
///
/// `100.64.0.0/10` is included because CGNAT space is where overlay networks
/// (Tailscale and friends) and carrier-side LANs live; it is not reachable from
/// the internet either.
fn default_recursion_cidrs() -> Vec<crate::cidr::IpCidr> {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fe80::/10",
        "fc00::/7",
    ]
    .iter()
    .map(|c| crate::cidr::IpCidr::parse(c).expect("valid default recursion CIDR"))
    .collect()
}

impl DnsServer {
    pub fn new(db: Database, rbl: Arc<RblChecker>, forwarders: Vec<SocketAddr>) -> Self {
        let forward_sockets = (0..FORWARD_POOL_SIZE)
            .map(|_| Arc::new(tokio::sync::Mutex::new(None)))
            .collect();
        Self {
            db,
            rbl,
            forwarders: Arc::new(ArcSwap::from_pointee(forwarders)),
            dns_cache: None,
            dns64_prefix: None,
            qname_randomization: true,
            ttl_drift_config: Arc::new(ArcSwap::from_pointee(
                crate::ttl_drift::TtlDriftConfig::default(),
            )),
            proxy_config: Arc::new(ArcSwap::from_pointee(None)),
            forward_sockets,
            forward_socket_idx: AtomicUsize::new(0),
            resolution_mode: Arc::new(ArcSwap::from_pointee(ResolutionMode::Forward)),
            resolver: Arc::new(ArcSwap::from_pointee(
                crate::resolver::IterativeResolver::with_defaults(),
            )),
            secure_upstreams: Arc::new(ArcSwap::from_pointee(Vec::new())),
            public_fallback: Arc::new(ArcSwap::from_pointee(Vec::new())),
            active_tier: AtomicUsize::new(TIER_ROOTS),
            deviation_streak: AtomicUsize::new(0),
            last_probe: AtomicU64::new(0),
            switch_grace_failures: AtomicU32::new(3),
            recovery_probe_secs: AtomicU64::new(60),
            answer_v4: AtomicBool::new(true),
            answer_v6: AtomicBool::new(true),
            overlay_cidrs: Arc::new(ArcSwap::from_pointee(default_overlay_cidrs())),
            recursion_cidrs: Arc::new(ArcSwap::from_pointee(default_recursion_cidrs())),
            ingress_listeners: Arc::new(DashMap::new()),
            ingress_port: AtomicU16::new(53),
            udp_shards: AtomicUsize::new(0),
        }
    }

    /// Creates a DnsServer with all optional features configurable.
    pub fn new_with_options(
        db: Database,
        rbl: Arc<RblChecker>,
        forwarders: Vec<SocketAddr>,
        dns_cache: Option<Arc<DnsCache>>,
        dns64_prefix: Option<Ipv6Addr>,
        qname_randomization: bool,
    ) -> Self {
        let forward_sockets = (0..FORWARD_POOL_SIZE)
            .map(|_| Arc::new(tokio::sync::Mutex::new(None)))
            .collect();
        Self {
            db,
            rbl,
            forwarders: Arc::new(ArcSwap::from_pointee(forwarders)),
            dns_cache,
            dns64_prefix,
            qname_randomization,
            ttl_drift_config: Arc::new(ArcSwap::from_pointee(
                crate::ttl_drift::TtlDriftConfig::default(),
            )),
            proxy_config: Arc::new(ArcSwap::from_pointee(None)),
            forward_sockets,
            forward_socket_idx: AtomicUsize::new(0),
            resolution_mode: Arc::new(ArcSwap::from_pointee(ResolutionMode::Forward)),
            resolver: Arc::new(ArcSwap::from_pointee(
                crate::resolver::IterativeResolver::with_defaults(),
            )),
            secure_upstreams: Arc::new(ArcSwap::from_pointee(Vec::new())),
            public_fallback: Arc::new(ArcSwap::from_pointee(Vec::new())),
            active_tier: AtomicUsize::new(TIER_ROOTS),
            deviation_streak: AtomicUsize::new(0),
            last_probe: AtomicU64::new(0),
            switch_grace_failures: AtomicU32::new(3),
            recovery_probe_secs: AtomicU64::new(60),
            answer_v4: AtomicBool::new(true),
            answer_v6: AtomicBool::new(true),
            overlay_cidrs: Arc::new(ArcSwap::from_pointee(default_overlay_cidrs())),
            recursion_cidrs: Arc::new(ArcSwap::from_pointee(default_recursion_cidrs())),
            ingress_listeners: Arc::new(DashMap::new()),
            ingress_port: AtomicU16::new(53),
            udp_shards: AtomicUsize::new(0),
        }
    }

    /// Sets the source ranges treated as untrusted network-overlay peers
    /// (WireGuard links). Only queries from these ranges are scope-enforced;
    /// every other source is a trusted local client. Replaces the default
    /// `10.64.0.0/10`.
    pub fn set_overlay_cidrs(&self, cidrs: Vec<crate::cidr::IpCidr>) {
        self.overlay_cidrs.store(Arc::new(cidrs));
    }

    /// Whether `ip` is a network-overlay (WireGuard) peer subject to scope
    /// enforcement, per the configured `overlay_cidrs`.
    fn is_overlay_peer(&self, ip: IpAddr) -> bool {
        self.overlay_cidrs.load().iter().any(|c| c.contains(ip))
    }

    /// Sets the source ranges permitted to drive upstream resolution. Replaces
    /// the defaults from [`default_recursion_cidrs`]. An empty list closes
    /// recursion to everyone, turning the server purely authoritative.
    pub fn set_recursion_cidrs(&self, cidrs: Vec<crate::cidr::IpCidr>) {
        self.recursion_cidrs.store(Arc::new(cidrs));
    }

    /// Whether `ip` may make this server resolve a name it does not hold locally.
    ///
    /// This is the open-resolver guard. `dns.bind` defaults to `0.0.0.0:53`, so
    /// on a routable interface every host on the internet can reach the listener;
    /// without this check each of them gets full recursive service, which is a
    /// reflection/amplification asset — a small spoofed query returns a large
    /// answer aimed at the spoofed victim, and the outbound traffic is billed to
    /// this box.
    ///
    /// Deliberately narrower than "is this source trusted": a stranger is still
    /// served data this server is authoritative for (that is a separate
    /// decision, and closing recursion must not turn the box into a
    /// non-answering black hole for its own zones). What they cannot do is make
    /// it go and ask someone else.
    fn may_recurse(&self, ip: IpAddr) -> bool {
        self.recursion_cidrs.load().iter().any(|c| c.contains(ip))
    }

    /// Sets the UDP/TCP port used by per-TLD ingress listeners (default 53).
    /// The bind IP is provided per-TLD; this is the shared port.
    pub fn set_ingress_port(&self, port: u16) {
        self.ingress_port.store(port, Ordering::Relaxed);
    }

    /// Sets how many `SO_REUSEPORT` sockets each UDP listener binds. `0` (the
    /// default) means one per available core. See `serve_udp`.
    pub fn set_udp_shards(&self, shards: usize) {
        self.udp_shards.store(shards, Ordering::Relaxed);
    }

    /// Resolves the configured shard count to a concrete number of sockets.
    fn udp_shard_count(&self) -> usize {
        match self.udp_shards.load(Ordering::Relaxed) {
            0 => std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            n => n,
        }
    }

    /// Number of live ingress listener IPs (for diagnostics/tests). An entry
    /// whose tasks have all exited is dead and is not counted — see
    /// `spawn_ingress_listener`.
    pub fn ingress_listener_count(&self) -> usize {
        self.ingress_listeners
            .iter()
            .filter(|e| e.value().iter().any(|h| !h.is_finished()))
            .count()
    }

    /// Whether a LIVE ingress listener is currently bound on `ip`. A registry
    /// entry whose UDP+TCP tasks have both exited (a failed bind) is not a
    /// listener and reports false, so this never claims an address is served
    /// when nothing is bound to it.
    pub fn has_ingress_listener(&self, ip: IpAddr) -> bool {
        self.ingress_listeners
            .get(&ip)
            .is_some_and(|e| e.value().iter().any(|h| !h.is_finished()))
    }

    /// Starts an ingress DNS listener (UDP + TCP) bound to `ip` on the configured
    /// ingress port. Idempotent: a no-op while one is LIVE on `ip` (so multiple
    /// TLDs can share one ingress IP). The tasks run until aborted by
    /// `stop_ingress_listener`.
    ///
    /// A dead entry is replaced rather than honoured. The registry records the
    /// abort handles unconditionally at spawn time, before either task has tried
    /// to bind — so a listener that failed to bind leaves an entry behind that
    /// says "active" while nothing is listening. That happens on every boot for a
    /// WireGuard overlay address: `sync_ingress_listeners` replays the TLD's
    /// ingress IP from the database before the overlay interface exists, both
    /// tasks fail `EADDRNOTAVAIL` and exit, and the corpse stays in the map. A
    /// presence-only check then makes every subsequent `AddScopeTld` re-add
    /// early-return — it logs success and binds nothing, permanently, for the
    /// life of the process. Treating an all-finished entry as absent is what lets
    /// the controller re-assert the listener once the interface is up.
    pub fn spawn_ingress_listener(self: &Arc<Self>, ip: IpAddr) {
        if let Some(entry) = self.ingress_listeners.get(&ip) {
            let alive = entry.value().iter().any(|h| !h.is_finished());
            // Drop the read guard before mutating the same shard.
            drop(entry);
            if alive {
                return;
            }
            self.ingress_listeners.remove(&ip);
        }
        let port = self.ingress_port.load(Ordering::Relaxed);
        let bind = SocketAddr::new(ip, port).to_string();

        let udp_srv = Arc::clone(self);
        let udp_bind = bind.clone();
        let udp = tokio::spawn(async move {
            if let Err(e) = udp_srv.serve_udp(&udp_bind).await {
                error!("Ingress UDP listener {} exited: {}", udp_bind, e);
            }
        });

        let tcp_srv = Arc::clone(self);
        let tcp_bind = bind.clone();
        let tcp = tokio::spawn(async move {
            if let Err(e) = tcp_srv.serve_tcp(&tcp_bind).await {
                error!("Ingress TCP listener {} exited: {}", tcp_bind, e);
            }
        });

        self.ingress_listeners
            .insert(ip, vec![udp.abort_handle(), tcp.abort_handle()]);
        info!("Started ingress DNS listener on {}", bind);
    }

    /// Stops the ingress DNS listener bound to `ip`, aborting its UDP+TCP tasks.
    /// A no-op if none is active on `ip`.
    pub fn stop_ingress_listener(&self, ip: IpAddr) {
        if let Some((_, handles)) = self.ingress_listeners.remove(&ip) {
            for h in handles {
                h.abort();
            }
            info!("Stopped ingress DNS listener on {}", ip);
        }
    }

    /// (Re)creates ingress listeners for every TLD that has an ingress IP in the
    /// database. Called at boot after the DnsServer Arc is built.
    pub fn sync_ingress_listeners(self: &Arc<Self>) {
        for ip in self.db.list_all_tld_ingress_ips() {
            self.spawn_ingress_listener(ip);
        }
    }

    /// Identifies the ingress listener a query arrived on, or `None` if it did
    /// not arrive on one. Returns `Some((owner_scope, ingress_ip))` only when
    /// (a) the query arrived on a concrete local listener IP, and (b) the queried
    /// name falls under a TLD whose configured ingress IP equals that listener
    /// IP. This is what confines ingress behavior to the ingress listener (a
    /// query for the same name on the main `:53` listener has `local_ip == None`
    /// and is unaffected).
    ///
    /// The owning scope drives resolution (the ingress listener serves that
    /// scope's partitioned records regardless of source IP), and the ingress IP
    /// is the rewrite target for programmed A/AAAA answers.
    fn ingress_target(&self, local_ip: Option<IpAddr>, qname: &str) -> Option<(String, IpAddr)> {
        let local_ip = local_ip?;
        let (owner, tld) = self.db.find_tld_owner(qname)?;
        let ingress = self.db.get_tld_ingress(&tld)?;
        (ingress == local_ip).then_some((owner, ingress))
    }

    /// Sets the upstream resolution mode (recursive-from-roots or forward).
    pub fn set_resolution_mode(&self, mode: ResolutionMode) {
        self.resolution_mode.store(Arc::new(mode));
    }

    /// Returns the current upstream resolution mode.
    pub fn get_resolution_mode(&self) -> ResolutionMode {
        **self.resolution_mode.load()
    }

    /// Returns the auto-mode currently committed tier index (0=roots, 1=secure,
    /// 2=local forwarder, 3=public). Useful for diagnostics and tests.
    pub fn active_tier(&self) -> usize {
        self.active_tier.load(Ordering::Relaxed)
    }

    /// Replaces the root hints used by the iterative resolver.
    ///
    /// Rebuilds the resolver *from the current one* so the delegation cache and
    /// the nameserver latency stats carry over. Constructing a fresh
    /// `IterativeResolver` here would silently discard everything learned so far
    /// and put every query back to walking from the roots.
    pub fn set_root_hints(&self, hints: Vec<IpAddr>) {
        let resolver = self.resolver.load_full();
        self.resolver
            .store(Arc::new(resolver.with_root_hints(hints)));
    }

    /// The current iterative resolver (delegation cache, root hints, latency stats).
    pub fn resolver(&self) -> Arc<crate::resolver::IterativeResolver> {
        self.resolver.load_full()
    }

    /// Installs a resolver backed by a persistent delegation cache.
    pub fn set_delegation_cache(
        &self,
        delegations: Arc<crate::delegation_cache::DelegationCache>,
        default_ttl: u32,
    ) {
        let current = self.resolver.load_full();
        self.resolver.store(Arc::new(
            crate::resolver::IterativeResolver::with_delegations(
                current.root_hints().to_vec(),
                delegations,
            )
            .with_default_ttl(default_ttl),
        ));
    }

    /// Sets the auto-mode encrypted (DoH/DoT) upstreams (the secure tier).
    pub fn set_secure_upstreams(&self, upstreams: Vec<crate::secure_client::SecureUpstream>) {
        self.secure_upstreams.store(Arc::new(upstreams));
    }

    /// Sets the auto-mode plaintext public resolvers (the last-resort tier).
    pub fn set_public_fallback(&self, targets: Vec<SocketAddr>) {
        self.public_fallback.store(Arc::new(targets));
    }

    /// Sets the auto-mode tuning: failure grace before a downward switch, and how
    /// often to probe the full chain from the top to reclaim a recovered tier.
    pub fn set_auto_params(&self, switch_grace_failures: u32, recovery_probe_secs: u64) {
        self.switch_grace_failures
            .store(switch_grace_failures, Ordering::Relaxed);
        self.recovery_probe_secs
            .store(recovery_probe_secs, Ordering::Relaxed);
    }

    /// Sets which address families are returned in answers. The routability
    /// probe (`probe.rs`) calls this to suppress a family the host can't reach,
    /// so clients fall back to the family that works instead of stalling on a
    /// dead one. `false` for a family turns A/AAAA answers of that type into
    /// NODATA (see `build_response_edns`).
    pub fn set_answer_families(&self, v4: bool, v6: bool) {
        self.answer_v4.store(v4, Ordering::Relaxed);
        self.answer_v6.store(v6, Ordering::Relaxed);
    }

    /// Returns the currently answered address families as `(v4, v6)`.
    pub fn answer_families(&self) -> (bool, bool) {
        (
            self.answer_v4.load(Ordering::Relaxed),
            self.answer_v6.load(Ordering::Relaxed),
        )
    }

    /// Drops A/AAAA answer records of any address family currently suppressed by
    /// the routability probe, so a client isn't handed an address in a family
    /// the host can't route (which stalls the connection). Applied at the single
    /// response exit (`handle_query`/`handle_query_from`), so it covers every
    /// answer source — local, cache, recursive, and raw upstream forwarders.
    ///
    /// Only the ANSWER section is filtered: that is what stub clients resolve
    /// addresses from. Emptying the answer for an A/AAAA query leaves NoError
    /// with no records — NODATA — the correct "no address in this family" signal
    /// that makes getaddrinfo fall back to the other family. When both families
    /// are enabled (the common case) this is a no-op that returns the bytes
    /// untouched.
    fn apply_family_filter(&self, response: Vec<u8>) -> Vec<u8> {
        let (v4, v6) = self.answer_families();
        if v4 && v6 {
            return response;
        }
        let mut msg = match hickory_proto::op::Message::from_bytes(&response) {
            Ok(m) => m,
            Err(_) => return response,
        };
        let answers = msg.take_answers();
        let before = answers.len();
        let mut dropped_v4 = 0u64;
        let mut dropped_v6 = 0u64;
        let kept: Vec<Record> = answers
            .into_iter()
            .filter(|r| match r.record_type() {
                RecordType::A => {
                    if !v4 {
                        dropped_v4 += 1;
                    }
                    v4
                }
                RecordType::AAAA => {
                    if !v6 {
                        dropped_v6 += 1;
                    }
                    v6
                }
                _ => true,
            })
            .collect();
        if dropped_v4 > 0 {
            metrics().answers_family_filtered.add(FAMILY_V4, dropped_v4);
        }
        if dropped_v6 > 0 {
            metrics().answers_family_filtered.add(FAMILY_V6, dropped_v6);
        }
        if kept.len() == before {
            // Nothing suppressed for this query; return the original bytes as-is
            // (msg is discarded — no need to re-serialize).
            return response;
        }
        for r in kept {
            msg.add_answer(r);
        }
        msg.to_bytes().unwrap_or(response)
    }

    /// Sets the TTL drift configuration.
    pub async fn set_ttl_drift_config(&self, config: crate::ttl_drift::TtlDriftConfig) {
        self.ttl_drift_config.store(Arc::new(config));
    }

    /// Gets the current TTL drift configuration.
    pub async fn get_ttl_drift_config(&self) -> crate::ttl_drift::TtlDriftConfig {
        self.ttl_drift_config.load().as_ref().clone()
    }

    /// Returns a reference to the database.
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Flushes the in-memory DNS cache (and its persistent backing store).
    ///
    /// **This does NOT touch the delegation cache, and must not.** Every gRPC
    /// zone/record/scope mutation calls this — adding one package would otherwise
    /// discard every delegation we have learned, sending the next lookup of every
    /// name back to the root servers. That is exactly the failure that motivated
    /// the delegation cache in the first place. Cross-tier invalidation lives in
    /// [`Self::flush_upstream_state`] instead.
    pub fn flush_cache(&self) {
        self.flush_cache_for(FLUSH_MUTATION);
    }

    /// Clears the response cache on an operator's explicit `FlushDnsCache`
    /// request. Identical to [`Self::flush_cache`] except for the metric label —
    /// an operator-driven flush and the automatic one that follows every record
    /// mutation are worth telling apart when working out why a cache is cold.
    pub fn flush_cache_explicit(&self) {
        self.flush_cache_for(FLUSH_EXPLICIT);
    }

    /// Clears the response cache, attributing it to `reason` (an index into
    /// [`crate::metrics::FLUSH_REASONS`]).
    fn flush_cache_for(&self, reason: usize) {
        metrics().cache_flushes.inc(reason);
        if let Some(ref cache) = self.dns_cache {
            cache.flush();
        }
    }

    /// Discards everything learned from the current upstream tier: cached
    /// answers, cached negatives, and cached delegations.
    ///
    /// Called only when the `auto` chain switches tiers. Delegations and answers
    /// obtained while talking to one upstream must not steer queries once we are
    /// talking to a different one — and on a degrade (say, to a network that
    /// filters :53) the cached nameserver addresses are unreachable anyway.
    pub fn flush_upstream_state(&self) {
        self.flush_cache_for(FLUSH_TIER_SWITCH);
        let resolver = self.resolver.load();
        resolver.delegations().flush();
        resolver.records().flush();
    }

    /// Updates the upstream forwarder list.
    pub async fn set_forwarders(&self, forwarders: Vec<SocketAddr>) {
        self.forwarders.store(Arc::new(forwarders));
    }

    /// Returns the current forwarder list.
    pub async fn get_forwarders(&self) -> Vec<SocketAddr> {
        self.forwarders.load().as_ref().clone()
    }

    /// Sets the proxy configuration for upstream forwarding.
    pub fn set_proxy_config(&self, config: Option<crate::doh_proxy::ProxyConfig>) {
        self.proxy_config.store(Arc::new(config));
    }

    /// Returns the current proxy configuration.
    pub fn get_proxy_config(&self) -> Option<crate::doh_proxy::ProxyConfig> {
        self.proxy_config.load().as_ref().clone()
    }

    /// Starts the UDP DNS listener.
    ///
    /// The listener is *sharded*: `udp_shard_count()` sockets are bound to the
    /// same `addr:port` with `SO_REUSEPORT`, each driving its own receive loop
    /// and sending its replies back out through its own socket. A single socket
    /// serialises the listener — one task drains it and every reply contends on
    /// it — which caps throughput far below CPU saturation. Sharding lets the
    /// kernel hash arriving datagrams across the shards so both directions scale
    /// across cores.
    ///
    /// `SO_REUSEPORT` is set only when more than one shard is requested. A
    /// single-shard listener therefore binds exactly as before and still fails
    /// on an occupied port rather than silently sharing it — which is what the
    /// ingress-listener bind-failure handling depends on.
    ///
    /// Shards run in a `JoinSet` owned by this future, so aborting the task that
    /// drives `serve_udp` (as `stop_ingress_listener` does) drops the set and
    /// aborts every shard with it.
    pub async fn serve_udp(self: Arc<Self>, bind_addr: &str) -> Result<()> {
        // Port 0 asks the kernel for an ephemeral port, which it would hand out
        // independently per socket — the shards would land on different ports
        // instead of sharing one. There is nothing to shard, so bind a single
        // socket and let the caller keep the port it was given.
        let ephemeral = {
            use std::net::ToSocketAddrs;
            bind_addr
                .to_socket_addrs()
                .ok()
                .and_then(|mut a| a.next())
                .is_some_and(|a| a.port() == 0)
        };
        let shards = if ephemeral {
            1
        } else {
            self.udp_shard_count().max(1)
        };
        let local_ip = concrete_bind_ip(bind_addr);

        // Bind every shard up front. The first failure is fatal — that is a real
        // bind error (port taken, address not yet available) and callers rely on
        // it being reported. A later shard failing is not: the address is
        // demonstrably bindable, so serve what we got and log the shortfall.
        let mut sockets = Vec::with_capacity(shards);
        for i in 0..shards {
            match bind_udp_shard(bind_addr, shards > 1) {
                Ok(sock) => sockets.push(sock),
                Err(e) if i > 0 => {
                    warn!(
                        "UDP {}: bound {}/{} shards ({}); continuing with fewer",
                        bind_addr, i, shards, e
                    );
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        info!(
            "DNS UDP server listening on {} ({} shard{})",
            bind_addr,
            sockets.len(),
            if sockets.len() == 1 { "" } else { "s" }
        );

        let mut set = tokio::task::JoinSet::new();
        for sock in sockets {
            let server = Arc::clone(&self);
            set.spawn(async move { server.udp_shard_loop(sock, local_ip).await });
        }

        // Every shard loop runs forever; this only resolves if they all stop.
        while set.join_next().await.is_some() {}
        Ok(())
    }

    /// One shard's receive loop: drain `socket`, spawn a task per query, and
    /// reply on the same shard socket.
    async fn udp_shard_loop(self: Arc<Self>, socket: UdpSocket, local_ip: Option<IpAddr>) {
        let socket = Arc::new(socket);
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    error!("UDP recv error: {}", e);
                    continue;
                }
            };

            let mut data = Vec::with_capacity(len);
            data.extend_from_slice(&buf[..len]);
            let server = Arc::clone(&self);
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                match server
                    .handle_query_proto(&data, Some(src.ip()), local_ip, Proto::Udp)
                    .await
                {
                    Ok(resp) => {
                        if let Err(e) = socket.send_to(&resp, src).await {
                            error!("UDP send error to {}: {}", src, e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to handle DNS query from {}: {}", src, e);
                    }
                }
            });
        }
    }

    /// Starts the TCP DNS listener.
    pub async fn serve_tcp(self: Arc<Self>, bind_addr: &str) -> Result<()> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind TCP listener to {}", bind_addr))?;
        info!("DNS TCP server listening on {}", bind_addr);
        let local_ip = concrete_bind_ip(bind_addr);
        // Bounds concurrent connections. A permit is acquired per accepted
        // connection and released when its task ends, so the listener keeps
        // accepting (and immediately dropping) once saturated rather than
        // queueing — a backlog would only move the exhaustion.
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_TCP_CONNECTIONS));

        loop {
            let (stream, src) = match listener.accept().await {
                Ok(r) => r,
                Err(e) => {
                    error!("TCP accept error: {}", e);
                    continue;
                }
            };

            let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                debug!(
                    "dropping TCP connection from {}: {} concurrent connections in use",
                    src, MAX_TCP_CONNECTIONS
                );
                drop(stream);
                continue;
            };

            let server = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = server.handle_tcp_connection(stream, src, local_ip).await {
                    debug!("TCP connection error from {}: {}", src, e);
                }
                drop(permit);
            });
        }
    }

    async fn handle_tcp_connection(
        &self,
        stream: tokio::net::TcpStream,
        src: SocketAddr,
        local_ip: Option<IpAddr>,
    ) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut reader, mut writer) = stream.into_split();

        loop {
            // Read 2-byte length prefix. Timed from the last thing that happened
            // on the connection, so a client reusing it across queries (RFC 7766)
            // is not disconnected mid-conversation, but one that stops talking is
            // reclaimed.
            let mut len_buf = [0u8; 2];
            let read =
                tokio::time::timeout(TCP_IDLE_TIMEOUT, reader.read_exact(&mut len_buf)).await;
            match read {
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {
                    debug!("closing idle TCP connection from {}", src);
                    return Ok(());
                }
            }
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            if msg_len > MAX_TCP_SIZE {
                warn!("TCP message too large from {}: {} bytes", src, msg_len);
                return Ok(());
            }

            let mut msg_buf = vec![0u8; msg_len];
            tokio::time::timeout(TCP_MESSAGE_TIMEOUT, reader.read_exact(&mut msg_buf))
                .await
                .map_err(|_| {
                    anyhow::anyhow!("{} announced {} bytes and did not send them", src, msg_len)
                })??;

            let response = self
                .handle_query_proto(&msg_buf, Some(src.ip()), local_ip, Proto::Tcp)
                .await?;
            let resp_len = (response.len() as u16).to_be_bytes();
            writer.write_all(&resp_len).await?;
            writer.write_all(&response).await?;
        }
    }

    /// Handles a raw DNS query and returns the raw response bytes.
    /// This is a convenience method that does not enforce network scoping.
    /// Used for tests where source IP context is not available.
    pub async fn handle_query(&self, query_data: &[u8]) -> Result<Vec<u8>> {
        self.handle_query_proto(query_data, None, None, Proto::Udp)
            .await
    }

    /// Handles a raw DNS query with source IP context for network scoping.
    ///
    /// When network scopes exist, the source IP must be associated with a
    /// network scope to receive DNS responses. Unassociated IPs receive
    /// REFUSED responses. When no network scopes are defined, the server
    /// operates in legacy mode without scope enforcement.
    pub async fn handle_query_from(&self, query_data: &[u8], source_ip: IpAddr) -> Result<Vec<u8>> {
        self.handle_query_on(query_data, source_ip, None).await
    }

    /// Handles a query, additionally aware of the concrete local listener IP the
    /// query arrived on (`None` for wildcard binds like `0.0.0.0:53`). The local
    /// IP gates the per-TLD ingress rewrite: programmed A/AAAA names under a TLD
    /// whose ingress IP equals `local_ip` are answered with that IP.
    pub async fn handle_query_on(
        &self,
        query_data: &[u8],
        source_ip: IpAddr,
        local_ip: Option<IpAddr>,
    ) -> Result<Vec<u8>> {
        self.handle_query_proto(query_data, Some(source_ip), local_ip, Proto::Udp)
            .await
    }

    /// The single instrumented entry point every transport funnels through.
    ///
    /// `proto` only labels metrics — it does not change resolution. The
    /// `handle_query`/`handle_query_from`/`handle_query_on` wrappers above keep
    /// their existing signatures (they are what the tests and the DoH handler
    /// call) and report `udp`; the UDP, TCP, DoT, DoH and DoQ listeners call
    /// this directly with their own transport so the `proto` label is accurate
    /// for real traffic.
    ///
    /// Putting the observation here rather than inside `resolve_query` is
    /// deliberate: `resolve_query` has some thirty exits, and instrumenting each
    /// would mean a new early return could silently escape the metrics. Here
    /// there is exactly one exit, and it is after `apply_family_filter`, so the
    /// recorded response size and rcode are what the client actually receives.
    pub async fn handle_query_proto(
        &self,
        query_data: &[u8],
        source_ip: Option<IpAddr>,
        local_ip: Option<IpAddr>,
        proto: Proto,
    ) -> Result<Vec<u8>> {
        let started = std::time::Instant::now();
        let tag = QueryTag::new();
        // Canonicalize once, here, before anything classifies the address. On a
        // dual-stack listener (`[::]:53` — a supported bind form, and the default
        // on Linux with `net.ipv6.bindv6only=0`) an IPv4 peer arrives as
        // `::ffff:10.64.0.1`. That is an `IpAddr::V6`, and `IpCidr::contains`
        // deliberately does not match across address families, so without this the
        // overlay peer is classified as a *trusted local source*: an unjoined peer
        // escapes REFUSED into the global namespace, and a joined one loses its
        // scope because `JoinNetwork` stored the plain IPv4 form.
        //
        // This lives here rather than in `handle_query_on` because the UDP, TCP,
        // DoT and DoQ listeners call this method directly, with their own
        // transport label, and never pass through that wrapper — canonicalizing
        // one level up would leave every one of them unprotected.
        let response = self
            .resolve_query(
                query_data,
                source_ip.map(|ip| ip.to_canonical()),
                local_ip.map(|ip| ip.to_canonical()),
                &tag,
            )
            .await?;
        let response = self.apply_family_filter(response);

        metrics().observe_query(QueryObservation {
            proto,
            rcode_index: tag.rcode_index(&response),
            qtype_index: crate::metrics::qtype_index(
                wire_qtype(query_data).unwrap_or(RecordType::Unknown(0)),
            ),
            source: tag.source(),
            query_bytes: query_data.len(),
            response_bytes: response.len(),
            truncated: wire_truncated(&response),
            elapsed: started.elapsed(),
        });

        Ok(response)
    }

    /// Core DNS resolution logic with optional network scope context and the
    /// optional local listener IP (used for the per-TLD ingress rewrite).
    ///
    /// `tag` collects which stage answered, for metrics; see [`QueryTag`].
    async fn resolve_query(
        &self,
        query_data: &[u8],
        source_ip: Option<IpAddr>,
        local_ip: Option<IpAddr>,
        tag: &QueryTag,
    ) -> Result<Vec<u8>> {
        let message = match hickory_proto::op::Message::from_bytes(query_data) {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to parse DNS query: {}", e);
                tag.set(AnswerSource::Error);
                metrics().malformed_queries.inc();
                return Ok(make_error_response(query_data, ResponseCode::FormErr));
            }
        };

        // Extract EDNS context from the query
        let edns_ctx = crate::edns::EdnsContext::from_message(&message);
        if edns_ctx.as_ref().is_some_and(|c| c.dnssec_ok) {
            metrics().edns_do_queries.inc();
        }

        // If EDNS version > 0, return BADVERS (RFC 6891 section 6.1.3)
        if let Some(ref ctx) = edns_ctx
            && ctx.is_unsupported_version()
        {
            debug!("Rejecting EDNS version {} query", ctx.version);
            // BADVERS is an extended rcode: its low nibble is 0, so the wire
            // header alone would report this as NOERROR. Label it explicitly.
            tag.set_with_rcode(
                AnswerSource::Error,
                crate::metrics::rcode_index(ResponseCode::BADVERS),
            );
            metrics().edns_unsupported_version.inc();
            return Ok(build_response_edns(
                &message,
                ResponseCode::from(0, 16), // BADVERS
                vec![],
                false,
                edns_ctx.as_ref(),
            ));
        }

        if message.message_type() != MessageType::Query {
            tag.set(AnswerSource::Error);
            metrics().malformed_queries.inc();
            return Ok(make_error_response(query_data, ResponseCode::NotImp));
        }

        if message.op_code() != OpCode::Query {
            tag.set(AnswerSource::Error);
            metrics().malformed_queries.inc();
            return Ok(make_error_response(query_data, ResponseCode::NotImp));
        }

        let questions = message.queries();
        if questions.is_empty() {
            tag.set(AnswerSource::Error);
            metrics().malformed_queries.inc();
            return Ok(make_error_response(query_data, ResponseCode::FormErr));
        }

        let question = &questions[0];
        let qname = question.name().to_string();
        let qtype = question.query_type();

        // Per-TLD ingress listener: a PROGRAMMED A/AAAA name under the TLD, asked
        // on that TLD's own ingress IP, is rewritten to the ingress IP (the
        // network's ingress controller) instead of its stored backend value. This
        // is confined to the name/listener pair — it stays `None` for a name that
        // is not under the listener's TLD (which therefore passes through with
        // its resolved value) and on the main listeners, which carry no concrete
        // local IP.
        let ingress_override = self.ingress_target(local_ip, &qname).map(|(_, ip)| ip);
        if ingress_override.is_some() {
            metrics().ingress_rewrites.inc();
        }

        // Determine network scope for this query.
        //
        // A query that ARRIVED on a TLD's ingress listener is served within that
        // listener's owning scope for EVERY name, not merely names under the
        // owned TLD: the listener is bound to the network's overlay address and
        // is that network's dedicated resolver. Owned TLDs stay partitioned (a
        // sibling network's TLD is still hidden below) while everything else
        // falls through to global resolution and forwarding — which is what lets
        // an overlay peer resolve the public internet through it. Keying the
        // scope off the queried NAME instead would drop a non-TLD name (e.g.
        // `google.com`) into the source-IP branch below, where an overlay peer
        // that never called JoinNetwork is REFUSED — so the ingress listener
        // would answer only its own TLD and nothing else.
        //
        // Off the ingress listeners, only WireGuard-overlay peers (source IP in
        // `overlay_cidrs`) are scope-enforced: an overlay peer must be joined to
        // a scope or it is REFUSED, and it sees only that scope's partitioned
        // TLDs. Every other source — loopback (the box's own resolver), the LAN,
        // container bridges — is a trusted local client: it is never refused and
        // resolves the GLOBAL namespace (public names plus the box's global
        // records). This is split-horizon: global records carry the box's
        // LAN-reachable address, while scoped overlay records carry the overlay
        // address, so each side gets an address it can actually route to.
        let scope_name =
            if let Some(scope) = local_ip.and_then(|ip| self.db.scope_for_ingress_ip(ip)) {
                // Ingress listener: dedicated to the owning scope, for every name.
                Some(scope)
            } else if let Some(ip) = source_ip {
                let ip_str = ip.to_string();
                if let Some(scope) = self.db.get_scope_for_ip(&ip_str) {
                    // Already joined to a network (only overlay addresses are ever
                    // joined): resolve within its scope, partitioned.
                    Some(scope)
                } else if self.db.has_scopes() && self.is_overlay_peer(ip) {
                    // An overlay peer that has not joined any network. It is not a
                    // member of anything, so refuse it.
                    debug!("Refusing DNS query from unassociated overlay peer {}", ip);
                    tag.set(AnswerSource::Refused);
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::Refused,
                        vec![],
                        false,
                        edns_ctx.as_ref(),
                    ));
                } else {
                    // Trusted local source (loopback/LAN/bridge): resolve the GLOBAL
                    // namespace — split-horizon. Never refused.
                    None
                }
            } else {
                None
            };

        debug!("DNS query: {} {:?} (scope: {:?})", qname, qtype, scope_name);

        // If we have a network scope, check scoped RBL first
        if let Some(ref scope) = scope_name {
            if let Some(ip) = extract_ip_from_name(&qname) {
                // Split out of the original `a || b` so the metric can say which
                // list matched. The short-circuit is unchanged: the local lookup
                // still only runs when no provider listed the address.
                let by_provider = self.rbl.is_listed(&ip).await;
                let by_local = !by_provider && self.db.lookup_local_rbl(&ip.to_string());
                if by_provider || by_local {
                    debug!("RBL block in scope {}: {} is blacklisted", scope, qname);
                    metrics().blocklist_blocks.inc(if by_provider {
                        BLOCK_RBL_PROVIDER
                    } else {
                        BLOCK_RBL_LOCAL
                    });
                    tag.set(AnswerSource::Rbl);
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NXDomain,
                        vec![],
                        true,
                        edns_ctx.as_ref(),
                    ));
                }
            }

            // Try scoped records first
            let record_kind = map_query_type_to_kind(qtype);
            if let Some(kind) = record_kind {
                // Check cache before hitting the database
                let mut scoped_cache_name =
                    String::with_capacity(1 + scope.len() + 1 + qname.len());
                scoped_cache_name.push('@');
                scoped_cache_name.push_str(scope);
                scoped_cache_name.push('/');
                scoped_cache_name.push_str(&qname);
                if let Some(ref cache) = self.dns_cache {
                    let cached = cache.lookup(&scoped_cache_name, Some(kind));
                    if !cached.is_empty() {
                        debug!(
                            "Cache hit (scoped) for {} {:?} in scope {}: {} records",
                            qname,
                            qtype,
                            scope,
                            cached.len()
                        );
                        let dns_records = build_scoped_answers(&cached, ingress_override);
                        tag.set(AnswerSource::Cache);
                        return Ok(build_response_edns(
                            &message,
                            ResponseCode::NoError,
                            dns_records,
                            true,
                            edns_ctx.as_ref(),
                        ));
                    }
                }

                let records = self.db.lookup_scoped(scope, &qname, Some(kind));
                if !records.is_empty() {
                    debug!(
                        "Scoped hit for {} {:?} in scope {}: {} records",
                        qname,
                        qtype,
                        scope,
                        records.len()
                    );
                    if let Some(ref cache) = self.dns_cache {
                        // See the global path below: a live local record must
                        // evict any negative previously cached for this name.
                        cache.invalidate_negative(&scoped_cache_name);
                        cache.invalidate_negative(&qname);
                        cache.insert_local(&scoped_cache_name, Some(kind), records.clone());
                    }
                    let dns_records = build_scoped_answers(&records, ingress_override);
                    tag.set(AnswerSource::Scoped);
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NoError,
                        dns_records,
                        true,
                        edns_ctx.as_ref(),
                    ));
                }

                // ANAME resolution: if querying A/AAAA and there's an ANAME, resolve it
                if kind == RecordKind::A || kind == RecordKind::AAAA {
                    let aname_records =
                        self.db
                            .lookup_scoped(scope, &qname, Some(RecordKind::ANAME));
                    if !aname_records.is_empty() {
                        let target = &aname_records[0].value;
                        let target_records = self.db.lookup_scoped(scope, target, Some(kind));
                        if !target_records.is_empty() {
                            let dns_records: Vec<Record> =
                                build_scoped_answers(&target_records, ingress_override)
                                    .into_iter()
                                    .filter_map(|mut rec| {
                                        rec.set_name(Name::from_ascii(&qname).ok()?);
                                        Some(rec)
                                    })
                                    .collect();
                            tag.set(AnswerSource::Scoped);
                            return Ok(build_response_edns(
                                &message,
                                ResponseCode::NoError,
                                dns_records,
                                true,
                                edns_ctx.as_ref(),
                            ));
                        }
                    }
                }
            }

            // Check CNAME in scoped records
            if record_kind.is_some() {
                let cname_records = self
                    .db
                    .lookup_scoped(scope, &qname, Some(RecordKind::CNAME));
                if !cname_records.is_empty() {
                    let dns_records = cname_records
                        .iter()
                        .filter_map(db_record_to_dns_record)
                        .collect();
                    tag.set(AnswerSource::Scoped);
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NoError,
                        dns_records,
                        true,
                        edns_ctx.as_ref(),
                    ));
                }
            }

            // Check DNAME in scoped records (walk up labels)
            if let Some(dname_result) = self.check_dname_scoped(scope, &qname, qtype, &message) {
                tag.set(AnswerSource::Scoped);
                return Ok(dname_result);
            }

            // Per-network TLD partition. If the query falls under a TLD owned by
            // some network scope, the namespace is partitioned: it is answered
            // only within the owning network and never leaks to upstream DNS.
            if let Some((owner, owned_tld)) = self.db.find_tld_owner(&qname) {
                if owner == *scope {
                    // Owned by the querying network. Local scoped records were
                    // already checked above and missed. Try this TLD's peer
                    // forwarders (other rolodex boxes on this overlay), then fall
                    // back to an authoritative NXDOMAIN — never forward upstream.
                    let peers = self.db.get_tld_forwarders_cached(scope, &owned_tld);
                    if !peers.is_empty()
                        && let Some(resp) = self.forward_to_tld_peers(query_data, &peers).await
                    {
                        debug!(
                            "Scoped TLD peer answer for {} (scope {} tld {})",
                            qname, scope, owned_tld
                        );
                        tag.set(AnswerSource::TldPeer);
                        return Ok(resp);
                    }
                    debug!(
                        "Scoped authoritative NXDOMAIN for {} (scope {} owns tld {}, no local/peer answer)",
                        qname, scope, owned_tld
                    );
                    tag.set(AnswerSource::AuthoritativeNxdomain);
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NXDomain,
                        vec![],
                        true,
                        edns_ctx.as_ref(),
                    ));
                }
                // Owned by a DIFFERENT network — hide it from this network.
                debug!(
                    "Hiding {} from scope {} (owned by scope {} tld {})",
                    qname, scope, owner, owned_tld
                );
                tag.set(AnswerSource::AuthoritativeNxdomain);
                return Ok(build_response_edns(
                    &message,
                    ResponseCode::NXDomain,
                    vec![],
                    true,
                    edns_ctx.as_ref(),
                ));
            }

            // Check if name falls under a scoped managed zone
            if let Ok(zones) = self.db.get_scoped_managed_zones(scope) {
                let normalized_qname = crate::db::normalize_name(&qname);
                for zone in &zones {
                    if normalized_qname.ends_with(zone) || normalized_qname == *zone {
                        let zone_records = self.db.lookup_scoped(scope, zone, None);
                        if !zone_records.is_empty() {
                            debug!(
                                "Scoped authoritative NXDOMAIN for {} (scope {} zone {} exists)",
                                qname, scope, zone
                            );
                            tag.set(AnswerSource::AuthoritativeNxdomain);
                            return Ok(build_response_edns(
                                &message,
                                ResponseCode::NXDomain,
                                vec![],
                                true,
                                edns_ctx.as_ref(),
                            ));
                        }
                    }
                }
            }

            // Fall through to global records and forwarding
        }

        // Check RBL for reverse DNS queries (global, non-scoped)
        if scope_name.is_none()
            && let Some(ip) = extract_ip_from_name(&qname)
        {
            let by_provider = self.rbl.is_listed(&ip).await;
            let by_local = !by_provider && self.db.lookup_local_rbl(&ip.to_string());
            if by_provider || by_local {
                debug!("RBL block: {} is blacklisted", qname);
                metrics().blocklist_blocks.inc(if by_provider {
                    BLOCK_RBL_PROVIDER
                } else {
                    BLOCK_RBL_LOCAL
                });
                tag.set(AnswerSource::Rbl);
                return Ok(build_response_edns(
                    &message,
                    ResponseCode::NXDomain,
                    vec![],
                    false,
                    edns_ctx.as_ref(),
                ));
            }
        }

        // Determine if this query is for an authoritative zone
        let is_authoritative = self.db.is_authoritative_zone(&qname);

        // Try local database first (split-horizon: local records take priority)
        // Uses a single UNION ALL query to fetch exact, wildcard, CNAME, and ANAME
        // results in one lock acquisition instead of 4+ separate queries.
        let record_kind = map_query_type_to_kind(qtype);
        if let Some(kind) = record_kind {
            // Check cache before hitting the database. Only local (authoritative)
            // cache entries are served here; upstream-cached answers are served
            // later, after the domain RBL gate, so RBLs keep precedence over any
            // externally-resolved entry.
            if let Some(ref cache) = self.dns_cache {
                let cached = cache.lookup_local_only(&qname, Some(kind));
                if !cached.is_empty() {
                    debug!(
                        "Cache hit (local) for {} {:?}: {} records",
                        qname,
                        qtype,
                        cached.len()
                    );
                    let dns_records = cached.iter().filter_map(db_record_to_dns_record).collect();
                    tag.set(AnswerSource::Cache);
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NoError,
                        dns_records,
                        is_authoritative,
                        edns_ctx.as_ref(),
                    ));
                }
            }

            if let Ok(result) = self.db.lookup_with_fallbacks(&qname, kind) {
                // Priority: exact > wildcard > CNAME > ANAME
                let records = if !result.exact.is_empty() {
                    result.exact
                } else if !result.wildcard.is_empty() {
                    result.wildcard
                } else {
                    Vec::new()
                };

                if !records.is_empty() {
                    debug!(
                        "Local hit for {} {:?}: {} records",
                        qname,
                        qtype,
                        records.len()
                    );
                    if let Some(ref cache) = self.dns_cache {
                        // A local record exists for this name, so any negative we
                        // cached for it earlier is now a lie — drop it, or a
                        // freshly-added name would keep returning NXDOMAIN until
                        // the negative TTL ran out.
                        cache.invalidate_negative(&qname);
                        cache.insert_local(&qname, Some(kind), records.clone());
                    }
                    let dns_records = records.iter().filter_map(db_record_to_dns_record).collect();
                    tag.set(AnswerSource::Local);
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NoError,
                        dns_records,
                        is_authoritative,
                        edns_ctx.as_ref(),
                    ));
                }

                // ANAME resolution: if querying A/AAAA and there's an ANAME, resolve it
                if (kind == RecordKind::A || kind == RecordKind::AAAA) && !result.aname.is_empty() {
                    let target = &result.aname[0].value;
                    if let Ok(target_records) = self.db.lookup(target, Some(kind))
                        && !target_records.is_empty()
                    {
                        let dns_records: Vec<Record> = target_records
                            .iter()
                            .filter_map(|r| {
                                let mut rec = db_record_to_dns_record(r)?;
                                rec.set_name(Name::from_ascii(&qname).ok()?);
                                Some(rec)
                            })
                            .collect();
                        tag.set(AnswerSource::Local);
                        return Ok(build_response_edns(
                            &message,
                            ResponseCode::NoError,
                            dns_records,
                            is_authoritative,
                            edns_ctx.as_ref(),
                        ));
                    }
                }

                // CNAME chain
                if !result.cname.is_empty() {
                    let dns_records = result
                        .cname
                        .iter()
                        .filter_map(db_record_to_dns_record)
                        .collect();
                    tag.set(AnswerSource::Local);
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NoError,
                        dns_records,
                        is_authoritative,
                        edns_ctx.as_ref(),
                    ));
                }
            }
        }

        // LAN/loopback source (scope_name == None): the global lookup above found
        // nothing. If the name falls under a TLD owned by a network scope, resolve
        // it from that owning scope so every network TLD is visible on the LAN.
        // Dual-homed names already returned their LAN-facing global record above,
        // so this serves scoped-only names (e.g. a network's zone apex) at their
        // stored value. Then try the TLD's peer forwarders; failing everything,
        // return an authoritative NXDOMAIN — a privately-owned TLD is never
        // forwarded upstream from the LAN.
        if scope_name.is_none()
            && let Some((owner, owned_tld)) = self.db.find_tld_owner(&qname)
        {
            if let Some(kind) = record_kind {
                let records = self.db.lookup_scoped(&owner, &qname, Some(kind));
                if !records.is_empty() {
                    debug!(
                        "LAN fallback hit for {} {:?} in owning scope {}: {} records",
                        qname,
                        qtype,
                        owner,
                        records.len()
                    );
                    let dns_records = build_scoped_answers(&records, ingress_override);
                    tag.set(AnswerSource::ScopeFallback);
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NoError,
                        dns_records,
                        true,
                        edns_ctx.as_ref(),
                    ));
                }
                // CNAME in the owning scope
                let cname_records = self
                    .db
                    .lookup_scoped(&owner, &qname, Some(RecordKind::CNAME));
                if !cname_records.is_empty() {
                    let dns_records = cname_records
                        .iter()
                        .filter_map(db_record_to_dns_record)
                        .collect();
                    tag.set(AnswerSource::ScopeFallback);
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NoError,
                        dns_records,
                        true,
                        edns_ctx.as_ref(),
                    ));
                }
            }
            // No local record in the owning scope: try that TLD's peer forwarders
            // (other rolodex boxes on the overlay), then authoritative NXDOMAIN.
            let peers = self.db.get_tld_forwarders_cached(&owner, &owned_tld);
            if !peers.is_empty()
                && let Some(resp) = self.forward_to_tld_peers(query_data, &peers).await
            {
                debug!(
                    "LAN fallback peer answer for {} (owning scope {} tld {})",
                    qname, owner, owned_tld
                );
                tag.set(AnswerSource::TldPeer);
                return Ok(resp);
            }
            debug!(
                "LAN fallback authoritative NXDOMAIN for {} (owning scope {} owns tld {})",
                qname, owner, owned_tld
            );
            tag.set(AnswerSource::AuthoritativeNxdomain);
            return Ok(build_response_edns(
                &message,
                ResponseCode::NXDomain,
                vec![],
                true,
                edns_ctx.as_ref(),
            ));
        }

        // Check DNAME (walk up labels checking for DNAME records, synthesize CNAME)
        if let Some(dname_result) = self.check_dname_global(&qname, qtype, &message) {
            tag.set(AnswerSource::Local);
            return Ok(dname_result);
        }

        // Check if this name falls under a managed zone (O(labels) via DashSet lookup)
        if let Some(zone) = self.db.find_managed_zone(&qname) {
            let zone_records = self.db.lookup(&zone, None);
            if let Ok(records) = zone_records
                && !records.is_empty()
            {
                debug!(
                    "Authoritative NXDOMAIN for {} (zone {} exists)",
                    qname, zone
                );
                tag.set(AnswerSource::AuthoritativeNxdomain);
                return Ok(build_response_edns(
                    &message,
                    ResponseCode::NXDomain,
                    vec![],
                    true,
                    edns_ctx.as_ref(),
                ));
            }
        }

        // Check explicit authoritative zones (O(labels) via DashSet lookup)
        if let Some(zone) = self.db.find_authoritative_zone(&qname) {
            debug!(
                "Authoritative NXDOMAIN for {} (authoritative zone {})",
                qname, zone
            );
            tag.set(AnswerSource::AuthoritativeNxdomain);
            return Ok(build_response_edns(
                &message,
                ResponseCode::NXDomain,
                vec![],
                true,
                edns_ctx.as_ref(),
            ));
        }

        // Open-resolver guard. Everything above answers from data this server
        // holds; everything below reaches for data it does not — the upstream
        // cache, a blocklist provider, a forwarder, the roots. That boundary is
        // exactly where "may this source make us recurse?" belongs, so a
        // stranger still gets our authoritative data (checked above) but cannot
        // make us resolve the internet on their behalf.
        //
        // REFUSED with an empty answer section is also the smallest reply
        // available: the response is no larger than the question that provoked
        // it, so a spoofed query gains an attacker nothing. Placing this before
        // the cache lookup matters for the same reason — a cached answer served
        // to a stranger amplifies just as well as a freshly-resolved one, and
        // warming the cache is how the attack is actually staged.
        //
        // `source_ip` is `None` only for callers that supply no peer (see
        // `handle_query`); those are in-process and are not gated here.
        if let Some(ip) = source_ip
            && !self.may_recurse(ip)
        {
            debug!(
                "Refusing recursion for {} from non-recursion source {}",
                qname, ip
            );
            return Ok(build_response_edns(
                &message,
                ResponseCode::Refused,
                vec![],
                false,
                edns_ctx.as_ref(),
            ));
        }

        // RBL precedence over external DNS: at this point the name was not
        // satisfied by any local/scoped record or managed zone, so it would be
        // answered from the upstream cache or by forwarding/iterating. If the
        // name itself is blacklisted by a domain-based RBL provider or a local
        // RBL entry, refuse to resolve it externally and return NXDOMAIN. This
        // is checked before the cache lookup so that a previously-cached
        // upstream answer is suppressed too. Reverse-DNS names are skipped here
        // because they are handled by the IP-based RBL checks above.
        //
        // The allowlist short-circuits the whole check: it is the operator's
        // escape hatch from a blocklist false positive, so it must beat both the
        // external providers and any local RBL entry, and it must run *before*
        // `is_name_listed` so an exempted name never even issues a provider
        // lookup.
        if extract_ip_from_name(&qname).is_none() {
            if self.db.is_dnsbl_allowlisted(&qname) {
                metrics().blocklist_allowlisted.inc();
            } else {
                let by_local = self.local_rbl_lists_name(&qname);
                let by_provider = !by_local && self.rbl.is_name_listed(&qname).await;
                if by_local || by_provider {
                    debug!("RBL block (domain): {} is blacklisted", qname);
                    metrics().blocklist_blocks.inc(if by_local {
                        BLOCK_RBL_LOCAL
                    } else {
                        BLOCK_DNSBL_PROVIDER
                    });
                    tag.set(AnswerSource::Blocklist);
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NXDomain,
                        vec![],
                        false,
                        edns_ctx.as_ref(),
                    ));
                }
            }
        }

        // Check DNS cache before forwarding upstream
        if let Some(ref cache) = self.dns_cache {
            let cached = cache.lookup(&qname, record_kind);
            if !cached.is_empty() {
                debug!(
                    "Cache hit for {} {:?}: {} records",
                    qname,
                    qtype,
                    cached.len()
                );
                let dns_records = cached.iter().filter_map(db_record_to_dns_record).collect();
                tag.set(AnswerSource::Cache);
                return Ok(build_response_edns(
                    &message,
                    ResponseCode::NoError,
                    dns_records,
                    false,
                    edns_ctx.as_ref(),
                ));
            }

            // A cached authoritative negative. Without this, every lookup of a
            // name that does not exist re-walks the delegation chain from the
            // root servers, every single time.
            if let Some(kind) = cache.lookup_negative(&qname, record_kind) {
                debug!("Negative cache hit for {} {:?}: {:?}", qname, qtype, kind);
                let rcode = match kind {
                    crate::dns_cache::NegativeKind::NxDomain => ResponseCode::NXDomain,
                    crate::dns_cache::NegativeKind::NoData => ResponseCode::NoError,
                };
                tag.set(AnswerSource::Cache);
                return Ok(build_response_edns(
                    &message,
                    rcode,
                    vec![],
                    false,
                    edns_ctx.as_ref(),
                ));
            }
        }

        // Upstream resolution: iterative from the roots (default) or forward.
        let forward_result = self.upstream_resolve(query_data, edns_ctx.as_ref()).await;

        // DNS64 synthesis: if AAAA query returned no answers and dns64_prefix is set,
        // re-query for A and synthesize AAAA records by embedding IPv4 in the prefix
        if let Ok(ref response_bytes) = forward_result
            && qtype == RecordType::AAAA
            && let Some(prefix) = self.dns64_prefix
            && let Ok(fwd_msg) = hickory_proto::op::Message::from_bytes(response_bytes)
        {
            let has_aaaa = fwd_msg
                .answers()
                .iter()
                .any(|a| a.record_type() == RecordType::AAAA);
            if !has_aaaa {
                // Build an A query for the same name
                let a_query = build_query_for_type(&qname, RecordType::A, message.id());
                if let Ok(a_response_bytes) =
                    self.upstream_resolve(&a_query, edns_ctx.as_ref()).await
                    && let Ok(a_msg) = hickory_proto::op::Message::from_bytes(&a_response_bytes)
                {
                    let synthesized: Vec<Record> = a_msg
                        .answers()
                        .iter()
                        .filter_map(|a_rec| {
                            if let RData::A(rdata::A(ipv4)) = a_rec.data() {
                                let synth_ipv6 = synthesize_dns64_address(&prefix, ipv4);
                                let name = a_rec.name().clone();
                                let mut rec = Record::from_rdata(
                                    name,
                                    a_rec.ttl(),
                                    RData::AAAA(rdata::AAAA(synth_ipv6)),
                                );
                                rec.set_dns_class(DNSClass::IN);
                                Some(rec)
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !synthesized.is_empty() {
                        debug!(
                            "DNS64 synthesized {} AAAA records for {}",
                            synthesized.len(),
                            qname
                        );
                        tag.set(AnswerSource::Dns64);
                        return Ok(build_response_edns(
                            &message,
                            ResponseCode::NoError,
                            synthesized,
                            false,
                            edns_ctx.as_ref(),
                        ));
                    }
                }
            }
        }

        // Normalize the cache-filling (first) response so it is byte-identical to
        // what a later cache HIT returns: serve the freshly-cached records through
        // the same build_response_edns path as the cache-hit branch above, instead
        // of the raw upstream wire bytes. This makes cold and warm answers uniform
        // and gives the address-family filter a single, consistent shape.
        //
        // Skipped when the client set the DNSSEC-OK (DO) bit: the cache/build path
        // carries only the answer section (no RRSIGs), so a validating client must
        // get the raw upstream response untouched. Also falls back to raw when
        // nothing cacheable landed (cache disabled, or a negative/uncacheable
        // answer) — those can't be reconstructed from the positive cache anyway.
        let dnssec_requested = edns_ctx.as_ref().is_some_and(|c| c.dnssec_ok);
        if forward_result.is_ok()
            && !dnssec_requested
            && let Some(ref cache) = self.dns_cache
        {
            let cached = cache.lookup(&qname, record_kind);
            if !cached.is_empty() {
                let dns_records = cached.iter().filter_map(db_record_to_dns_record).collect();
                return Ok(build_response_edns(
                    &message,
                    ResponseCode::NoError,
                    dns_records,
                    false,
                    edns_ctx.as_ref(),
                ));
            }
        }

        forward_result
    }

    /// Checks for DNAME records in global database by walking up labels.
    /// RFC 6672: synthesize a CNAME from the DNAME.
    fn check_dname_global(
        &self,
        qname: &str,
        _qtype: RecordType,
        message: &hickory_proto::op::Message,
    ) -> Option<Vec<u8>> {
        let normalized = crate::db::normalize_name(qname);
        let parts: Vec<&str> = normalized.trim_end_matches('.').split('.').collect();
        // Walk up from qname, checking each parent for DNAME
        for i in 1..parts.len() {
            let parent = format!("{}.", parts[i..].join("."));
            if let Ok(dname_records) = self.db.lookup(&parent, Some(RecordKind::DNAME))
                && !dname_records.is_empty()
            {
                let dname_target = &dname_records[0].value;
                // Synthesize CNAME: replace parent suffix with dname target
                let prefix = parts[..i].join(".");
                let synth_target = format!("{}.{}", prefix, dname_target.trim_end_matches('.'));
                let synth_cname = crate::db::DnsRecord {
                    id: None,
                    name: normalized.clone(),
                    record_type: RecordKind::CNAME,
                    value: crate::db::normalize_name(&synth_target),
                    ttl: dname_records[0].ttl,
                    priority: 0,
                };
                let mut dns_records = Vec::new();
                // Add the DNAME record
                if let Some(dr) = db_record_to_dns_record(&dname_records[0]) {
                    dns_records.push(dr);
                }
                // Add the synthesized CNAME
                if let Some(cr) = db_record_to_dns_record(&synth_cname) {
                    dns_records.push(cr);
                }
                return Some(build_response_ex(
                    message,
                    ResponseCode::NoError,
                    dns_records,
                    true,
                ));
            }
        }
        None
    }

    /// Checks for DNAME records in scoped database by walking up labels.
    fn check_dname_scoped(
        &self,
        scope: &str,
        qname: &str,
        _qtype: RecordType,
        message: &hickory_proto::op::Message,
    ) -> Option<Vec<u8>> {
        let normalized = crate::db::normalize_name(qname);
        let parts: Vec<&str> = normalized.trim_end_matches('.').split('.').collect();
        for i in 1..parts.len() {
            let parent = format!("{}.", parts[i..].join("."));
            let dname_records = self
                .db
                .lookup_scoped(scope, &parent, Some(RecordKind::DNAME));
            if !dname_records.is_empty() {
                let dname_target = &dname_records[0].value;
                let prefix = parts[..i].join(".");
                let synth_target = format!("{}.{}", prefix, dname_target.trim_end_matches('.'));
                let synth_cname = crate::db::DnsRecord {
                    id: None,
                    name: normalized.clone(),
                    record_type: RecordKind::CNAME,
                    value: crate::db::normalize_name(&synth_target),
                    ttl: dname_records[0].ttl,
                    priority: 0,
                };
                let mut dns_records = Vec::new();
                if let Some(dr) = db_record_to_dns_record(&dname_records[0]) {
                    dns_records.push(dr);
                }
                if let Some(cr) = db_record_to_dns_record(&synth_cname) {
                    dns_records.push(cr);
                }
                return Some(build_response_ex(
                    message,
                    ResponseCode::NoError,
                    dns_records,
                    true,
                ));
            }
        }
        None
    }

    /// Resolves a query that was not satisfied locally, dispatching on the
    /// configured resolution mode: iterative from the root servers (default)
    /// or forwarding to the configured upstream resolvers.
    async fn upstream_resolve(
        &self,
        query_data: &[u8],
        edns_ctx: Option<&crate::edns::EdnsContext>,
    ) -> Result<Vec<u8>> {
        match **self.resolution_mode.load() {
            ResolutionMode::Forward => self.forward_query(query_data).await,
            ResolutionMode::Recursive => self.iterative_query(query_data, edns_ctx).await,
            ResolutionMode::Auto => self.auto_resolve(query_data, edns_ctx).await,
        }
    }

    /// Resolves via the resilient fallback chain: roots → secure (DoH/DoT) →
    /// local forwarder → public :53. A sticky `active_tier` is tried first (so a
    /// network that filters :53 doesn't pay the root/timeout on every query);
    /// lower tiers below it provide the actual answer when it fails. Periodically
    /// a query probes the whole chain from the top to reclaim a recovered tier.
    /// The committed tier changes only after a grace period of failures (or
    /// immediately on recovery), and every committed change flushes the cache
    /// first to avoid serving answers cached under a different upstream.
    async fn auto_resolve(
        &self,
        query_data: &[u8],
        edns_ctx: Option<&crate::edns::EdnsContext>,
    ) -> Result<Vec<u8>> {
        let message = match hickory_proto::op::Message::from_bytes(query_data) {
            Ok(m) => m,
            Err(_) => return Ok(make_error_response(query_data, ResponseCode::FormErr)),
        };
        if message.queries().is_empty() {
            return Ok(make_error_response(query_data, ResponseCode::FormErr));
        }

        let start = self.auto_start_tier();
        for tier in start..TIER_COUNT {
            let tier_started = std::time::Instant::now();
            metrics().tier_attempts.inc(tier);
            if let Some(response) = self.try_tier(tier, query_data, &message, edns_ctx).await {
                metrics().tier_wins.inc(tier);
                metrics().upstream_duration.observe(
                    tier,
                    tier_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
                );
                // Commit any tier change (flushing the cache first) BEFORE caching
                // this answer, so the fresh answer survives the flush.
                self.note_auto_winner(tier);
                self.cache_from_wire(&response);
                return Ok(response);
            }
            metrics().tier_failures.inc(tier);
        }
        metrics().upstream_exhausted.inc();
        Ok(make_error_response(query_data, ResponseCode::ServFail))
    }

    /// Pre-warms the auto-resolution chain at startup so the first *client*
    /// query doesn't pay the cold-tier cost. The sticky `active_tier` begins at
    /// [`TIER_ROOTS`]; on a network that filters plaintext :53 the root tier is
    /// unreachable and only degrades to the secure (DoH/DoT) tier after
    /// `switch_grace_failures` real-query failures — so without this the first
    /// several client queries each eat a root timeout before falling through to
    /// DoH. Issuing a few canary resolutions here drives that degrade (and
    /// completes the secure upstream's TCP+TLS handshake) before traffic
    /// arrives. It is a no-op outside auto mode, and on a healthy network where
    /// the roots answer it leaves the tier at roots (a couple of throwaway
    /// lookups). Fire-and-forget: spawn it, never block startup on it.
    pub async fn prewarm_auto(&self) {
        if !matches!(**self.resolution_mode.load(), ResolutionMode::Auto) {
            return;
        }
        let Some(query) = build_canary_query() else {
            return;
        };
        // Enough attempts to commit a degrade past dead roots (grace consecutive
        // deviations), plus one; bounded so a fully-offline host can't spin.
        let grace = self.switch_grace_failures.load(Ordering::Relaxed).max(1);
        for _ in 0..grace.saturating_add(1) {
            if self.active_tier() != TIER_ROOTS {
                break;
            }
            let _ = self.upstream_resolve(&query, None).await;
        }
        info!(
            "auto resolution pre-warm complete: committed tier {}",
            self.active_tier()
        );
    }

    /// Picks the tier a query starts at: normally the sticky `active_tier`, but
    /// once every `recovery_probe_secs` (when degraded below roots) it starts at
    /// the top so a recovered, more-preferred tier can be detected. The
    /// compare-exchange ensures only one concurrent query probes per interval.
    fn auto_start_tier(&self) -> usize {
        let active = self.active_tier.load(Ordering::Relaxed);
        if active == TIER_ROOTS {
            return TIER_ROOTS;
        }
        let now = unix_now_secs();
        let probe_secs = self.recovery_probe_secs.load(Ordering::Relaxed);
        let last = self.last_probe.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= probe_secs
            && self
                .last_probe
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            metrics().recovery_probes.inc();
            TIER_ROOTS
        } else {
            active
        }
    }

    /// Records which tier answered and, if it deviates from the active tier,
    /// updates the sticky tier — immediately on recovery (winner more preferred
    /// than active) or after `switch_grace_failures` consecutive failures on
    /// degrade (winner less preferred). Any committed change flushes the cache
    /// first so cross-tier answers can't linger (cache-poisoning guard).
    fn note_auto_winner(&self, winner: usize) {
        let active = self.active_tier.load(Ordering::Relaxed);
        if winner == active {
            self.deviation_streak.store(0, Ordering::Relaxed);
        } else if winner < active {
            // Recovery: a more-preferred (more-trusted) tier answered. Safe
            // direction — switch immediately.
            self.flush_upstream_state();
            self.active_tier.store(winner, Ordering::Relaxed);
            self.deviation_streak.store(0, Ordering::Relaxed);
            metrics().tier_switches.inc(TIER_SWITCH_RECOVER);
            info!(
                "auto resolution recovered to tier {} (was {}); cache flushed",
                winner, active
            );
        } else {
            // Degrade: the active tier failed and a lower tier answered. Only
            // commit the switch after the failure grace period.
            let grace = self.switch_grace_failures.load(Ordering::Relaxed).max(1);
            let streak = self.deviation_streak.fetch_add(1, Ordering::Relaxed) + 1;
            if streak >= grace as usize {
                self.flush_upstream_state();
                self.active_tier.store(winner, Ordering::Relaxed);
                self.deviation_streak.store(0, Ordering::Relaxed);
                metrics().tier_switches.inc(TIER_SWITCH_DEGRADE);
                warn!(
                    "auto resolution degraded to tier {} after {} failures (was {}); cache flushed",
                    winner, streak, active
                );
            }
        }
    }

    /// Attempts a single resolution tier, returning the raw wire response only if
    /// it is definitive (transport succeeded and rcode is NoError/NXDomain).
    async fn try_tier(
        &self,
        tier: usize,
        query_data: &[u8],
        message: &hickory_proto::op::Message,
        edns_ctx: Option<&crate::edns::EdnsContext>,
    ) -> Option<Vec<u8>> {
        match tier {
            TIER_ROOTS => self.tier_roots(message, edns_ctx).await,
            TIER_SECURE => self.tier_secure(query_data).await,
            TIER_LOCAL => {
                let targets = self.forwarders.load();
                self.tier_forward(query_data, &targets).await
            }
            TIER_PUBLIC => {
                let targets = self.public_fallback.load();
                self.tier_forward(query_data, &targets).await
            }
            _ => None,
        }
    }

    /// Roots tier: iterative resolution from the root servers.
    async fn tier_roots(
        &self,
        message: &hickory_proto::op::Message,
        edns_ctx: Option<&crate::edns::EdnsContext>,
    ) -> Option<Vec<u8>> {
        let question = message.queries().first()?;
        let resolver = self.resolver.load_full();
        match resolver
            .resolve(
                question.name(),
                question.query_type(),
                question.query_class(),
            )
            .await
        {
            Ok(res) if matches!(res.rcode, ResponseCode::NoError | ResponseCode::NXDomain) => Some(
                build_response_edns(message, res.rcode, res.answers, false, edns_ctx),
            ),
            Ok(_) => None,
            Err(e) => {
                debug!("auto: root recursion for {} failed: {}", question.name(), e);
                None
            }
        }
    }

    /// Secure tier: DoH/DoT to each configured encrypted upstream in order
    /// (DoH first by default — :443 survives filtering that blocks DoT's :853).
    async fn tier_secure(&self, query_data: &[u8]) -> Option<Vec<u8>> {
        let upstreams = self.secure_upstreams.load();
        for up in upstreams.iter() {
            metrics().upstream_queries.inc(&up.label);
            match crate::secure_client::query(query_data, up, SECURE_TIER_TIMEOUT).await {
                Ok(resp) if response_is_definitive(&resp) => return Some(resp),
                Ok(_) => continue,
                Err(e) => {
                    debug!("auto: secure upstream {} failed: {}", up.label, e);
                    continue;
                }
            }
        }
        None
    }

    /// Forwarding tier: plaintext Do53 to each target in order (used for both the
    /// local-forwarder and public-fallback tiers).
    async fn tier_forward(&self, query_data: &[u8], targets: &[SocketAddr]) -> Option<Vec<u8>> {
        for target in targets {
            let label = target.to_string();
            match self.forward_one(query_data, target).await {
                Ok(resp) if response_is_definitive(&resp) => {
                    metrics().upstream_queries.inc(&label);
                    return Some(resp);
                }
                Ok(_) => {
                    metrics().upstream_queries.inc(&label);
                    continue;
                }
                Err(e) => {
                    metrics().upstream_queries.inc(&label);
                    debug!("auto: forward to {} failed: {}", target, e);
                    continue;
                }
            }
        }
        None
    }

    /// Resolves a query iteratively starting at the root servers.
    async fn iterative_query(
        &self,
        query_data: &[u8],
        edns_ctx: Option<&crate::edns::EdnsContext>,
    ) -> Result<Vec<u8>> {
        let message = match hickory_proto::op::Message::from_bytes(query_data) {
            Ok(m) => m,
            Err(_) => return Ok(make_error_response(query_data, ResponseCode::FormErr)),
        };
        let question = match message.queries().first() {
            Some(q) => q,
            None => return Ok(make_error_response(query_data, ResponseCode::FormErr)),
        };

        let resolver = self.resolver.load_full();
        match resolver
            .resolve(
                question.name(),
                question.query_type(),
                question.query_class(),
            )
            .await
        {
            Ok(res) => {
                if res.rcode == ResponseCode::NoError && !res.answers.is_empty() {
                    self.cache_answers(question, &res.answers);
                } else if let Some(ttl) = res.negative_ttl(resolver.default_ttl()) {
                    // An authoritative negative. The SOA's TTL is honoured as sent;
                    // where there is no SOA, `default_ttl` applies. Cache it so the
                    // next lookup of this name does not re-walk from the roots.
                    self.cache_negative(question, res.rcode, ttl);
                }
                Ok(build_response_edns(
                    &message,
                    res.rcode,
                    res.answers,
                    false,
                    edns_ctx,
                ))
            }
            Err(e) => {
                warn!("Iterative resolution for {} failed: {}", question.name(), e);
                Ok(make_error_response(query_data, ResponseCode::ServFail))
            }
        }
    }

    /// Checks whether a query name is present in the local RBL blocklist,
    /// tolerating the trailing-dot/case differences between stored entries and
    /// wire-format query names. The local RBL set holds arbitrary strings, so
    /// an operator may have added either `example.com` or `example.com.`.
    fn local_rbl_lists_name(&self, qname: &str) -> bool {
        if self.db.lookup_local_rbl(qname) {
            return true;
        }
        let normalized = crate::rbl::normalize_rbl_name(qname);
        !normalized.is_empty() && normalized != qname && self.db.lookup_local_rbl(&normalized)
    }

    /// Inserts a set of answer records into the DNS cache, keyed by the QUESTION
    /// that produced them — `question.name()` + `map_query_type_to_kind(qtype)`,
    /// the exact key the read path looks up (and the same rule `cache_negative`
    /// uses).
    ///
    /// Keying on the first *answer record* instead is silently wrong for any
    /// name behind a CNAME. `index.crates.io A` comes back as a chain —
    /// `index.crates.io CNAME` → `fastly-index.crates.io CNAME` → A records on a
    /// third name — whose first record is a CNAME, so the entry landed under
    /// `index.crates.io.:CNAME` while every lookup asked for
    /// `index.crates.io.:A`. Those keys never meet, so the name was
    /// *permanently* uncacheable and every query paid a full upstream round
    /// trip. That is most of the CDN-fronted internet (Fastly, CloudFront, S3);
    /// it only looked fine in testing because a name like `example.com` answers
    /// with an A record for itself, making the wrong key accidentally correct.
    ///
    /// The whole answer set is stored under that one key, CNAME chain included,
    /// which is what a resolver is expected to hand back for a chained name.
    fn cache_answers(&self, question: &hickory_proto::op::Query, answers: &[Record]) {
        if let Some(ref cache) = self.dns_cache {
            let name = question.name().to_string();
            let kind = map_query_type_to_kind(question.query_type());
            let ttl = answers.iter().map(|a| a.ttl()).min().unwrap_or(300);
            let cache_records: Vec<crate::db::DnsRecord> =
                answers.iter().filter_map(dns_record_to_db_record).collect();
            if !cache_records.is_empty() {
                cache.insert(&name, kind, cache_records, ttl);
            }
        }
    }

    /// Caches an authoritative negative answer for the question that produced it.
    ///
    /// Keyed exactly like the positive cache (`question.name()` +
    /// `map_query_type_to_kind(qtype)`), so `handle_query`'s negative lookup hits
    /// on the same key it would have used for a positive answer.
    fn cache_negative(&self, question: &hickory_proto::op::Query, rcode: ResponseCode, ttl: u32) {
        let Some(ref cache) = self.dns_cache else {
            return;
        };
        let kind = match rcode {
            ResponseCode::NXDomain => crate::dns_cache::NegativeKind::NxDomain,
            ResponseCode::NoError => crate::dns_cache::NegativeKind::NoData,
            // Only authoritative negatives are cacheable; SERVFAIL and friends
            // are transient and must be retried.
            _ => return,
        };
        let name = question.name().to_string();
        let record_kind = map_query_type_to_kind(question.query_type());
        debug!("Caching negative for {} ({:?}) ttl={}", name, kind, ttl);
        cache.insert_negative(&name, record_kind, kind, ttl);
    }

    /// Forwards a DNS query to the configured upstream resolvers.
    async fn forward_query(&self, query_data: &[u8]) -> Result<Vec<u8>> {
        let forwarders = self.forwarders.load();
        if forwarders.is_empty() {
            metrics().upstream_exhausted.inc();
            return Ok(make_error_response(query_data, ResponseCode::ServFail));
        }

        // Try each forwarder in order
        for forwarder in forwarders.iter() {
            metrics().upstream_queries.inc(&forwarder.to_string());
            match self.forward_one(query_data, forwarder).await {
                Ok(response) => {
                    self.cache_from_wire(&response);
                    return Ok(response);
                }
                Err(e) => {
                    warn!("Forward to {} failed: {}", forwarder, e);
                    continue;
                }
            }
        }

        metrics().upstream_exhausted.inc();
        Ok(make_error_response(query_data, ResponseCode::ServFail))
    }

    /// Forwards a query to a network's per-TLD peer rolodex servers (other
    /// members of the same overlay that are authoritative for records under the
    /// shared TLD). Returns the first DEFINITIVE (NoError/NXDOMAIN) answer; a
    /// peer returning ServFail/Refused/timeout is skipped and the next is tried.
    /// Returns None if no peer gives a definitive answer, so the caller can fall
    /// back to an authoritative NXDOMAIN. Peer answers are intentionally NOT
    /// written to the global upstream cache — they are network-scoped.
    async fn forward_to_tld_peers(
        &self,
        query_data: &[u8],
        peers: &[SocketAddr],
    ) -> Option<Vec<u8>> {
        for target in peers {
            match self.forward_one(query_data, target).await {
                Ok(resp) if response_is_definitive(&resp) => return Some(resp),
                Ok(_) => continue,
                Err(e) => {
                    debug!("TLD peer forward to {} failed: {}", target, e);
                    continue;
                }
            }
        }
        None
    }

    /// Sends one query to one upstream over Do53, tunneling through the proxy if
    /// one is configured.
    async fn forward_one(&self, query_data: &[u8], target: &SocketAddr) -> Result<Vec<u8>> {
        let proxy = self.proxy_config.load();
        if let Some(ref proxy_cfg) = **proxy {
            crate::doh_proxy::forward_via_proxy(query_data, target, proxy_cfg).await
        } else {
            self.forward_udp(query_data, target).await
        }
    }

    /// Inserts a raw wire response's answers into the cache when it carries a
    /// positive answer (NoError with at least one record).
    fn cache_from_wire(&self, response: &[u8]) {
        if self.dns_cache.is_some()
            && let Ok(msg) = hickory_proto::op::Message::from_bytes(response)
            && msg.response_code() == ResponseCode::NoError
            && !msg.answers().is_empty()
            // The question is echoed in the response, and it — not the first
            // answer record — is what the entry must be keyed on. A response
            // without one cannot be keyed correctly, so it is not cached at all
            // rather than cached somewhere nothing will look.
            && let Some(question) = msg.queries().first()
        {
            self.cache_answers(question, msg.answers());
        }
    }

    async fn forward_udp(&self, query_data: &[u8], target: &SocketAddr) -> Result<Vec<u8>> {
        // Acquire a socket from the pool (round-robin)
        let idx = self.forward_socket_idx.fetch_add(1, Ordering::Relaxed) % FORWARD_POOL_SIZE;
        let mut socket_guard = self.forward_sockets[idx].lock().await;
        // Lazily bind the socket on first use
        if socket_guard.is_none() {
            *socket_guard = Some(UdpSocket::bind("0.0.0.0:0").await?);
        }
        let socket = socket_guard
            .as_ref()
            .context("forward socket not initialized after bind")?;

        // Apply QNAME case randomization (0x20 encoding) if enabled
        let (send_data, randomized_name) = if self.qname_randomization {
            match randomize_qname_case(query_data) {
                Some((modified, original_qname, rand_name)) => {
                    (modified, Some((original_qname, rand_name)))
                }
                None => (query_data.to_vec(), None),
            }
        } else {
            (query_data.to_vec(), None)
        };

        // What an acceptable reply has to look like. Everything here is decided
        // from the datagram we are about to send, never from the one that comes
        // back — a response does not get to tell us what it was answering.
        if send_data.len() < 12 {
            anyhow::bail!("refusing to forward a truncated query");
        }
        let expected_id = u16::from_be_bytes([send_data[0], send_data[1]]);
        let sent_question = hickory_proto::op::Message::from_bytes(&send_data)
            .ok()
            .and_then(|m| m.queries().first().cloned());

        socket.send_to(&send_data, target).await?;

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        // Short: a filtered/black-holed forwarder must fail fast so the auto
        // chain moves on rather than stalling the query for seconds.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1500);

        // Read until a datagram passes every check, or the deadline expires.
        //
        // Looping rather than judging the first datagram is deliberate: the
        // socket is pooled and long-lived, so a late reply to an *earlier* query
        // can be sitting in the buffer, and an off-path injector who lands one
        // packet would otherwise deny the query outright. A rejected datagram is
        // discarded and the real answer is still awaited.
        let response = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                anyhow::bail!("forwarder timeout");
            }
            let (len, from) = tokio::time::timeout(remaining, socket.recv_from(&mut buf))
                .await
                .context("forwarder timeout")?
                .context("forwarder recv error")?;

            // The pooled sockets are unconnected, so the kernel hands us
            // datagrams from anyone. A reply from an address we did not query is
            // not an answer to our question.
            if from != *target {
                debug!("discarding forwarder datagram from unexpected source {from}");
                continue;
            }
            // The transaction id is the one thing an off-path forger must guess.
            if len < 2 || u16::from_be_bytes([buf[0], buf[1]]) != expected_id {
                debug!("discarding forwarder response with mismatched transaction id");
                continue;
            }
            let Ok(msg) = hickory_proto::op::Message::from_bytes(&buf[..len]) else {
                debug!("discarding unparseable forwarder response from {target}");
                continue;
            };
            // The response must answer the question we asked — name, type, and
            // class. `sent_question` is None only for a query we could not parse
            // ourselves, in which case there is nothing to compare against.
            if let Some(asked) = &sent_question {
                let Some(got) = msg.queries().first() else {
                    debug!("discarding forwarder response with no question section");
                    continue;
                };
                if got.query_type() != asked.query_type()
                    || got.query_class() != asked.query_class()
                    || !got.name().eq_case(asked.name())
                {
                    // `eq_case` is case-*sensitive*, which is what enforces 0x20:
                    // a forger who could not observe the outbound query cannot
                    // reproduce the randomized capitalization. When
                    // randomization is off this is still the correct check, just
                    // a weaker one.
                    if let Some((original_qname, sent_randomized)) = &randomized_name {
                        warn!(
                            "QNAME case/question mismatch from {}: sent '{}', got '{}' \
                             (original: '{}') — discarding",
                            target,
                            sent_randomized,
                            got.name(),
                            original_qname
                        );
                    } else {
                        debug!("discarding forwarder response answering a different question");
                    }
                    continue;
                }
            }

            break buf[..len].to_vec();
        };
        // Release the socket back to the pool
        drop(socket_guard);

        Ok(response)
    }
}

/// Current wall-clock time in unix seconds (0 if the clock is before the epoch).
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether a raw wire response is a definitive answer for auto-mode tier
/// selection: it parses and its rcode is NoError or NXDomain (an authoritative
/// yes/no). ServFail/Refused/unparseable are treated as "try the next tier".
fn response_is_definitive(response: &[u8]) -> bool {
    match hickory_proto::op::Message::from_bytes(response) {
        Ok(msg) => matches!(
            msg.response_code(),
            ResponseCode::NoError | ResponseCode::NXDomain
        ),
        Err(_) => false,
    }
}

/// Extracts an IP address from a DNS name for RBL checking.
/// This handles reverse DNS names (in-addr.arpa / ip6.arpa) by reconstructing the IP.
pub(crate) fn extract_ip_from_name(name: &str) -> Option<IpAddr> {
    let name = name.trim_end_matches('.');

    // Check for IPv4 reverse DNS (x.x.x.x.in-addr.arpa)
    if let Some(stripped) = name.strip_suffix(".in-addr.arpa") {
        let parts: Vec<&str> = stripped.split('.').collect();
        if parts.len() == 4 {
            let octets: Vec<u8> = parts.iter().rev().filter_map(|p| p.parse().ok()).collect();
            if octets.len() == 4 {
                return Some(IpAddr::V4(Ipv4Addr::new(
                    octets[0], octets[1], octets[2], octets[3],
                )));
            }
        }
    }

    // Check for IPv6 reverse DNS (nibbles.ip6.arpa)
    if let Some(stripped) = name.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = stripped.split('.').collect();
        if nibbles.len() == 32 {
            let mut bytes = [0u8; 16];
            for i in 0..16 {
                let high = u8::from_str_radix(nibbles[31 - i * 2], 16).ok()?;
                let low = u8::from_str_radix(nibbles[31 - i * 2 - 1], 16).ok()?;
                bytes[i] = (high << 4) | low;
            }
            return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
        }
    }

    None
}

/// Maps a hickory RecordType to our internal RecordKind.
fn map_query_type_to_kind(rt: RecordType) -> Option<RecordKind> {
    match rt {
        RecordType::A => Some(RecordKind::A),
        RecordType::AAAA => Some(RecordKind::AAAA),
        RecordType::CNAME => Some(RecordKind::CNAME),
        RecordType::MX => Some(RecordKind::MX),
        RecordType::TXT => Some(RecordKind::TXT),
        RecordType::NS => Some(RecordKind::NS),
        RecordType::SOA => Some(RecordKind::SOA),
        RecordType::SRV => Some(RecordKind::SRV),
        RecordType::PTR => Some(RecordKind::PTR),
        RecordType::TLSA => Some(RecordKind::TLSA),
        RecordType::CERT => Some(RecordKind::CERT),
        RecordType::SSHFP => Some(RecordKind::SSHFP),
        RecordType::DNSKEY => Some(RecordKind::DNSKEY),
        RecordType::RRSIG => Some(RecordKind::RRSIG),
        RecordType::NSEC => Some(RecordKind::NSEC),
        RecordType::NSEC3 => Some(RecordKind::NSEC3),
        RecordType::NSEC3PARAM => Some(RecordKind::NSEC3PARAM),
        _ => {
            // Handle types that hickory may not have direct variants for
            let code: u16 = rt.into();
            match code {
                256 => Some(RecordKind::URI),     // URI (RFC 7553)
                39 => Some(RecordKind::DNAME),    // DNAME (RFC 6672)
                43 => Some(RecordKind::DS),       // DS
                63 => Some(RecordKind::ZONEMD),   // ZONEMD (RFC 9156)
                65305 => Some(RecordKind::ANAME), // ANAME (draft)
                _ => None,
            }
        }
    }
}

/// Parses `bind_addr` ("ip:port") and returns the bound IP only when it is a
/// concrete (non-wildcard) address. A wildcard bind (`0.0.0.0`/`[::]`) yields
/// `None` because a single packet's true destination IP is not recoverable
/// without per-packet `IP_PKTINFO`; ingress listeners always bind a concrete IP.
/// Binds one UDP shard socket for `bind_addr`.
///
/// `SO_REUSEPORT` is set only when the listener is actually sharded. Linux
/// requires *every* socket on a shared `addr:port` to carry the option, so a
/// single-shard listener still collides with (and reports) a port already held
/// by anything else — the behaviour the ingress bind-failure handling relies on.
/// The option must be set before `bind`.
fn bind_udp_shard(bind_addr: &str, reuse_port: bool) -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::ToSocketAddrs;

    let addr = bind_addr
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve UDP bind address {}", bind_addr))?
        .next()
        .with_context(|| format!("no address resolved for UDP bind address {}", bind_addr))?;

    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .with_context(|| format!("failed to create UDP socket for {}", bind_addr))?;
    if reuse_port {
        sock.set_reuse_port(true)
            .with_context(|| format!("failed to set SO_REUSEPORT for {}", bind_addr))?;
    }
    sock.set_nonblocking(true)
        .with_context(|| format!("failed to set non-blocking mode for {}", bind_addr))?;
    sock.bind(&addr.into())
        .with_context(|| format!("failed to bind UDP socket to {}", bind_addr))?;

    UdpSocket::from_std(sock.into())
        .with_context(|| format!("failed to register UDP socket for {}", bind_addr))
}

fn concrete_bind_ip(bind_addr: &str) -> Option<IpAddr> {
    bind_addr
        .parse::<SocketAddr>()
        .ok()
        .map(|sa| sa.ip())
        .filter(|ip| !ip.is_unspecified())
}

/// Builds the hickory answer records for a scoped lookup, applying the per-TLD
/// ingress rewrite: when `override_ip` is set, an A/AAAA record of the matching
/// address family has its value replaced with the ingress IP (the ingress
/// controller). Records of a different type or family pass through unchanged.
fn build_scoped_answers(
    records: &[crate::db::DnsRecord],
    override_ip: Option<IpAddr>,
) -> Vec<Record> {
    records
        .iter()
        .filter_map(|r| match override_ip {
            Some(IpAddr::V4(v4)) if r.record_type == RecordKind::A => {
                let mut r2 = r.clone();
                r2.value = v4.to_string();
                db_record_to_dns_record(&r2)
            }
            Some(IpAddr::V6(v6)) if r.record_type == RecordKind::AAAA => {
                let mut r2 = r.clone();
                r2.value = v6.to_string();
                db_record_to_dns_record(&r2)
            }
            _ => db_record_to_dns_record(r),
        })
        .collect()
}

/// Converts a database record to a hickory DNS record.
/// Encodes a record hickory has no native RData variant for as its real wire
/// RDATA under its real type code.
///
/// These types were previously served as TXT carrying the stored string, which
/// answers a DNSKEY query with a TXT record — unusable to any client that asked
/// for the type it asked for, and fatal for RRSIG, whose whole purpose is to be
/// parsed and verified. The encoder is the same one the signer computes
/// signatures over, so what is served is byte-for-byte what was signed.
fn opaque_rdata(db_rec: &crate::db::DnsRecord) -> Option<RData> {
    let rdata = crate::dnssec::canonical_rdata(db_rec)?;
    if rdata.is_empty() {
        return None;
    }
    Some(RData::Unknown {
        code: RecordType::from(db_rec.record_type.wire_type()),
        rdata: rdata::NULL::with(rdata),
    })
}

fn db_record_to_dns_record(db_rec: &crate::db::DnsRecord) -> Option<Record> {
    let name = Name::from_ascii(&db_rec.name).ok()?;
    let rdata = match db_rec.record_type {
        RecordKind::A => {
            let ip: Ipv4Addr = db_rec.value.parse().ok()?;
            RData::A(rdata::A(ip))
        }
        RecordKind::AAAA => {
            let ip: Ipv6Addr = db_rec.value.parse().ok()?;
            RData::AAAA(rdata::AAAA(ip))
        }
        RecordKind::CNAME => {
            let target = Name::from_ascii(&db_rec.value).ok()?;
            RData::CNAME(rdata::CNAME(target))
        }
        RecordKind::MX => {
            let target = Name::from_ascii(&db_rec.value).ok()?;
            RData::MX(rdata::MX::new(db_rec.priority as u16, target))
        }
        RecordKind::TXT => RData::TXT(rdata::TXT::new(vec![db_rec.value.clone()])),
        RecordKind::NS => {
            let target = Name::from_ascii(&db_rec.value).ok()?;
            RData::NS(rdata::NS(target))
        }
        RecordKind::SOA => {
            // SOA value format: "mname rname serial refresh retry expire minimum"
            let parts: Vec<&str> = db_rec.value.split_whitespace().collect();
            if parts.len() >= 7 {
                let mname = Name::from_ascii(parts[0]).ok()?;
                let rname = Name::from_ascii(parts[1]).ok()?;
                let serial: u32 = parts[2].parse().ok()?;
                let refresh: i32 = parts[3].parse().ok()?;
                let retry: i32 = parts[4].parse().ok()?;
                let expire: i32 = parts[5].parse().ok()?;
                let minimum: u32 = parts[6].parse().ok()?;
                RData::SOA(rdata::SOA::new(
                    mname, rname, serial, refresh, retry, expire, minimum,
                ))
            } else {
                return None;
            }
        }
        RecordKind::SRV => {
            // SRV value format: "weight port target"
            let parts: Vec<&str> = db_rec.value.split_whitespace().collect();
            if parts.len() >= 3 {
                let weight: u16 = parts[0].parse().ok()?;
                let port: u16 = parts[1].parse().ok()?;
                let target = Name::from_ascii(parts[2]).ok()?;
                RData::SRV(rdata::SRV::new(
                    db_rec.priority as u16,
                    weight,
                    port,
                    target,
                ))
            } else {
                return None;
            }
        }
        RecordKind::PTR => {
            let target = Name::from_ascii(&db_rec.value).ok()?;
            RData::PTR(rdata::PTR(target))
        }
        RecordKind::DNAME => {
            // DNAME is type 39 but hickory doesn't have a native DNAME variant.
            // We use ANAME's structure since it's also a name-pointing record.
            let target = Name::from_ascii(&db_rec.value).ok()?;
            // Build as CNAME format but the record type in the wire format
            // will be set based on what the caller specifies. For DNAME synthesis
            // purposes, we primarily use this for internal lookup.
            RData::CNAME(rdata::CNAME(target))
        }
        RecordKind::SSHFP => {
            // SSHFP: "algorithm fp_type hex_fingerprint"
            let parts: Vec<&str> = db_rec.value.split_whitespace().collect();
            if parts.len() >= 3 {
                let algorithm: rdata::sshfp::Algorithm = parts[0].parse::<u8>().ok()?.into();
                let fp_type: rdata::sshfp::FingerprintType = parts[1].parse::<u8>().ok()?.into();
                let fingerprint = hex::decode(parts[2]).ok()?;
                RData::SSHFP(rdata::SSHFP::new(algorithm, fp_type, fingerprint))
            } else {
                return None;
            }
        }
        RecordKind::ANAME => {
            // ANAME is resolved to its target at query time and never appears on
            // the wire as itself, so there is no encoding to get right here.
            RData::TXT(rdata::TXT::new(vec![db_rec.value.clone()]))
        }
        RecordKind::URI | RecordKind::ZONEMD => opaque_rdata(db_rec)?,
        RecordKind::TLSA => {
            // TLSA: "usage selector matching_type hex_data"
            let parts: Vec<&str> = db_rec.value.split_whitespace().collect();
            if parts.len() >= 4 {
                let usage: u8 = parts[0].parse().ok()?;
                let selector: u8 = parts[1].parse().ok()?;
                let matching_type: u8 = parts[2].parse().ok()?;
                let cert_data = hex::decode(parts[3]).ok()?;
                RData::TLSA(rdata::TLSA::new(
                    hickory_proto::rr::rdata::tlsa::CertUsage::from(usage),
                    hickory_proto::rr::rdata::tlsa::Selector::from(selector),
                    hickory_proto::rr::rdata::tlsa::Matching::from(matching_type),
                    cert_data,
                ))
            } else {
                return None;
            }
        }
        RecordKind::CERT => {
            // CERT (RFC 4398): "cert_type key_tag algorithm base64_cert_data"
            let parts: Vec<&str> = db_rec.value.split_whitespace().collect();
            if parts.len() >= 4 {
                let cert_type: u16 = parts[0].parse().ok()?;
                let key_tag: u16 = parts[1].parse().ok()?;
                let algorithm: u8 = parts[2].parse().ok()?;
                let cert_data =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, parts[3])
                        .ok()?;
                RData::CERT(rdata::CERT::new(
                    hickory_proto::rr::rdata::cert::CertType::from(cert_type),
                    key_tag,
                    hickory_proto::rr::rdata::cert::Algorithm::from(algorithm),
                    cert_data,
                ))
            } else {
                return None;
            }
        }
        RecordKind::DNSKEY | RecordKind::DS | RecordKind::RRSIG => opaque_rdata(db_rec)?,
        RecordKind::NSEC | RecordKind::NSEC3 | RecordKind::NSEC3PARAM => {
            // Never generated by this server, so there is no stored format to
            // encode. Serving them as TXT would answer a DNSSEC query with
            // something that is not the type asked for.
            return None;
        }
    };

    let mut record = Record::from_rdata(name, db_rec.ttl, rdata);
    record.set_dns_class(DNSClass::IN);
    Some(record)
}

/// Builds a DNS response message (without EDNS).
#[cfg(test)]
fn build_response(
    query: &hickory_proto::op::Message,
    rcode: ResponseCode,
    answers: Vec<Record>,
) -> Vec<u8> {
    build_response_ex(query, rcode, answers, false)
}

/// Builds a DNS response message with optional authoritative flag.
fn build_response_ex(
    query: &hickory_proto::op::Message,
    rcode: ResponseCode,
    answers: Vec<Record>,
    authoritative: bool,
) -> Vec<u8> {
    let mut response = hickory_proto::op::Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(rcode);
    response.set_recursion_desired(query.recursion_desired());
    response.set_recursion_available(true);
    response.set_authoritative(authoritative);

    // Copy the question section
    for q in query.queries() {
        response.add_query(q.clone());
    }

    for answer in answers {
        response.add_answer(answer);
    }

    response.to_bytes().unwrap_or_default()
}

/// Builds a wire A-record query for a stable, always-resolvable public name,
/// used by [`DnsServer::prewarm_auto`] to exercise the auto-tier machinery at
/// startup. The answer is irrelevant — the query just needs to run the real
/// resolution path so the sticky tier can commit past a filtered :53.
fn build_canary_query() -> Option<Vec<u8>> {
    use hickory_proto::op::{Message, Query};
    let mut msg = Message::new();
    msg.set_id(0)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(Name::from_ascii("one.one.one.one.").ok()?)
        .set_query_type(RecordType::A)
        .set_query_class(DNSClass::IN);
    msg.add_query(q);
    msg.to_bytes().ok()
}

/// Creates an error response preserving the query ID.
fn make_error_response(query_data: &[u8], rcode: ResponseCode) -> Vec<u8> {
    if query_data.len() >= 2 {
        let id = u16::from_be_bytes([query_data[0], query_data[1]]);
        let mut response = hickory_proto::op::Message::new();
        response.set_id(id);
        response.set_message_type(MessageType::Response);
        response.set_response_code(rcode);
        response.to_bytes().unwrap_or_default()
    } else {
        Vec::new()
    }
}

/// Builds a DNS response with EDNS OPT record if EDNS was present in the query.
fn build_response_edns(
    query: &hickory_proto::op::Message,
    rcode: ResponseCode,
    answers: Vec<Record>,
    authoritative: bool,
    edns_ctx: Option<&crate::edns::EdnsContext>,
) -> Vec<u8> {
    let mut response = hickory_proto::op::Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(rcode);
    response.set_recursion_desired(query.recursion_desired());
    response.set_recursion_available(true);
    response.set_authoritative(authoritative);

    // Copy the question section
    for q in query.queries() {
        response.add_query(q.clone());
    }

    for answer in answers {
        response.add_answer(answer);
    }

    // If the query included EDNS, add OPT record to the response
    if let Some(ctx) = edns_ctx {
        crate::edns::add_edns_to_response(&mut response, ctx.max_payload, ctx.dnssec_ok);
    }

    response.to_bytes().unwrap_or_default()
}

/// Builds a DNS query message for a specific record type (used for DNS64 A re-query).
fn build_query_for_type(name: &str, qtype: RecordType, id: u16) -> Vec<u8> {
    let mut msg = hickory_proto::op::Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);

    let mut query = hickory_proto::op::Query::new();
    if let Ok(n) = Name::from_ascii(name) {
        query.set_name(n);
    }
    query.set_query_type(qtype);
    query.set_query_class(DNSClass::IN);
    msg.add_query(query);

    msg.to_bytes().unwrap_or_default()
}

/// Synthesizes a DNS64 IPv6 address by embedding an IPv4 address in the prefix.
/// Uses the well-known prefix format (RFC 6052): prefix::/96 with IPv4 in last 32 bits.
fn synthesize_dns64_address(prefix: &Ipv6Addr, ipv4: &Ipv4Addr) -> Ipv6Addr {
    let mut octets = prefix.octets();
    let v4_octets = ipv4.octets();
    // Embed IPv4 in the last 4 bytes (bits 96-127) of the IPv6 address
    octets[12] = v4_octets[0];
    octets[13] = v4_octets[1];
    octets[14] = v4_octets[2];
    octets[15] = v4_octets[3];
    Ipv6Addr::from(octets)
}

/// Reads the question's QTYPE straight off the wire.
///
/// Read from bytes rather than from a parsed `Message` because the metrics
/// wrapper sits outside `resolve_query`, which has already done the real parse —
/// re-parsing the whole message just to label a counter would put a second
/// allocation-heavy parse on every query. Question names are never compressed,
/// so walking the labels is enough; a malformed or truncated query yields `None`
/// and folds into the `OTHER` label.
fn wire_qtype(query: &[u8]) -> Option<RecordType> {
    // 12-byte header, then QNAME labels, then QTYPE.
    let mut pos = 12;
    loop {
        let label_len = *query.get(pos)? as usize;
        // A compression pointer (top two bits set) has no business in a
        // question; treat it as unparseable rather than chasing it.
        if label_len & 0xc0 != 0 {
            return None;
        }
        pos += 1;
        if label_len == 0 {
            break;
        }
        pos += label_len;
    }
    let hi = *query.get(pos)? as u16;
    let lo = *query.get(pos + 1)? as u16;
    Some(RecordType::from((hi << 8) | lo))
}

/// Reads the RCODE nibble from a response header.
fn wire_rcode(response: &[u8]) -> u8 {
    response.get(3).map(|b| b & 0x0f).unwrap_or(0)
}

/// Whether a response has the TC (truncated) bit set.
fn wire_truncated(response: &[u8]) -> bool {
    response.get(2).is_some_and(|b| b & 0x02 != 0)
}

/// Extracts a DNS QNAME from wire-format label encoding into a dotted string.
fn extract_qname(data: &[u8]) -> Option<String> {
    let mut name = String::with_capacity(64);
    let mut pos = 0;
    loop {
        if pos >= data.len() {
            return None;
        }
        let label_len = data[pos] as usize;
        if label_len == 0 {
            break;
        }
        if pos + 1 + label_len > data.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        for i in 1..=label_len {
            name.push(data[pos + i] as char);
        }
        pos += label_len + 1;
    }
    name.push('.');
    Some(name)
}

/// Randomizes the case of the QNAME in a DNS query for 0x20 encoding.
/// Returns (modified_bytes, original_qname, randomized_qname), or None if parsing fails.
///
/// Operates directly on DNS wire-format bytes for efficiency: the QNAME starts
/// at byte offset 12 (after the 12-byte DNS header) and uses label encoding
/// (length byte followed by ASCII label bytes). Case is toggled in-place by
/// flipping the 0x20 bit on ASCII alphabetic bytes.
pub fn randomize_qname_case(query_data: &[u8]) -> Option<(Vec<u8>, String, String)> {
    // DNS header is 12 bytes; need at least header + 1 byte for QNAME
    if query_data.len() < 13 {
        return None;
    }

    let original_name = extract_qname(&query_data[12..])?;
    let mut modified = Vec::with_capacity(query_data.len());
    modified.extend_from_slice(query_data);

    let mut rng = rand::rng();
    let mut pos = 12;
    loop {
        if pos >= modified.len() {
            return None;
        }
        let label_len = modified[pos] as usize;
        if label_len == 0 {
            break;
        }
        if pos + 1 + label_len > modified.len() {
            return None;
        }
        for i in 1..=label_len {
            if modified[pos + i].is_ascii_alphabetic() && rng.random_bool(0.5) {
                modified[pos + i] ^= 0x20;
            }
        }
        pos += label_len + 1;
    }

    let randomized_name = extract_qname(&modified[12..])?;
    Some((modified, original_name, randomized_name))
}

/// Converts a hickory DNS Record to a database DnsRecord (for cache insertion).
fn dns_record_to_db_record(record: &Record) -> Option<crate::db::DnsRecord> {
    let name = record.name().to_string();
    let ttl = record.ttl();
    let (record_type, value, priority) = match record.data() {
        RData::A(rdata::A(ip)) => (RecordKind::A, ip.to_string(), 0u32),
        RData::AAAA(rdata::AAAA(ip)) => (RecordKind::AAAA, ip.to_string(), 0u32),
        RData::CNAME(rdata::CNAME(target)) => (RecordKind::CNAME, target.to_string(), 0u32),
        RData::MX(mx) => (
            RecordKind::MX,
            mx.exchange().to_string(),
            mx.preference() as u32,
        ),
        RData::TXT(txt) => {
            let value = txt
                .iter()
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>()
                .join("");
            (RecordKind::TXT, value, 0u32)
        }
        RData::NS(rdata::NS(target)) => (RecordKind::NS, target.to_string(), 0u32),
        RData::PTR(rdata::PTR(target)) => (RecordKind::PTR, target.to_string(), 0u32),
        _ => return None,
    };

    Some(crate::db::DnsRecord {
        id: None,
        name,
        record_type,
        value,
        ttl,
        priority,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Database, DnsRecord, RecordKind};
    use crate::rbl::{RblAnswer, RblChecker, RblProvider, RblResolver};
    use hickory_proto::op::Message;
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use std::net::Ipv4Addr;

    struct NeverListedResolver;

    #[async_trait::async_trait]
    impl RblResolver for NeverListedResolver {
        async fn lookup_rbl(&self, _query: &str) -> Result<Option<RblAnswer>, anyhow::Error> {
            Ok(None)
        }
    }

    struct AlwaysListedResolver;

    #[async_trait::async_trait]
    impl RblResolver for AlwaysListedResolver {
        async fn lookup_rbl(&self, _query: &str) -> Result<Option<RblAnswer>, anyhow::Error> {
            Ok(Some(RblAnswer::listed(300)))
        }
    }

    /// Mock resolver that lists a query only if it begins with one of the given
    /// name prefixes, simulating a domain blocklist (e.g. `dbl.spamhaus.org`)
    /// that lists some names but not others.
    struct PrefixListedResolver {
        listed_prefixes: Vec<String>,
    }

    #[async_trait::async_trait]
    impl RblResolver for PrefixListedResolver {
        async fn lookup_rbl(&self, query: &str) -> Result<Option<RblAnswer>, anyhow::Error> {
            if self
                .listed_prefixes
                .iter()
                .any(|p| query.starts_with(p.as_str()))
            {
                Ok(Some(RblAnswer::listed(300)))
            } else {
                Ok(None)
            }
        }
    }

    /// Builds a server whose DNSBL (domain blocklist) is enabled with a single
    /// `dbl.test` provider backed by the given resolver. The IP-based RBL is left
    /// disabled to prove domain blocking is driven by the DNSBL config alone.
    async fn make_test_server_with_dnsbl(
        db: Database,
        resolver: Arc<dyn RblResolver>,
    ) -> Arc<DnsServer> {
        let rbl = Arc::new(RblChecker::with_resolver(false, vec![], resolver));
        rbl.set_dnsbl_config(
            true,
            vec![RblProvider {
                zone: "dbl.test".to_string(),
                enabled: true,
                ..Default::default()
            }],
        )
        .await;
        Arc::new(DnsServer::new(db, rbl, vec![]))
    }

    fn make_test_server(db: Database) -> Arc<DnsServer> {
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        Arc::new(DnsServer::new(db, rbl, vec![]))
    }

    fn make_test_server_with_rbl(db: Database, listed: bool) -> Arc<DnsServer> {
        let resolver: Arc<dyn RblResolver> = if listed {
            Arc::new(AlwaysListedResolver)
        } else {
            Arc::new(NeverListedResolver)
        };
        let rbl = Arc::new(RblChecker::with_resolver(
            true,
            vec![RblProvider {
                zone: "test.rbl".to_string(),
                enabled: true,
                ..Default::default()
            }],
            resolver,
        ));
        Arc::new(DnsServer::new(db, rbl, vec![]))
    }

    fn build_query(name: &str, qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(1234);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);

        let mut query = hickory_proto::op::Query::new();
        query.set_name(Name::from_ascii(name).unwrap());
        query.set_query_type(qtype);
        query.set_query_class(DNSClass::IN);
        msg.add_query(query);

        msg.to_bytes().unwrap()
    }

    #[tokio::test]
    async fn test_local_a_record_lookup() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "test.local.".to_string(),
            record_type: RecordKind::A,
            value: "192.168.1.100".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("test.local.", RecordType::A);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        if let RData::A(rdata::A(ip)) = response.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 100));
        } else {
            panic!("expected A record");
        }
    }

    #[tokio::test]
    async fn test_local_aaaa_record_lookup() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "test.local.".to_string(),
            record_type: RecordKind::AAAA,
            value: "::1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("test.local.", RecordType::AAAA);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_family_filter_suppresses_aaaa_as_nodata() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "dual.local.".to_string(),
            record_type: RecordKind::AAAA,
            value: "2001:db8::1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "dual.local.".to_string(),
            record_type: RecordKind::A,
            value: "192.0.2.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        // Simulate the routability probe deciding IPv6 is unroutable.
        server.set_answer_families(true, false);

        // AAAA query -> NODATA (NoError, no answers), so getaddrinfo falls back to A.
        let aaaa = build_query("dual.local.", RecordType::AAAA);
        let resp = Message::from_bytes(&server.handle_query(&aaaa).await.unwrap()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 0, "AAAA must be suppressed to NODATA");

        // The A query for the same name is unaffected.
        let a = build_query("dual.local.", RecordType::A);
        let resp = Message::from_bytes(&server.handle_query(&a).await.unwrap()).unwrap();
        assert_eq!(resp.answers().len(), 1);
        assert!(matches!(resp.answers()[0].data(), RData::A(_)));
    }

    #[tokio::test]
    async fn test_family_filter_suppresses_a_as_nodata() {
        // Symmetric case: a v6-only host suppresses A answers.
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "v4.local.".to_string(),
            record_type: RecordKind::A,
            value: "192.0.2.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        server.set_answer_families(false, true);

        let a = build_query("v4.local.", RecordType::A);
        let resp = Message::from_bytes(&server.handle_query(&a).await.unwrap()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 0);
    }

    #[tokio::test]
    async fn test_family_filter_noop_when_both_enabled() {
        // Regression: both families enabled (the default) returns answers
        // untouched — same behavior as before the feature existed.
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "v6.local.".to_string(),
            record_type: RecordKind::AAAA,
            value: "2001:db8::1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        assert_eq!(server.answer_families(), (true, true));
        let aaaa = build_query("v6.local.", RecordType::AAAA);
        let resp = Message::from_bytes(&server.handle_query(&aaaa).await.unwrap()).unwrap();
        assert_eq!(resp.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_apply_family_filter_strips_from_raw_wire() {
        // Directly exercise the wire-level filter, which is what covers raw
        // upstream (forwarder/secure) answers that never pass through
        // build_response_edns.
        let server = make_test_server(Database::open_memory().unwrap());

        // A response carrying both an A and an AAAA answer, as an upstream
        // recursive/forward answer would.
        let mut msg = Message::new();
        msg.set_id(42);
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_response_code(ResponseCode::NoError);
        let mut q = hickory_proto::op::Query::new();
        q.set_name(Name::from_ascii("dual.example.").unwrap());
        q.set_query_type(RecordType::A);
        q.set_query_class(DNSClass::IN);
        msg.add_query(q);
        msg.add_answer(Record::from_rdata(
            Name::from_ascii("dual.example.").unwrap(),
            300,
            RData::A(rdata::A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        msg.add_answer(Record::from_rdata(
            Name::from_ascii("dual.example.").unwrap(),
            300,
            RData::AAAA(rdata::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        ));
        let wire = msg.to_bytes().unwrap();

        // v6 down: AAAA dropped, A kept.
        server.set_answer_families(true, false);
        let filtered = Message::from_bytes(&server.apply_family_filter(wire.clone())).unwrap();
        assert_eq!(filtered.answers().len(), 1);
        assert!(matches!(filtered.answers()[0].data(), RData::A(_)));

        // Both families up: untouched, byte-identical.
        server.set_answer_families(true, true);
        assert_eq!(server.apply_family_filter(wire.clone()), wire);
    }

    #[tokio::test]
    async fn test_local_cname_record_lookup() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "alias.local.".to_string(),
            record_type: RecordKind::CNAME,
            value: "real.local.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("alias.local.", RecordType::A);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        // Should return the CNAME when querying for A record
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_local_mx_record_lookup() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "example.local.".to_string(),
            record_type: RecordKind::MX,
            value: "mail.example.local.".to_string(),
            ttl: 300,
            priority: 10,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("example.local.", RecordType::MX);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_local_txt_record_lookup() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "txt.local.".to_string(),
            record_type: RecordKind::TXT,
            value: "v=spf1 include:example.com ~all".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("txt.local.", RecordType::TXT);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_nonexistent_record_no_forwarders() {
        let db = Database::open_memory().unwrap();
        let server = make_test_server(db);
        let query = build_query("nonexistent.example.com.", RecordType::A);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        // No forwarders configured, should get SERVFAIL
        assert_eq!(response.response_code(), ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn test_malformed_query() {
        let db = Database::open_memory().unwrap();
        let server = make_test_server(db);
        let response_bytes = server.handle_query(&[0, 1]).await.unwrap();
        // Should get a response (possibly empty or error)
        assert!(!response_bytes.is_empty());
    }

    #[tokio::test]
    async fn test_multiple_records_same_name() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "multi.local.".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "multi.local.".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.2".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("multi.local.", RecordType::A);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 2);
    }

    #[tokio::test]
    async fn test_split_horizon_local_preferred() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "internal.company.com.".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.50".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("internal.company.com.", RecordType::A);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        if let RData::A(rdata::A(ip)) = response.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 50));
        }
    }

    /// RBL/DNSBL fills are fire-and-forget: the first query for a listed name
    /// primes the blocklist cache and is not blocked yet (it falls through — to
    /// ServFail with no forwarders, or to a cached/local answer). These helpers
    /// poll until the block lands (NXDOMAIN) so tests assert the eventual state.
    async fn query_until_blocked(server: &Arc<DnsServer>, query: &[u8]) -> Message {
        for _ in 0..200 {
            let resp = Message::from_bytes(&server.handle_query(query).await.unwrap()).unwrap();
            if resp.response_code() == ResponseCode::NXDomain {
                return resp;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        Message::from_bytes(&server.handle_query(query).await.unwrap()).unwrap()
    }

    async fn query_from_until_blocked(
        server: &Arc<DnsServer>,
        query: &[u8],
        source: std::net::IpAddr,
    ) -> Message {
        for _ in 0..200 {
            let resp = Message::from_bytes(&server.handle_query_from(query, source).await.unwrap())
                .unwrap();
            if resp.response_code() == ResponseCode::NXDomain {
                return resp;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        Message::from_bytes(&server.handle_query_from(query, source).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn test_rbl_blocks_reverse_dns() {
        let db = Database::open_memory().unwrap();
        let server = make_test_server_with_rbl(db, true);
        // Query for a reverse DNS name (blocked once the async RBL fill lands).
        let query = build_query("100.1.168.192.in-addr.arpa.", RecordType::PTR);
        let response = query_until_blocked(&server, &query).await;

        assert_eq!(response.response_code(), ResponseCode::NXDomain);
    }

    /// RBL precedence over external DNS: a domain-blocklisted name (e.g.
    /// `googleadservices.com`) must be answered with NXDOMAIN rather than being
    /// forwarded upstream, while a locally-defined name in the same query batch
    /// (e.g. `gitea.default.home`, which may have been planted by a package)
    /// continues to resolve from the local database.
    #[tokio::test]
    async fn test_rbl_blocks_forwarded_domain_but_not_local() {
        let db = Database::open_memory().unwrap();
        // A local record that must keep resolving regardless of RBL state.
        db.add_record(&DnsRecord {
            id: None,
            name: "gitea.default.home.".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.5".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let resolver = Arc::new(PrefixListedResolver {
            listed_prefixes: vec!["googleadservices.com.".to_string()],
        });
        let server = make_test_server_with_dnsbl(db, resolver).await;

        // The blocklisted external name is refused with NXDOMAIN. With no
        // forwarders configured an unblocked external name would SERVFAIL, so
        // NXDOMAIN proves the RBL fired before forwarding.
        let blocked = build_query("googleadservices.com.", RecordType::A);
        let blocked_resp = query_until_blocked(&server, &blocked).await;
        assert_eq!(blocked_resp.response_code(), ResponseCode::NXDomain);
        assert!(blocked_resp.answers().is_empty());

        // The local record resolves normally — RBL never gates local data.
        let local = build_query("gitea.default.home.", RecordType::A);
        let local_resp = Message::from_bytes(&server.handle_query(&local).await.unwrap()).unwrap();
        assert_eq!(local_resp.response_code(), ResponseCode::NoError);
        assert_eq!(local_resp.answers().len(), 1);
        if let RData::A(rdata::A(ip)) = local_resp.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 5));
        } else {
            panic!("expected A record for local name");
        }

        // A non-blocklisted external name is not over-blocked: with no
        // forwarders it falls through to SERVFAIL rather than NXDOMAIN.
        let allowed = build_query("example.org.", RecordType::A);
        let allowed_resp =
            Message::from_bytes(&server.handle_query(&allowed).await.unwrap()).unwrap();
        assert_eq!(allowed_resp.response_code(), ResponseCode::ServFail);
    }

    /// RBL precedence must also override a previously-cached upstream answer:
    /// once a name is blocklisted, a cache entry for it is suppressed instead of
    /// being served.
    #[tokio::test]
    async fn test_rbl_blocks_cached_upstream_domain() {
        let db = Database::open_memory().unwrap();
        let resolver = Arc::new(PrefixListedResolver {
            listed_prefixes: vec!["ads.tracker.example.".to_string()],
        });
        let rbl = Arc::new(RblChecker::with_resolver(false, vec![], resolver));
        rbl.set_dnsbl_config(
            true,
            vec![RblProvider {
                zone: "dbl.test".to_string(),
                enabled: true,
                ..Default::default()
            }],
        )
        .await;
        let cache = Arc::new(crate::dns_cache::DnsCache::new(
            Database::open_memory().unwrap(),
        ));
        // Seed the cache as if an upstream answer had been stored earlier.
        cache.insert(
            "ads.tracker.example.",
            Some(RecordKind::A),
            vec![DnsRecord {
                id: None,
                name: "ads.tracker.example.".to_string(),
                record_type: RecordKind::A,
                value: "203.0.113.7".to_string(),
                ttl: 300,
                priority: 0,
            }],
            300,
        );
        let server = Arc::new(DnsServer::new_with_options(
            db,
            rbl,
            vec![],
            Some(cache),
            None,
            true,
        ));

        let query = build_query("ads.tracker.example.", RecordType::A);
        let resp = query_until_blocked(&server, &query).await;
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
        assert!(resp.answers().is_empty());
    }

    /// A local RBL entry (DB-backed, independent of DNS providers) blocks a
    /// forward domain name, tolerating trailing-dot differences between the
    /// stored entry and the wire-format query name.
    #[tokio::test]
    async fn test_local_rbl_blocks_forward_domain() {
        let db = Database::open_memory().unwrap();
        // Stored without a trailing dot, as an operator would type it.
        db.add_local_rbl_entry("tracker.example.com", "ad tracker")
            .unwrap();

        // RBL DNS providers are disabled; only the local list is consulted.
        let server = make_test_server(db);

        let blocked = build_query("tracker.example.com.", RecordType::A);
        let blocked_resp =
            Message::from_bytes(&server.handle_query(&blocked).await.unwrap()).unwrap();
        assert_eq!(blocked_resp.response_code(), ResponseCode::NXDomain);

        // An unrelated external name is not blocked (SERVFAIL, no forwarders).
        let allowed = build_query("safe.example.com.", RecordType::A);
        let allowed_resp =
            Message::from_bytes(&server.handle_query(&allowed).await.unwrap()).unwrap();
        assert_eq!(allowed_resp.response_code(), ResponseCode::ServFail);
    }

    /// A DNSBL resolver that lists everything and counts the lookups it was
    /// asked to perform, so a test can prove an allowlisted name never reaches a
    /// provider at all.
    struct CountingListedResolver {
        lookups: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl RblResolver for CountingListedResolver {
        async fn lookup_rbl(&self, _query: &str) -> Result<Option<RblAnswer>, anyhow::Error> {
            self.lookups.fetch_add(1, Ordering::Relaxed);
            Ok(Some(RblAnswer::listed(300)))
        }
    }

    /// An allowlisted name is exempt from the DNSBL check, and the exemption
    /// covers everything under it. With a resolver that lists every name, any
    /// name that is *not* allowlisted is NXDOMAIN, so a SERVFAIL (no forwarders
    /// configured) is proof the query fell through the blocklist step.
    #[tokio::test]
    async fn test_dnsbl_allowlist_exempts_name_and_subdomains() {
        let db = Database::open_memory().unwrap();
        db.add_dnsbl_allowlist_entry("vendor.example.com", "false positive")
            .unwrap();
        let server = make_test_server_with_dnsbl(db, Arc::new(AlwaysListedResolver)).await;

        for name in [
            "vendor.example.com.",
            "cdn.vendor.example.com.",
            "a.b.vendor.example.com.",
        ] {
            let query = build_query(name, RecordType::A);
            let resp = Message::from_bytes(&server.handle_query(&query).await.unwrap()).unwrap();
            assert_eq!(
                resp.response_code(),
                ResponseCode::ServFail,
                "{} should be exempt from the DNSBL",
                name
            );
        }

        // A name outside the allowlist is still blocked.
        let blocked = build_query("ads.example.net.", RecordType::A);
        let blocked_resp = query_until_blocked(&server, &blocked).await;
        assert_eq!(blocked_resp.response_code(), ResponseCode::NXDomain);
    }

    /// A near-miss of an allowlist entry is not exempt: the match is on label
    /// boundaries, not a string suffix.
    #[tokio::test]
    async fn test_dnsbl_allowlist_does_not_over_match() {
        let db = Database::open_memory().unwrap();
        db.add_dnsbl_allowlist_entry("example.com", "vendor")
            .unwrap();
        let server = make_test_server_with_dnsbl(db, Arc::new(AlwaysListedResolver)).await;

        let blocked = build_query("notexample.com.", RecordType::A);
        let blocked_resp = query_until_blocked(&server, &blocked).await;
        assert_eq!(blocked_resp.response_code(), ResponseCode::NXDomain);
    }

    /// The allowlist runs *before* the provider lookup, so an exempt name costs
    /// no upstream blocklist query at all — the point being that an allowlist
    /// entry removes the name from the check rather than discarding its verdict.
    #[tokio::test]
    async fn test_dnsbl_allowlist_issues_no_provider_lookup() {
        let db = Database::open_memory().unwrap();
        db.add_dnsbl_allowlist_entry("vendor.example.com", "")
            .unwrap();
        let lookups = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(CountingListedResolver {
            lookups: lookups.clone(),
        });
        let server = make_test_server_with_dnsbl(db, resolver).await;

        let query = build_query("cdn.vendor.example.com.", RecordType::A);
        for _ in 0..5 {
            let resp = Message::from_bytes(&server.handle_query(&query).await.unwrap()).unwrap();
            assert_eq!(resp.response_code(), ResponseCode::ServFail);
        }
        // The fills are fire-and-forget; give any spawned task a chance to run
        // before concluding that none was spawned.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(lookups.load(Ordering::Relaxed), 0);

        // The same server does issue lookups for a name that is not exempt.
        let other = build_query("ads.example.net.", RecordType::A);
        query_until_blocked(&server, &other).await;
        assert!(lookups.load(Ordering::Relaxed) > 0);
    }

    /// The allowlist is the operator's escape hatch, so it also overrides a
    /// local RBL entry for the same name.
    #[tokio::test]
    async fn test_dnsbl_allowlist_overrides_local_rbl_entry() {
        let db = Database::open_memory().unwrap();
        db.add_local_rbl_entry("tracker.example.com", "ad tracker")
            .unwrap();
        db.add_dnsbl_allowlist_entry("tracker.example.com", "needed by vendor app")
            .unwrap();
        // DNS-based providers are disabled; only the local list would block.
        let server = make_test_server(db);

        let query = build_query("tracker.example.com.", RecordType::A);
        let resp = Message::from_bytes(&server.handle_query(&query).await.unwrap()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::ServFail);
    }

    /// Removing the allowlist entry restores blocking immediately — the answer
    /// is not served from a stale cache, because the blocklist step runs ahead
    /// of the DNS cache lookup.
    #[tokio::test]
    async fn test_dnsbl_allowlist_removal_restores_blocking() {
        let db = Database::open_memory().unwrap();
        db.add_dnsbl_allowlist_entry("vendor.example.com", "")
            .unwrap();
        let server = make_test_server_with_dnsbl(db.clone(), Arc::new(AlwaysListedResolver)).await;

        let query = build_query("vendor.example.com.", RecordType::A);
        let resp = Message::from_bytes(&server.handle_query(&query).await.unwrap()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::ServFail);

        assert!(
            db.remove_dnsbl_allowlist_entry("vendor.example.com")
                .unwrap()
        );
        let blocked = query_until_blocked(&server, &query).await;
        assert_eq!(blocked.response_code(), ResponseCode::NXDomain);
    }

    /// Builds a server with both RBL and DNSBL globally ENABLED but with empty
    /// provider lists — the default configuration — to prove an enabled-but-empty
    /// blocklist blocks nothing.
    async fn make_test_server_empty_blocklists(db: Database) -> Arc<DnsServer> {
        let rbl = Arc::new(RblChecker::with_resolver(
            true,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        rbl.set_dnsbl_config(true, vec![]).await;
        Arc::new(DnsServer::new(db, rbl, vec![]))
    }

    #[tokio::test]
    async fn test_empty_rbl_does_not_block_reverse_dns() {
        let db = Database::open_memory().unwrap();
        // A local PTR record so the reverse query has a real answer.
        db.add_record(&DnsRecord {
            id: None,
            name: "100.1.168.192.in-addr.arpa.".to_string(),
            record_type: RecordKind::PTR,
            value: "host.local.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server_empty_blocklists(db).await;

        // With RBL enabled but no providers, the reverse lookup is not blocked
        // and resolves from the local database.
        let q = build_query("100.1.168.192.in-addr.arpa.", RecordType::PTR);
        let resp = Message::from_bytes(&server.handle_query(&q).await.unwrap()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);

        // A reverse lookup with no local record is likewise not blocked; it
        // falls through to SERVFAIL (no forwarders) rather than NXDOMAIN.
        let q2 = build_query("200.1.168.192.in-addr.arpa.", RecordType::PTR);
        let resp2 = Message::from_bytes(&server.handle_query(&q2).await.unwrap()).unwrap();
        assert_eq!(resp2.response_code(), ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn test_empty_dnsbl_does_not_block_forward_domain() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "gitea.default.home.".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.5".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server_empty_blocklists(db).await;

        // Local record resolves normally.
        let local = build_query("gitea.default.home.", RecordType::A);
        let local_resp = Message::from_bytes(&server.handle_query(&local).await.unwrap()).unwrap();
        assert_eq!(local_resp.response_code(), ResponseCode::NoError);
        assert_eq!(local_resp.answers().len(), 1);

        // An external name is NOT blocked by the enabled-but-empty DNSBL; it
        // falls through to forwarding and SERVFAILs (no forwarders), proving it
        // was never turned into an NXDOMAIN block.
        let ext = build_query("googleadservices.com.", RecordType::A);
        let ext_resp = Message::from_bytes(&server.handle_query(&ext).await.unwrap()).unwrap();
        assert_eq!(ext_resp.response_code(), ResponseCode::ServFail);
    }

    #[test]
    fn test_extract_ip_from_name_ipv4() {
        let ip = extract_ip_from_name("100.1.168.192.in-addr.arpa.");
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
    }

    #[test]
    fn test_extract_ip_from_name_not_reverse() {
        let ip = extract_ip_from_name("example.com.");
        assert_eq!(ip, None);
    }

    #[test]
    fn test_extract_ip_from_name_ipv6() {
        let name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.";
        let ip = extract_ip_from_name(name);
        assert_eq!(ip, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_map_query_type_to_kind() {
        assert_eq!(map_query_type_to_kind(RecordType::A), Some(RecordKind::A));
        assert_eq!(
            map_query_type_to_kind(RecordType::AAAA),
            Some(RecordKind::AAAA)
        );
        assert_eq!(
            map_query_type_to_kind(RecordType::CNAME),
            Some(RecordKind::CNAME)
        );
        assert_eq!(map_query_type_to_kind(RecordType::MX), Some(RecordKind::MX));
        assert_eq!(
            map_query_type_to_kind(RecordType::TXT),
            Some(RecordKind::TXT)
        );
        assert_eq!(map_query_type_to_kind(RecordType::NS), Some(RecordKind::NS));
        assert_eq!(
            map_query_type_to_kind(RecordType::SOA),
            Some(RecordKind::SOA)
        );
        assert_eq!(
            map_query_type_to_kind(RecordType::SRV),
            Some(RecordKind::SRV)
        );
        assert_eq!(
            map_query_type_to_kind(RecordType::PTR),
            Some(RecordKind::PTR)
        );
        assert_eq!(
            map_query_type_to_kind(RecordType::CERT),
            Some(RecordKind::CERT)
        );
    }

    #[test]
    fn test_db_record_to_dns_record_cert() {
        // CERT (RFC 4398): "cert_type key_tag algorithm base64_cert_data"
        let payload = b"fake der bytes";
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, payload);
        let db_rec = DnsRecord {
            id: None,
            name: "_ca.example.com.".to_string(),
            record_type: RecordKind::CERT,
            value: format!("1 0 0 {}", b64),
            ttl: 3600,
            priority: 0,
        };
        let rec = db_record_to_dns_record(&db_rec).expect("CERT record");
        assert_eq!(rec.record_type(), RecordType::CERT);
        match rec.data() {
            RData::CERT(cert) => {
                assert_eq!(u16::from(cert.cert_type()), 1); // PKIX
                assert_eq!(cert.key_tag(), 0);
                assert_eq!(u8::from(cert.algorithm()), 0);
                assert_eq!(cert.cert_data(), payload);
            }
            other => panic!("expected CERT rdata, got {:?}", other),
        }
    }

    #[test]
    fn test_db_record_to_dns_record_cert_malformed() {
        let db_rec = DnsRecord {
            id: None,
            name: "_ca.example.com.".to_string(),
            record_type: RecordKind::CERT,
            value: "1 0 0 not!base64!".to_string(),
            ttl: 3600,
            priority: 0,
        };
        assert!(db_record_to_dns_record(&db_rec).is_none());
        let too_short = DnsRecord {
            value: "1 0 0".to_string(),
            ..db_rec
        };
        assert!(db_record_to_dns_record(&too_short).is_none());
    }

    #[test]
    fn test_db_record_to_dns_record_a() {
        let db_rec = DnsRecord {
            id: None,
            name: "test.local.".to_string(),
            record_type: RecordKind::A,
            value: "192.168.1.1".to_string(),
            ttl: 300,
            priority: 0,
        };
        let record = db_record_to_dns_record(&db_rec).unwrap();
        assert_eq!(record.record_type(), RecordType::A);
        assert_eq!(record.ttl(), 300);
    }

    #[test]
    fn test_db_record_to_dns_record_invalid_ip() {
        let db_rec = DnsRecord {
            id: None,
            name: "test.local.".to_string(),
            record_type: RecordKind::A,
            value: "not-an-ip".to_string(),
            ttl: 300,
            priority: 0,
        };
        assert!(db_record_to_dns_record(&db_rec).is_none());
    }

    #[tokio::test]
    async fn test_set_forwarders() {
        let db = Database::open_memory().unwrap();
        let server = make_test_server(db);
        assert!(server.get_forwarders().await.is_empty());

        server
            .set_forwarders(vec!["8.8.8.8:53".parse().unwrap()])
            .await;
        let forwarders = server.get_forwarders().await;
        assert_eq!(forwarders.len(), 1);
    }

    #[tokio::test]
    async fn test_resolution_mode_default_and_set() {
        let db = Database::open_memory().unwrap();
        let server = make_test_server(db);
        // The library default is Forward so tests stay hermetic.
        assert_eq!(server.get_resolution_mode(), ResolutionMode::Forward);
        server.set_resolution_mode(ResolutionMode::Recursive);
        assert_eq!(server.get_resolution_mode(), ResolutionMode::Recursive);
    }

    fn response_with_rcode(rcode: ResponseCode) -> Vec<u8> {
        let mut m = Message::new();
        m.set_id(1);
        m.set_message_type(MessageType::Response);
        m.set_response_code(rcode);
        m.to_bytes().unwrap()
    }

    #[test]
    fn test_response_is_definitive() {
        // NoError and NXDomain are authoritative yes/no answers.
        assert!(response_is_definitive(&response_with_rcode(
            ResponseCode::NoError
        )));
        assert!(response_is_definitive(&response_with_rcode(
            ResponseCode::NXDomain
        )));
        // ServFail/Refused mean "couldn't answer" — fall through to the next tier.
        assert!(!response_is_definitive(&response_with_rcode(
            ResponseCode::ServFail
        )));
        assert!(!response_is_definitive(&response_with_rcode(
            ResponseCode::Refused
        )));
        // Garbage never parses.
        assert!(!response_is_definitive(&[0u8, 1]));
    }

    // Auto mode: a downward (degrade) switch only commits after the failure
    // grace period; the active tier stays put until then.
    #[tokio::test]
    async fn test_auto_switch_respects_grace() {
        let db = Database::open_memory().unwrap();
        let server = make_test_server(db);
        server.set_auto_params(3, 60);
        assert_eq!(server.active_tier(), TIER_ROOTS);

        // Two deviations (roots failing, local answering) — below grace, no switch.
        server.note_auto_winner(TIER_LOCAL);
        assert_eq!(server.active_tier(), TIER_ROOTS);
        server.note_auto_winner(TIER_LOCAL);
        assert_eq!(server.active_tier(), TIER_ROOTS);
        // Third consecutive deviation reaches grace — switch commits.
        server.note_auto_winner(TIER_LOCAL);
        assert_eq!(server.active_tier(), TIER_LOCAL);
    }

    // A single success on the active tier resets the deviation streak, so a
    // lone flap can never accumulate into a switch.
    #[tokio::test]
    async fn test_auto_flap_does_not_switch() {
        let db = Database::open_memory().unwrap();
        let server = make_test_server(db);
        server.set_auto_params(3, 60);
        server.note_auto_winner(TIER_LOCAL); // deviation
        server.note_auto_winner(TIER_ROOTS); // active answered — resets streak
        server.note_auto_winner(TIER_LOCAL); // deviation (streak restarts at 1)
        server.note_auto_winner(TIER_LOCAL); // 2
        assert_eq!(server.active_tier(), TIER_ROOTS); // still not switched
    }

    // Auto mode: recovery to a more-preferred tier is immediate and flushes the
    // cache first (cross-tier poisoning guard).
    #[tokio::test]
    async fn test_auto_recovery_immediate_and_flushes_cache() {
        let db = Database::open_memory().unwrap();
        let cache = Arc::new(crate::dns_cache::DnsCache::new(db.clone()));
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        let server =
            DnsServer::new_with_options(db.clone(), rbl, vec![], Some(cache.clone()), None, false);

        // Pretend we had degraded to the local tier and cached an answer there.
        server.active_tier.store(TIER_LOCAL, Ordering::Relaxed);
        cache.insert(
            "cached.example.",
            Some(RecordKind::A),
            vec![DnsRecord {
                id: None,
                name: "cached.example.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            }],
            300,
        );
        assert_eq!(cache.stats().total_entries, 1);

        // Roots (more preferred) answered again → immediate switch up + flush.
        server.note_auto_winner(TIER_ROOTS);
        assert_eq!(server.active_tier(), TIER_ROOTS);
        assert_eq!(cache.stats().total_entries, 0);
    }

    // Auto mode: once degraded, the start tier is the sticky active tier, except
    // for a periodic probe from the top to reclaim a recovered tier.
    #[tokio::test]
    async fn test_auto_start_tier_probes_periodically() {
        let db = Database::open_memory().unwrap();
        let server = make_test_server(db);

        // At the top there is nothing to probe for.
        assert_eq!(server.auto_start_tier(), TIER_ROOTS);

        // Degraded, with a recent probe: start at the sticky active tier (fast).
        server.active_tier.store(TIER_LOCAL, Ordering::Relaxed);
        server.set_auto_params(3, 3600);
        server.last_probe.store(unix_now_secs(), Ordering::Relaxed);
        assert_eq!(server.auto_start_tier(), TIER_LOCAL);

        // Probe interval elapsed: start from the top once, then revert to sticky.
        server.last_probe.store(0, Ordering::Relaxed);
        assert_eq!(server.auto_start_tier(), TIER_ROOTS);
        assert_eq!(server.auto_start_tier(), TIER_LOCAL);
    }

    #[tokio::test]
    async fn test_recursive_mode_local_record_wins() {
        // In recursive mode, a locally-defined record must still be served
        // from the database (split-horizon: local always wins) without ever
        // attempting to reach the root servers.
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "local.example.".to_string(),
            record_type: RecordKind::A,
            value: "10.1.2.3".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        server.set_resolution_mode(ResolutionMode::Recursive);

        let query = build_query("local.example.", RecordType::A);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
    }

    #[test]
    fn test_build_response() {
        let query_bytes = build_query("test.local.", RecordType::A);
        let query = Message::from_bytes(&query_bytes).unwrap();

        let response_bytes = build_response(&query, ResponseCode::NoError, vec![]);
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.id(), query.id());
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }

    #[test]
    fn test_make_error_response() {
        let query_bytes = build_query("test.local.", RecordType::A);
        let response_bytes = make_error_response(&query_bytes, ResponseCode::ServFail);
        let response = Message::from_bytes(&response_bytes).unwrap();
        assert_eq!(response.response_code(), ResponseCode::ServFail);
    }

    // ================================================================
    // Network Scoping Tests
    // ================================================================

    use crate::db::{NetworkAssociation, NetworkScope};

    #[tokio::test]
    async fn test_scoped_record_lookup() {
        let db = Database::open_memory().unwrap();

        // Create a scope and add a scoped record
        db.create_network_scope(&NetworkScope {
            name: "testnet".to_string(),
            home_domain: "testnet.home".to_string(),
        })
        .unwrap();

        db.add_scoped_record(
            "testnet",
            &DnsRecord {
                id: None,
                name: "server.testnet.home.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        // Associate an IP with the scope
        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.50".to_string(),
            scope_name: "testnet".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("server.testnet.home.", RecordType::A);
        let response_bytes = server
            .handle_query_from(&query, "192.168.1.50".parse().unwrap())
            .await
            .unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        if let RData::A(rdata::A(ip)) = response.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 1));
        } else {
            panic!("expected A record");
        }
    }

    #[tokio::test]
    async fn test_unassociated_overlay_peer_refused_when_scopes_exist() {
        let db = Database::open_memory().unwrap();

        // Create a scope but don't associate the querying IP.
        db.create_network_scope(&NetworkScope {
            name: "private".to_string(),
            home_domain: "private.home".to_string(),
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("anything.com.", RecordType::A);
        // An unassociated *overlay* peer (10.64.0.0/10) is refused: it is a
        // WireGuard link that hasn't joined any network.
        let response_bytes = server
            .handle_query_from(&query, "10.64.0.99".parse().unwrap())
            .await
            .unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::Refused);
    }

    #[tokio::test]
    async fn test_unassociated_lan_client_not_refused_when_scopes_exist() {
        let db = Database::open_memory().unwrap();

        // A scope exists, but a LAN client is a trusted local source: it must
        // NOT be refused even though it isn't joined to any network.
        db.create_network_scope(&NetworkScope {
            name: "private".to_string(),
            home_domain: "private.home".to_string(),
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("anything.com.", RecordType::A);
        let response_bytes = server
            .handle_query_from(&query, "192.168.1.99".parse().unwrap())
            .await
            .unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_ne!(response.response_code(), ResponseCode::Refused);
    }

    #[tokio::test]
    async fn test_no_scopes_allows_all_queries() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "open.test.".to_string(),
            record_type: RecordKind::A,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("open.test.", RecordType::A);
        let response_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_scoped_records_isolated_between_scopes() {
        let db = Database::open_memory().unwrap();

        // Create two scopes with different views
        db.create_network_scope(&NetworkScope {
            name: "scope_a".to_string(),
            home_domain: "a.home".to_string(),
        })
        .unwrap();
        db.create_network_scope(&NetworkScope {
            name: "scope_b".to_string(),
            home_domain: "b.home".to_string(),
        })
        .unwrap();

        // Same name, different values per scope
        db.add_scoped_record(
            "scope_a",
            &DnsRecord {
                id: None,
                name: "shared.internal.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();
        db.add_scoped_record(
            "scope_b",
            &DnsRecord {
                id: None,
                name: "shared.internal.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.2".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        // Associate IPs
        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.1".to_string(),
            scope_name: "scope_a".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();
        db.join_network(&NetworkAssociation {
            ip_address: "192.168.2.1".to_string(),
            scope_name: "scope_b".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("shared.internal.", RecordType::A);

        // Query from scope_a IP
        let resp_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        if let RData::A(rdata::A(ip)) = resp.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 1));
        }

        // Query from scope_b IP
        let resp_bytes = server
            .handle_query_from(&query, "192.168.2.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        if let RData::A(rdata::A(ip)) = resp.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 2));
        }
    }

    #[tokio::test]
    async fn test_scoped_rbl_blocks_reverse_dns() {
        let db = Database::open_memory().unwrap();

        db.create_network_scope(&NetworkScope {
            name: "rblscope".to_string(),
            home_domain: "rblscope.home".to_string(),
        })
        .unwrap();
        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.1".to_string(),
            scope_name: "rblscope".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server_with_rbl(db, true);
        let query = build_query("100.1.168.192.in-addr.arpa.", RecordType::PTR);
        let resp = query_from_until_blocked(&server, &query, "192.168.1.1".parse().unwrap()).await;
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn test_scoped_cname_lookup() {
        let db = Database::open_memory().unwrap();

        db.create_network_scope(&NetworkScope {
            name: "cnamescope".to_string(),
            home_domain: "cnamescope.home".to_string(),
        })
        .unwrap();

        db.add_scoped_record(
            "cnamescope",
            &DnsRecord {
                id: None,
                name: "alias.cnamescope.home.".to_string(),
                record_type: RecordKind::CNAME,
                value: "real.cnamescope.home.".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.1".to_string(),
            scope_name: "cnamescope".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("alias.cnamescope.home.", RecordType::A);
        let resp_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();

        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_scoped_managed_zone_nxdomain() {
        let db = Database::open_memory().unwrap();

        db.create_network_scope(&NetworkScope {
            name: "zonescope".to_string(),
            home_domain: "zonescope.home".to_string(),
        })
        .unwrap();

        // Add a record at the zone level to make it authoritative
        db.add_scoped_record(
            "zonescope",
            &DnsRecord {
                id: None,
                name: "zonescope.home.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        // Also add a record under the zone
        db.add_scoped_record(
            "zonescope",
            &DnsRecord {
                id: None,
                name: "existing.zonescope.home.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.2".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.1".to_string(),
            scope_name: "zonescope".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server(db);

        // Query for a known name should succeed
        let query = build_query("existing.zonescope.home.", RecordType::A);
        let resp_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);

        // Query for a non-existent name under the scoped managed zone
        let query = build_query("nonexistent.zonescope.home.", RecordType::A);
        let resp_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();

        // Should get authoritative NXDOMAIN since the zone exists but name doesn't
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn test_expired_association_refused() {
        let db = Database::open_memory().unwrap();

        db.create_network_scope(&NetworkScope {
            name: "expirenet".to_string(),
            home_domain: "expirenet.home".to_string(),
        })
        .unwrap();

        db.add_scoped_record(
            "expirenet",
            &DnsRecord {
                id: None,
                name: "host.expirenet.home.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        // An overlay peer (10.64.0.0/10) so that, once its association expires,
        // it falls back to the "unassociated overlay peer" refusal path rather
        // than the trusted-local path.
        db.join_network(&NetworkAssociation {
            ip_address: "10.64.0.1".to_string(),
            scope_name: "expirenet".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server(db.clone());

        // Should resolve while association is active
        let query = build_query("host.expirenet.home.", RecordType::A);
        let resp_bytes = server
            .handle_query_from(&query, "10.64.0.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);

        // Expire the association cache entry
        db.expire_association("10.64.0.1");

        // Should get REFUSED after association expires
        let resp_bytes = server
            .handle_query_from(&query, "10.64.0.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::Refused);
    }

    #[tokio::test]
    async fn test_scoped_query_falls_through_to_global() {
        let db = Database::open_memory().unwrap();

        db.create_network_scope(&NetworkScope {
            name: "fallthrough".to_string(),
            home_domain: "fallthrough.home".to_string(),
        })
        .unwrap();

        // Add a global record (not scoped)
        db.add_record(&DnsRecord {
            id: None,
            name: "global.test.".to_string(),
            record_type: RecordKind::A,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.1".to_string(),
            scope_name: "fallthrough".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("global.test.", RecordType::A);
        let resp_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();

        // Should still resolve global records even when in a scope
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
    }

    // ================================================================
    // extract_qname tests
    // ================================================================

    #[test]
    fn test_extract_qname_simple() {
        // "example.com." in wire format: \x07example\x03com\x00
        let data = b"\x07example\x03com\x00";
        assert_eq!(extract_qname(data).unwrap(), "example.com.");
    }

    #[test]
    fn test_extract_qname_subdomain() {
        // "sub.example.com." in wire format
        let data = b"\x03sub\x07example\x03com\x00";
        assert_eq!(extract_qname(data).unwrap(), "sub.example.com.");
    }

    #[test]
    fn test_extract_qname_single_label() {
        let data = b"\x03com\x00";
        assert_eq!(extract_qname(data).unwrap(), "com.");
    }

    #[test]
    fn test_extract_qname_empty() {
        // Root label only
        let data = b"\x00";
        assert_eq!(extract_qname(data).unwrap(), ".");
    }

    #[test]
    fn test_extract_qname_truncated() {
        // Label says 7 bytes but only 3 follow
        let data = b"\x07exa";
        assert!(extract_qname(data).is_none());
    }

    #[test]
    fn test_extract_qname_empty_input() {
        assert!(extract_qname(b"").is_none());
    }

    // ================================================================
    // randomize_qname_case tests
    // ================================================================

    #[test]
    fn test_randomize_qname_case_preserves_structure() {
        let query = build_query("example.com.", RecordType::A);
        let result = randomize_qname_case(&query);
        assert!(result.is_some());
        let (modified, original, _randomized) = result.unwrap();

        // Original name should be correct
        assert_eq!(original.to_lowercase(), "example.com.");

        // Modified bytes should be valid DNS and same length
        assert_eq!(modified.len(), query.len());

        // Should parse as a valid DNS message
        let msg = Message::from_bytes(&modified).unwrap();
        assert_eq!(msg.id(), 1234);
        assert_eq!(msg.queries().len(), 1);
    }

    #[test]
    fn test_randomize_qname_case_only_changes_alpha() {
        let query = build_query("test-123.example.com.", RecordType::A);
        // Run many times to exercise randomness
        for _ in 0..20 {
            if let Some((modified, _, _)) = randomize_qname_case(&query) {
                // DNS header (12 bytes) should be identical
                assert_eq!(&modified[..12], &query[..12]);

                // Non-alpha bytes in labels should be unchanged
                // Walk labels and check digits/hyphens
                let mut pos = 12;
                while pos < modified.len() {
                    let label_len = modified[pos] as usize;
                    if label_len == 0 {
                        break;
                    }
                    // Label length byte unchanged
                    assert_eq!(modified[pos], query[pos]);
                    for i in 1..=label_len {
                        let orig = query[pos + i];
                        let modif = modified[pos + i];
                        if !orig.is_ascii_alphabetic() {
                            // Non-alpha bytes must be unchanged
                            assert_eq!(modif, orig);
                        } else {
                            // Alpha bytes should differ only by case bit
                            assert_eq!(modif.to_ascii_lowercase(), orig.to_ascii_lowercase());
                        }
                    }
                    pos += label_len + 1;
                }
            }
        }
    }

    #[test]
    fn test_randomize_qname_case_too_short() {
        assert!(randomize_qname_case(b"").is_none());
        assert!(randomize_qname_case(b"short").is_none());
        assert!(randomize_qname_case(&[0u8; 12]).is_none());
    }

    #[test]
    fn test_randomize_qname_case_round_trip_names() {
        let query = build_query("My.DnS.Name.", RecordType::AAAA);
        let (_, original, randomized) = randomize_qname_case(&query).unwrap();
        // Both should normalize to the same lowercase name
        assert_eq!(original.to_lowercase(), randomized.to_lowercase());
    }

    // ================================================================
    // lookup_with_fallbacks integration tests
    // ================================================================

    #[tokio::test]
    async fn test_lookup_with_fallbacks_exact_hit() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "exact.example.com.".to_string(),
            record_type: RecordKind::A,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("exact.example.com.", RecordType::A);
        let resp_bytes = server.handle_query(&query).await.unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_lookup_with_fallbacks_cname_fallback() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "alias.example.com.".to_string(),
            record_type: RecordKind::CNAME,
            value: "target.example.com.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("alias.example.com.", RecordType::A);
        let resp_bytes = server.handle_query(&query).await.unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_lookup_with_fallbacks_aname_resolution() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "aname.example.com.".to_string(),
            record_type: RecordKind::ANAME,
            value: "target.example.com.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "target.example.com.".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("aname.example.com.", RecordType::A);
        let resp_bytes = server.handle_query(&query).await.unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        if let RData::A(rdata::A(ip)) = resp.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 1));
        } else {
            panic!("expected A record");
        }
    }

    #[tokio::test]
    async fn test_lookup_with_fallbacks_exact_over_cname() {
        let db = Database::open_memory().unwrap();
        // Both exact A and CNAME exist - exact should win
        db.add_record(&DnsRecord {
            id: None,
            name: "both.example.com.".to_string(),
            record_type: RecordKind::A,
            value: "1.1.1.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "both.example.com.".to_string(),
            record_type: RecordKind::CNAME,
            value: "other.example.com.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("both.example.com.", RecordType::A);
        let resp_bytes = server.handle_query(&query).await.unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        // Should get the A record, not the CNAME
        if let RData::A(rdata::A(ip)) = resp.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(1, 1, 1, 1));
        } else {
            panic!("expected A record, not CNAME");
        }
    }

    #[test]
    fn build_canary_query_is_a_valid_recursive_a_query() {
        let bytes = build_canary_query().expect("canary query builds");
        let msg = Message::from_bytes(&bytes).expect("canary query parses");
        let q = msg.queries().first().expect("has a question");
        assert_eq!(q.query_type(), RecordType::A);
        assert_eq!(q.name().to_ascii(), "one.one.one.one.");
        assert!(msg.recursion_desired());
    }

    // ================================================================
    // Per-network TLD partition + per-TLD peer forwarding
    // ================================================================

    /// Spawns a minimal UDP "peer rolodex" on loopback. If `answer` is Some, it
    /// replies NoError with that A record for any query; if None, it replies
    /// SERVFAIL (a non-definitive answer, to exercise forwarder failover).
    /// Returns the bound address. The task runs until the test ends.
    async fn spawn_mock_peer(answer: Option<Ipv4Addr>) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (len, src) = match socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let query = match Message::from_bytes(&buf[..len]) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let mut resp = Message::new();
                resp.set_id(query.id());
                resp.set_message_type(MessageType::Response);
                resp.set_op_code(OpCode::Query);
                if let Some(q) = query.queries().first() {
                    resp.add_query(q.clone());
                    match answer {
                        Some(ip) => {
                            resp.set_response_code(ResponseCode::NoError);
                            let rec =
                                Record::from_rdata(q.name().clone(), 60, RData::A(rdata::A(ip)));
                            resp.add_answer(rec);
                        }
                        None => {
                            resp.set_response_code(ResponseCode::ServFail);
                        }
                    }
                }
                if let Ok(bytes) = resp.to_bytes() {
                    socket.send_to(&bytes, src).await.ok();
                }
            }
        });
        addr
    }

    fn office_scope(db: &Database) {
        db.create_network_scope(&NetworkScope {
            name: "office".to_string(),
            home_domain: "office.home".to_string(),
        })
        .unwrap();
        db.add_scope_tld("office", "office").unwrap();
        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.1".to_string(),
            scope_name: "office".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();
    }

    #[tokio::test]
    async fn test_owned_tld_serves_scoped_record() {
        let db = Database::open_memory().unwrap();
        office_scope(&db);
        db.add_scoped_record(
            "office",
            &DnsRecord {
                id: None,
                name: "gitea.office.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.7".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("gitea.office.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_from(&query, "192.168.1.1".parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
    }

    /// Builds an office scope owning `office.` with a scoped A record
    /// `gitea.office. -> 10.0.0.7` and an ingress listener on `ingress`.
    fn ingress_scope(db: &Database, ingress: IpAddr) {
        office_scope(db);
        db.set_tld_listener("office", "office", ingress).unwrap();
        db.add_scoped_record(
            "office",
            &DnsRecord {
                id: None,
                name: "gitea.office.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.7".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();
    }

    fn answer_a(resp: &Message) -> Ipv4Addr {
        match resp.answers()[0].data() {
            RData::A(rdata::A(ip)) => *ip,
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_ingress_override_rewrites_on_ingress_listener() {
        // A programmed A name under an ingress TLD, queried on that TLD's ingress
        // listener, is rewritten to the ingress IP (the ingress controller) —
        // NOT the stored backend value.
        let ingress: IpAddr = "127.0.0.9".parse().unwrap();
        let db = Database::open_memory().unwrap();
        ingress_scope(&db, ingress);
        let server = make_test_server(db);

        let query = build_query("gitea.office.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_on(&query, "127.0.0.1".parse().unwrap(), Some(ingress))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(answer_a(&resp), Ipv4Addr::new(127, 0, 0, 9));
    }

    #[tokio::test]
    async fn test_ingress_no_override_on_main_listener() {
        // The same name on the main listener (no concrete local IP), queried by a
        // scope member, resolves to the stored backend value — the rewrite is
        // confined to the ingress listener. `office_scope` joins 192.168.1.1.
        let ingress: IpAddr = "127.0.0.9".parse().unwrap();
        let db = Database::open_memory().unwrap();
        ingress_scope(&db, ingress);
        let server = make_test_server(db);

        let query = build_query("gitea.office.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_from(&query, "192.168.1.1".parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(answer_a(&resp), Ipv4Addr::new(10, 0, 0, 7));
    }

    #[tokio::test]
    async fn test_ingress_no_override_on_wrong_listener_ip() {
        // A query arriving on a concrete listener IP that is NOT this TLD's
        // ingress IP is not rewritten (e.g. another TLD's ingress listener).
        // Queried by a scope member so it resolves the scoped backend value.
        let ingress: IpAddr = "127.0.0.9".parse().unwrap();
        let other: IpAddr = "127.0.0.8".parse().unwrap();
        let db = Database::open_memory().unwrap();
        ingress_scope(&db, ingress);
        let server = make_test_server(db);

        let query = build_query("gitea.office.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_on(&query, "192.168.1.1".parse().unwrap(), Some(other))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(answer_a(&resp), Ipv4Addr::new(10, 0, 0, 7));
    }

    #[tokio::test]
    async fn test_ingress_no_synthesis_for_unprogrammed_name() {
        // Only PROGRAMMED names are subject to the rewrite. A name with no record
        // under the ingress TLD is an authoritative NXDOMAIN even on the ingress
        // listener — no wildcard synthesis to the ingress IP.
        let ingress: IpAddr = "127.0.0.9".parse().unwrap();
        let db = Database::open_memory().unwrap();
        ingress_scope(&db, ingress);
        let server = make_test_server(db);

        let query = build_query("missing.office.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_on(&query, "127.0.0.1".parse().unwrap(), Some(ingress))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
        assert!(resp.answers().is_empty());
    }

    #[tokio::test]
    async fn test_ingress_override_only_matching_family() {
        // An IPv4 ingress IP does not rewrite an AAAA answer; the stored AAAA
        // value passes through unchanged (family mismatch).
        let ingress: IpAddr = "127.0.0.9".parse().unwrap();
        let db = Database::open_memory().unwrap();
        office_scope(&db);
        db.set_tld_listener("office", "office", ingress).unwrap();
        db.add_scoped_record(
            "office",
            &DnsRecord {
                id: None,
                name: "gitea.office.".to_string(),
                record_type: RecordKind::AAAA,
                value: "fd00::7".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();
        let server = make_test_server(db);

        let query = build_query("gitea.office.", RecordType::AAAA);
        let resp = Message::from_bytes(
            &server
                .handle_query_on(&query, "127.0.0.1".parse().unwrap(), Some(ingress))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        match resp.answers()[0].data() {
            RData::AAAA(rdata::AAAA(ip)) => {
                assert_eq!(*ip, "fd00::7".parse::<Ipv6Addr>().unwrap())
            }
            other => panic!("expected AAAA record, got {:?}", other),
        }
    }

    /// A WireGuard peer of the network: inside the default overlay CIDR
    /// (10.64.0.0/10) and — as in production — never joined to a scope. Only the
    /// box's own ingress IP is joined; the peers are not.
    const OVERLAY_PEER: &str = "10.81.113.179";

    #[tokio::test]
    async fn test_ingress_listener_resolves_name_outside_its_tld() {
        // Regression: an ingress listener is its network's resolver for the WHOLE
        // namespace, not just its own TLD. Scope used to be selected from the
        // queried NAME, so a name outside the TLD fell into the source-IP branch,
        // where an unassociated overlay peer is REFUSED — a WireGuard client could
        // resolve `gitea.office.` and nothing else. It must resolve, and pass
        // through with its own value (the rewrite is confined to the owned TLD).
        let ingress: IpAddr = "127.0.0.9".parse().unwrap();
        let db = Database::open_memory().unwrap();
        ingress_scope(&db, ingress);
        db.add_record(&DnsRecord {
            id: None,
            name: "example.com.".to_string(),
            record_type: RecordKind::A,
            value: "93.184.216.34".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        let server = make_test_server(db);

        let query = build_query("example.com.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_on(&query, OVERLAY_PEER.parse().unwrap(), Some(ingress))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(answer_a(&resp), Ipv4Addr::new(93, 184, 216, 34));
    }

    #[tokio::test]
    async fn test_ingress_listener_rewrites_owned_tld_for_overlay_peer() {
        // The other half: the same unassociated overlay peer still gets the owned
        // TLD's programmed name rewritten to the ingress IP.
        let ingress: IpAddr = "127.0.0.9".parse().unwrap();
        let db = Database::open_memory().unwrap();
        ingress_scope(&db, ingress);
        let server = make_test_server(db);

        let query = build_query("gitea.office.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_on(&query, OVERLAY_PEER.parse().unwrap(), Some(ingress))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(answer_a(&resp), Ipv4Addr::new(127, 0, 0, 9));
    }

    #[tokio::test]
    async fn test_ingress_listener_still_hides_sibling_network_tld() {
        // Serving the whole namespace must not dissolve the partition: a sibling
        // network's owned TLD stays hidden (authoritative NXDOMAIN), never served
        // and never forwarded.
        let ingress: IpAddr = "127.0.0.9".parse().unwrap();
        let db = Database::open_memory().unwrap();
        ingress_scope(&db, ingress);
        db.create_network_scope(&NetworkScope {
            name: "lab".to_string(),
            home_domain: "lab.home".to_string(),
        })
        .unwrap();
        db.add_scope_tld("lab", "lab").unwrap();
        db.add_scoped_record(
            "lab",
            &DnsRecord {
                id: None,
                name: "secret.lab.".to_string(),
                record_type: RecordKind::A,
                value: "10.9.9.9".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();
        let server = make_test_server(db);

        let query = build_query("secret.lab.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_on(&query, OVERLAY_PEER.parse().unwrap(), Some(ingress))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
        assert!(resp.answers().is_empty());
    }

    #[tokio::test]
    async fn test_unassociated_overlay_peer_still_refused_off_ingress() {
        // The ingress relaxation is confined to the ingress listener. The same
        // unassociated overlay peer hitting the MAIN listener (no concrete local
        // IP) is still refused — scope enforcement off the listener is unchanged.
        let ingress: IpAddr = "127.0.0.9".parse().unwrap();
        let db = Database::open_memory().unwrap();
        ingress_scope(&db, ingress);
        let server = make_test_server(db);

        let query = build_query("example.com.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_from(&query, OVERLAY_PEER.parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::Refused);
    }

    #[tokio::test]
    async fn test_spawn_and_stop_ingress_listener_registry() {
        // The listener registry is idempotent per IP and torn down on stop.
        let db = Database::open_memory().unwrap();
        let server = make_test_server(db);
        server.set_ingress_port(0); // ephemeral port — avoids privileged :53
        let ip: IpAddr = "127.0.0.20".parse().unwrap();

        assert!(!server.has_ingress_listener(ip));
        server.spawn_ingress_listener(ip);
        assert!(server.has_ingress_listener(ip));
        assert_eq!(server.ingress_listener_count(), 1);
        // Idempotent: a second spawn for the same IP does not add a listener.
        server.spawn_ingress_listener(ip);
        assert_eq!(server.ingress_listener_count(), 1);

        server.stop_ingress_listener(ip);
        assert!(!server.has_ingress_listener(ip));
        assert_eq!(server.ingress_listener_count(), 0);
    }

    /// Polls `cond` until it holds, or panics after ~2s. Used to await the
    /// asynchronous exit of a listener task whose bind failed.
    async fn wait_until(mut cond: impl FnMut() -> bool) {
        for _ in 0..200 {
            if cond() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("condition not met within 2s");
    }

    /// Regression: a listener whose bind FAILED must not poison its IP.
    ///
    /// The registry records abort handles at spawn time — before either task has
    /// tried to bind — so a failed bind leaves an entry behind that claims the
    /// address is served while nothing is listening on it. This is not a corner
    /// case: it happens on every boot for a WireGuard overlay address, because
    /// `sync_ingress_listeners` replays the TLD's ingress IP from the database
    /// before the overlay interface exists, so both tasks fail EADDRNOTAVAIL and
    /// exit. With a presence-only check, every later `AddScopeTld` re-add
    /// early-returns on the corpse: rolodex logs "Added TLD ... with ingress
    /// listener <ip>" and binds nothing, permanently — the controller can never
    /// bring the listener up once the interface appears, and every peer's DNS
    /// lands on a closed port.
    #[tokio::test]
    async fn test_failed_ingress_bind_does_not_poison_ip() {
        let db = Database::open_memory().unwrap();
        let server = make_test_server(db);
        let ip: IpAddr = "127.0.0.21".parse().unwrap();

        // Occupy the ingress port on `ip` for BOTH protocols so the spawned UDP
        // and TCP tasks each fail to bind — the same outcome as binding an
        // address the host does not have yet, without touching the host's
        // addresses. Loopback only; nothing outside this process is affected.
        let tcp_squatter = std::net::TcpListener::bind((ip, 0)).unwrap();
        let port = tcp_squatter.local_addr().unwrap().port();
        let udp_squatter = std::net::UdpSocket::bind((ip, port)).unwrap();
        server.set_ingress_port(port);

        server.spawn_ingress_listener(ip);

        // Both tasks fail and exit. The registry must report the listener as
        // absent rather than claim an unbound address is being served.
        wait_until(|| !server.has_ingress_listener(ip)).await;
        assert_eq!(server.ingress_listener_count(), 0);

        // The address becomes bindable — the overlay interface came up. A re-add
        // must actually retry the bind instead of early-returning on the dead
        // entry. This is the assertion the old code failed.
        drop(tcp_squatter);
        drop(udp_squatter);
        server.spawn_ingress_listener(ip);
        assert!(server.has_ingress_listener(ip));
        assert_eq!(server.ingress_listener_count(), 1);

        server.stop_ingress_listener(ip);
        assert!(!server.has_ingress_listener(ip));
        assert_eq!(server.ingress_listener_count(), 0);
    }

    /// Sends `query` from a fresh client socket and returns the parsed response.
    /// Each call uses a new ephemeral source port, so the kernel's `SO_REUSEPORT`
    /// hash picks a different shard per call — which is exactly what makes this
    /// a test of the shard fan-out and not of one lucky socket. Retries while the
    /// listener is still coming up.
    async fn udp_query(target: &str, query: &[u8]) -> Message {
        for _ in 0..200 {
            let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            if client.send_to(query, target).await.is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            }
            let mut buf = vec![0u8; MAX_UDP_SIZE];
            match tokio::time::timeout(
                std::time::Duration::from_millis(250),
                client.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok((len, _))) => return Message::from_bytes(&buf[..len]).unwrap(),
                _ => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }
        panic!("no UDP response from {} within 2s", target);
    }

    /// Reserves a free loopback port and releases it, so the caller can bind a
    /// listener there. Nothing outside this process is touched.
    fn free_loopback_port() -> u16 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        port
    }

    /// A sharded listener must be indistinguishable from the single-socket one
    /// on the client side. The kernel hashes each source port to one of the
    /// shards, so a client that reconnects lands on an arbitrary shard — every
    /// one of them has to serve the same view. A shard that bound but never got
    /// wired to the query handler would show up here as a timeout on some
    /// fraction of the queries, not on all of them.
    #[tokio::test]
    async fn test_sharded_udp_listener_answers_from_any_shard() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "shard.test.".to_string(),
            record_type: RecordKind::A,
            value: "127.0.0.30".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        let server = make_test_server(db);
        server.set_udp_shards(4);

        let bind = format!("127.0.0.1:{}", free_loopback_port());
        let srv = Arc::clone(&server);
        let listen = bind.clone();
        let handle = tokio::spawn(async move { srv.serve_udp(&listen).await });

        let query = build_query("shard.test.", RecordType::A);
        for _ in 0..24 {
            let resp = udp_query(&bind, &query).await;
            assert_eq!(resp.response_code(), ResponseCode::NoError);
            assert_eq!(answer_a(&resp), Ipv4Addr::new(127, 0, 0, 30));
        }

        handle.abort();
    }

    /// Aborting the task that drives `serve_udp` must take the shards down with
    /// it. The shards are spawned inside the future rather than by the caller, so
    /// the caller's abort handle no longer points at them directly — they are
    /// held in a `JoinSet` that the future owns, and dropping it aborts them. If
    /// that ownership were broken the shards would outlive the abort and keep the
    /// port bound, and `stop_ingress_listener` would silently stop stopping
    /// anything.
    #[tokio::test]
    async fn test_aborting_serve_udp_releases_all_shards() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "up.test.".to_string(),
            record_type: RecordKind::A,
            value: "127.0.0.31".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        let server = make_test_server(db);
        server.set_udp_shards(4);

        let bind = format!("127.0.0.1:{}", free_loopback_port());
        let srv = Arc::clone(&server);
        let listen = bind.clone();
        let handle = tokio::spawn(async move { srv.serve_udp(&listen).await });

        // Confirm it is actually up before aborting, so a pass cannot come from
        // the listener never having bound in the first place. A locally-served
        // name keeps this off the upstream path entirely.
        let query = build_query("up.test.", RecordType::A);
        assert_eq!(
            answer_a(&udp_query(&bind, &query).await),
            Ipv4Addr::new(127, 0, 0, 31)
        );

        handle.abort();

        // Every shard socket must be closed: a plain, non-REUSEPORT bind on the
        // same address only succeeds once they are all gone.
        let addr: SocketAddr = bind.parse().unwrap();
        wait_until(|| std::net::UdpSocket::bind(addr).is_ok()).await;
    }

    /// The ingress bind-failure handling depends on a busy port being reported as
    /// an error, and `SO_REUSEPORT` is precisely the option that turns such a
    /// collision into silent sharing. Linux only shares a port when *every*
    /// socket on it set the option, so a squatter that did not set it still
    /// collides — but this pins that, because the day it stops holding,
    /// `sync_ingress_listeners` starts "succeeding" against ports owned by other
    /// processes and steals their traffic.
    #[tokio::test]
    async fn test_sharded_bind_still_fails_on_port_held_without_reuseport() {
        let db = Database::open_memory().unwrap();
        let server = make_test_server(db);
        server.set_udp_shards(4);

        let addr: SocketAddr = format!("127.0.0.1:{}", free_loopback_port())
            .parse()
            .unwrap();
        let squatter = std::net::UdpSocket::bind(addr).unwrap();

        let err = Arc::clone(&server)
            .serve_udp(&addr.to_string())
            .await
            .expect_err("bind must fail while another socket holds the port");
        assert!(
            format!("{:#}", err).contains("failed to bind UDP socket"),
            "unexpected error: {:#}",
            err
        );

        drop(squatter);
    }

    /// A single-shard listener must not set `SO_REUSEPORT` at all — otherwise two
    /// rolodex listeners configured for the same address would quietly split the
    /// traffic between them instead of the second one reporting the conflict.
    #[tokio::test]
    async fn test_single_shard_listener_does_not_share_its_port() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "solo.test.".to_string(),
            record_type: RecordKind::A,
            value: "127.0.0.32".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        let server = make_test_server(db);
        server.set_udp_shards(1);

        let bind = format!("127.0.0.1:{}", free_loopback_port());
        let srv = Arc::clone(&server);
        let listen = bind.clone();
        let handle = tokio::spawn(async move { srv.serve_udp(&listen).await });

        let query = build_query("solo.test.", RecordType::A);
        assert_eq!(
            answer_a(&udp_query(&bind, &query).await),
            Ipv4Addr::new(127, 0, 0, 32)
        );

        // The second listener asks for several shards, so it *does* set
        // SO_REUSEPORT. It must still be refused, because the first socket did
        // not — otherwise the two would split the traffic silently.
        server.set_udp_shards(4);
        let second = Arc::clone(&server).serve_udp(&bind).await;
        assert!(
            second.is_err(),
            "a single-shard listener must not let a second listener share its port"
        );

        handle.abort();
    }

    /// Regression: a CNAME-chained answer must be cached under the QUESTION, not
    /// under its first answer record.
    ///
    /// `index.crates.io A` comes back as `index.crates.io CNAME` →
    /// `fastly-index.crates.io CNAME` → A records on a third name. Keying on
    /// `answers[0]` filed that under `index.crates.io.:CNAME` while every lookup
    /// asked for `index.crates.io.:A`, so the name was permanently uncacheable
    /// and every single query paid a full upstream round trip — which is most of
    /// the CDN-fronted internet. It went unnoticed because a name like
    /// `example.com` answers with an A record for itself, making the wrong key
    /// accidentally right; every test used names of that shape.
    #[tokio::test]
    async fn test_cname_chain_is_cached_under_the_question() {
        let db = Database::open_memory().unwrap();
        let cache = Arc::new(crate::dns_cache::DnsCache::new(db.clone()));
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        let server =
            DnsServer::new_with_options(db, rbl, vec![], Some(Arc::clone(&cache)), None, true);

        let mut question = hickory_proto::op::Query::new();
        question
            .set_name(Name::from_ascii("index.crates.io.").unwrap())
            .set_query_type(RecordType::A)
            .set_query_class(DNSClass::IN);

        let answers = vec![
            Record::from_rdata(
                Name::from_ascii("index.crates.io.").unwrap(),
                96,
                RData::CNAME(rdata::CNAME(
                    Name::from_ascii("fastly-index.crates.io.").unwrap(),
                )),
            ),
            Record::from_rdata(
                Name::from_ascii("fastly-index.crates.io.").unwrap(),
                96,
                RData::CNAME(rdata::CNAME(
                    Name::from_ascii("dualstack.k.sni.global.fastly.net.").unwrap(),
                )),
            ),
            Record::from_rdata(
                Name::from_ascii("dualstack.k.sni.global.fastly.net.").unwrap(),
                24,
                RData::A(rdata::A(Ipv4Addr::new(151, 101, 2, 137))),
            ),
        ];

        server.cache_answers(&question, &answers);

        // The key the read path actually uses.
        let hit = cache.lookup("index.crates.io.", Some(RecordKind::A));
        assert!(
            !hit.is_empty(),
            "a CNAME-chained answer must be retrievable by the name and type that were ASKED for"
        );
        assert_eq!(
            hit.len(),
            3,
            "the whole chain is served, not just the CNAME"
        );
    }

    /// Regression: 0x20 encoding must not poison the cache key.
    ///
    /// The two sides of the cache do not see the same case. Reads use the case
    /// the client sent; writes use the case the question came back in — and with
    /// `security.qname_case_randomization` (on by default) a forwarded query
    /// goes out as `eXaMpLe.CoM` and the response echoes that back. A key built
    /// from the raw string therefore stores every upstream answer under a
    /// randomly-cased key no lookup can ever reproduce, disabling the cache
    /// wholesale — every name, not just chained ones.
    #[tokio::test]
    async fn test_cache_key_survives_qname_case_randomization() {
        let db = Database::open_memory().unwrap();
        let cache = Arc::new(crate::dns_cache::DnsCache::new(db.clone()));
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        let server =
            DnsServer::new_with_options(db, rbl, vec![], Some(Arc::clone(&cache)), None, true);

        // The question exactly as a 0x20-randomized response echoes it back.
        let mut question = hickory_proto::op::Query::new();
        question
            .set_name(Name::from_ascii("eXaMpLe.CoM.").unwrap())
            .set_query_type(RecordType::A)
            .set_query_class(DNSClass::IN);

        let answers = vec![Record::from_rdata(
            Name::from_ascii("eXaMpLe.CoM.").unwrap(),
            300,
            RData::A(rdata::A(Ipv4Addr::new(93, 184, 216, 34))),
        )];

        server.cache_answers(&question, &answers);

        // The client asked in lowercase and must get the hit.
        assert!(
            !cache.lookup("example.com.", Some(RecordKind::A)).is_empty(),
            "a randomized-case response must be findable by the lowercase name the client queried"
        );
    }

    #[tokio::test]
    async fn test_split_horizon_overlay_scoped_local_global() {
        // Split-horizon for a network package name under an owned TLD:
        //   - a joined WireGuard-overlay peer resolves the SCOPED record (the
        //     overlay IP, reachable over the tunnel);
        //   - the host's loopback / a LAN client resolves the GLOBAL record (the
        //     box's LAN IP, reachable on the local network).
        // Each side is handed an address it can actually route to. This is how a
        // package like `gitea.default.fart` is reachable from both networks.
        let db = Database::open_memory().unwrap();
        db.create_network_scope(&NetworkScope {
            name: "office".to_string(),
            home_domain: "office.home".to_string(),
        })
        .unwrap();
        db.add_scope_tld("office", "office").unwrap();
        // The overlay peer is a joined member (overlay addresses are the only
        // IPs the controller ever joins).
        db.join_network(&NetworkAssociation {
            ip_address: "10.64.0.5".to_string(),
            scope_name: "office".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();
        // Scoped record -> overlay IP (served to the wireguard peer).
        db.add_scoped_record(
            "office",
            &DnsRecord {
                id: None,
                name: "gitea.office.".to_string(),
                record_type: RecordKind::A,
                value: "10.83.6.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();
        // Global record -> LAN IP (served to local clients).
        db.add_record(&DnsRecord {
            id: None,
            name: "gitea.office.".to_string(),
            record_type: RecordKind::A,
            value: "192.168.122.50".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("gitea.office.", RecordType::A);

        let answer_from = |src: IpAddr| {
            let server = server.clone();
            let query = query.clone();
            async move {
                let resp =
                    Message::from_bytes(&server.handle_query_from(&query, src).await.unwrap())
                        .unwrap();
                assert_eq!(resp.response_code(), ResponseCode::NoError);
                assert_eq!(resp.answers().len(), 1);
                match resp.answers()[0].data() {
                    RData::A(rdata::A(ip)) => *ip,
                    other => panic!("expected A record, got {other:?}"),
                }
            }
        };

        // WireGuard overlay peer -> scoped overlay IP.
        assert_eq!(
            answer_from("10.64.0.5".parse().unwrap()).await,
            Ipv4Addr::new(10, 83, 6, 1)
        );
        // Loopback (the box itself) -> global LAN IP.
        assert_eq!(
            answer_from("127.0.0.1".parse().unwrap()).await,
            Ipv4Addr::new(192, 168, 122, 50)
        );
        // A LAN client -> global LAN IP too (trusted local, not an overlay peer).
        assert_eq!(
            answer_from("192.168.122.77".parse().unwrap()).await,
            Ipv4Addr::new(192, 168, 122, 50)
        );
    }

    // Create an owned-TLD network scope with a single scoped A record. Mirrors the
    // town-os EnsureNetworkScope/EnsureScopedTLD plumbing: the scope owns `tld` via
    // its home_domain (the implicit primary TLD — no add_scope_tld needed) and
    // holds one scoped record.
    fn owned_tld_scope(db: &Database, scope: &str, tld: &str, name: &str, ip: &str) {
        db.create_network_scope(&NetworkScope {
            name: scope.to_string(),
            home_domain: format!("{tld}."),
        })
        .unwrap();
        db.add_scoped_record(
            scope,
            &DnsRecord {
                id: None,
                name: name.to_string(),
                record_type: RecordKind::A,
                value: ip.to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();
    }

    // Extract the single A answer's IPv4 from a resolved response, asserting NoError.
    fn expect_single_a(resp: &Message) -> Ipv4Addr {
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1, "expected exactly one answer");
        match resp.answers()[0].data() {
            RData::A(rdata::A(ip)) => *ip,
            other => panic!("expected A record, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_lan_fallback_resolves_all_owned_tlds() {
        // A LAN/loopback client (not on any WireGuard overlay, joined to nothing)
        // resolves EVERY network's owned TLD from that network's scope — .fart AND
        // .fart2 — so all TLDs are visible on the LAN even though the records are
        // stored scoped. This is the LAN->owning-scope fallback.
        let db = Database::open_memory().unwrap();
        owned_tld_scope(&db, "fart", "fart", "gitea.default.fart.", "10.83.6.1");
        owned_tld_scope(&db, "fart2", "fart2", "wiki.default.fart2.", "10.99.0.2");

        let server = make_test_server(db);
        let lan: IpAddr = "192.168.122.77".parse().unwrap();

        let fart = Message::from_bytes(
            &server
                .handle_query_from(&build_query("gitea.default.fart.", RecordType::A), lan)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(expect_single_a(&fart), Ipv4Addr::new(10, 83, 6, 1));

        let fart2 = Message::from_bytes(
            &server
                .handle_query_from(&build_query("wiki.default.fart2.", RecordType::A), lan)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(expect_single_a(&fart2), Ipv4Addr::new(10, 99, 0, 2));
    }

    #[tokio::test]
    async fn test_lan_fallback_unknown_owned_name_is_authoritative_nxdomain() {
        // A LAN query for a name under an owned TLD that has no record must NOT be
        // forwarded upstream (a private TLD never leaks to the public internet).
        // make_test_server has no forwarders, so a fall-through would be SERVFAIL;
        // asserting an authoritative NXDOMAIN proves the fallback fired.
        let db = Database::open_memory().unwrap();
        owned_tld_scope(&db, "fart", "fart", "gitea.default.fart.", "10.83.6.1");

        let server = make_test_server(db);
        let lan: IpAddr = "192.168.122.77".parse().unwrap();
        let resp = Message::from_bytes(
            &server
                .handle_query_from(&build_query("absent.default.fart.", RecordType::A), lan)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
        assert!(resp.authoritative());
    }

    #[tokio::test]
    async fn test_wg_peer_partition_hides_sibling_tld_and_home() {
        // TLDs are partitioned across WireGuard endpoints: a peer joined to `fart`
        // resolves .fart, but .fart2 (a sibling network) and .home (the LAN-only,
        // DNS-only owned scope) are both hidden with an authoritative NXDOMAIN.
        let db = Database::open_memory().unwrap();
        owned_tld_scope(&db, "fart", "fart", "gitea.default.fart.", "10.83.6.1");
        owned_tld_scope(&db, "fart2", "fart2", "wiki.default.fart2.", "10.99.0.2");
        // .home is a DNS-only owned scope (no WG transport) with a GLOBAL record.
        db.create_network_scope(&NetworkScope {
            name: "home".to_string(),
            home_domain: "home.".to_string(),
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "nginx.default.home.".to_string(),
            record_type: RecordKind::A,
            value: "192.168.122.50".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        // A WireGuard-overlay peer joined to fart.
        db.join_network(&NetworkAssociation {
            ip_address: "10.64.0.5".to_string(),
            scope_name: "fart".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server(db);
        let peer: IpAddr = "10.64.0.5".parse().unwrap();

        // Own TLD resolves (scoped overlay IP).
        let own = Message::from_bytes(
            &server
                .handle_query_from(&build_query("gitea.default.fart.", RecordType::A), peer)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(expect_single_a(&own), Ipv4Addr::new(10, 83, 6, 1));

        // Sibling network's TLD is hidden.
        let sibling = Message::from_bytes(
            &server
                .handle_query_from(&build_query("wiki.default.fart2.", RecordType::A), peer)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(sibling.response_code(), ResponseCode::NXDomain);
        assert!(sibling.authoritative());

        // .home is hidden from the WG peer even though it has a global record.
        let home = Message::from_bytes(
            &server
                .handle_query_from(&build_query("nginx.default.home.", RecordType::A), peer)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(home.response_code(), ResponseCode::NXDomain);
        assert!(home.authoritative());
    }

    #[tokio::test]
    async fn test_lan_resolves_home_global_record() {
        // .home is LAN-only: a LAN client resolves its GLOBAL record directly (the
        // global lookup wins before the fallback), even though .home is an owned
        // scope for the sake of hiding it from WG peers.
        let db = Database::open_memory().unwrap();
        db.create_network_scope(&NetworkScope {
            name: "home".to_string(),
            home_domain: "home.".to_string(),
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "nginx.default.home.".to_string(),
            record_type: RecordKind::A,
            value: "192.168.122.50".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let lan: IpAddr = "192.168.122.77".parse().unwrap();
        let resp = Message::from_bytes(
            &server
                .handle_query_from(&build_query("nginx.default.home.", RecordType::A), lan)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(expect_single_a(&resp), Ipv4Addr::new(192, 168, 122, 50));
    }

    #[tokio::test]
    async fn test_loopback_bypasses_scope_refusal() {
        // A scope exists, so an unassociated remote IP would be REFUSED — but
        // loopback (the host's resolver path) must never be refused, otherwise
        // creating any network kills the box's own DNS. A non-owned public name
        // has no local answer and no forwarder here, so it will not be NoError;
        // the point is that it is NOT Refused.
        let db = Database::open_memory().unwrap();
        office_scope(&db);

        let server = make_test_server(db);
        let query = build_query("example.com.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_from(&query, "127.0.0.1".parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_ne!(resp.response_code(), ResponseCode::Refused);
    }

    #[tokio::test]
    async fn test_owned_tld_no_record_no_forwarder_nxdomain() {
        let db = Database::open_memory().unwrap();
        office_scope(&db);

        // make_test_server has NO global forwarders, so a fall-through would
        // yield SERVFAIL. Asserting NXDOMAIN proves the partition fired.
        let server = make_test_server(db);
        let query = build_query("absent.office.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_from(&query, "192.168.1.1".parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
        assert!(resp.authoritative());
    }

    #[tokio::test]
    async fn test_owned_tld_forwards_to_peer() {
        let db = Database::open_memory().unwrap();
        office_scope(&db);
        let peer = spawn_mock_peer(Some(Ipv4Addr::new(10, 9, 9, 9))).await;
        db.set_scope_tld_forwarders("office", "office", &[peer.to_string()])
            .unwrap();

        let server = make_test_server(db);
        let query = build_query("app.office.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_from(&query, "192.168.1.1".parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        if let RData::A(rdata::A(ip)) = resp.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(10, 9, 9, 9));
        } else {
            panic!("expected A record from peer");
        }
    }

    #[tokio::test]
    async fn test_owned_tld_forwarder_failover() {
        let db = Database::open_memory().unwrap();
        office_scope(&db);
        // First peer SERVFAILs (non-definitive); second answers.
        let dead = spawn_mock_peer(None).await;
        let good = spawn_mock_peer(Some(Ipv4Addr::new(10, 8, 8, 8))).await;
        db.set_scope_tld_forwarders("office", "office", &[dead.to_string(), good.to_string()])
            .unwrap();

        let server = make_test_server(db);
        let query = build_query("svc.office.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_from(&query, "192.168.1.1".parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        if let RData::A(rdata::A(ip)) = resp.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(10, 8, 8, 8));
        } else {
            panic!("expected A record from second peer");
        }
    }

    #[tokio::test]
    async fn test_cross_scope_tld_hidden() {
        let db = Database::open_memory().unwrap();
        office_scope(&db);
        // A different scope owns lab. with a forwarder configured.
        db.create_network_scope(&NetworkScope {
            name: "lab".to_string(),
            home_domain: "lab.home".to_string(),
        })
        .unwrap();
        db.add_scope_tld("lab", "lab").unwrap();
        let peer = spawn_mock_peer(Some(Ipv4Addr::new(10, 5, 5, 5))).await;
        db.set_scope_tld_forwarders("lab", "lab", &[peer.to_string()])
            .unwrap();

        // Query from the office network for a name under lab. is hidden.
        let server = make_test_server(db);
        let query = build_query("secret.lab.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_from(&query, "192.168.1.1".parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
        assert!(resp.authoritative());
        assert!(resp.answers().is_empty());
    }

    #[tokio::test]
    async fn test_partition_does_not_forward_upstream() {
        let db = Database::open_memory().unwrap();
        office_scope(&db);

        // Configure a bogus GLOBAL forwarder. A name under the querying scope's
        // owned TLD must still NXDOMAIN (partition) rather than be forwarded.
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        let server = Arc::new(DnsServer::new(
            db,
            rbl,
            vec!["203.0.113.1:53".parse().unwrap()],
        ));
        let query = build_query("nothing.office.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_from(&query, "192.168.1.1".parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
        assert!(resp.authoritative());
    }

    #[tokio::test]
    async fn test_non_owned_name_falls_through() {
        let db = Database::open_memory().unwrap();
        office_scope(&db);

        // A name NOT under any owned TLD falls through to upstream. With no
        // global forwarders that is SERVFAIL — proving the partition did not
        // hijack a non-owned name into an authoritative NXDOMAIN.
        let server = make_test_server(db);
        let query = build_query("example.com.", RecordType::A);
        let resp = Message::from_bytes(
            &server
                .handle_query_from(&query, "192.168.1.1".parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::ServFail);
    }

    /// The default recursion ranges cover every network physically attached to
    /// the box — and nothing that is routable from the internet.
    #[test]
    fn default_recursion_ranges_cover_local_networks_only() {
        let server = make_test_server(Database::open_memory().unwrap());
        for local in [
            "127.0.0.1",
            "192.168.1.10",
            "10.0.0.5",
            "10.64.0.1", // the WireGuard overlay, inside 10/8
            "172.16.4.4",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(
                server.may_recurse(local.parse().unwrap()),
                "{} is a local source and must get recursion",
                local
            );
        }
        for public in [
            "198.51.100.7",
            "8.8.8.8",
            "203.0.113.1",
            "2001:4860:4860::8888",
        ] {
            assert!(
                !server.may_recurse(public.parse().unwrap()),
                "{} is routable from the internet and must not get recursion",
                public
            );
        }
    }

    /// An IPv4-mapped source is canonicalized before classification, so it is
    /// judged the same as its plain form (see `handle_query_on`).
    #[tokio::test]
    async fn recursion_guard_sees_through_ipv4_mapped_sources() {
        let server = make_test_server(Database::open_memory().unwrap());
        // Forward with no forwarders: a source that *does* get recursion fails
        // immediately instead of walking to the real root servers.
        server.set_resolution_mode(ResolutionMode::Forward);
        let query = build_query("not-local.example.", RecordType::A);

        let refused = Message::from_bytes(
            &server
                .handle_query_from(&query, "::ffff:198.51.100.7".parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(refused.response_code(), ResponseCode::Refused);

        // The LAN, in the same spelling, is not refused. (No forwarders are
        // configured, so it SERVFAILs — it got recursion and recursion failed.)
        let served = Message::from_bytes(
            &server
                .handle_query_from(&query, "::ffff:192.168.1.10".parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(served.response_code(), ResponseCode::ServFail);
    }

    /// `set_recursion_cidrs` replaces the defaults; an empty list closes
    /// recursion entirely, leaving a purely authoritative server.
    #[test]
    fn recursion_ranges_are_replaceable() {
        let server = make_test_server(Database::open_memory().unwrap());
        server.set_recursion_cidrs(vec![crate::cidr::IpCidr::parse("198.51.100.0/24").unwrap()]);
        assert!(server.may_recurse("198.51.100.7".parse().unwrap()));
        assert!(!server.may_recurse("192.168.1.10".parse().unwrap()));

        server.set_recursion_cidrs(vec![]);
        assert!(!server.may_recurse("127.0.0.1".parse().unwrap()));
    }
}
