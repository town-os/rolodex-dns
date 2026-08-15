use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Index into [`crate::metrics::BLOCK_KINDS`] for a provider lookup.
const BLOCK_DNSBL_PROVIDER: usize = 1;

/// Outcome indices for the second dimension of
/// [`crate::metrics::Metrics::blocklist_lookups`].
const LOOKUP_LISTED: usize = 0;
const LOOKUP_NOT_LISTED: usize = 1;
const LOOKUP_ERROR: usize = 2;
const LOOKUP_REFUSED: usize = 3;

/// How long a provider stays rotated out after a refusal when neither the
/// provider nor its list configures a value.
pub const DEFAULT_REFUSAL_COOLDOWN_SECS: u64 = 3600;

/// The `refusal_codes` spelling that means "this provider has no refusal codes"
/// — i.e. disable refusal detection rather than fall back to
/// [`DEFAULT_REFUSAL_CODES`]. An empty list cannot mean that, because an empty
/// list is what every configuration written before this feature existed has.
pub const REFUSAL_CODES_NONE: &str = "none";

/// The documented "your query was refused" codes of the blocklists an operator
/// is likely to configure. A DNSxL answers both a listing and a complaint about
/// the querier with an `A` record under `127.0.0.0/8`, so the *only* thing that
/// separates "this name is malicious" from "stop querying me from a public
/// resolver" is which address came back. Treating the latter as a listing makes
/// the server return NXDOMAIN for **every** name checked against that provider,
/// which is why Spamhaus states these must never be read as reputation.
///
/// | Code | Meaning |
/// | ---- | ------- |
/// | `127.255.255.0/24` | Spamhaus error range: `.252` typo in the zone name, `.254` query via a public/open resolver, `.255` excessive queries |
/// | `127.0.1.255` | Spamhaus DBL answering an IP query — "IP queries not supported" |
/// | `127.0.2.255` | Spamhaus ZRD answering an IP query — same |
/// | `127.0.0.1` | URIBL/SURBL "query blocked" (public resolver / over quota). RFC 5782 §5 also forbids a DNSxL from listing `127.0.0.1`, so it is never a legitimate listing |
/// | `127.0.0.255` | URIBL "query blocked" (over quota) |
///
/// Used when a provider's `refusal_codes` list is empty, so an existing
/// deployment gets the safe reading without editing its configuration. A
/// provider whose *listings* legitimately collide with one of these (a private
/// blocklist answering `127.0.0.1`, say) sets its own list, or
/// [`REFUSAL_CODES_NONE`] to opt out.
pub const DEFAULT_REFUSAL_CODES: &[&str] = &[
    "127.255.255.0/24",
    "127.0.1.255",
    "127.0.2.255",
    "127.0.0.1",
    "127.0.0.255",
];

/// One refusal-code pattern: an IPv4 address, optionally with a prefix length.
///
/// A prefix rather than a bare address because the providers document whole
/// ranges — Spamhaus reserves all of `127.255.255.0/24` for errors and adds
/// codes to it over time, so enumerating today's three would silently start
/// treating tomorrow's fourth as a listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusalCode {
    /// The base address, masked to `prefix`.
    base: Ipv4Addr,
    /// Prefix length in bits; 32 for a bare address.
    prefix: u8,
}

impl RefusalCode {
    /// Parses `127.0.0.1` or `127.255.255.0/24`. The base is masked to the
    /// prefix, so `127.255.255.9/24` and `127.255.255.0/24` are the same code.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (addr_str, prefix) = match s.split_once('/') {
            Some((a, p)) => {
                let prefix: u8 = p
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid prefix in refusal code '{s}'"))?;
                if prefix > 32 {
                    return Err(format!("prefix /{prefix} too long in refusal code '{s}'"));
                }
                (a, prefix)
            }
            None => (s, 32),
        };
        let addr: Ipv4Addr = addr_str
            .trim()
            .parse()
            .map_err(|_| format!("invalid IPv4 address in refusal code '{s}'"))?;
        Ok(Self {
            base: mask_v4(addr, prefix),
            prefix,
        })
    }

    /// Whether `ip` — a code a provider returned — falls in this pattern.
    pub fn matches(&self, ip: Ipv4Addr) -> bool {
        mask_v4(ip, self.prefix) == self.base
    }
}

impl fmt::Display for RefusalCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.prefix == 32 {
            write!(f, "{}", self.base)
        } else {
            write!(f, "{}/{}", self.base, self.prefix)
        }
    }
}

/// Zeroes all bits of `ip` below the top `prefix` bits.
fn mask_v4(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let m = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    (u32::from(ip) & m).into()
}

/// Resolves a configured `refusal_codes` list into the patterns to match with.
///
/// - empty ⇒ [`DEFAULT_REFUSAL_CODES`], so a configuration written before this
///   existed still stops reading error codes as listings;
/// - exactly [`REFUSAL_CODES_NONE`] ⇒ no patterns, refusal detection off;
/// - anything else ⇒ exactly those patterns, with the defaults **not** merged in,
///   so an operator who spells the list out gets the list they spelled out.
pub fn resolve_refusal_codes(specs: &[String]) -> Result<Vec<RefusalCode>, String> {
    if specs.is_empty() {
        return DEFAULT_REFUSAL_CODES
            .iter()
            .map(|s| RefusalCode::parse(s))
            .collect();
    }
    if specs.len() == 1 && specs[0].trim().eq_ignore_ascii_case(REFUSAL_CODES_NONE) {
        return Ok(Vec::new());
    }
    if let Some(bad) = specs
        .iter()
        .find(|s| s.trim().eq_ignore_ascii_case(REFUSAL_CODES_NONE))
    {
        return Err(format!(
            "refusal code '{bad}' disables refusal detection and must be the only entry"
        ));
    }
    specs.iter().map(|s| RefusalCode::parse(s)).collect()
}

/// How long past its TTL a cached **positive** keeps blocking while a refill
/// runs. See [`DnsblChecker::cached_verdict`] for why an expired positive is not
/// simply dropped.
const STALE_POSITIVE_GRACE: Duration = Duration::from_secs(600);

/// What the result cache can say about one provider lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CachedVerdict {
    /// A live entry, within its TTL.
    Fresh(bool),
    /// A positive past its TTL but inside [`STALE_POSITIVE_GRACE`]: keep
    /// blocking, and refresh it in the background.
    StalePositive,
    /// Nothing usable — allow the query now and fill in the background.
    Miss,
}

/// A cached blocklist lookup result.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Whether the name is listed in this provider's zone.
    listed: bool,
    /// When the entry expires.
    expires_at: Instant,
}

/// A domain-blocklist provider configuration used at runtime.
#[derive(Debug, Clone)]
pub struct DnsblProvider {
    /// The DNSBL zone (e.g. "zen.spamhaus.org").
    pub zone: String,
    /// Whether this provider is enabled.
    pub enabled: bool,
    /// Codes this provider returns to mean "I refused your query", already
    /// resolved from configuration by [`resolve_refusal_codes`]. Empty disables
    /// refusal detection for this provider. An `Arc` so the hot path clones a
    /// refcount rather than a `Vec` per provider per query.
    pub refusal_codes: Arc<[RefusalCode]>,
    /// How long this provider is rotated out of the lookup rotation after a
    /// refusal. `None` uses the list-wide default (see
    /// [`DnsblChecker::set_refusal_cooldown`]).
    pub cooldown: Option<Duration>,
}

impl Default for DnsblProvider {
    fn default() -> Self {
        Self {
            zone: String::new(),
            enabled: true,
            refusal_codes: default_refusal_codes(),
            cooldown: None,
        }
    }
}

impl DnsblProvider {
    /// A provider with the built-in default refusal codes and the list-wide
    /// cooldown. Use struct-update syntax to override either.
    pub fn new(zone: impl Into<String>, enabled: bool) -> Self {
        Self {
            zone: zone.into(),
            enabled,
            ..Self::default()
        }
    }

    /// The configured refusal codes rendered back to their configuration
    /// spelling, for `Get*Config` round-trips and the CLI.
    pub fn refusal_code_strings(&self) -> Vec<String> {
        if self.refusal_codes.is_empty() {
            return vec![REFUSAL_CODES_NONE.to_string()];
        }
        self.refusal_codes.iter().map(|c| c.to_string()).collect()
    }
}

/// [`DEFAULT_REFUSAL_CODES`] parsed. The constants are checked by a unit test,
/// so a parse failure here is unreachable and yields an empty list rather than
/// a panic on a code path that runs at boot.
fn default_refusal_codes() -> Arc<[RefusalCode]> {
    DEFAULT_REFUSAL_CODES
        .iter()
        .filter_map(|s| RefusalCode::parse(s).ok())
        .collect()
}

/// What a blocklist zone returned for one query.
///
/// The `A` records are kept rather than reduced to a boolean because a DNSxL
/// encodes *both* its verdict and its complaints in them: `127.0.0.2` is a
/// listing and `127.255.255.254` is "you are querying via a public resolver",
/// and only the address tells them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsblAnswer {
    /// The returned `A` records, in the order the provider sent them.
    pub codes: Vec<Ipv4Addr>,
    /// TTL of the first `A` record.
    pub ttl: u32,
}

impl DnsblAnswer {
    /// An answer carrying one code.
    pub fn single(code: Ipv4Addr, ttl: u32) -> Self {
        Self {
            codes: vec![code],
            ttl,
        }
    }

    /// The conventional listing answer, `127.0.0.2` (RFC 5782 §2.1).
    pub fn listed(ttl: u32) -> Self {
        Self::single(Ipv4Addr::new(127, 0, 0, 2), ttl)
    }
}

/// How one provider answered one lookup, after the returned codes have been
/// read against the provider's refusal codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsblVerdict {
    /// The provider listed the queried IP/name.
    Listed,
    /// The provider answered, and did not list it.
    NotListed,
    /// The provider refused the query; the code it refused with is carried.
    /// **Not** a listing, and not a negative either — we learned nothing about
    /// the queried name.
    Refused(Ipv4Addr),
}

/// Reads a provider's answer against its refusal codes.
///
/// A refusal anywhere in the answer wins over a listing in the same answer.
/// A provider that is complaining is not simultaneously reporting reputation,
/// and erring this way fails *open* (nothing is blocked) where the other order
/// fails closed on every name the provider is asked about.
pub fn classify(answer: Option<&DnsblAnswer>, refusal_codes: &[RefusalCode]) -> DnsblVerdict {
    let Some(answer) = answer else {
        return DnsblVerdict::NotListed;
    };
    if let Some(code) = answer
        .codes
        .iter()
        .find(|c| refusal_codes.iter().any(|r| r.matches(**c)))
    {
        return DnsblVerdict::Refused(*code);
    }
    if answer.codes.is_empty() {
        DnsblVerdict::NotListed
    } else {
        DnsblVerdict::Listed
    }
}

/// Trait for performing blocklist DNS lookups, enabling mock testing.
/// Uses async_trait for dyn-compatibility.
#[async_trait::async_trait]
pub trait DnsblResolver: Send + Sync {
    /// Looks up the given query name's `A` records.
    ///
    /// Returns `Ok(Some(answer))` with the codes the zone returned, or
    /// `Ok(None)` when it returned none (NXDOMAIN/NODATA — definitively not
    /// listed). The codes are returned rather than a verdict because whether a
    /// code means "listed" or "refused" is per-provider configuration, which
    /// the resolver does not hold.
    async fn lookup(&self, query: &str) -> Result<Option<DnsblAnswer>, anyhow::Error>;
}

/// Default blocklist resolver using hickory-resolver.
pub struct HickoryDnsblResolver {
    resolver: hickory_resolver::TokioResolver,
}

impl Default for HickoryDnsblResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl HickoryDnsblResolver {
    pub fn new() -> Self {
        let resolver = hickory_resolver::TokioResolver::builder_tokio()
            .expect("failed to create system resolver")
            .build();
        Self { resolver }
    }
}

#[async_trait::async_trait]
impl DnsblResolver for HickoryDnsblResolver {
    async fn lookup(&self, query: &str) -> Result<Option<DnsblAnswer>, anyhow::Error> {
        match self.resolver.lookup_ip(query).await {
            Ok(response) => Ok(a_answer(response.as_lookup().records())),
            Err(e) => {
                // On any error (including NXDOMAIN), treat as not listed
                // to avoid false positives
                debug!("blocklist lookup for {}: {}", query, e);
                Ok(None)
            }
        }
    }
}

/// Blocklist resolver that resolves provider queries the way rolodex resolves
/// everything else — **recursively from the root servers**, with the configured
/// forwarder(s) as a fallback — instead of via the system resolver.
///
/// This matters for correctness, not just policy. The system resolver is
/// `/etc/resolv.conf`, which on Town OS points at systemd-resolved → rolodex
/// itself. Resolving a blocklist name (`<name>.<zone>`) through that path
/// re-enters rolodex's own query handler, which runs the DNSBL check *again* on
/// the blocklist lookup, appends the zone once more (`<name>.<zone>.<zone>…`),
/// and loops forever — the process spins emitting ever-longer names and never
/// answers the original query. Recursing from the roots (or forwarding to a real
/// upstream) never touches the local resolver, so there is no loop.
pub struct RecursiveDnsblResolver {
    /// Iterative (root-recursive) resolver — the primary path.
    resolver: crate::resolver::IterativeResolver,
    /// Upstream forwarders to fall back to when root recursion can't reach an
    /// answer (e.g. a network that filters outbound :53 to the roots but permits
    /// a local/host-proxied forwarder). Tried in order.
    forwarders: Vec<SocketAddr>,
    /// Per-query timeout for the forwarder fallback.
    timeout: Duration,
}

impl RecursiveDnsblResolver {
    /// Builds a resolver recursing from `root_hints` (built-in roots when empty),
    /// falling back to `forwarders`.
    pub fn new(root_hints: Vec<IpAddr>, forwarders: Vec<SocketAddr>) -> Self {
        Self {
            resolver: crate::resolver::IterativeResolver::new(root_hints),
            forwarders,
            timeout: Duration::from_secs(5),
        }
    }
}

#[async_trait::async_trait]
impl DnsblResolver for RecursiveDnsblResolver {
    async fn lookup(&self, query: &str) -> Result<Option<DnsblAnswer>, anyhow::Error> {
        use hickory_proto::op::ResponseCode;
        use hickory_proto::rr::{DNSClass, Name, RecordType};

        let name = match Name::from_ascii(query) {
            Ok(n) => n,
            Err(e) => {
                debug!("blocklist: skipping unparseable name {}: {}", query, e);
                return Ok(None);
            }
        };

        // 1. Recurse from the roots. This uses its own sockets to the root and
        //    authoritative servers — it never queries the local stub, so the
        //    DNSBL check is not re-triggered and cannot loop.
        match self
            .resolver
            .resolve(&name, RecordType::A, DNSClass::IN)
            .await
        {
            Ok(res) => match res.rcode {
                ResponseCode::NoError => return Ok(a_answer(&res.answers)),
                ResponseCode::NXDomain => return Ok(None),
                // ServFail/Refused/etc. are not definitive — try a forwarder.
                other => debug!(
                    "blocklist roots lookup for {} returned {:?}; trying forwarder",
                    query, other
                ),
            },
            Err(e) => debug!(
                "blocklist roots lookup for {} failed: {}; trying forwarder",
                query, e
            ),
        }

        // 2. Forwarder fallback (a real upstream, still never the local stub).
        for fwd in &self.forwarders {
            match query_forwarder_a(&name, *fwd, self.timeout).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!(
                        "blocklist forwarder {} lookup for {} failed: {}",
                        fwd, query, e
                    );
                    continue;
                }
            }
        }

        // Nothing resolved it — fail open (never block on a resolution failure).
        Ok(None)
    }
}

/// Collects the `A` records in `answers` into an [`DnsblAnswer`], or `None` when
/// there are none — a DNSxL answers with an `A` record (`127.0.0.x`), so its
/// absence (NODATA) means the zone had nothing to say. The addresses are kept
/// because they are the provider's verdict *or* its refusal; see [`classify`].
fn a_answer(answers: &[hickory_proto::rr::Record]) -> Option<DnsblAnswer> {
    use hickory_proto::rr::{RData, rdata};
    let mut codes = Vec::new();
    let mut ttl = 0;
    for rec in answers {
        if let RData::A(rdata::A(ip)) = rec.data() {
            if codes.is_empty() {
                ttl = rec.ttl();
            }
            codes.push(*ip);
        }
    }
    if codes.is_empty() {
        None
    } else {
        Some(DnsblAnswer { codes, ttl })
    }
}

/// Resolves `name`/A against a single forwarder over UDP and classifies it:
/// `Ok(Some(answer))` with the returned codes, `Ok(None)` definitively nothing
/// (NXDOMAIN/NODATA), `Err` when the forwarder gave no usable answer (so the
/// caller tries the next).
async fn query_forwarder_a(
    name: &hickory_proto::rr::Name,
    forwarder: SocketAddr,
    timeout: Duration,
) -> Result<Option<DnsblAnswer>, anyhow::Error> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, RecordType};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

    let mut msg = Message::new();
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(name.clone());
    q.set_query_type(RecordType::A);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    let query = msg.to_bytes()?;

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(&query, forwarder).await?;
    let mut buf = [0u8; 1500];
    let n = tokio::time::timeout(timeout, socket.recv(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("forwarder {} timed out", forwarder))??;
    let resp = Message::from_bytes(&buf[..n])?;
    match resp.response_code() {
        ResponseCode::NoError => Ok(a_answer(resp.answers())),
        ResponseCode::NXDomain => Ok(None),
        other => anyhow::bail!("forwarder {} returned {:?}", forwarder, other),
    }
}

/// The DNSBL checker performs domain-blocklist lookups.
///
/// A name is checked by prepending it to each configured provider zone
/// (`googleadservices.com` + `dbl.spamhaus.org` ->
/// `googleadservices.com.dbl.spamhaus.org`) and reading the `A` records that
/// come back. Results are cached in memory for the TTL the provider returned.
pub struct DnsblChecker {
    /// Whether domain-blocklist checking is globally enabled.
    enabled: AtomicBool,
    /// Configured providers, queried with the name prepended to the zone.
    providers: ArcSwap<Vec<DnsblProvider>>,
    /// Cache of lookup results keyed by "<name>/<zone>".
    cache: Arc<DashMap<String, CacheEntry>>,
    /// DNS resolver for blocklist lookups.
    resolver: Arc<dyn DnsblResolver>,
    /// Whether outbound plaintext DNS (:53) — which provider lookups require —
    /// is currently usable. When false the provider checks are SKIPPED entirely
    /// (they would only time out and add latency on a network that filters
    /// :53). Updated by a background probe; the local DB-backed blocklist is
    /// unaffected. Defaults to true so behavior is unchanged until a probe says
    /// otherwise.
    resolver_available: AtomicBool,
    /// Cache keys with an async fill currently in flight. Lookups are
    /// fire-and-forget: on a cache miss the query is answered immediately and
    /// the verdict is resolved in the background, then served from cache on a
    /// later query. This set dedups concurrent misses for the same
    /// `<name>/<zone>` so they don't fan out duplicate lookups.
    inflight: Arc<DashMap<String, ()>>,
    /// Providers currently rotated out of the lookup rotation because they
    /// refused a query, keyed by zone. See [`DnsblChecker::rotated_out`].
    rotated: Arc<DashMap<String, RotatedOut>>,
    /// Seconds a refusing provider stays rotated out when the provider itself
    /// configures no value.
    refusal_cooldown_secs: AtomicU64,
}

/// A provider taken out of rotation after refusing a query.
#[derive(Debug, Clone)]
struct RotatedOut {
    /// The code it refused with, kept so the operator is told *which* complaint
    /// it was — a typo in the zone name and an over-quota resolver need
    /// different fixes.
    code: Ipv4Addr,
    /// When the provider returns to rotation.
    until: Instant,
}

/// A provider currently out of rotation, as reported over the management API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotatedProvider {
    /// The provider's zone.
    pub zone: String,
    /// The refusal code that took it out of rotation.
    pub code: String,
    /// Seconds until it is queried again.
    pub seconds_remaining: u64,
}

/// One provider's share of a blocklist check: the cache slot to consult and
/// what to do on a miss.
struct ProviderLookup {
    /// `<ip-or-name>/<zone>` — the shared result cache's key.
    cache_key: String,
    /// The name to resolve, e.g. `4.3.2.1.zen.spamhaus.org`.
    query: String,
    /// The provider's zone, which is what rotation is keyed on.
    zone: String,
    /// The provider's refusal codes.
    refusal_codes: Arc<[RefusalCode]>,
    /// How long a refusal from this provider rotates it out.
    cooldown: Duration,
}

impl Default for DnsblChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsblChecker {
    /// Creates a checker with the default hickory resolver, starting disabled
    /// with no providers; configure it via [`set_config`](Self::set_config).
    pub fn new() -> Self {
        Self::with_resolver(Arc::new(HickoryDnsblResolver::new()))
    }

    /// Creates a checker with a custom resolver (for testing).
    pub fn with_resolver(resolver: Arc<dyn DnsblResolver>) -> Self {
        Self {
            enabled: AtomicBool::new(false),
            providers: ArcSwap::from_pointee(Vec::new()),
            cache: Arc::new(DashMap::new()),
            resolver,
            resolver_available: AtomicBool::new(true),
            inflight: Arc::new(DashMap::new()),
            rotated: Arc::new(DashMap::new()),
            refusal_cooldown_secs: AtomicU64::new(DEFAULT_REFUSAL_COOLDOWN_SECS),
        }
    }

    /// Sets how long a refusing provider is rotated out when the provider does
    /// not configure its own value. `0` restores
    /// [`DEFAULT_REFUSAL_COOLDOWN_SECS`] — a zero cooldown would mean the next
    /// query re-asks the provider that just told us to stop, which is the
    /// behaviour rotation exists to prevent.
    pub fn set_refusal_cooldown(&self, secs: u64) {
        let secs = if secs == 0 {
            DEFAULT_REFUSAL_COOLDOWN_SECS
        } else {
            secs
        };
        self.refusal_cooldown_secs.store(secs, Ordering::Relaxed);
    }

    /// The default rotate-out duration.
    pub fn refusal_cooldown(&self) -> Duration {
        Duration::from_secs(self.refusal_cooldown_secs.load(Ordering::Relaxed))
    }

    /// Providers currently out of rotation, with the code that removed them and
    /// the seconds until they return. Expired entries are pruned in passing, so
    /// this is also what keeps the map from growing across a long uptime.
    pub fn rotated_out(&self) -> Vec<RotatedProvider> {
        let now = Instant::now();
        self.rotated.retain(|_, r| r.until > now);
        self.rotated
            .iter()
            .map(|e| RotatedProvider {
                zone: e.key().clone(),
                code: e.value().code.to_string(),
                seconds_remaining: e.value().until.saturating_duration_since(now).as_secs(),
            })
            .collect()
    }

    /// How many providers are currently out of rotation. Sampled by the
    /// Prometheus collector; synchronous and allocation-free because a scrape
    /// must not await.
    pub fn rotated_out_count(&self) -> usize {
        let now = Instant::now();
        self.rotated
            .iter()
            .filter(|e| e.value().until > now)
            .count()
    }

    /// Returns `Some(remaining)` while `zone` is out of rotation, evicting the
    /// entry once it has expired.
    fn rotated_out_for(&self, zone: &str) -> Option<Duration> {
        if let Some(entry) = self.rotated.get(zone) {
            let now = Instant::now();
            if entry.until > now {
                return Some(entry.until.saturating_duration_since(now));
            }
            drop(entry);
            self.rotated.remove(zone);
            info!("blocklist provider {} returned to rotation", zone);
        }
        None
    }

    /// Whether resolver-backed provider lookups are currently usable (outbound
    /// :53 reachable).
    pub fn resolver_available(&self) -> bool {
        self.resolver_available.load(Ordering::Relaxed)
    }

    /// Updates the resolver-availability flag, logging a prominent flag on every
    /// transition so an operator can see when blocklists are dropped/restored.
    pub fn set_resolver_available(&self, available: bool) {
        let previous = self.resolver_available.swap(available, Ordering::Relaxed);
        if previous == available {
            return;
        }
        if available {
            info!("blocklists re-enabled: outbound DNS port 53 is reachable again");
        } else {
            warn!(
                "blocklists DISABLED: outbound DNS port 53 appears filtered — skipping all \
                 resolver-backed provider lookups (the local DB-backed blocklist still \
                 applies)"
            );
        }
    }

    /// Returns the cached verdict for `cache_key`. Never performs a network
    /// lookup.
    ///
    /// An expired **positive** does not become a miss. A miss is answered by
    /// allowing the query (see [`check_cached_or_fill`](Self::check_cached_or_fill)),
    /// so evicting a positive the moment its TTL runs out unblocks the name for
    /// every query until the background refill lands — the blocklist fails
    /// *open*, on a cycle as short as the provider's TTL. Spamhaus DBL answers
    /// with a 60-second TTL, so a listed domain came back to life for a moment
    /// every single minute, which is indistinguishable from the blocklist simply
    /// not working.
    ///
    /// So an expired positive is served stale — it keeps blocking — while a
    /// refill runs, for up to [`STALE_POSITIVE_GRACE`] past expiry. The grace is
    /// bounded because "keep blocking forever" is the opposite failure: a
    /// genuinely delisted name has to be able to come back, and the refill only
    /// overwrites the entry when the provider actually answers (a lookup error
    /// caches nothing). It is generous next to the sub-second refill it covers,
    /// because what it is really covering is a provider having a bad minute.
    ///
    /// An expired **negative** is a miss as before: allowing a name whose
    /// not-listed verdict just went stale is what the code already did on every
    /// cold name, and failing open there is the deliberate hot-path tradeoff.
    fn cached_verdict(&self, cache_key: &str) -> CachedVerdict {
        if let Some(entry) = self.cache.get(cache_key) {
            let now = Instant::now();
            if entry.expires_at > now {
                return CachedVerdict::Fresh(entry.listed);
            }
            if entry.listed && now < entry.expires_at + STALE_POSITIVE_GRACE {
                return CachedVerdict::StalePositive;
            }
            // Past all usefulness: drop the reference before removing.
            drop(entry);
            self.cache.remove(cache_key);
        }
        CachedVerdict::Miss
    }

    /// Cache-only verdict across a set of provider lookups, with fire-and-forget
    /// async fill of any misses.
    ///
    /// Returns `true` as soon as any provider has a fresh **positive** in cache —
    /// a warm listing blocks immediately, and we never wait for the other
    /// providers ("first positive wins, don't wait for all of them"). For any
    /// provider without a cached verdict, an async fill is fired (see
    /// [`fill_cache_async`](Self::fill_cache_async)); the current query is NOT
    /// blocked on the network — a cold name is allowed now and its verdict is
    /// served from cache on a later query once the lookup lands.
    ///
    /// A positive whose TTL has run out still blocks while its refill runs (see
    /// [`cached_verdict`](Self::cached_verdict)) — otherwise expiry would unblock
    /// a listed name once per TTL. That case fires its fill and then returns,
    /// rather than returning early the way a warm positive does.
    ///
    /// A provider that is **rotated out** (see [`rotate_out`](Self::rotate_out))
    /// is skipped for the *fill* only. Its already-cached verdicts still count:
    /// rotation says "this provider will not answer new questions", not "the
    /// answers it already gave were wrong", and dropping those would unblock
    /// genuinely-listed names for the length of the cooldown.
    fn check_cached_or_fill(
        &self,
        lookups: impl IntoIterator<Item = ProviderLookup>,
        kind: usize,
    ) -> bool {
        let mut misses = Vec::new();
        // Set by an expired positive being served stale. Unlike a warm positive
        // it does NOT return early: the whole point is that this entry is due a
        // refresh, so its fill has to be fired before we answer.
        let mut stale_block = false;
        for lookup in lookups {
            match self.cached_verdict(&lookup.cache_key) {
                CachedVerdict::Fresh(true) => return true, // warm positive → block now
                CachedVerdict::Fresh(false) => {}          // warm negative → nothing to do
                CachedVerdict::StalePositive => {
                    stale_block = true;
                    misses.push(lookup);
                }
                CachedVerdict::Miss => misses.push(lookup),
            }
        }
        // No warm positive: fill the cold and stale verdicts in the background.
        for lookup in misses {
            if self.rotated_out_for(&lookup.zone).is_some() {
                crate::metrics::metrics().blocklist_skipped.inc();
                continue;
            }
            self.fill_cache_async(lookup, kind);
        }
        stale_block
    }

    /// Fire-and-forget: unless a fill for this cache key is already in flight,
    /// spawn a background task that resolves the query and populates the result
    /// cache (positive with the provider's TTL, negative for 5 minutes; errors
    /// are left uncached so the next query retries). The hot path never awaits
    /// this.
    ///
    /// A refusal is neither: nothing is cached and the provider is rotated out.
    fn fill_cache_async(&self, lookup: ProviderLookup, kind: usize) {
        let ProviderLookup {
            cache_key,
            query,
            zone,
            refusal_codes,
            cooldown,
        } = lookup;
        // Dedup: if a lookup for this key is already running, don't fan out.
        if self.inflight.insert(cache_key.clone(), ()).is_some() {
            return;
        }
        let resolver = self.resolver.clone();
        let cache = self.cache.clone();
        let inflight = self.inflight.clone();
        let rotated = self.rotated.clone();
        tokio::spawn(async move {
            match resolver.lookup(&query).await {
                Ok(answer) => match classify(answer.as_ref(), &refusal_codes) {
                    DnsblVerdict::Listed => {
                        // `classify` only returns Listed for a non-empty answer.
                        let ttl = answer.as_ref().map(|a| a.ttl).unwrap_or(300);
                        debug!("blocklist async fill: {} listed (TTL: {})", query, ttl);
                        crate::metrics::metrics()
                            .blocklist_lookups
                            .inc(kind, LOOKUP_LISTED);
                        cache.insert(
                            cache_key.clone(),
                            CacheEntry {
                                listed: true,
                                expires_at: Instant::now() + Duration::from_secs(ttl as u64),
                            },
                        );
                    }
                    DnsblVerdict::NotListed => {
                        crate::metrics::metrics()
                            .blocklist_lookups
                            .inc(kind, LOOKUP_NOT_LISTED);
                        cache.insert(
                            cache_key.clone(),
                            CacheEntry {
                                listed: false,
                                expires_at: Instant::now() + Duration::from_secs(300),
                            },
                        );
                    }
                    DnsblVerdict::Refused(code) => {
                        let m = crate::metrics::metrics();
                        m.blocklist_lookups.inc(kind, LOOKUP_REFUSED);
                        m.blocklist_refusals.inc(kind);
                        rotate_out(&rotated, &zone, code, cooldown, &query);
                    }
                },
                Err(e) => {
                    debug!("blocklist async lookup failed for {}: {}", query, e);
                    crate::metrics::metrics()
                        .blocklist_lookups
                        .inc(kind, LOOKUP_ERROR);
                }
            }
            inflight.remove(&cache_key);
        });
    }

    /// Checks if a domain name is listed in any enabled DNSBL provider.
    ///
    /// This is the domain-blocklist counterpart to [`is_listed`](Self::is_listed):
    /// rather than reversing an IP, the query name's labels are prepended to the
    /// provider zone (e.g. `googleadservices.com` + `dbl.spamhaus.org` ->
    /// `googleadservices.com.dbl.spamhaus.org`).
    ///
    /// Returns true if the name is blacklisted and should be blocked (NXDOMAIN).
    /// Used to give DNSBLs precedence over externally-resolved (forwarded or
    /// iterative) answers.
    pub async fn is_name_listed(&self, name: &str) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return false;
        }
        // Outbound :53 is filtered — skip the doomed lookups (see the flag field).
        if !self.resolver_available.load(Ordering::Relaxed) {
            crate::metrics::metrics().blocklist_skipped.inc();
            return false;
        }

        let normalized = normalize_blocklist_name(name);
        if normalized.is_empty() {
            return false;
        }

        let providers = self.providers.load();
        let default_cooldown = self.refusal_cooldown();
        let lookups = providers
            .iter()
            .filter(|p| p.enabled)
            .map(|p| name_lookup(&normalized, p, default_cooldown));
        self.check_cached_or_fill(lookups, BLOCK_DNSBL_PROVIDER)
    }

    /// Updates the DNSBL (domain blocklist) configuration. The shared result
    /// cache is flushed so that newly added/removed providers take effect
    /// immediately rather than serving a stale not-listed verdict.
    pub async fn set_config(&self, enabled: bool, providers: Vec<DnsblProvider>) {
        self.enabled.store(enabled, Ordering::Relaxed);
        self.providers.store(Arc::new(providers));
        self.cache.clear();
        self.rotated.clear();
    }

    /// Returns the current DNSBL configuration.
    pub async fn get_config(&self) -> (bool, Vec<DnsblProvider>) {
        let enabled = self.enabled.load(Ordering::Relaxed);
        let providers = self.providers.load();
        (enabled, providers.as_ref().clone())
    }

    /// Returns whether DNSBL checking is enabled.
    pub async fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Flushes the result cache, and returns every rotated-out provider to
    /// rotation — a flush is the operator's "re-check everything", and a
    /// provider held out for the rest of an hour's cooldown would not be
    /// re-checked.
    pub async fn flush_cache(&self) {
        self.cache.clear();
        self.rotated.clear();
    }

    /// Number of entries in the blocklist result cache. Sampled by the
    /// Prometheus collector; synchronous because a scrape must not await.
    pub fn cache_entries(&self) -> usize {
        self.cache.len()
    }
}

/// Builds the per-provider lookup for a name-based (DNSBL) check. `normalized`
/// must already have been through [`normalize_blocklist_name`].
fn name_lookup(
    normalized: &str,
    provider: &DnsblProvider,
    default_cooldown: Duration,
) -> ProviderLookup {
    ProviderLookup {
        cache_key: format!("{}/{}", normalized, provider.zone),
        query: format!("{}.{}", normalized, provider.zone),
        zone: provider.zone.clone(),
        refusal_codes: provider.refusal_codes.clone(),
        cooldown: provider.cooldown.unwrap_or(default_cooldown),
    }
}

/// Takes `zone` out of rotation for `cooldown` after it refused `query`.
///
/// Nothing is cached for the query that triggered it: a refusal is not a
/// negative answer, and caching it as one would assert "not listed" for a name
/// the provider never actually judged. Takes the map rather than `&self`
/// because the background fill task owns clones, not a borrow of the checker.
fn rotate_out(
    rotated: &DashMap<String, RotatedOut>,
    zone: &str,
    code: Ipv4Addr,
    cooldown: Duration,
    query: &str,
) {
    let already = rotated
        .insert(
            zone.to_string(),
            RotatedOut {
                code,
                until: Instant::now() + cooldown,
            },
        )
        .is_some();
    if !already {
        warn!(
            "blocklist provider {} refused query {} with code {} — rotating it out for {}s (its \
             answers are complaints, not reputation, and must not be read as listings)",
            zone,
            query,
            code,
            cooldown.as_secs()
        );
    }
}

/// Normalizes a domain name for blocklist lookups: lowercased with the trailing
/// dot stripped, so that `GoogleAdServices.com.` and `googleadservices.com`
/// produce the same query and cache key.
pub fn normalize_blocklist_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Probes whether outbound **plaintext DNS on port 53** works, by sending a UDP
/// query for a stable name to public resolvers and awaiting any reply. This is
/// the transport blocklist provider lookups depend on; when it fails, those only
/// time out and add latency, so [`DnsblChecker::set_resolver_available`] is driven
/// off this to skip them. Deliberately a *direct* :53 test (not via the system
/// resolver) so it reflects raw :53 reachability, not a DoH-backed fallback.
pub async fn probe_public_dns53() -> bool {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use hickory_proto::serialize::binary::BinEncodable;

    let mut msg = Message::new();
    msg.set_id(0x5311);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut q = Query::new();
    // A name that always resolves, so a reply means :53 works (not NXDOMAIN).
    let Ok(name) = Name::from_ascii("one.one.one.one.") else {
        return false;
    };
    q.set_name(name);
    q.set_query_type(RecordType::A);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    let Ok(query) = msg.to_bytes() else {
        return false;
    };

    for target in ["1.1.1.1:53", "8.8.8.8:53"] {
        if probe_dns53_target(&query, target).await {
            return true;
        }
    }
    false
}

/// Sends one UDP :53 query to `target` and reports whether a reply arrived.
async fn probe_dns53_target(query: &[u8], target: &str) -> bool {
    let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
        return false;
    };
    if socket.send_to(query, target).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    matches!(
        tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf)).await,
        Ok(Ok(n)) if n > 0
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ================================================================
    // Refusal codes
    //
    // A DNSxL answers a listing and a complaint about the querier with the same
    // record type in the same address block, so every test here is really about
    // one question: does an error code get read as reputation? A validator that
    // says "listed" for 127.255.255.254 blocks the entire internet, and it does
    // so only once the provider decides we are over quota — long after the
    // deployment looked fine.
    // ================================================================

    #[test]
    fn refusal_code_parses_bare_address_and_prefix() {
        let bare = RefusalCode::parse("127.0.0.1").unwrap();
        assert!(bare.matches(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!bare.matches(Ipv4Addr::new(127, 0, 0, 2)));
        assert_eq!(bare.to_string(), "127.0.0.1");

        let range = RefusalCode::parse("127.255.255.0/24").unwrap();
        for last in [252u8, 253, 254, 255] {
            assert!(
                range.matches(Ipv4Addr::new(127, 255, 255, last)),
                "the Spamhaus error range must cover 127.255.255.{last}, including codes \
                 they have not published yet"
            );
        }
        assert!(!range.matches(Ipv4Addr::new(127, 0, 0, 2)));
        assert_eq!(range.to_string(), "127.255.255.0/24");
    }

    #[test]
    fn refusal_code_masks_base_to_prefix() {
        // A prefix written with host bits set is the same network.
        assert_eq!(
            RefusalCode::parse("127.255.255.254/24").unwrap(),
            RefusalCode::parse("127.255.255.0/24").unwrap()
        );
    }

    #[test]
    fn refusal_code_rejects_malformed() {
        for bad in [
            "",
            "notanip",
            "127.0.0.1/33",
            "127.0.0.1/x",
            "::1",
            "127.0.0.256",
        ] {
            assert!(
                RefusalCode::parse(bad).is_err(),
                "'{bad}' must not parse — a code that silently does not apply is a code \
                 that reads as a listing"
            );
        }
    }

    #[test]
    fn default_refusal_codes_all_parse() {
        // `default_refusal_codes` drops unparseable entries rather than
        // panicking at boot, so without this a typo in the constant would
        // silently remove a code from the built-in set.
        let parsed = default_refusal_codes();
        assert_eq!(parsed.len(), DEFAULT_REFUSAL_CODES.len());
        // Spot-check that each documented provider code is covered.
        for (code, why) in [
            ([127, 255, 255, 252], "Spamhaus: typo in the DNSBL name"),
            (
                [127, 255, 255, 254],
                "Spamhaus: query via a public resolver",
            ),
            ([127, 255, 255, 255], "Spamhaus: excessive queries"),
            ([127, 0, 1, 255], "Spamhaus DBL: IP queries not supported"),
            ([127, 0, 2, 255], "Spamhaus ZRD: IP queries not supported"),
            ([127, 0, 0, 1], "URIBL/SURBL: query blocked"),
            ([127, 0, 0, 255], "URIBL: query blocked"),
        ] {
            let ip = Ipv4Addr::from(code);
            assert!(
                parsed.iter().any(|c| c.matches(ip)),
                "{ip} must be a refusal code by default ({why})"
            );
        }
        // …and that real listings are not.
        for listing in [
            [127, 0, 0, 2],
            [127, 0, 0, 3],
            [127, 0, 0, 4],
            [127, 0, 0, 10],
        ] {
            let ip = Ipv4Addr::from(listing);
            assert!(
                !parsed.iter().any(|c| c.matches(ip)),
                "{ip} is a Spamhaus listing and must not be read as a refusal"
            );
        }
    }

    #[test]
    fn resolve_refusal_codes_empty_uses_defaults() {
        // Every configuration written before this feature existed has an empty
        // list; it must get the safe reading without being edited.
        let resolved = resolve_refusal_codes(&[]).unwrap();
        assert_eq!(resolved.len(), DEFAULT_REFUSAL_CODES.len());
    }

    #[test]
    fn resolve_refusal_codes_none_disables() {
        let resolved = resolve_refusal_codes(&["none".to_string()]).unwrap();
        assert!(resolved.is_empty());
        // Case-insensitive, because it is a configuration keyword.
        assert!(
            resolve_refusal_codes(&["NONE".to_string()])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn resolve_refusal_codes_explicit_does_not_merge_defaults() {
        let resolved = resolve_refusal_codes(&["127.9.9.9".to_string()]).unwrap();
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].matches(Ipv4Addr::new(127, 9, 9, 9)));
        assert!(
            !resolved[0].matches(Ipv4Addr::new(127, 255, 255, 254)),
            "an explicit list is the list; silently adding the defaults would mean an \
             operator cannot narrow it"
        );
    }

    #[test]
    fn resolve_refusal_codes_rejects_none_mixed_with_codes() {
        let err = resolve_refusal_codes(&["none".to_string(), "127.0.0.1".to_string()])
            .expect_err("'none' plus a code is contradictory and must not be guessed at");
        assert!(err.contains("only entry"), "unhelpful error: {err}");
    }

    #[test]
    fn resolve_refusal_codes_rejects_bad_code() {
        assert!(resolve_refusal_codes(&["127.0.0.1".to_string(), "junk".to_string()]).is_err());
    }

    #[test]
    fn classify_reads_refusal_over_listing() {
        let codes = default_refusal_codes();
        let listing = DnsblAnswer::listed(300);
        assert_eq!(classify(Some(&listing), &codes), DnsblVerdict::Listed);

        // A refusal alongside a listing is still a refusal: a provider that is
        // complaining is not simultaneously reporting reputation, and this
        // direction fails open rather than blocking every name.
        let mixed = DnsblAnswer {
            codes: vec![
                Ipv4Addr::new(127, 0, 0, 2),
                Ipv4Addr::new(127, 255, 255, 254),
            ],
            ttl: 300,
        };
        assert_eq!(
            classify(Some(&mixed), &codes),
            DnsblVerdict::Refused(Ipv4Addr::new(127, 255, 255, 254))
        );
    }

    #[test]
    fn classify_verdicts() {
        let codes = default_refusal_codes();
        assert_eq!(classify(None, &codes), DnsblVerdict::NotListed);
        assert_eq!(
            classify(Some(&DnsblAnswer::listed(300)), &codes),
            DnsblVerdict::Listed
        );
        assert_eq!(
            classify(
                Some(&DnsblAnswer::single(Ipv4Addr::new(127, 255, 255, 255), 300)),
                &codes
            ),
            DnsblVerdict::Refused(Ipv4Addr::new(127, 255, 255, 255))
        );
        // With detection disabled the same code reads as a listing — which is
        // exactly the failure the defaults exist to prevent, and is why `none`
        // is opt-in rather than the default.
        assert_eq!(
            classify(
                Some(&DnsblAnswer::single(Ipv4Addr::new(127, 255, 255, 255), 300)),
                &[]
            ),
            DnsblVerdict::Listed
        );
    }

    /// A resolver that always answers with a fixed code, counting its calls —
    /// the query *count* is what distinguishes "rotated out" from "still being
    /// asked", which is the whole point of rotation.
    struct FixedCodeResolver {
        code: Ipv4Addr,
        count: Arc<std::sync::atomic::AtomicU32>,
    }

    impl FixedCodeResolver {
        fn new(code: [u8; 4]) -> Self {
            Self {
                code: Ipv4Addr::from(code),
                count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            }
        }

        fn counter(&self) -> Arc<std::sync::atomic::AtomicU32> {
            self.count.clone()
        }
    }

    #[async_trait::async_trait]
    impl DnsblResolver for FixedCodeResolver {
        async fn lookup(&self, _query: &str) -> Result<Option<DnsblAnswer>, anyhow::Error> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Some(DnsblAnswer::single(self.code, 300)))
        }
    }

    /// Waits for the background fill to have run at least `n` times.
    async fn wait_for_lookups(counter: &std::sync::atomic::AtomicU32, n: u32) {
        for _ in 0..200 {
            if counter.load(std::sync::atomic::Ordering::SeqCst) >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!(
            "expected at least {n} lookups, saw {}",
            counter.load(std::sync::atomic::Ordering::SeqCst)
        );
    }

    /// A checker with one enabled provider using the built-in refusal codes.
    async fn refusal_checker(
        resolver: Arc<dyn DnsblResolver>,
        cooldown: Option<Duration>,
    ) -> DnsblChecker {
        let checker = DnsblChecker::with_resolver(resolver);
        checker
            .set_config(
                true,
                vec![DnsblProvider {
                    zone: "test.example".to_string(),
                    enabled: true,
                    cooldown,
                    ..Default::default()
                }],
            )
            .await;
        checker
    }

    /// The finding this whole mechanism exists for: a provider answering with
    /// its documented "excessive queries" code must not block the queried IP.
    /// Before refusal codes existed, any `A` record meant "listed", so the
    /// moment a blocklist rate-limited us the server NXDOMAINed every name it
    /// checked — a self-inflicted outage that looks exactly like the blocklist
    /// working.
    #[tokio::test]
    async fn refusal_code_does_not_list() {
        let resolver = Arc::new(FixedCodeResolver::new([127, 255, 255, 255]));
        let counter = resolver.counter();
        let checker = refusal_checker(resolver, None).await;
        let name = "one.example.";

        assert!(
            !checker.is_name_listed(name).await,
            "cold query is never blocking"
        );
        wait_for_lookups(&counter, 1).await;
        assert!(
            !checker.is_name_listed(name).await,
            "127.255.255.255 is 'excessive queries', not a listing"
        );
    }

    /// …and the provider is taken out of rotation, so we stop hammering a
    /// blocklist that has just told us to stop.
    #[tokio::test]
    async fn refusal_rotates_provider_out() {
        let resolver = Arc::new(FixedCodeResolver::new([127, 255, 255, 254]));
        let counter = resolver.counter();
        // An hour, so nothing can expire mid-test.
        let checker = refusal_checker(resolver, Some(Duration::from_secs(3600))).await;

        assert!(!checker.is_name_listed("one.example.").await);
        wait_for_lookups(&counter, 1).await;

        let rotated = checker.rotated_out();
        assert_eq!(rotated.len(), 1);
        assert_eq!(rotated[0].zone, "test.example");
        assert_eq!(rotated[0].code, "127.255.255.254");
        assert!(rotated[0].seconds_remaining > 3500);
        assert_eq!(checker.rotated_out_count(), 1);

        // Different IPs, so no cache entry can be what suppresses the lookups.
        for last in 5..15u8 {
            assert!(!checker.is_name_listed(&format!("h{last}.example.")).await);
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a rotated-out provider must not be queried again"
        );
    }

    /// Rotation is for a configurable duration, not forever: once it lapses the
    /// provider is asked again, so a transient over-quota period heals itself.
    #[tokio::test]
    async fn rotation_expires_after_the_configured_cooldown() {
        let resolver = Arc::new(FixedCodeResolver::new([127, 255, 255, 255]));
        let counter = resolver.counter();
        let checker = refusal_checker(resolver, Some(Duration::from_millis(50))).await;
        let name = "one.example.";

        assert!(!checker.is_name_listed(name).await);
        wait_for_lookups(&counter, 1).await;
        assert_eq!(checker.rotated_out_count(), 1);

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            checker.rotated_out_count(),
            0,
            "the cooldown must lapse on its own"
        );
        // A fresh key (the first is cached negative? no — a refusal caches
        // nothing, so the same key refills).
        assert!(!checker.is_name_listed(name).await);
        wait_for_lookups(&counter, 2).await;
    }

    /// A refusal caches nothing. Caching it as a negative would assert "not
    /// listed" for a name the provider never judged, and hold that for the
    /// negative TTL after the provider recovers.
    #[tokio::test]
    async fn refusal_is_not_cached_as_a_negative() {
        let resolver = Arc::new(FixedCodeResolver::new([127, 255, 255, 252]));
        let counter = resolver.counter();
        let checker = refusal_checker(resolver, Some(Duration::from_millis(30))).await;
        let name = "one.example.";

        assert!(!checker.is_name_listed(name).await);
        wait_for_lookups(&counter, 1).await;
        assert_eq!(checker.cache_entries(), 0, "a refusal is not a verdict");
    }

    /// A cached listing from before the refusal keeps blocking. Rotation says
    /// "this provider will not answer new questions", not "the answers it
    /// already gave were wrong" — dropping them would unblock genuinely-listed
    /// names for the whole cooldown.
    #[tokio::test]
    async fn rotation_keeps_honouring_already_cached_listings() {
        /// Lists the first query, then refuses every one after it.
        struct ListThenRefuse {
            calls: std::sync::atomic::AtomicU32,
        }
        #[async_trait::async_trait]
        impl DnsblResolver for ListThenRefuse {
            async fn lookup(&self, _query: &str) -> Result<Option<DnsblAnswer>, anyhow::Error> {
                let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(Some(if n == 0 {
                    DnsblAnswer::listed(300)
                } else {
                    DnsblAnswer::single(Ipv4Addr::new(127, 255, 255, 255), 300)
                }))
            }
        }

        let checker = refusal_checker(
            Arc::new(ListThenRefuse {
                calls: std::sync::atomic::AtomicU32::new(0),
            }),
            Some(Duration::from_secs(3600)),
        )
        .await;
        let listed = "listed.example.";

        assert!(eventually_listed_name(&checker, listed).await);

        // A second IP triggers the refusal and rotates the provider out.
        assert!(!checker.is_name_listed("other.example.").await);
        for _ in 0..200 {
            if checker.rotated_out_count() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(checker.rotated_out_count(), 1);

        assert!(
            checker.is_name_listed(listed).await,
            "the cached listing predates the refusal and is still valid"
        );
    }

    /// Flushing the cache is the operator's "re-check everything", so it must
    /// also return rotated-out providers — otherwise the flush is answered by
    /// a provider that is not being asked.
    #[tokio::test]
    async fn flush_cache_returns_providers_to_rotation() {
        let resolver = Arc::new(FixedCodeResolver::new([127, 255, 255, 254]));
        let counter = resolver.counter();
        let checker = refusal_checker(resolver, Some(Duration::from_secs(3600))).await;

        assert!(!checker.is_name_listed("one.example.").await);
        wait_for_lookups(&counter, 1).await;
        assert_eq!(checker.rotated_out_count(), 1);

        checker.flush_cache().await;
        assert_eq!(checker.rotated_out_count(), 0);
        assert!(!checker.is_name_listed("third.example.").await);
        wait_for_lookups(&counter, 2).await;
    }

    /// Reconfiguring likewise, since a typo in the zone name is both a cause of
    /// refusal and the thing an operator reconfigures to fix.
    #[tokio::test]
    async fn set_config_returns_providers_to_rotation() {
        let resolver = Arc::new(FixedCodeResolver::new([127, 255, 255, 252]));
        let counter = resolver.counter();
        let checker = refusal_checker(resolver, Some(Duration::from_secs(3600))).await;

        assert!(!checker.is_name_listed("one.example.").await);
        wait_for_lookups(&counter, 1).await;
        assert_eq!(checker.rotated_out_count(), 1);

        checker
            .set_config(true, vec![DnsblProvider::new("test.example", true)])
            .await;
        assert_eq!(checker.rotated_out_count(), 0);
    }

    /// Opting out with `none` restores the old reading, and is the only way to
    /// get it. Pinned so the escape hatch is known to work for a private
    /// blocklist whose listings collide with a default code.
    #[tokio::test]
    async fn refusal_detection_can_be_disabled_per_provider() {
        let resolver = Arc::new(FixedCodeResolver::new([127, 0, 0, 1]));
        let checker = DnsblChecker::with_resolver(resolver);
        checker
            .set_config(
                true,
                vec![DnsblProvider {
                    zone: "test.example".to_string(),
                    enabled: true,
                    refusal_codes: resolve_refusal_codes(&["none".to_string()]).unwrap().into(),
                    cooldown: None,
                }],
            )
            .await;
        let name = "one.example.";
        assert!(
            eventually_listed_name(&checker, name).await,
            "with detection off, 127.0.0.1 is read as a listing"
        );
        assert_eq!(checker.rotated_out_count(), 0);
    }

    /// The list-wide cooldown default.
    #[tokio::test]
    async fn dnsbl_refusal_rotates_out() {
        let resolver = Arc::new(FixedCodeResolver::new([127, 0, 1, 255]));
        let counter = resolver.counter();
        let checker = DnsblChecker::with_resolver(resolver);
        checker
            .set_config(
                true,
                vec![DnsblProvider {
                    zone: "dbl.test".to_string(),
                    enabled: true,
                    cooldown: Some(Duration::from_secs(3600)),
                    ..Default::default()
                }],
            )
            .await;

        assert!(!checker.is_name_listed("example.com.").await);
        wait_for_lookups(&counter, 1).await;
        assert!(
            !checker.is_name_listed("other.example.").await,
            "127.0.1.255 is the DBL saying 'IP queries not supported', not a listing"
        );
        assert_eq!(checker.rotated_out_count(), 1);
    }

    /// The list-wide default applies to providers that configure none, and `0`
    /// is refused rather than honoured: a zero cooldown re-asks the provider
    /// that just told us to stop, which is the behaviour rotation prevents.
    #[test]
    fn list_wide_cooldown_defaults_and_rejects_zero() {
        let checker = DnsblChecker::with_resolver(Arc::new(MockResolver::new(false)));
        assert_eq!(
            checker.refusal_cooldown(),
            Duration::from_secs(DEFAULT_REFUSAL_COOLDOWN_SECS)
        );
        checker.set_refusal_cooldown(120);
        assert_eq!(checker.refusal_cooldown(), Duration::from_secs(120));
        checker.set_refusal_cooldown(0);
        assert_eq!(
            checker.refusal_cooldown(),
            Duration::from_secs(DEFAULT_REFUSAL_COOLDOWN_SECS)
        );
    }

    #[test]
    fn refusal_code_strings_round_trip() {
        let p = DnsblProvider::new("test.example", true);
        assert_eq!(p.refusal_code_strings().len(), DEFAULT_REFUSAL_CODES.len());
        assert!(
            p.refusal_code_strings()
                .contains(&"127.255.255.0/24".to_string())
        );

        let off = DnsblProvider {
            refusal_codes: Arc::from(Vec::new()),
            ..DnsblProvider::new("test.example", true)
        };
        assert_eq!(
            off.refusal_code_strings(),
            vec![REFUSAL_CODES_NONE.to_string()],
            "a disabled provider must read back as 'none', not as empty — empty means \
             'use the defaults' on the way back in"
        );
    }

    // Simple mock resolver for tests
    struct MockResolver {
        listed: bool,
    }

    impl MockResolver {
        fn new(listed: bool) -> Self {
            Self { listed }
        }
    }

    #[async_trait::async_trait]
    impl DnsblResolver for MockResolver {
        async fn lookup(&self, _query: &str) -> Result<Option<DnsblAnswer>, anyhow::Error> {
            if self.listed {
                Ok(Some(DnsblAnswer::listed(300)))
            } else {
                Ok(None)
            }
        }
    }

    // Counting resolver to verify caching behavior
    struct CountingResolver {
        listed: bool,
        count: std::sync::atomic::AtomicU32,
    }

    impl CountingResolver {
        fn new(listed: bool) -> Self {
            Self {
                listed,
                count: std::sync::atomic::AtomicU32::new(0),
            }
        }

        fn count(&self) -> u32 {
            self.count.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl DnsblResolver for CountingResolver {
        async fn lookup(&self, _query: &str) -> Result<Option<DnsblAnswer>, anyhow::Error> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.listed {
                Ok(Some(DnsblAnswer::listed(300)))
            } else {
                Ok(None)
            }
        }
    }

    async fn eventually_listed_name(checker: &DnsblChecker, name: &str) -> bool {
        for _ in 0..200 {
            if checker.is_name_listed(name).await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        false
    }

    #[tokio::test]
    async fn test_resolver_unavailable_skips_lookups() {
        let counting = Arc::new(CountingResolver::new(true)); // would list everything
        let checker = DnsblChecker::with_resolver(counting.clone());
        checker
            .set_config(
                true,
                vec![DnsblProvider {
                    zone: "dbl.test".to_string(),
                    enabled: true,
                    ..Default::default()
                }],
            )
            .await;

        // :53 down → both IP-RBL and DNSBL checks are skipped: no lookups issued,
        // nothing reported as listed.
        checker.set_resolver_available(false);
        assert!(!checker.is_name_listed("one.example.").await);
        assert!(!checker.is_name_listed("evil.example.com").await);
        assert_eq!(
            counting.count(),
            0,
            "no lookups should be attempted while :53 is down"
        );

        // :53 recovers → lookups resume and the (listed) resolver blocks again
        // (once the async fill lands).
        checker.set_resolver_available(true);
        assert!(eventually_listed_name(&checker, "one.example.").await);
        assert!(eventually_listed_name(&checker, "evil.example.com").await);
        assert!(counting.count() >= 1);
    }

    #[tokio::test]
    async fn recursive_rbl_forwarder_classifies_listed_and_not_listed() {
        use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record, rdata};
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

        // Mock forwarder: A? for a name containing "listed" -> 127.0.0.2 (TTL 111);
        // anything else -> NXDOMAIN.
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let Ok(req) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                let mut resp = Message::new();
                resp.set_id(req.id());
                resp.set_message_type(MessageType::Response);
                resp.set_op_code(OpCode::Query);
                for q in req.queries() {
                    resp.add_query(q.clone());
                }
                let q0 = req.queries().first().cloned();
                let listed = q0
                    .as_ref()
                    .map(|q| q.name().to_ascii().contains("listed"))
                    .unwrap_or(false);
                if let (true, Some(q)) = (listed, q0) {
                    resp.set_response_code(ResponseCode::NoError);
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        111,
                        RData::A(rdata::A(Ipv4Addr::new(127, 0, 0, 2))),
                    ));
                } else {
                    resp.set_response_code(ResponseCode::NXDomain);
                }
                let _ = sock.send_to(&resp.to_bytes().unwrap(), src).await;
            }
        });

        // Exercises the forwarder-fallback path directly (fast; no roots/network).
        let listed = query_forwarder_a(
            &Name::from_ascii("evil.listed.example.").unwrap(),
            addr,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(
            listed,
            Some(DnsblAnswer::single(Ipv4Addr::new(127, 0, 0, 2), 111)),
            "listed name must resolve to an A → its codes and TTL"
        );

        let clean = query_forwarder_a(
            &Name::from_ascii("good.example.").unwrap(),
            addr,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(clean, None, "NXDOMAIN → not listed");
    }

    #[tokio::test]
    async fn flush_cache_forces_a_fresh_lookup() {
        let resolver = Arc::new(CountingResolver::new(true));
        let checker = dnsbl_checker(resolver.clone()).await;
        let name = "one.example.";

        assert!(eventually_listed_name(&checker, name).await);
        assert_eq!(resolver.count(), 1);

        checker.flush_cache().await;

        // After a flush the verdict must be resolved again (fresh async fill).
        assert!(eventually_listed_name(&checker, name).await);
        assert_eq!(resolver.count(), 2);
    }

    #[test]
    fn test_normalize_blocklist_name() {
        assert_eq!(normalize_blocklist_name("Example.COM."), "example.com");
        assert_eq!(normalize_blocklist_name("example.com"), "example.com");
        assert_eq!(normalize_blocklist_name("."), "");
    }

    /// Builds a checker with DNSBL enabled and a single `dbl.test` provider.
    async fn dnsbl_checker(resolver: Arc<dyn DnsblResolver>) -> DnsblChecker {
        let checker = DnsblChecker::with_resolver(resolver);
        checker
            .set_config(
                true,
                vec![DnsblProvider {
                    zone: "dbl.test".to_string(),
                    enabled: true,
                    ..Default::default()
                }],
            )
            .await;
        checker
    }

    #[tokio::test]
    async fn test_is_name_listed_listed() {
        let checker = dnsbl_checker(Arc::new(MockResolver::new(true))).await;
        assert!(eventually_listed_name(&checker, "googleadservices.com.").await);
    }

    #[tokio::test]
    async fn test_is_name_listed_not_listed() {
        let checker = dnsbl_checker(Arc::new(MockResolver::new(false))).await;
        assert!(!checker.is_name_listed("example.com.").await);
    }

    #[tokio::test]
    async fn test_is_name_listed_disabled() {
        // DNSBL globally disabled: even a listed name is not reported.
        let checker = DnsblChecker::with_resolver(Arc::new(MockResolver::new(true)));
        checker
            .set_config(
                false,
                vec![DnsblProvider {
                    zone: "dbl.test".to_string(),
                    enabled: true,
                    ..Default::default()
                }],
            )
            .await;
        assert!(!checker.is_name_listed("googleadservices.com.").await);
    }

    #[tokio::test]
    async fn test_is_name_listed_caches() {
        let resolver = Arc::new(CountingResolver::new(true));
        let checker = dnsbl_checker(resolver.clone()).await;
        // Trailing-dot and case differences normalize to the same cache key, so
        // the async fill runs once and the second (normalized) lookup is cached.
        assert!(eventually_listed_name(&checker, "Ads.Example.com.").await);
        assert_eq!(resolver.count(), 1);
        assert!(checker.is_name_listed("ads.example.com").await);
        assert_eq!(resolver.count(), 1);
    }

    /// A resolver that lists everything with an already-expired TTL, and counts
    /// how many times it was asked. Spamhaus DBL answers with a 60-second TTL,
    /// so on a real box a listed name's cache entry expires constantly; TTL 0 is
    /// that same situation with the waiting removed.
    struct ExpiredListingResolver {
        count: std::sync::atomic::AtomicU32,
    }

    impl ExpiredListingResolver {
        fn new() -> Self {
            Self {
                count: std::sync::atomic::AtomicU32::new(0),
            }
        }

        fn count(&self) -> u32 {
            self.count.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl DnsblResolver for ExpiredListingResolver {
        async fn lookup(&self, _query: &str) -> Result<Option<DnsblAnswer>, anyhow::Error> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Some(DnsblAnswer::listed(0)))
        }
    }

    /// An expired positive keeps blocking while it is refreshed.
    ///
    /// A cache miss is answered by ALLOWING the query, so dropping a positive the
    /// instant its TTL runs out means every expiry unblocks the name until the
    /// background refill lands — the blocklist fails open once per TTL. Against a
    /// provider like Spamhaus DBL (60-second TTLs) that is a hole that reopens
    /// every minute.
    ///
    /// The control is `test_is_name_listed_not_listed`: a name no provider lists
    /// is not blocked, so this passing is not just "blocks everything".
    #[tokio::test]
    async fn test_expired_positive_still_blocks_while_refreshing() {
        let resolver = Arc::new(ExpiredListingResolver::new());
        let checker = dnsbl_checker(resolver.clone()).await;

        // First check is cold: allowed, and it primes the cache.
        assert!(eventually_listed_name(&checker, "ads.example.com.").await);
        let after_first = resolver.count();
        assert!(after_first >= 1, "the cold check must fire a fill");

        // The entry landed already expired. Every subsequent check must still
        // block rather than fall open while the refill runs.
        for _ in 0..5 {
            assert!(
                checker.is_name_listed("ads.example.com.").await,
                "an expired positive must keep blocking, not unblock the name"
            );
        }

        // ...and it is genuinely being refreshed, not just pinned forever.
        tokio::time::sleep(Duration::from_millis(20)).await;
        checker.is_name_listed("ads.example.com.").await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            resolver.count() > after_first,
            "a stale positive must fire a refill"
        );
    }

    #[tokio::test]
    async fn test_enabled_but_empty_dnsbl_is_noop() {
        // DNSBL globally enabled with no providers: nothing is queried.
        let resolver = Arc::new(CountingResolver::new(true));
        let checker = DnsblChecker::with_resolver(resolver.clone());
        checker.set_config(true, vec![]).await;
        assert!(!checker.is_name_listed("googleadservices.com.").await);
        assert_eq!(resolver.count(), 0);
    }

    #[tokio::test]
    async fn test_dnsbl_get_set_config() {
        let checker = DnsblChecker::with_resolver(Arc::new(MockResolver::new(true)));

        let (enabled, providers) = checker.get_config().await;
        assert!(!enabled);
        assert!(providers.is_empty());
        assert!(!checker.is_enabled().await);

        checker
            .set_config(
                true,
                vec![DnsblProvider {
                    zone: "dbl.spamhaus.org".to_string(),
                    enabled: true,
                    ..Default::default()
                }],
            )
            .await;

        let (enabled, providers) = checker.get_config().await;
        assert!(enabled);
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].zone, "dbl.spamhaus.org");
        assert!(checker.is_enabled().await);
    }

    #[tokio::test]
    async fn a_disabled_provider_is_not_queried() {
        let resolver = Arc::new(CountingResolver::new(true));
        let checker = DnsblChecker::with_resolver(resolver.clone());
        let name = "one.example.";
        assert!(!checker.is_name_listed(name).await);
        assert_eq!(resolver.count(), 0);
    }
}
