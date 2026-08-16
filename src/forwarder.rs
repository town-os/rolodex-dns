//! Upstream forwarders: one type for every transport rolodex can send a query
//! over, and the health that decides whether it is worth sending one.
//!
//! Plaintext DNS is not a separate concept here, it is the transport with no
//! encryption — `Transport::Do53Udp`. Before this, DoH/DoT lived in
//! `secure_upstreams` and Do53 lived in `forwarders`/`public_fallback`, three
//! config keys of two different shapes, and `auto`'s tiers were those keys in a
//! fixed order. That split had a cost beyond tidiness: `secure_upstreams` had no
//! gRPC setter, so on a network where only the encrypted transports work, the
//! one tier that could answer was the one nothing could reconfigure at runtime,
//! and the tier that *was* programmable was the one that could not answer.
//!
//! With one type the tier a forwarder belongs to is [`Preference`], derived from
//! the forwarder itself rather than from the config key it arrived in. A DoQ
//! upstream is in the encrypted tier because it is encrypted; a DoT server on
//! the LAN is too. Nothing has to be taught where to file a new transport.

use anyhow::{Context, Result, bail};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use tokio_rustls::rustls::pki_types::ServerName;

/// Consecutive failures after which a forwarder is skipped rather than tried.
///
/// The point is the network that black-holes a transport outright: every query
/// to it costs the full per-forwarder timeout and none of them will ever
/// succeed. Three is enough to distinguish that from a packet loss blip, and
/// small enough that a box does not spend minutes paying for the distinction.
const FAILURE_THRESHOLD: u32 = 3;

/// How long a forwarder stays skipped before one query is allowed through to
/// see whether it came back.
///
/// A skip that never expires is a forwarder deleted by a transient failure, so
/// this is a circuit breaker rather than a blocklist: after the cooldown the
/// next query goes to it, and a single success restores it. Long enough that a
/// genuinely dead address is not retried constantly, short enough that a network
/// change is noticed without an operator doing anything.
const OPEN_COOLDOWN_MS: u64 = 30_000;

/// Milliseconds since an arbitrary process-start baseline.
///
/// A monotonic stamp that fits in an atomic, so health needs no lock on the
/// query path — and no `Mutex` whose poisoning would have to be handled without
/// `unwrap` on every read.
fn now_millis() -> u64 {
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    u64::try_from(
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

/// The transport a forwarder is reached over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Plaintext DNS over UDP (RFC 1035), the historical `forwarders:` entry.
    Do53Udp,
    /// Plaintext DNS over TCP (RFC 7766).
    Do53Tcp,
    /// DNS-over-TLS (RFC 7858), :853.
    Dot,
    /// DNS-over-HTTPS (RFC 8484), :443.
    Doh,
    /// DNS-over-QUIC (RFC 9250), :853 over UDP.
    Doq,
}

impl Transport {
    /// Whether the transport encrypts the query in flight.
    ///
    /// This is what puts a forwarder in the most-preferred forwarding tier, so
    /// it is deliberately a property of the transport and not a flag an entry
    /// can set: "encrypted" has to mean the same thing for every forwarder or
    /// the tier stops meaning anything.
    pub fn is_encrypted(self) -> bool {
        !matches!(self, Transport::Do53Udp | Transport::Do53Tcp)
    }

    /// Whether the transport authenticates a server certificate, and therefore
    /// needs a name to validate it against.
    pub fn needs_server_name(self) -> bool {
        self.is_encrypted()
    }

    /// The URL scheme this transport round-trips through.
    pub fn scheme(self) -> &'static str {
        match self {
            Transport::Do53Udp => "udp",
            Transport::Do53Tcp => "tcp",
            Transport::Dot => "tls",
            Transport::Doh => "https",
            Transport::Doq => "quic",
        }
    }

    /// The port assumed when a forwarder names none.
    pub fn default_port(self) -> u16 {
        match self {
            Transport::Do53Udp | Transport::Do53Tcp => 53,
            Transport::Dot | Transport::Doq => 853,
            Transport::Doh => 443,
        }
    }

    /// Parses a URL scheme. Both the protocol name and the common abbreviation
    /// are accepted, because both are what people write.
    fn from_scheme(scheme: &str) -> Result<Self> {
        match scheme.to_ascii_lowercase().as_str() {
            "udp" | "do53" | "dns" => Ok(Transport::Do53Udp),
            "tcp" => Ok(Transport::Do53Tcp),
            "tls" | "dot" => Ok(Transport::Dot),
            "https" | "doh" => Ok(Transport::Doh),
            "quic" | "doq" => Ok(Transport::Doq),
            other => bail!(
                "unsupported forwarder transport '{other}' (use udp, tcp, tls/dot, https/doh or quic/doq)"
            ),
        }
    }
}

/// How much rolodex would rather use a forwarder, most-preferred first.
///
/// This is `auto`'s forwarding tier, derived rather than configured. The
/// ordering reproduces exactly what the fixed tiers did — encrypted upstreams,
/// then the local plaintext forwarder, then public plaintext resolvers — with
/// one difference that is the whole point: it is now a consequence of what the
/// forwarder IS, so an entry cannot end up in the wrong tier by being written
/// under the wrong config key.
///
/// Private before public for plaintext because a resolver on the local segment
/// is both faster and the one that still answers on a network filtering
/// outbound :53 — which is the situation the plaintext tiers exist for at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Preference {
    /// Any encrypted transport: DoH, DoT, DoQ.
    Encrypted,
    /// Plaintext to an address on this network.
    PlaintextPrivate,
    /// Plaintext to a public address.
    PlaintextPublic,
}

/// Per-forwarder health, shared across reprogramming.
///
/// It has to outlive the `Forwarder` values it describes. `ProgramRolodex`
/// re-pushes the whole forwarder list on every tick, so health owned by the
/// list would be reset every few seconds and a circuit breaker that resets
/// faster than it opens is not a circuit breaker. [`carry_health`] moves these
/// across a replacement by label.
#[derive(Debug, Default)]
pub struct Health {
    consecutive_failures: AtomicU32,
    /// Millisecond stamp before which the forwarder is skipped. Zero means
    /// closed (in service).
    open_until: AtomicU64,
}

impl Health {
    /// Whether a query should be sent to this forwarder now.
    ///
    /// Returns true while closed, and again once the cooldown has elapsed —
    /// the half-open probe. It does not reset the breaker itself: only a real
    /// success does, in [`Self::record_success`].
    pub fn is_usable(&self) -> bool {
        let open_until = self.open_until.load(Ordering::Relaxed);
        open_until == 0 || now_millis() >= open_until
    }

    /// Records a definitive answer: the forwarder works, so the breaker closes
    /// outright rather than decaying. One good answer after a network is fixed
    /// should not leave two failures banked against the next blip.
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.open_until.store(0, Ordering::Relaxed);
    }

    /// Records a failure, opening the breaker at [`FAILURE_THRESHOLD`].
    pub fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= FAILURE_THRESHOLD {
            self.open_until.store(
                now_millis().saturating_add(OPEN_COOLDOWN_MS),
                Ordering::Relaxed,
            );
        }
    }

    /// Consecutive failures recorded since the last success.
    pub fn failures(&self) -> u32 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }
}

/// An upstream this server can forward a query to.
#[derive(Debug, Clone)]
pub struct Forwarder {
    pub transport: Transport,
    /// The address dialed, always a literal. An encrypted forwarder is dialed
    /// by IP and validated by name precisely so it needs no working DNS to be
    /// reached — which is the only way an encrypted upstream can be the thing
    /// that fixes a box with no working DNS.
    pub addr: SocketAddr,
    /// Name presented as SNI and validated against the certificate. `None` for
    /// plaintext transports, which authenticate nothing.
    pub server_name: Option<ServerName<'static>>,
    /// The same name as a string, for SNI logging and the DoH `Host` header.
    pub hostname: Option<String>,
    /// DoH request path. `None` for every other transport.
    pub path: Option<String>,
    /// Human-readable identity, and the metrics label. Stable across a
    /// reprogramming, which is what lets health be carried over by it.
    pub label: String,
    pub health: Arc<Health>,
}

impl Forwarder {
    /// Parses a forwarder from its string form.
    ///
    /// A bare `ip:port` is plaintext UDP, which is what every existing
    /// `forwarders:` entry and every `SetForwarders` caller sends — so the
    /// historical spelling keeps working untouched and unqualified, and the
    /// scheme is what a caller adds to ask for something else:
    ///
    /// ```text
    /// 8.8.8.8:53                                   plaintext UDP
    /// tcp://8.8.8.8:53                             plaintext TCP
    /// tls://cloudflare-dns.com@1.1.1.1:853         DoT
    /// https://cloudflare-dns.com@1.1.1.1/dns-query DoH
    /// quic://dns.adguard.com@94.140.14.14:853      DoQ
    /// ```
    ///
    /// The `name@ip` authority is the load-bearing part of the encrypted forms:
    /// it carries both halves of what a TLS upstream needs — the address to
    /// dial and the name to validate — in one string, so the list stays a list
    /// of strings and nothing has to resolve a hostname before it can ask a
    /// resolver anything. Where the address is itself the identity in the
    /// certificate (`https://1.1.1.1/dns-query`, whose leaf carries an IP SAN),
    /// the `name@` half may be omitted.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty forwarder");
        }

        let (transport, rest) = match spec.split_once("://") {
            Some((scheme, rest)) => (Transport::from_scheme(scheme)?, rest),
            // No scheme is the historical plaintext form, kept unqualified so
            // that every config file and API caller written before transports
            // were nameable still parses.
            None => (Transport::Do53Udp, spec),
        };
        if rest.is_empty() {
            bail!("forwarder '{spec}' names no address");
        }

        // The path belongs to DoH alone; for everything else a trailing slash
        // is a typo worth rejecting rather than silently dropping, since it
        // would otherwise read as a path that is being honoured.
        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, Some(format!("/{path}"))),
            None => (rest, None),
        };
        if path.is_some() && transport != Transport::Doh {
            bail!("forwarder '{spec}': a path is only meaningful for https/doh");
        }

        let (name, host_port) = match authority.rsplit_once('@') {
            Some((name, host_port)) => (Some(name.to_string()), host_port),
            None => (None, authority),
        };
        if name.as_ref().is_some_and(|n| n.is_empty()) {
            bail!("forwarder '{spec}': empty server name before '@'");
        }

        let addr = parse_host_port(host_port, transport.default_port())
            .with_context(|| format!("forwarder '{spec}': invalid address '{host_port}'"))?;

        // An encrypted forwarder validates a certificate, so it needs a name.
        // Falling back to the dialed IP is correct rather than lax: rustls
        // validates it against the certificate's IP SANs, which is exactly the
        // check `https://1.1.1.1/dns-query` should get, and a certificate
        // without that SAN fails the handshake instead of being trusted.
        let (server_name, hostname) = if transport.needs_server_name() {
            let name = name.unwrap_or_else(|| addr.ip().to_string());
            let parsed = ServerName::try_from(name.clone())
                .with_context(|| format!("forwarder '{spec}': invalid server name '{name}'"))?;
            (Some(parsed.to_owned()), Some(name))
        } else {
            if name.is_some() {
                bail!(
                    "forwarder '{spec}': a server name is only meaningful for an encrypted transport"
                );
            }
            (None, None)
        };

        let label = match transport {
            // Deliberately the bare address, matching what this forwarder has
            // always been called: it is the `upstream_queries_total{server=...}`
            // label value, and relabelling every existing plaintext forwarder
            // would silently break every dashboard and alert built on it.
            Transport::Do53Udp => addr.to_string(),
            _ => {
                let identity = hostname.clone().unwrap_or_else(|| addr.to_string());
                format!("{}://{identity}", transport.scheme())
            }
        };

        Ok(Self {
            transport,
            addr,
            server_name,
            hostname,
            path: path
                .or_else(|| (transport == Transport::Doh).then(|| DEFAULT_DOH_PATH.to_string())),
            label,
            health: Arc::new(Health::default()),
        })
    }

    /// Builds a forwarder from the older `secure_upstreams:` config shape,
    /// which spells the same thing across four fields instead of one string.
    ///
    /// That shape is kept because a config file written against it must keep
    /// parsing: serde rejects an unknown field outright, so dropping it would
    /// be a hard startup failure on every box whose `rolodex.yml` still has one
    /// — and under `Restart=always` a startup failure in the resolver is a
    /// crash loop with DNS down for everything on the box.
    pub fn from_secure_config(cfg: &crate::config::SecureUpstreamConfig) -> Result<Self> {
        let transport = Transport::from_scheme(&cfg.transport)?;
        if !transport.is_encrypted() {
            bail!(
                "secure upstream transport '{}' is not encrypted (use tls/dot, https/doh or quic/doq)",
                cfg.transport
            );
        }
        let spec = match transport {
            Transport::Doh => format!(
                "{}://{}@{}{}",
                transport.scheme(),
                cfg.hostname,
                cfg.addr,
                cfg.path
            ),
            _ => format!("{}://{}@{}", transport.scheme(), cfg.hostname, cfg.addr),
        };
        Self::parse(&spec)
    }

    /// The tier this forwarder belongs to, derived from what it is.
    pub fn preference(&self) -> Preference {
        if self.transport.is_encrypted() {
            return Preference::Encrypted;
        }
        if is_private(self.addr.ip()) {
            Preference::PlaintextPrivate
        } else {
            Preference::PlaintextPublic
        }
    }

    /// Whether a query should be sent to this forwarder right now.
    pub fn is_usable(&self) -> bool {
        self.health.is_usable()
    }

    /// The string form this forwarder round-trips through, so what an API
    /// reports back is something it would accept again.
    pub fn to_spec(&self) -> String {
        match self.transport {
            Transport::Do53Udp => self.addr.to_string(),
            _ => {
                let scheme = self.transport.scheme();
                let path = self.path.clone().unwrap_or_default();
                match &self.hostname {
                    Some(name) if name != &self.addr.ip().to_string() => {
                        format!("{scheme}://{name}@{}{path}", self.addr)
                    }
                    _ => format!("{scheme}://{}{path}", self.addr),
                }
            }
        }
    }
}

/// The DoH path assumed when a forwarder names none. RFC 8484 does not mandate
/// it, but every public resolver serves it.
pub const DEFAULT_DOH_PATH: &str = "/dns-query";

impl From<SocketAddr> for Forwarder {
    /// A bare socket address is plaintext UDP.
    ///
    /// This is the conversion that keeps every caller predating typed
    /// forwarders working unchanged — the constructors, `set_forwarders`, the
    /// config's plaintext lists — because that is exactly what a bare address
    /// has always meant.
    fn from(addr: SocketAddr) -> Self {
        Self {
            transport: Transport::Do53Udp,
            addr,
            server_name: None,
            hostname: None,
            path: None,
            label: addr.to_string(),
            health: Arc::new(Health::default()),
        }
    }
}

/// Parses `host:port`, or a bare host taking `default_port`.
///
/// Bracketed IPv6 is handled explicitly because the two spellings collide:
/// `::1` is a bare address with colons in it, and `[::1]:853` is an address and
/// a port. Trying `SocketAddr` first and a bare `IpAddr` second resolves them
/// without guessing.
fn parse_host_port(spec: &str, default_port: u16) -> Result<SocketAddr> {
    if let Ok(addr) = spec.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let bare = spec
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(spec);
    let ip: IpAddr = bare
        .parse()
        .with_context(|| format!("'{spec}' is not an ip or ip:port"))?;
    Ok(SocketAddr::new(ip, default_port))
}

/// Whether an address is on this network rather than the public internet.
///
/// Loopback counts: a resolver on `127.0.0.1` is as local as one gets. Rolodex
/// refusing to forward to its own listener is a separate concern, enforced
/// where forwarders are accepted, not here.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        // Unique-local (fc00::/7) and link-local (fe80::/10).
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Moves health from the forwarders currently in service onto their
/// replacements, matching by label.
///
/// Without this a circuit breaker could never open on a Town OS box:
/// `ProgramRolodex` re-pushes the identical forwarder list every tick, and a
/// list that carries its own health would arrive with a clean one each time,
/// resetting the breaker faster than [`FAILURE_THRESHOLD`] could trip it.
pub fn carry_health(existing: &[Forwarder], incoming: &mut [Forwarder]) {
    for forwarder in incoming.iter_mut() {
        if let Some(previous) = existing.iter().find(|e| e.label == forwarder.label) {
            forwarder.health = Arc::clone(&previous.health);
        }
    }
}

/// Splits forwarders into the three forwarding tiers, most-preferred first,
/// preserving the order within each.
///
/// Order within a tier is the order the operator gave, not a ranking: a tier is
/// tried in sequence and the first definitive answer wins, so reordering by
/// health here would quietly change which resolver sees most of the traffic.
/// Health decides whether a forwarder is *tried*, in `Forwarder::is_usable` —
/// not where it sits.
pub fn by_preference(forwarders: &[Forwarder]) -> [Vec<Forwarder>; 3] {
    let mut tiers: [Vec<Forwarder>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    let mut seen = std::collections::HashSet::new();
    for forwarder in forwarders {
        // Deduplicated by label, because the three source lists overlap by
        // design: the same encrypted upstream can be both a compiled-in
        // `secure_upstreams` default and something a controller programs into
        // `forwarders`. Listed twice it would be dialled twice per query, and
        // its two copies would carry two independent circuit breakers — so the
        // one that stayed closed would keep the dead address in service.
        if !seen.insert(forwarder.label.clone()) {
            continue;
        }
        let index = match forwarder.preference() {
            Preference::Encrypted => 0,
            Preference::PlaintextPrivate => 1,
            Preference::PlaintextPublic => 2,
        };
        tiers[index].push(forwarder.clone());
    }
    tiers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_address_is_plaintext_udp() {
        let f = Forwarder::parse("8.8.8.8:53").expect("parse");
        assert_eq!(f.transport, Transport::Do53Udp);
        assert_eq!(f.addr, "8.8.8.8:53".parse::<SocketAddr>().expect("addr"));
        assert!(f.server_name.is_none());
        assert!(f.path.is_none());
    }

    // The label of a plaintext forwarder is the metrics label value that has
    // always identified it. A scheme added here would relabel every existing
    // counter, which is the one change a dashboard cannot survive.
    #[test]
    fn plaintext_label_stays_the_bare_address() {
        assert_eq!(
            Forwarder::parse("8.8.8.8:53").expect("parse").label,
            "8.8.8.8:53"
        );
        assert_eq!(
            Forwarder::parse("udp://8.8.8.8:53").expect("parse").label,
            "8.8.8.8:53"
        );
    }

    #[test]
    fn secure_labels_match_the_historical_spelling() {
        let doh =
            Forwarder::parse("https://cloudflare-dns.com@1.1.1.1:443/dns-query").expect("parse");
        assert_eq!(doh.label, "https://cloudflare-dns.com");
        let dot = Forwarder::parse("tls://dns.google@8.8.8.8:853").expect("parse");
        assert_eq!(dot.label, "tls://dns.google");
    }

    #[test]
    fn parses_every_transport() {
        for (spec, want) in [
            ("8.8.8.8:53", Transport::Do53Udp),
            ("udp://8.8.8.8:53", Transport::Do53Udp),
            ("tcp://8.8.8.8:53", Transport::Do53Tcp),
            ("tls://dns.google@8.8.8.8:853", Transport::Dot),
            ("dot://dns.google@8.8.8.8:853", Transport::Dot),
            (
                "https://cloudflare-dns.com@1.1.1.1/dns-query",
                Transport::Doh,
            ),
            ("quic://dns.adguard.com@94.140.14.14:853", Transport::Doq),
            ("doq://dns.adguard.com@94.140.14.14:853", Transport::Doq),
        ] {
            let f = Forwarder::parse(spec).unwrap_or_else(|e| panic!("{spec}: {e}"));
            assert_eq!(f.transport, want, "{spec}");
        }
    }

    #[test]
    fn default_ports_come_from_the_transport() {
        assert_eq!(
            Forwarder::parse("udp://8.8.8.8")
                .expect("parse")
                .addr
                .port(),
            53
        );
        assert_eq!(
            Forwarder::parse("tls://dns.google@8.8.8.8")
                .expect("parse")
                .addr
                .port(),
            853
        );
        assert_eq!(
            Forwarder::parse("https://cloudflare-dns.com@1.1.1.1")
                .expect("parse")
                .addr
                .port(),
            443
        );
        assert_eq!(
            Forwarder::parse("quic://dns.adguard.com@94.140.14.14")
                .expect("parse")
                .addr
                .port(),
            853
        );
    }

    #[test]
    fn doh_defaults_its_path() {
        let f = Forwarder::parse("https://cloudflare-dns.com@1.1.1.1").expect("parse");
        assert_eq!(f.path.as_deref(), Some(DEFAULT_DOH_PATH));
    }

    // The certificate is validated against the IP's SANs, which is a real check
    // and the one this form should get — not a waiver of validation.
    #[test]
    fn encrypted_forwarder_may_omit_the_name_and_validate_the_ip() {
        let f = Forwarder::parse("https://1.1.1.1/dns-query").expect("parse");
        assert_eq!(f.hostname.as_deref(), Some("1.1.1.1"));
        assert!(f.server_name.is_some());
    }

    #[test]
    fn ipv6_parses_bracketed_and_bare() {
        assert_eq!(
            Forwarder::parse("udp://[2001:4860:4860::8888]:53")
                .expect("parse")
                .addr
                .port(),
            53
        );
        assert_eq!(
            Forwarder::parse("tls://dns.google@[2001:4860:4860::8888]")
                .expect("parse")
                .addr
                .port(),
            853
        );
    }

    #[test]
    fn rejects_nonsense() {
        for spec in [
            "",
            "   ",
            "gopher://8.8.8.8:53",
            "udp://",
            "udp://not-an-ip",
            // A name is meaningless without a certificate to check it against.
            "udp://name@8.8.8.8:53",
            // A path is meaningless without HTTP.
            "tls://dns.google@8.8.8.8:853/dns-query",
            "tls://@8.8.8.8:853",
        ] {
            assert!(
                Forwarder::parse(spec).is_err(),
                "expected {spec:?} to be rejected"
            );
        }
    }

    #[test]
    fn preference_is_derived_from_the_forwarder() {
        let cases = [
            ("https://cloudflare-dns.com@1.1.1.1", Preference::Encrypted),
            ("tls://dns.google@8.8.8.8:853", Preference::Encrypted),
            ("quic://dns.adguard.com@94.140.14.14", Preference::Encrypted),
            // Encrypted to a LAN address is still the encrypted tier.
            ("tls://dns.home@192.168.1.5:853", Preference::Encrypted),
            ("192.168.122.1:53", Preference::PlaintextPrivate),
            ("10.0.0.53:53", Preference::PlaintextPrivate),
            ("127.0.0.53:53", Preference::PlaintextPrivate),
            ("8.8.8.8:53", Preference::PlaintextPublic),
            ("1.1.1.1:53", Preference::PlaintextPublic),
        ];
        for (spec, want) in cases {
            let f = Forwarder::parse(spec).unwrap_or_else(|e| panic!("{spec}: {e}"));
            assert_eq!(f.preference(), want, "{spec}");
        }
    }

    // The ordering is the whole tier system, so it is pinned rather than left
    // to the declaration order of the enum.
    #[test]
    fn encrypted_outranks_private_which_outranks_public() {
        assert!(Preference::Encrypted < Preference::PlaintextPrivate);
        assert!(Preference::PlaintextPrivate < Preference::PlaintextPublic);
    }

    #[test]
    fn by_preference_groups_and_keeps_order_within_a_tier() {
        let forwarders: Vec<Forwarder> = [
            "8.8.8.8:53",
            "https://cloudflare-dns.com@1.1.1.1",
            "192.168.122.1:53",
            "1.1.1.1:53",
            "tls://dns.google@8.8.8.8:853",
        ]
        .iter()
        .map(|s| Forwarder::parse(s).expect("parse"))
        .collect();

        let [encrypted, private, public] = by_preference(&forwarders);
        assert_eq!(
            encrypted
                .iter()
                .map(|f| f.label.as_str())
                .collect::<Vec<_>>(),
            ["https://cloudflare-dns.com", "tls://dns.google"]
        );
        assert_eq!(
            private.iter().map(|f| f.label.as_str()).collect::<Vec<_>>(),
            ["192.168.122.1:53"]
        );
        assert_eq!(
            public.iter().map(|f| f.label.as_str()).collect::<Vec<_>>(),
            ["8.8.8.8:53", "1.1.1.1:53"]
        );
    }

    // The three source lists overlap by design, so the same upstream arriving
    // twice must be dialled once — and must keep ONE breaker, or the duplicate
    // that stayed closed would hold a dead address in service forever.
    #[test]
    fn by_preference_deduplicates_across_source_lists() {
        let forwarders: Vec<Forwarder> = [
            "https://cloudflare-dns.com@1.1.1.1/dns-query",
            "8.8.8.8:53",
            // The same two again, as a second list would supply them.
            "https://cloudflare-dns.com@1.1.1.1/dns-query",
            "8.8.8.8:53",
        ]
        .iter()
        .map(|s| Forwarder::parse(s).expect("parse"))
        .collect();

        let [encrypted, _, public] = by_preference(&forwarders);
        assert_eq!(
            encrypted.len(),
            1,
            "duplicate encrypted upstream not folded"
        );
        assert_eq!(public.len(), 1, "duplicate plaintext forwarder not folded");
    }

    #[test]
    fn round_trips_through_its_spec() {
        for spec in [
            "8.8.8.8:53",
            "tcp://8.8.8.8:53",
            "tls://dns.google@8.8.8.8:853",
            "https://cloudflare-dns.com@1.1.1.1:443/dns-query",
            "quic://dns.adguard.com@94.140.14.14:853",
        ] {
            let parsed = Forwarder::parse(spec).unwrap_or_else(|e| panic!("{spec}: {e}"));
            let reparsed = Forwarder::parse(&parsed.to_spec())
                .unwrap_or_else(|e| panic!("{spec} -> {}: {e}", parsed.to_spec()));
            assert_eq!(reparsed.label, parsed.label, "{spec}");
            assert_eq!(reparsed.transport, parsed.transport, "{spec}");
            assert_eq!(reparsed.addr, parsed.addr, "{spec}");
        }
    }

    #[test]
    fn health_opens_only_after_the_threshold() {
        let health = Health::default();
        for _ in 0..FAILURE_THRESHOLD - 1 {
            health.record_failure();
            assert!(
                health.is_usable(),
                "opened before {FAILURE_THRESHOLD} failures"
            );
        }
        health.record_failure();
        assert!(
            !health.is_usable(),
            "did not open at {FAILURE_THRESHOLD} failures"
        );
    }

    // The control for the test above: a breaker that only ever opens is a
    // forwarder deleted by a blip. A success has to put it straight back into
    // service, with no failures banked against the next one.
    #[test]
    fn health_closes_on_success() {
        let health = Health::default();
        for _ in 0..FAILURE_THRESHOLD {
            health.record_failure();
        }
        assert!(!health.is_usable());

        health.record_success();
        assert!(health.is_usable());
        assert_eq!(health.failures(), 0);
    }

    // Reprogramming pushes an identical list every tick. Health that did not
    // survive that could never reach the threshold at all.
    #[test]
    fn health_is_carried_across_a_reprogramming() {
        let existing = vec![Forwarder::parse("8.8.8.8:53").expect("parse")];
        for _ in 0..FAILURE_THRESHOLD {
            existing[0].health.record_failure();
        }
        assert!(!existing[0].is_usable());

        let mut incoming = vec![
            Forwarder::parse("8.8.8.8:53").expect("parse"),
            Forwarder::parse("1.1.1.1:53").expect("parse"),
        ];
        assert!(incoming[0].is_usable(), "a fresh parse starts healthy");

        carry_health(&existing, &mut incoming);
        assert!(!incoming[0].is_usable(), "health was not carried over");
        assert!(
            incoming[1].is_usable(),
            "an unrelated forwarder inherited health"
        );
    }
}
