use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Configuration for the rolodex-dns server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// DNS listener configuration.
    pub dns: DnsConfig,
    /// gRPC management interface configuration.
    pub grpc: GrpcConfig,
    /// Upstream forwarder configuration.
    pub forwarders: Vec<String>,
    /// Upstream resolution strategy (recursive-from-roots by default).
    #[serde(default)]
    pub resolution: ResolutionConfig,
    /// DNSSEC validation of upstream answers.
    #[serde(default)]
    pub dnssec: DnssecConfig,
    /// Database file path for persistent DNS records.
    pub database_path: String,
    /// RBL (Realtime Blackhole List) configuration.
    pub rbl: RblSettings,
    /// DNSBL (domain blocklist) configuration.
    #[serde(default)]
    pub dnsbl: DnsblSettings,
    /// DNS-over-TLS (DoT) listener configuration.
    #[serde(default)]
    pub dot: Option<DotConfig>,
    /// DNS-over-HTTPS (DoH) listener configuration.
    #[serde(default)]
    pub doh: Option<DohConfig>,
    /// DNS-over-QUIC (DoQ) listener configuration.
    #[serde(default)]
    pub doq: Option<DoqConfig>,
    /// Upstream proxy configuration.
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,
    /// TTL drift adjustment settings.
    #[serde(default)]
    pub ttl_drift: TtlDriftSettings,
    /// DNS64 synthesis configuration.
    #[serde(default)]
    pub dns64: Dns64Config,
    /// Security settings.
    #[serde(default)]
    pub security: SecurityConfig,
    /// Address-family answer preference (probe v4/v6 routability; suppress a
    /// family the host can't reach so clients fall back to the working stack).
    #[serde(default)]
    pub address_family: AddressFamilyConfig,
    /// DHCP server configuration (disabled when absent).
    #[serde(default)]
    pub dhcp: Option<DhcpConfig>,
    /// ACME issuer / certificate-authority configuration (disabled when absent).
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
    /// Prometheus metrics endpoint (disabled when absent).
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
}

/// A DNS bind entry: protocol (udp/tcp) paired with a bind address.
///
/// Serializes as a single-key map: `{udp: "addr"}` or `{tcp: "addr"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsBind {
    Udp(String),
    Tcp(String),
}

impl Serialize for DnsBind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            DnsBind::Udp(addr) => map.serialize_entry("udp", addr)?,
            DnsBind::Tcp(addr) => map.serialize_entry("tcp", addr)?,
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for DnsBind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de;
        use std::collections::HashMap;

        let map = HashMap::<String, String>::deserialize(deserializer)?;
        if map.len() != 1 {
            return Err(de::Error::custom(
                "expected a single-key map with 'udp' or 'tcp'",
            ));
        }
        let (key, value) = map.into_iter().next().expect("checked len == 1");
        match key.as_str() {
            "udp" => Ok(DnsBind::Udp(value)),
            "tcp" => Ok(DnsBind::Tcp(value)),
            other => Err(de::Error::unknown_variant(other, &["udp", "tcp"])),
        }
    }
}

impl DnsBind {
    /// Returns the bind address string regardless of protocol.
    pub fn addr(&self) -> &str {
        match self {
            DnsBind::Udp(a) | DnsBind::Tcp(a) => a,
        }
    }
}

/// DNS listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// List of protocol + address pairs to bind (e.g. `[{udp: "0.0.0.0:53"}, {tcp: "0.0.0.0:53"}]`).
    pub bind: Vec<DnsBind>,
    /// Automatically maintain reverse PTR records for A and AAAA records added
    /// through the management interface. When enabled, adding an A record also
    /// creates the matching `in-addr.arpa` PTR and adding an AAAA record creates
    /// the matching `ip6.arpa` PTR; removing the forward record removes the PTR.
    /// Disabled by default (opt in to let Rolodex manage reverse zones).
    #[serde(default)]
    pub auto_ptr: bool,
    /// UDP/TCP port for per-TLD ingress listeners started via the gRPC
    /// `AddScopeTld` (with a `listen_ip`). The bind IP is provided per-TLD; this
    /// is the shared port. Defaults to 53; lower it for unprivileged dev runs.
    #[serde(default = "default_ingress_listen_port")]
    pub ingress_listen_port: u16,
    /// Number of `SO_REUSEPORT` sockets to bind per UDP listen address.
    ///
    /// A single UDP socket serialises the whole listener: one task drains it
    /// with `recv_from` and every reply goes back out through it, so receive is
    /// single-threaded and the kernel takes a per-socket lock on both ends. That
    /// caps throughput well below saturation no matter how many cores are free.
    /// Binding N sockets to the same `addr:port` with `SO_REUSEPORT` lets the
    /// kernel hash arriving datagrams across N independent receive loops, each
    /// with its own socket for replies.
    ///
    /// `0` (the default) means one shard per available core. `1` restores the
    /// old single-socket behaviour and is also what any single-shard listener
    /// uses — `SO_REUSEPORT` is only set when more than one shard is requested,
    /// so a lone listener still fails loudly on an occupied port instead of
    /// silently sharing it with another process.
    #[serde(default)]
    pub udp_shards: usize,
}

fn default_ingress_listen_port() -> u16 {
    53
}

impl DnsConfig {
    /// Returns all UDP bind address strings.
    pub fn udp_addrs(&self) -> impl Iterator<Item = &str> {
        self.bind.iter().filter_map(|e| match e {
            DnsBind::Udp(a) => Some(a.as_str()),
            _ => None,
        })
    }
    /// Returns all TCP bind address strings.
    pub fn tcp_addrs(&self) -> impl Iterator<Item = &str> {
        self.bind.iter().filter_map(|e| match e {
            DnsBind::Tcp(a) => Some(a.as_str()),
            _ => None,
        })
    }
}

/// Detects the primary outbound IP address by asking the OS which interface
/// would route to a public address. No data is sent over the network.
fn detect_primary_ip() -> Result<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .context("failed to bind UDP socket for primary IP detection")?;
    socket
        .connect("8.8.8.8:53")
        .context("failed to detect primary IP: no default route?")?;
    let addr = socket
        .local_addr()
        .context("failed to get local address for primary IP detection")?;
    Ok(addr.ip())
}

/// Resolves IP addresses assigned to the named network interface.
///
/// Returns all IPv4 and IPv6 addresses on the interface, each formatted
/// as `"ip:port"` (IPv4) or `"[ip]:port"` (IPv6, bracketed for socket parsing).
fn resolve_interface_addrs(iface_name: &str, port: u16) -> Result<Vec<String>> {
    let addrs = nix::ifaddrs::getifaddrs().context("failed to enumerate network interfaces")?;
    let mut found_interface = false;
    let mut result = Vec::new();
    for ia in addrs {
        if ia.interface_name != iface_name {
            continue;
        }
        found_interface = true;
        if let Some(addr) = ia.address {
            if let Some(sin) = addr.as_sockaddr_in() {
                let ip = sin.ip();
                result.push(format!("{}:{}", ip, port));
            } else if let Some(sin6) = addr.as_sockaddr_in6() {
                let ip = sin6.ip();
                result.push(format!("[{}]:{}", ip, port));
            }
        }
    }
    if !found_interface {
        anyhow::bail!("no interface named '{}' found", iface_name);
    }
    if result.is_empty() {
        anyhow::bail!("interface '{}' has no IP addresses assigned", iface_name);
    }
    Ok(result)
}

/// Resolves a bind address specification into one or more concrete socket addresses.
///
/// Accepts four forms:
/// - `"ip:port"` — literal IPv4 address, returned as-is in a single-element Vec
/// - `"[ipv6]:port"` — bracketed IPv6 literal, returned as-is
/// - `"primary:port"` — resolved to the OS default-route outbound IP address
/// - `"interface_name:port"` — resolved to all IP addresses on the named interface
///
/// Each resolved address is a concrete socket address string suitable for binding.
pub fn resolve_bind_addrs(addr: &str) -> Result<Vec<String>> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        anyhow::bail!("bind address must not be empty");
    }
    // Bracketed IPv6 literal: [::1]:port
    if trimmed.starts_with('[') {
        return Ok(vec![trimmed.to_string()]);
    }
    // Split on the last colon to separate host from port
    let Some(colon_pos) = trimmed.rfind(':') else {
        anyhow::bail!(
            "bind address '{}' must include a port (e.g. 'eth0:53' or '127.0.0.1:53')",
            trimmed
        );
    };
    let host = &trimmed[..colon_pos];
    let port_str = &trimmed[colon_pos + 1..];
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("invalid port in bind address '{}': '{}'", trimmed, port_str))?;
    // "primary" keyword — detect outbound IP via default route
    if host.eq_ignore_ascii_case("primary") {
        let ip = detect_primary_ip()?;
        return Ok(vec![format!("{}:{}", ip, port)]);
    }
    // If host parses as an IP address, it's a literal — pass through
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(vec![trimmed.to_string()]);
    }
    // Otherwise treat host as a network interface name
    resolve_interface_addrs(host, port)
}

/// Rejects a gRPC TCP listener that exposes the management plane with
/// authentication disabled.
///
/// An empty `grpc.shared_secret` makes `check_auth` early-return `Ok(())` for
/// every TCP RPC, so the management plane is unauthenticated: whoever reaches
/// the port can rewrite any DNS record, mint EAB credentials, and ensure zone
/// CAs. That is the documented development configuration on loopback and a
/// total, silent exposure of the box on anything else — the server comes up
/// looking healthy and logs nothing unusual.
///
/// `resolved` is the output of [`resolve_bind_addrs`] for `configured`; the
/// original string is carried through only for the error message, since
/// `primary:50051` and `eth0:50051` do not name their addresses. `0.0.0.0` and
/// `::` are not loopback — they cover every routable address on the host.
pub fn check_grpc_exposure(configured: &str, resolved: &[String], secret: &str) -> Result<()> {
    if !secret.is_empty() {
        return Ok(());
    }
    for bind in resolved {
        let addr: std::net::SocketAddr = bind
            .parse()
            .with_context(|| format!("invalid gRPC TCP bind address: {}", bind))?;
        if !addr.ip().is_loopback() {
            anyhow::bail!(
                "refusing to start: grpc.tcp_bind resolves to {} (from '{}') with an empty \
                 grpc.shared_secret, which disables authentication on the management plane. \
                 Set grpc.shared_secret, bind gRPC to loopback, or set grpc.tcp_bind to \"\" \
                 and use the Unix socket.",
                addr,
                configured
            );
        }
    }
    Ok(())
}

/// gRPC management interface configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    /// TCP address to bind the gRPC server (e.g. "127.0.0.1:50051").
    /// Set to empty string to disable TCP gRPC.
    pub tcp_bind: String,
    /// Unix socket path for the gRPC server.
    /// Set to empty string to disable Unix socket.
    pub unix_socket: String,
    /// Shared secret for authenticating TCP gRPC requests.
    /// Not required for Unix socket connections.
    pub shared_secret: String,
}

/// RBL provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RblProviderConfig {
    /// The RBL zone to query (e.g. "zen.spamhaus.org").
    pub zone: String,
    /// Whether this provider is enabled.
    pub enabled: bool,
    /// Codes this provider returns to mean "I refused your query" rather than
    /// "this is listed" — see [`crate::rbl::DEFAULT_REFUSAL_CODES`]. Each entry
    /// is an IPv4 address or `address/prefix`. Empty (the default, and what
    /// every configuration predating this field has) uses the built-in set; the
    /// single entry `none` disables refusal detection for this provider.
    #[serde(default)]
    pub refusal_codes: Vec<String>,
    /// How long this provider is rotated out of the lookup rotation after a
    /// refusal. Absent uses the list-wide `refusal_cooldown_secs`.
    #[serde(default)]
    pub refusal_cooldown_secs: Option<u64>,
}

/// RBL settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RblSettings {
    /// Whether RBL checking is globally enabled.
    pub enabled: bool,
    /// List of RBL providers.
    pub providers: Vec<RblProviderConfig>,
    /// Default seconds a refusing provider stays rotated out, for providers
    /// that do not set their own. `0` means the built-in default.
    #[serde(default = "default_refusal_cooldown_secs")]
    pub refusal_cooldown_secs: u64,
}

/// The built-in rotate-out duration, used when nothing configures one.
fn default_refusal_cooldown_secs() -> u64 {
    crate::rbl::DEFAULT_REFUSAL_COOLDOWN_SECS
}

impl RblProviderConfig {
    /// Converts to the runtime provider, resolving the refusal codes.
    ///
    /// An unparseable code is an error rather than a skipped entry: a code that
    /// silently does not apply turns back into "the provider's complaint reads
    /// as a listing", which is the failure this whole mechanism exists to stop,
    /// and it would do so invisibly.
    pub fn to_provider(&self) -> Result<crate::rbl::RblProvider, String> {
        let refusal_codes = crate::rbl::resolve_refusal_codes(&self.refusal_codes)
            .map_err(|e| format!("blocklist provider '{}': {e}", self.zone))?;
        Ok(crate::rbl::RblProvider {
            zone: self.zone.clone(),
            enabled: self.enabled,
            refusal_codes: refusal_codes.into(),
            cooldown: self
                .refusal_cooldown_secs
                .filter(|s| *s > 0)
                .map(std::time::Duration::from_secs),
        })
    }
}

/// Converts a configured provider list, reporting the first bad entry.
pub fn to_providers(
    providers: &[RblProviderConfig],
) -> Result<Vec<crate::rbl::RblProvider>, String> {
    providers.iter().map(|p| p.to_provider()).collect()
}

/// DNSBL (domain blocklist) settings.
///
/// DNSBL providers are queried by prepending the looked-up domain name to the
/// zone (e.g. `dbl.spamhaus.org`), as opposed to RBL providers which are queried
/// with a reversed IP. DNSBL listings take precedence over forwarded/iterative
/// answers. Disabled with no providers by default; operators add the providers
/// they want via config or `SetDnsblConfig`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsblSettings {
    /// Whether DNSBL checking is globally enabled.
    pub enabled: bool,
    /// List of DNSBL providers.
    pub providers: Vec<RblProviderConfig>,
    /// Default seconds a refusing provider stays rotated out, for providers
    /// that do not set their own. `0` means the built-in default. Independent
    /// of the RBL setting because the two lists are configured independently.
    #[serde(default = "default_refusal_cooldown_secs")]
    pub refusal_cooldown_secs: u64,
}

impl Default for DnsblSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            providers: Vec::new(),
            refusal_cooldown_secs: default_refusal_cooldown_secs(),
        }
    }
}

/// TLS configuration for encrypted DNS transports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the TLS certificate file.
    pub cert_path: Option<String>,
    /// Path to the TLS private key file.
    pub key_path: Option<String>,
    /// Whether to automatically generate a self-signed certificate if none is provided.
    #[serde(default = "default_true")]
    pub auto_self_signed: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            auto_self_signed: true,
        }
    }
}

/// DNS-over-TLS (DoT) listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotConfig {
    /// Address to bind the DoT listener (e.g. "0.0.0.0:853").
    #[serde(default = "default_dot_bind")]
    pub bind: String,
    /// TLS settings for the DoT listener.
    #[serde(default)]
    pub tls: TlsConfig,
}

impl Default for DotConfig {
    fn default() -> Self {
        Self {
            bind: default_dot_bind(),
            tls: TlsConfig::default(),
        }
    }
}

/// DNS-over-HTTPS (DoH) listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DohConfig {
    /// Address to bind the DoH listener (e.g. "0.0.0.0:443").
    #[serde(default = "default_doh_bind")]
    pub bind: String,
    /// TLS settings for the DoH listener.
    #[serde(default)]
    pub tls: TlsConfig,
    /// Whether to enable HTTP/3 (QUIC) transport for DoH.
    #[serde(default)]
    pub enable_h3: bool,
}

impl Default for DohConfig {
    fn default() -> Self {
        Self {
            bind: default_doh_bind(),
            tls: TlsConfig::default(),
            enable_h3: false,
        }
    }
}

/// DNS-over-QUIC (DoQ) listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoqConfig {
    /// Address to bind the DoQ listener (e.g. "0.0.0.0:8853").
    #[serde(default = "default_doq_bind")]
    pub bind: String,
    /// TLS settings for the DoQ listener.
    #[serde(default)]
    pub tls: TlsConfig,
}

impl Default for DoqConfig {
    fn default() -> Self {
        Self {
            bind: default_doq_bind(),
            tls: TlsConfig::default(),
        }
    }
}

/// ACME issuer / certificate-authority configuration.
///
/// When present, Rolodex runs an RFC 8555 ACME server (the `bind` listener,
/// client-facing) plus a trusted-network enrollment portal (the `portal_bind`
/// listener). Omit the section to disable both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// Address to bind the client-facing ACME HTTPS listener (e.g. "0.0.0.0:8555").
    #[serde(default = "default_acme_bind")]
    pub bind: String,
    /// Address to bind the trusted-network enrollment portal (e.g. "127.0.0.1:8500").
    #[serde(default = "default_acme_portal_bind")]
    pub portal_bind: String,
    /// TLS settings for the ACME and portal listeners.
    #[serde(default)]
    pub tls: TlsConfig,
    /// External base URL of the ACME directory advertised to clients
    /// (e.g. "https://dns.example.com:8555/acme"). Must be reachable by clients.
    #[serde(default = "default_acme_directory_url")]
    pub directory_url: String,
    /// Common name for the Rolodex root CA created at boot.
    #[serde(default = "default_acme_root_cn")]
    pub root_ca_cn: String,
    /// Validity of issued leaf certificates, in days.
    #[serde(default = "default_acme_leaf_validity_days")]
    pub leaf_validity_days: i64,
    /// Default port used to place the auto-published DANE-TA TLSA record.
    #[serde(default = "default_acme_tlsa_port")]
    pub tlsa_port: u16,
    /// Default protocol used to place the auto-published DANE-TA TLSA record.
    #[serde(default = "default_acme_tlsa_proto")]
    pub tlsa_proto: String,
    /// Whether External Account Binding is required for account registration.
    #[serde(default = "default_true")]
    pub require_eab: bool,
    /// Issuance scope: "managed_zones" (only names under an intermediate-backed
    /// zone) or "any".
    #[serde(default = "default_acme_issuance_scope")]
    pub issuance_scope: String,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            bind: default_acme_bind(),
            portal_bind: default_acme_portal_bind(),
            tls: TlsConfig::default(),
            directory_url: default_acme_directory_url(),
            root_ca_cn: default_acme_root_cn(),
            leaf_validity_days: default_acme_leaf_validity_days(),
            tlsa_port: default_acme_tlsa_port(),
            tlsa_proto: default_acme_tlsa_proto(),
            require_eab: true,
            issuance_scope: default_acme_issuance_scope(),
        }
    }
}

impl AcmeConfig {
    /// Returns true if issuance is allowed for any name (not just managed zones).
    pub fn issuance_any(&self) -> bool {
        self.issuance_scope.eq_ignore_ascii_case("any")
    }
}

/// Upstream proxy configuration for forwarding DNS queries through a proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Proxy URL (e.g. "socks5://127.0.0.1:1080").
    pub url: String,
    /// Optional authentication credentials for the proxy.
    pub auth: Option<String>,
    /// Proxy mode (e.g. "connect", "socks5").
    #[serde(default = "default_proxy_mode")]
    pub mode: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            auth: None,
            mode: default_proxy_mode(),
        }
    }
}

/// TTL drift settings for adjusting cached record TTLs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlDriftSettings {
    /// Drift mode: "disabled", "fixed", or "logarithmic".
    #[serde(default = "default_ttl_drift_mode")]
    pub mode: String,
    /// Fixed TTL adjustment duration (e.g. "0s", "30s", "-10s").
    #[serde(default = "default_ttl_drift_fixed_adjustment")]
    pub fixed_adjustment: String,
    /// Logarithmic multiplier for TTL drift calculations.
    #[serde(default = "default_ttl_drift_log_multiplier")]
    pub log_multiplier: f64,
}

impl Default for TtlDriftSettings {
    fn default() -> Self {
        Self {
            mode: default_ttl_drift_mode(),
            fixed_adjustment: default_ttl_drift_fixed_adjustment(),
            log_multiplier: default_ttl_drift_log_multiplier(),
        }
    }
}

/// DNS64 configuration for synthesizing AAAA records from A records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dns64Config {
    /// Whether DNS64 synthesis is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// The NAT64 prefix used for address synthesis (e.g. "64:ff9b::").
    #[serde(default = "default_dns64_prefix")]
    pub prefix: String,
}

impl Default for Dns64Config {
    fn default() -> Self {
        Self {
            enabled: false,
            prefix: default_dns64_prefix(),
        }
    }
}

/// Prometheus metrics endpoint configuration.
///
/// Opt-in: the section is absent by default and no listener is started, so an
/// existing deployment gains no new open port on upgrade. The default bind is
/// loopback because the endpoint is unauthenticated plain HTTP — see
/// [`crate::metrics::serve_metrics`] for why that is the right trade here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// HTTP bind address for the `/metrics` endpoint. Supports the same
    /// `primary:port` and `interface:port` forms as every other bind address.
    /// Port 9153 matches CoreDNS's convention for DNS exporters.
    #[serde(default = "default_metrics_bind")]
    pub bind: String,
    /// TLDs that get their own `tld` label value on the per-TLD query metrics,
    /// over and above the ones tracked automatically.
    ///
    /// Every TLD a network scope owns — including each scope's implicit `.home`
    /// domain — is tracked without being listed here; this is the opt-in list
    /// for everything else. Names not under a tracked TLD fold into the `other`
    /// series, which is what bounds the dimension: the queried name is chosen by
    /// the client, so an unbounded `tld` label would let a scanner sweeping junk
    /// TLDs mint series until the registry ate the process.
    ///
    /// The entry `common` expands to [`crate::metrics::COMMON_TLDS`], so the
    /// usual public TLDs are one line rather than twenty. Entries are
    /// case-insensitive and the trailing dot is optional.
    ///
    /// This list is additive with the one stored by `SetTrackedTlds`: the
    /// effective set is the union of both plus the owned TLDs, so an operator
    /// cannot remove a config-pinned entry over the API — restart-surviving
    /// intent stays in the file.
    #[serde(default)]
    pub tracked_tlds: Vec<String>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            bind: default_metrics_bind(),
            tracked_tlds: Vec::new(),
        }
    }
}

fn default_metrics_bind() -> String {
    "127.0.0.1:9153".to_string()
}

/// DHCP server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    /// UDP bind address for the DHCP server (default "0.0.0.0:67").
    #[serde(default = "default_dhcp_bind")]
    pub bind: String,
    /// Default lease duration in seconds (default 3600 = 1 hour).
    #[serde(default = "default_dhcp_lease_duration")]
    pub default_lease_duration: u64,
    /// Duration in seconds after lease expiry before IP is reclaimed (default 86400 = 24 hours).
    #[serde(default = "default_dhcp_reclaim_timeout")]
    pub reclaim_timeout: u64,
    /// Interval in seconds for the background lease expiry sweep (default 60).
    #[serde(default = "default_dhcp_sweep_interval")]
    pub sweep_interval: u64,
    /// TLD used for hostname DNS registration (e.g. "example.com" produces
    /// "<hostname>.lan.example.com."). Required when DHCP is enabled.
    pub tld: String,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            bind: default_dhcp_bind(),
            default_lease_duration: default_dhcp_lease_duration(),
            reclaim_timeout: default_dhcp_reclaim_timeout(),
            sweep_interval: default_dhcp_sweep_interval(),
            tld: String::new(),
        }
    }
}

/// Upstream resolution strategy.
///
/// Modes:
/// - `auto` (the default): a resilient fallback chain — resolve iteratively from
///   the root servers first, then, if that fails (e.g. a network that filters
///   outbound port 53), fall back in order to (1) DoT/DoH to the configured
///   `secure_upstreams` over an encrypted transport that bypasses :53 filtering,
///   (2) the configured plaintext `forwarders` (the local/DHCP resolver), and
///   (3) the plaintext `public_fallback` resolvers over :53 as a last resort.
/// - `recursive`: iterative from the root servers only, never contacting an
///   upstream.
/// - `forward`: forward unmatched queries to the configured `forwarders` only
///   (legacy behavior).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionConfig {
    /// Resolution mode: `auto` (root-first fallback chain), `recursive`
    /// (iterative from the roots only), or `forward` (configured forwarders only).
    #[serde(default = "default_resolution_mode")]
    pub mode: String,
    /// Optional override for the root server hints used in recursive/auto mode.
    /// When empty, the built-in IANA root server addresses are used.
    #[serde(default)]
    pub root_hints: Vec<String>,
    /// Encrypted (DoH/DoT) upstreams tried in `auto` mode after root recursion
    /// fails — chosen because they use ports (443/853) that survive :53 filtering.
    /// Defaults to Cloudflare and Google over **DoH (:443)**, which looks like
    /// ordinary HTTPS and survives DPI that also blocks DoT's :853.
    #[serde(default = "default_secure_upstreams")]
    pub secure_upstreams: Vec<SecureUpstreamConfig>,
    /// Plaintext public resolvers (`ip:port`, Do53) tried LAST in `auto` mode.
    /// Defaults to Cloudflare/Google on :53.
    #[serde(default = "default_public_fallback")]
    pub public_fallback: Vec<String>,
    /// `auto` mode: how many consecutive deciding queries must resolve via a
    /// *different* tier than the current active one before the active tier is
    /// switched. Keeps a single flaky query from thrashing the method (and the
    /// cache). Default 3.
    #[serde(default = "default_switch_grace_failures")]
    pub switch_grace_failures: u32,
    /// `auto` mode: once degraded to a lower tier, how often (seconds) to retry
    /// the full chain from the top so a recovered, more-preferred tier can be
    /// reclaimed. Default 60.
    #[serde(default = "default_recovery_probe_secs")]
    pub recovery_probe_secs: u64,
    /// Delegations (zone -> nameservers, learned while walking down from the
    /// roots) whose TTL exceeds this many seconds are persisted to the database,
    /// so a restart comes back warm instead of re-walking the root servers for
    /// every name. Shorter-lived delegations are kept in memory only. Root and
    /// TLD NS sets carry multi-day TTLs, so in practice the entries actually
    /// worth keeping are the ones that survive. Default 300 (5m).
    #[serde(default = "default_delegation_persist_min_ttl")]
    pub delegation_persist_min_ttl: u32,
    /// TTL applied wherever a record or response supplies none of its own: an
    /// NXDOMAIN/NODATA with no SOA, a delegation or glue record with a zero TTL.
    ///
    /// A TTL that *is* present is always honoured exactly as sent — including an
    /// SOA's negative TTL, which is never clamped. This is only the fallback for
    /// when there is nothing to honour. Default 300 (5m).
    #[serde(default = "default_ttl_secs")]
    pub default_ttl: u32,
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self {
            mode: default_resolution_mode(),
            root_hints: Vec::new(),
            secure_upstreams: default_secure_upstreams(),
            public_fallback: default_public_fallback(),
            switch_grace_failures: default_switch_grace_failures(),
            recovery_probe_secs: default_recovery_probe_secs(),
            delegation_persist_min_ttl: default_delegation_persist_min_ttl(),
            default_ttl: default_ttl_secs(),
        }
    }
}

/// DNSSEC validation of answers resolved from upstream.
///
/// Validation applies to the **iterative** path only — `recursive` mode, and the
/// roots tier of `auto` mode. It cannot apply to the forwarding tiers: a
/// forwarded response is a recursive resolver's summary, and validating it would
/// mean re-resolving the whole chain ourselves, which is what the roots tier
/// already is. An `auto` chain that has degraded past tier 0 is therefore
/// unvalidated, and says so — see the `AD` handling in `dns_server.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecConfig {
    /// Whether to validate. On by default: a validating resolver that ships
    /// switched off validates nothing until someone remembers to turn it on,
    /// which in practice means never.
    ///
    /// Set to `false` to resolve exactly as before — no DO bit on outbound
    /// queries, no chain of trust, no SERVFAIL for bogus data.
    #[serde(default = "default_dnssec_validate")]
    pub validate: bool,
    /// Trust anchors, in DNSKEY presentation form: `"<flags> <protocol>
    /// <algorithm> <base64 key>"`, e.g. `"257 3 8 AwEAAaz/..."` — the four RDATA
    /// fields as `dig DNSKEY <zone>` prints them.
    ///
    /// Every field is validated at startup and a bad one is a hard failure, not
    /// a fallback to the IANA keys: an anchor that cannot match a real DNSKEY
    /// makes every signed zone fail with nothing pointing at the anchor as the
    /// cause. See `dnssec_validate::Anchors::from_dnskey_strings`.
    ///
    /// Empty means the IANA root keys compiled into hickory (KSK-2017 and its
    /// 2024 successor), which is what any deployment resolving the real internet
    /// wants. An override replaces them outright rather than adding to them, so
    /// a test hierarchy or a private root is anchored to its own key and to
    /// nothing else — an anchor list that still trusted IANA would let the real
    /// root vouch for names inside a private namespace.
    #[serde(default)]
    pub trust_anchors: Vec<String>,
}

impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            validate: default_dnssec_validate(),
            trust_anchors: Vec::new(),
        }
    }
}

fn default_dnssec_validate() -> bool {
    true
}

/// A single encrypted upstream (DoH/DoT) used in `auto` mode. The `addr` is
/// dialed by IP:port (so it needs no prior DNS), and `hostname` is the TLS SNI /
/// certificate name validated against it (both Cloudflare's and Google's certs
/// include their resolver IPs as SANs, so dialing by IP still verifies).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureUpstreamConfig {
    /// Transport: `https` (DoH, RFC 8484, :443 — preferred) or `tls` (DoT, RFC 7858, :853).
    #[serde(default = "default_secure_transport")]
    pub transport: String,
    /// Upstream socket address, dialed directly, e.g. `1.1.1.1:443`.
    pub addr: String,
    /// TLS server name to send as SNI and validate the certificate against,
    /// e.g. `cloudflare-dns.com` for 1.1.1.1 or `dns.google` for 8.8.8.8.
    pub hostname: String,
    /// DoH request path (ignored for DoT). Defaults to `/dns-query`.
    #[serde(default = "default_doh_path")]
    pub path: String,
}

/// Security-related configuration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Whether to randomize the case of QNAME labels (0x20 encoding) for cache-poisoning resistance.
    #[serde(default = "default_true")]
    pub qname_case_randomization: bool,
    /// Source CIDRs treated as untrusted network-overlay peers (WireGuard
    /// links). Network-scope enforcement applies **only** to these ranges: a
    /// query from here must be joined to a scope (else REFUSED) and sees only
    /// its own scope's partitioned TLDs. Every other source — loopback, the
    /// LAN, container bridges — is trusted and resolves the full view (public
    /// names plus any scope's records, keyed by the query's owned TLD).
    /// Defaults to Town OS's WireGuard overlay range `10.64.0.0/10` (see
    /// `SubnetForNetwork` in the controller's `wireguard/ipam.go`).
    #[serde(default = "default_overlay_cidrs")]
    pub overlay_cidrs: Vec<String>,

    /// Source CIDRs permitted to drive **upstream** resolution. A query from
    /// outside these ranges is still answered from local/authoritative data but
    /// is REFUSED rather than forwarded or resolved iteratively.
    ///
    /// `dns.bind` defaults to `0.0.0.0:53`, so on a routable interface the
    /// listener is reachable from the whole internet; recursing for it would
    /// make this box an open resolver — a reflection/amplification asset whose
    /// outbound traffic you pay for. The default list is every range that is
    /// unroutable from the internet (loopback, RFC 1918, link-local, ULA,
    /// CGNAT), which covers the LAN, the container bridges, and the WireGuard
    /// overlay. Widen it only for source ranges you actually intend to serve.
    ///
    /// This is a separate axis from `overlay_cidrs`: that one decides who is
    /// *scope-enforced*, this one decides who gets recursion at all.
    #[serde(default = "default_recursion_cidrs")]
    pub recursion_cidrs: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            qname_case_randomization: true,
            overlay_cidrs: default_overlay_cidrs(),
            recursion_cidrs: default_recursion_cidrs(),
        }
    }
}

fn default_overlay_cidrs() -> Vec<String> {
    vec!["10.64.0.0/10".to_string()]
}

fn default_recursion_cidrs() -> Vec<String> {
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
    .map(|s| s.to_string())
    .collect()
}

/// Address-family answer preference. In `auto` mode a background probe (see
/// `probe.rs`) periodically tests real IPv4/IPv6 internet routability and
/// suppresses A or AAAA answers for a family the host cannot reach — so a client
/// isn't handed an address in a dead family and stall on it. `off` always
/// answers both families (legacy behavior); `force4` / `force6` pin a single
/// family (mainly for testing) without probing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressFamilyConfig {
    /// `auto` (probe and suppress), `off` (answer both, always), `force4`
    /// (IPv4 only), or `force6` (IPv6 only).
    #[serde(default = "default_address_family_mode")]
    pub mode: String,
    /// Seconds between routability probes in `auto` mode.
    #[serde(default = "default_af_probe_interval_secs")]
    pub probe_interval_secs: u64,
    /// Consecutive failed probe cycles before a previously-up family is marked
    /// unreachable (debounce against flaps). Recovery is immediate on the first
    /// success. The very first probe at startup is decisive (no grace) so a boot
    /// onto a dead-family link suppresses it from the first query.
    #[serde(default = "default_af_fail_threshold")]
    pub fail_threshold: u32,
    /// Per-target TCP-connect timeout (seconds) for each probe.
    #[serde(default = "default_af_probe_timeout_secs")]
    pub probe_timeout_secs: u64,
    /// `ip:port` targets probed for IPv4 reachability (TCP connect; first success
    /// marks IPv4 up). Use literal IPs on :443. Defaults to public anycast
    /// resolvers — :443 because it is what real traffic uses and survives the
    /// :53/:853 filtering some networks impose.
    #[serde(default = "default_af_targets_v4")]
    pub targets_v4: Vec<String>,
    /// `[ip]:port` targets probed for IPv6 reachability.
    #[serde(default = "default_af_targets_v6")]
    pub targets_v6: Vec<String>,
}

impl Default for AddressFamilyConfig {
    fn default() -> Self {
        Self {
            mode: default_address_family_mode(),
            probe_interval_secs: default_af_probe_interval_secs(),
            fail_threshold: default_af_fail_threshold(),
            probe_timeout_secs: default_af_probe_timeout_secs(),
            targets_v4: default_af_targets_v4(),
            targets_v6: default_af_targets_v6(),
        }
    }
}

fn default_address_family_mode() -> String {
    "auto".to_string()
}

fn default_af_probe_interval_secs() -> u64 {
    30
}

fn default_af_fail_threshold() -> u32 {
    2
}

fn default_af_probe_timeout_secs() -> u64 {
    2
}

fn default_af_targets_v4() -> Vec<String> {
    vec!["1.1.1.1:443".to_string(), "8.8.8.8:443".to_string()]
}

fn default_af_targets_v6() -> Vec<String> {
    vec![
        "[2606:4700:4700::1111]:443".to_string(),
        "[2001:4860:4860::8888]:443".to_string(),
    ]
}

fn default_true() -> bool {
    true
}

fn default_resolution_mode() -> String {
    "auto".to_string()
}

fn default_secure_transport() -> String {
    "https".to_string()
}

fn default_doh_path() -> String {
    "/dns-query".to_string()
}

fn default_secure_upstreams() -> Vec<SecureUpstreamConfig> {
    // DoH over :443 preferred (survives DPI that blocks DoT's :853).
    vec![
        SecureUpstreamConfig {
            transport: "https".to_string(),
            addr: "1.1.1.1:443".to_string(),
            hostname: "cloudflare-dns.com".to_string(),
            path: "/dns-query".to_string(),
        },
        SecureUpstreamConfig {
            transport: "https".to_string(),
            addr: "8.8.8.8:443".to_string(),
            hostname: "dns.google".to_string(),
            path: "/dns-query".to_string(),
        },
    ]
}

fn default_public_fallback() -> Vec<String> {
    vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()]
}

fn default_switch_grace_failures() -> u32 {
    3
}

fn default_delegation_persist_min_ttl() -> u32 {
    crate::delegation_cache::DEFAULT_PERSIST_MIN_TTL
}

fn default_ttl_secs() -> u32 {
    crate::resolver::DEFAULT_TTL
}

fn default_recovery_probe_secs() -> u64 {
    60
}

fn default_dot_bind() -> String {
    "0.0.0.0:853".to_string()
}

fn default_doh_bind() -> String {
    "0.0.0.0:443".to_string()
}

fn default_doq_bind() -> String {
    "0.0.0.0:8853".to_string()
}

fn default_proxy_mode() -> String {
    "connect".to_string()
}

fn default_acme_bind() -> String {
    "0.0.0.0:8555".to_string()
}

fn default_acme_portal_bind() -> String {
    "127.0.0.1:8500".to_string()
}

fn default_acme_directory_url() -> String {
    "https://localhost:8555/acme".to_string()
}

fn default_acme_root_cn() -> String {
    "Rolodex Root CA".to_string()
}

fn default_acme_leaf_validity_days() -> i64 {
    90
}

fn default_acme_tlsa_port() -> u16 {
    443
}

fn default_acme_tlsa_proto() -> String {
    "tcp".to_string()
}

fn default_acme_issuance_scope() -> String {
    "managed_zones".to_string()
}

fn default_ttl_drift_mode() -> String {
    "disabled".to_string()
}

fn default_ttl_drift_fixed_adjustment() -> String {
    "0s".to_string()
}

fn default_ttl_drift_log_multiplier() -> f64 {
    0.1
}

fn default_dns64_prefix() -> String {
    "64:ff9b::".to_string()
}

fn default_dhcp_bind() -> String {
    "0.0.0.0:67".to_string()
}

fn default_dhcp_lease_duration() -> u64 {
    3600
}

fn default_dhcp_reclaim_timeout() -> u64 {
    86400
}

fn default_dhcp_sweep_interval() -> u64 {
    60
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dns: DnsConfig {
                bind: vec![
                    DnsBind::Udp("0.0.0.0:53".to_string()),
                    DnsBind::Tcp("0.0.0.0:53".to_string()),
                ],
                auto_ptr: false,
                ingress_listen_port: default_ingress_listen_port(),
                udp_shards: 0,
            },
            grpc: GrpcConfig {
                tcp_bind: "127.0.0.1:50051".to_string(),
                unix_socket: "/var/run/rolodex-dns.sock".to_string(),
                shared_secret: String::new(),
            },
            forwarders: vec!["8.8.8.8:53".to_string(), "8.8.4.4:53".to_string()],
            resolution: ResolutionConfig::default(),
            dnssec: DnssecConfig::default(),
            database_path: "rolodex-dns.db".to_string(),
            rbl: RblSettings {
                enabled: false,
                providers: Vec::new(),
                refusal_cooldown_secs: default_refusal_cooldown_secs(),
            },
            dnsbl: DnsblSettings::default(),
            dot: None,
            doh: None,
            doq: None,
            proxy: None,
            ttl_drift: TtlDriftSettings::default(),
            dns64: Dns64Config::default(),
            security: SecurityConfig::default(),
            address_family: AddressFamilyConfig::default(),
            dhcp: None,
            acme: None,
            metrics: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(
            config.dns.bind,
            vec![
                DnsBind::Udp("0.0.0.0:53".to_string()),
                DnsBind::Tcp("0.0.0.0:53".to_string()),
            ]
        );
        assert_eq!(config.grpc.tcp_bind, "127.0.0.1:50051");
        // RBL and DNSBL default to disabled with empty provider lists.
        assert!(!config.rbl.enabled);
        assert!(config.rbl.providers.is_empty());
        assert!(!config.dnsbl.enabled);
        assert!(config.dnsbl.providers.is_empty());
        // Resolution defaults to the auto fallback chain with no custom hints,
        // and ships built-in secure (DoT) and public (:53) fallback upstreams.
        assert_eq!(config.resolution.mode, "auto");
        assert!(config.resolution.root_hints.is_empty());
        assert_eq!(config.resolution.secure_upstreams.len(), 2);
        assert_eq!(
            config.resolution.public_fallback,
            vec!["1.1.1.1:53", "8.8.8.8:53"]
        );
    }

    #[test]
    fn test_resolution_config_defaults_when_omitted() {
        // A YAML document without a `resolution:` section must default to
        // auto mode (the field is `#[serde(default)]`).
        let yaml = "dns:\n  bind:\n    - udp: \"0.0.0.0:53\"\ngrpc:\n  tcp_bind: \"127.0.0.1:50051\"\n  unix_socket: \"\"\n  shared_secret: \"\"\nforwarders: []\ndatabase_path: \"x.db\"\nrbl:\n  enabled: false\n  providers: []\n";
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.resolution.mode, "auto");
        assert!(config.resolution.root_hints.is_empty());
        // Secure + public fallbacks are populated by their serde defaults.
        assert_eq!(config.resolution.secure_upstreams.len(), 2);
        assert_eq!(config.resolution.secure_upstreams[0].addr, "1.1.1.1:443");
        assert_eq!(
            config.resolution.secure_upstreams[0].hostname,
            "cloudflare-dns.com"
        );
        assert_eq!(config.resolution.secure_upstreams[0].transport, "https");
    }

    /// A configuration written before refusal codes existed must keep parsing,
    /// and must land on the built-in codes — the whole point of the defaults is
    /// that an unmodified deployment stops reading a provider's "stop querying
    /// me" answer as a listing.
    #[test]
    fn rbl_provider_without_refusal_fields_gets_defaults() {
        let yaml = "dns:\n  bind:\n    - udp: \"0.0.0.0:53\"\ngrpc:\n  tcp_bind: \"127.0.0.1:50051\"\n  unix_socket: \"\"\n  shared_secret: \"\"\nforwarders: []\ndatabase_path: \"x.db\"\nrbl:\n  enabled: true\n  providers:\n    - zone: \"zen.spamhaus.org\"\n      enabled: true\n";
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(config.rbl.providers[0].refusal_codes.is_empty());
        assert!(config.rbl.providers[0].refusal_cooldown_secs.is_none());
        assert_eq!(
            config.rbl.refusal_cooldown_secs,
            crate::rbl::DEFAULT_REFUSAL_COOLDOWN_SECS
        );

        let provider = config.rbl.providers[0].to_provider().unwrap();
        assert_eq!(
            provider.refusal_codes.len(),
            crate::rbl::DEFAULT_REFUSAL_CODES.len()
        );
        assert!(
            provider.cooldown.is_none(),
            "no override means the list default"
        );
    }

    #[test]
    fn rbl_provider_refusal_fields_parse() {
        let yaml = "dns:\n  bind:\n    - udp: \"0.0.0.0:53\"\ngrpc:\n  tcp_bind: \"127.0.0.1:50051\"\n  unix_socket: \"\"\n  shared_secret: \"\"\nforwarders: []\ndatabase_path: \"x.db\"\nrbl:\n  enabled: true\n  refusal_cooldown_secs: 900\n  providers:\n    - zone: \"private.rbl\"\n      enabled: true\n      refusal_codes: [\"none\"]\n    - zone: \"zen.spamhaus.org\"\n      enabled: true\n      refusal_codes: [\"127.255.255.0/24\"]\n      refusal_cooldown_secs: 1800\n";
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.rbl.refusal_cooldown_secs, 900);

        let private = config.rbl.providers[0].to_provider().unwrap();
        assert!(
            private.refusal_codes.is_empty(),
            "'none' disables detection"
        );

        let zen = config.rbl.providers[1].to_provider().unwrap();
        assert_eq!(zen.refusal_codes.len(), 1);
        assert_eq!(zen.cooldown, Some(std::time::Duration::from_secs(1800)));
    }

    /// A malformed code is an error, not a dropped entry: a code that silently
    /// does not apply is a refusal that reads as a listing.
    #[test]
    fn rbl_provider_rejects_malformed_refusal_code() {
        let provider = RblProviderConfig {
            zone: "bad.rbl".to_string(),
            enabled: true,
            refusal_codes: vec!["127.0.0.1".to_string(), "not-an-ip".to_string()],
            refusal_cooldown_secs: None,
        };
        let err = provider.to_provider().expect_err("must not be accepted");
        assert!(
            err.contains("bad.rbl"),
            "error should name the provider: {err}"
        );
        assert!(to_providers(std::slice::from_ref(&provider)).is_err());
    }

    #[test]
    fn test_resolution_config_roundtrip() {
        let mut config = Config::default();
        config.resolution.mode = "forward".to_string();
        config.resolution.root_hints = vec!["198.41.0.4".to_string()];
        let serialized = serde_yaml_ng::to_string(&config).unwrap();
        let deserialized: Config = serde_yaml_ng::from_str(&serialized).unwrap();
        assert_eq!(deserialized.resolution.mode, "forward");
        assert_eq!(deserialized.resolution.root_hints, vec!["198.41.0.4"]);
    }

    #[test]
    fn test_rbl_dnsbl_default_to_empty() {
        // Both blocklists ship empty: the server queries no external provider
        // until an operator configures one.
        let config = Config::default();
        assert!(config.rbl.providers.is_empty());
        assert!(config.dnsbl.providers.is_empty());
    }

    #[test]
    fn test_config_without_dnsbl_section_uses_default() {
        // Existing configs predating the dnsbl section must still parse, and
        // default to a disabled DNSBL with no providers.
        let yaml = "dns:\n  bind:\n    - udp: \"0.0.0.0:53\"\ngrpc:\n  tcp_bind: \"127.0.0.1:50051\"\n  unix_socket: \"\"\n  shared_secret: \"\"\nforwarders: []\ndatabase_path: \"x.db\"\nrbl:\n  enabled: false\n  providers: []\n";
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(!config.dnsbl.enabled);
        assert!(config.dnsbl.providers.is_empty());
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let serialized = serde_yaml_ng::to_string(&config).unwrap();
        let deserialized: Config = serde_yaml_ng::from_str(&serialized).unwrap();
        assert_eq!(deserialized.dns.bind, config.dns.bind);
        assert_eq!(deserialized.forwarders.len(), config.forwarders.len());
    }

    #[test]
    fn test_new_config_fields_defaults() {
        let config = Config::default();

        // Optional encrypted transport configs default to None
        assert!(config.dot.is_none());
        assert!(config.doh.is_none());
        assert!(config.doq.is_none());
        assert!(config.proxy.is_none());

        // TTL drift defaults
        assert_eq!(config.ttl_drift.mode, "disabled");
        assert_eq!(config.ttl_drift.fixed_adjustment, "0s");
        assert!((config.ttl_drift.log_multiplier - 0.1).abs() < f64::EPSILON);

        // DNS64 defaults
        assert!(!config.dns64.enabled);
        assert_eq!(config.dns64.prefix, "64:ff9b::");

        // Security defaults
        assert!(config.security.qname_case_randomization);
    }

    #[test]
    fn test_new_config_fields_serialization() {
        // Build a config with all new fields populated
        let config = Config {
            dot: Some(DotConfig {
                bind: "0.0.0.0:853".to_string(),
                tls: TlsConfig {
                    cert_path: Some("/etc/certs/dot.pem".to_string()),
                    key_path: Some("/etc/certs/dot.key".to_string()),
                    auto_self_signed: false,
                },
            }),
            doh: Some(DohConfig {
                bind: "0.0.0.0:443".to_string(),
                tls: TlsConfig::default(),
                enable_h3: false,
            }),
            doq: Some(DoqConfig {
                bind: "0.0.0.0:8853".to_string(),
                tls: TlsConfig::default(),
            }),
            proxy: Some(ProxyConfig {
                url: "socks5://127.0.0.1:1080".to_string(),
                auth: Some("user:pass".to_string()),
                mode: "socks5".to_string(),
            }),
            ttl_drift: TtlDriftSettings {
                mode: "logarithmic".to_string(),
                fixed_adjustment: "30s".to_string(),
                log_multiplier: 0.5,
            },
            dns64: Dns64Config {
                enabled: true,
                prefix: "64:ff9b::".to_string(),
            },
            security: SecurityConfig {
                qname_case_randomization: false,
                overlay_cidrs: default_overlay_cidrs(),
                recursion_cidrs: default_recursion_cidrs(),
            },
            ..Config::default()
        };

        // Round-trip through YAML
        let serialized = serde_yaml_ng::to_string(&config).unwrap();
        let deserialized: Config = serde_yaml_ng::from_str(&serialized).unwrap();

        // Verify DoT
        let dot = deserialized.dot.unwrap();
        assert_eq!(dot.bind, "0.0.0.0:853");
        assert_eq!(dot.tls.cert_path.as_deref(), Some("/etc/certs/dot.pem"));
        assert_eq!(dot.tls.key_path.as_deref(), Some("/etc/certs/dot.key"));
        assert!(!dot.tls.auto_self_signed);

        // Verify DoH
        let doh = deserialized.doh.unwrap();
        assert_eq!(doh.bind, "0.0.0.0:443");
        assert!(doh.tls.auto_self_signed);

        // Verify DoQ
        let doq = deserialized.doq.unwrap();
        assert_eq!(doq.bind, "0.0.0.0:8853");

        // Verify Proxy
        let proxy = deserialized.proxy.unwrap();
        assert_eq!(proxy.url, "socks5://127.0.0.1:1080");
        assert_eq!(proxy.auth.as_deref(), Some("user:pass"));
        assert_eq!(proxy.mode, "socks5");

        // Verify TTL drift
        assert_eq!(deserialized.ttl_drift.mode, "logarithmic");
        assert_eq!(deserialized.ttl_drift.fixed_adjustment, "30s");
        assert!((deserialized.ttl_drift.log_multiplier - 0.5).abs() < f64::EPSILON);

        // Verify DNS64
        assert!(deserialized.dns64.enabled);
        assert_eq!(deserialized.dns64.prefix, "64:ff9b::");

        // Verify Security
        assert!(!deserialized.security.qname_case_randomization);
    }

    #[test]
    fn test_new_config_fields_omitted_in_yaml() {
        // Verify that a minimal YAML (without the new fields) deserializes
        // correctly, with all new fields taking their defaults.
        let yaml = r#"
dns:
  bind:
    - udp: "0.0.0.0:53"
    - tcp: "0.0.0.0:53"
grpc:
  tcp_bind: "127.0.0.1:50051"
  unix_socket: "/var/run/rolodex-dns.sock"
  shared_secret: ""
forwarders:
  - "8.8.8.8:53"
database_path: "rolodex-dns.db"
rbl:
  enabled: false
  providers: []
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(config.dot.is_none());
        assert!(config.doh.is_none());
        assert!(config.doq.is_none());
        assert!(config.proxy.is_none());
        assert_eq!(config.ttl_drift.mode, "disabled");
        assert!(!config.dns64.enabled);
        assert!(config.security.qname_case_randomization);
    }

    #[test]
    fn test_multi_bind_addresses_parse() {
        let yaml = r#"
dns:
  bind:
    - udp: "127.0.0.1:5300"
    - udp: "127.0.0.2:5300"
    - tcp: "127.0.0.1:5300"
    - tcp: "127.0.0.2:5300"
    - tcp: "10.0.0.1:53"
grpc:
  tcp_bind: "127.0.0.1:50051"
  unix_socket: "/var/run/rolodex-dns.sock"
  shared_secret: ""
forwarders:
  - "8.8.8.8:53"
database_path: "rolodex-dns.db"
rbl:
  enabled: false
  providers: []
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        let udp: Vec<&str> = config.dns.udp_addrs().collect();
        assert_eq!(udp, vec!["127.0.0.1:5300", "127.0.0.2:5300"]);
        let tcp: Vec<&str> = config.dns.tcp_addrs().collect();
        assert_eq!(tcp, vec!["127.0.0.1:5300", "127.0.0.2:5300", "10.0.0.1:53"]);
    }

    #[test]
    fn test_empty_bind_list_parse() {
        let yaml = r#"
dns:
  bind: []
grpc:
  tcp_bind: "127.0.0.1:50051"
  unix_socket: "/var/run/rolodex-dns.sock"
  shared_secret: ""
forwarders: []
database_path: "rolodex-dns.db"
rbl:
  enabled: false
  providers: []
"#;
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(config.dns.bind.is_empty());
    }

    #[test]
    fn test_multi_bind_serialization_roundtrip() {
        let mut config = Config::default();
        config.dns.bind = vec![
            DnsBind::Udp("127.0.0.1:53".to_string()),
            DnsBind::Udp("10.0.0.1:53".to_string()),
            DnsBind::Tcp("127.0.0.1:53".to_string()),
            DnsBind::Tcp("10.0.0.1:53".to_string()),
            DnsBind::Tcp("192.168.1.1:5353".to_string()),
        ];
        let yaml = serde_yaml_ng::to_string(&config).unwrap();
        let deserialized: Config = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(config.dns.bind, deserialized.dns.bind);
    }

    #[test]
    fn test_resolve_bind_addrs_ipv4_passthrough() {
        let result = resolve_bind_addrs("127.0.0.1:5300").unwrap();
        assert_eq!(result, vec!["127.0.0.1:5300"]);

        let result = resolve_bind_addrs("0.0.0.0:53").unwrap();
        assert_eq!(result, vec!["0.0.0.0:53"]);
    }

    #[test]
    fn test_resolve_bind_addrs_ipv6_passthrough() {
        let result = resolve_bind_addrs("[::1]:5300").unwrap();
        assert_eq!(result, vec!["[::1]:5300"]);
    }

    #[test]
    fn test_resolve_bind_addrs_loopback_interface() {
        let result = resolve_bind_addrs("lo:53").unwrap();
        assert!(!result.is_empty());
        // lo always has 127.0.0.1
        assert!(
            result.iter().any(|a| a == "127.0.0.1:53"),
            "expected 127.0.0.1:53 in {:?}",
            result
        );
    }

    #[test]
    fn test_resolve_bind_addrs_nonexistent_interface() {
        let result = resolve_bind_addrs("nonexistent99:53");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("no interface named"),
            "unexpected error: {}",
            msg
        );
    }

    #[test]
    fn test_resolve_bind_addrs_no_port() {
        let result = resolve_bind_addrs("eth0");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("must include a port"),
            "unexpected error: {}",
            msg
        );
    }

    #[test]
    fn test_resolve_bind_addrs_invalid_port() {
        let result = resolve_bind_addrs("eth0:abc");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("invalid port"), "unexpected error: {}", msg);
    }

    #[test]
    fn test_resolve_bind_addrs_empty() {
        let result = resolve_bind_addrs("");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_bind_addrs_bare_ipv6() {
        // Bare IPv6 like ::1:53 — rfind splits to host "::1", port "53"
        // "::1" parses as IpAddr, so it passes through as literal
        let result = resolve_bind_addrs("::1:53").unwrap();
        assert_eq!(result, vec!["::1:53"]);
    }

    #[test]
    fn test_resolve_bind_addrs_interface_returns_multiple_addresses() {
        // lo has both 127.0.0.1 and ::1 on Linux
        let result = resolve_bind_addrs("lo:9999").unwrap();
        assert!(
            result.len() >= 2,
            "expected lo to have at least IPv4 + IPv6, got {:?}",
            result
        );
        assert!(
            result.iter().any(|a| a == "127.0.0.1:9999"),
            "expected 127.0.0.1:9999 in {:?}",
            result
        );
        assert!(
            result.iter().any(|a| a == "[::1]:9999"),
            "expected [::1]:9999 in {:?}",
            result
        );
    }

    #[test]
    fn test_resolve_bind_addrs_all_results_are_parseable_socket_addrs() {
        let result = resolve_bind_addrs("lo:4321").unwrap();
        for addr in &result {
            let parsed: std::net::SocketAddr = addr
                .parse()
                .unwrap_or_else(|e| panic!("'{}' should parse as SocketAddr: {}", addr, e));
            assert_eq!(parsed.port(), 4321);
        }
    }

    #[test]
    fn test_resolve_bind_addrs_port_zero() {
        // Port 0 is valid (OS assigns ephemeral)
        let result = resolve_bind_addrs("127.0.0.1:0").unwrap();
        assert_eq!(result, vec!["127.0.0.1:0"]);
    }

    #[test]
    fn test_resolve_bind_addrs_whitespace_trimmed() {
        let result = resolve_bind_addrs("  127.0.0.1:53  ").unwrap();
        assert_eq!(result, vec!["127.0.0.1:53"]);
    }

    #[test]
    fn test_resolve_bind_addrs_port_overflow() {
        let result = resolve_bind_addrs("127.0.0.1:99999");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_bind_addrs_primary_resolves_to_routable_ip() {
        let result = resolve_bind_addrs("primary:53").unwrap();
        assert_eq!(result.len(), 1);
        let addr: std::net::SocketAddr = result[0].parse().expect("should be a valid socket addr");
        assert_eq!(addr.port(), 53);
        assert!(!addr.ip().is_loopback());
        assert!(!addr.ip().is_unspecified());
    }

    #[test]
    fn test_resolve_bind_addrs_primary_custom_port() {
        let result = resolve_bind_addrs("primary:5300").unwrap();
        assert_eq!(result.len(), 1);
        let addr: std::net::SocketAddr = result[0].parse().unwrap();
        assert_eq!(addr.port(), 5300);
    }

    #[test]
    fn test_resolve_bind_addrs_primary_case_insensitive() {
        let r1 = resolve_bind_addrs("PRIMARY:853").unwrap();
        let r2 = resolve_bind_addrs("Primary:853").unwrap();
        let r3 = resolve_bind_addrs("primary:853").unwrap();
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
        let addr: std::net::SocketAddr = r1[0].parse().unwrap();
        assert_eq!(addr.port(), 853);
    }
    #[test]
    fn empty_secret_on_loopback_is_allowed() {
        // The documented development configuration.
        assert!(
            check_grpc_exposure("127.0.0.1:50051", &["127.0.0.1:50051".to_string()], "").is_ok()
        );
        assert!(check_grpc_exposure("[::1]:50051", &["[::1]:50051".to_string()], "").is_ok());
    }

    #[test]
    fn empty_secret_on_a_routable_bind_is_refused() {
        for bind in [
            "0.0.0.0:50051",
            "[::]:50051",
            "192.168.1.5:50051",
            "203.0.113.9:50051",
        ] {
            assert!(
                check_grpc_exposure(bind, &[bind.to_string()], "").is_err(),
                "{} with no shared secret must be refused",
                bind
            );
        }
    }

    #[test]
    fn a_secret_permits_any_bind() {
        assert!(
            check_grpc_exposure("0.0.0.0:50051", &["0.0.0.0:50051".to_string()], "hunter2").is_ok()
        );
    }

    #[test]
    fn one_routable_address_condemns_an_interface_bind() {
        // `eth0:50051` resolves to every address on the interface; a single
        // routable one is enough to expose the management plane.
        let resolved = vec![
            "127.0.0.1:50051".to_string(),
            "192.168.1.5:50051".to_string(),
        ];
        assert!(check_grpc_exposure("eth0:50051", &resolved, "").is_err());
    }

    #[test]
    fn metrics_tracked_tlds_parse_and_default_to_empty() {
        // Absent list must mean "track nothing but the owned TLDs", not "track
        // everything": a default that put a client-chosen value into a label
        // would be a cardinality bug in every deployment that never touched it.
        let bare: MetricsConfig = serde_yaml_ng::from_str("bind: \"127.0.0.1:9153\"").unwrap();
        assert!(bare.tracked_tlds.is_empty());

        let listed: MetricsConfig = serde_yaml_ng::from_str(
            "bind: \"127.0.0.1:9153\"\ntracked_tlds:\n  - common\n  - lab.internal\n",
        )
        .unwrap();
        assert_eq!(listed.tracked_tlds, vec!["common", "lab.internal"]);
    }

    #[test]
    fn a_metrics_section_written_before_tracked_tlds_existed_still_parses() {
        // The field was added after the section shipped; an existing config
        // must not become unloadable on upgrade.
        // Build the YAML an older deployment would have on disk by serializing a
        // current config and deleting the field, rather than hand-writing a
        // minimal document that would drift from the real schema.
        let base = Config {
            metrics: Some(MetricsConfig::default()),
            ..Default::default()
        };
        let yaml = serde_yaml_ng::to_string(&base).expect("serialize");
        let without: String = yaml
            .lines()
            .filter(|l| !l.trim_start().starts_with("tracked_tlds"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !without.contains("tracked_tlds"),
            "the field under test is still present"
        );

        let cfg: Config =
            serde_yaml_ng::from_str(&without).expect("parse config without the field");
        let metrics = cfg.metrics.expect("metrics section");
        assert_eq!(metrics.bind, "127.0.0.1:9153");
        assert!(metrics.tracked_tlds.is_empty());
    }
}
