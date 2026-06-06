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
    /// Database file path for persistent DNS records.
    pub database_path: String,
    /// RBL (Realtime Blackhole List) configuration.
    pub rbl: RblSettings,
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
    /// DHCP server configuration (disabled when absent).
    #[serde(default)]
    pub dhcp: Option<DhcpConfig>,
    /// ACME issuer / certificate-authority configuration (disabled when absent).
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
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
}

/// RBL settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RblSettings {
    /// Whether RBL checking is globally enabled.
    pub enabled: bool,
    /// List of RBL providers.
    pub providers: Vec<RblProviderConfig>,
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

/// Security-related configuration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Whether to randomize the case of QNAME labels (0x20 encoding) for cache-poisoning resistance.
    #[serde(default = "default_true")]
    pub qname_case_randomization: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            qname_case_randomization: true,
        }
    }
}

fn default_true() -> bool {
    true
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
            },
            grpc: GrpcConfig {
                tcp_bind: "127.0.0.1:50051".to_string(),
                unix_socket: "/var/run/rolodex-dns.sock".to_string(),
                shared_secret: String::new(),
            },
            forwarders: vec!["8.8.8.8:53".to_string(), "8.8.4.4:53".to_string()],
            database_path: "rolodex-dns.db".to_string(),
            rbl: RblSettings {
                enabled: false,
                providers: default_rbl_providers(),
            },
            dot: None,
            doh: None,
            doq: None,
            proxy: None,
            ttl_drift: TtlDriftSettings::default(),
            dns64: Dns64Config::default(),
            security: SecurityConfig::default(),
            dhcp: None,
            acme: None,
        }
    }
}

/// Returns the default RBL providers, matching what unbound commonly supports.
///
/// These are the standard DNSBL zones used for spam and malware filtering:
/// - `zen.spamhaus.org` - Combined Spamhaus blocklist (SBL + XBL + PBL + CSS)
/// - `bl.spamcop.net` - SpamCop blocklist
/// - `b.barracudacentral.org` - Barracuda Reputation Block List
/// - `dnsbl.sorbs.net` - SORBS aggregate zone
/// - `dbl.spamhaus.org` - Spamhaus Domain Block List
pub fn default_rbl_providers() -> Vec<RblProviderConfig> {
    vec![
        RblProviderConfig {
            zone: "zen.spamhaus.org".to_string(),
            enabled: true,
        },
        RblProviderConfig {
            zone: "bl.spamcop.net".to_string(),
            enabled: true,
        },
        RblProviderConfig {
            zone: "b.barracudacentral.org".to_string(),
            enabled: true,
        },
        RblProviderConfig {
            zone: "dnsbl.sorbs.net".to_string(),
            enabled: true,
        },
        RblProviderConfig {
            zone: "dbl.spamhaus.org".to_string(),
            enabled: true,
        },
    ]
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
        assert!(!config.rbl.enabled);
        assert!(!config.rbl.providers.is_empty());
    }

    #[test]
    fn test_default_rbl_providers() {
        let providers = default_rbl_providers();
        assert_eq!(providers.len(), 5);
        assert!(providers.iter().all(|p| p.enabled));
        assert!(providers.iter().any(|p| p.zone == "zen.spamhaus.org"));
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
        let mut config = Config::default();
        config.dot = Some(DotConfig {
            bind: "0.0.0.0:853".to_string(),
            tls: TlsConfig {
                cert_path: Some("/etc/certs/dot.pem".to_string()),
                key_path: Some("/etc/certs/dot.key".to_string()),
                auto_self_signed: false,
            },
        });
        config.doh = Some(DohConfig {
            bind: "0.0.0.0:443".to_string(),
            tls: TlsConfig::default(),
            enable_h3: false,
        });
        config.doq = Some(DoqConfig {
            bind: "0.0.0.0:8853".to_string(),
            tls: TlsConfig::default(),
        });
        config.proxy = Some(ProxyConfig {
            url: "socks5://127.0.0.1:1080".to_string(),
            auth: Some("user:pass".to_string()),
            mode: "socks5".to_string(),
        });
        config.ttl_drift = TtlDriftSettings {
            mode: "logarithmic".to_string(),
            fixed_adjustment: "30s".to_string(),
            log_multiplier: 0.5,
        };
        config.dns64 = Dns64Config {
            enabled: true,
            prefix: "64:ff9b::".to_string(),
        };
        config.security = SecurityConfig {
            qname_case_randomization: false,
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
}
