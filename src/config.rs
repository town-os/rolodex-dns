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
}

/// DNS listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Address to bind the DNS UDP listener (e.g. "0.0.0.0:53").
    pub udp_bind: String,
    /// Address to bind the DNS TCP listener (e.g. "0.0.0.0:53").
    pub tcp_bind: String,
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

impl Default for Config {
    fn default() -> Self {
        Self {
            dns: DnsConfig {
                udp_bind: "0.0.0.0:53".to_string(),
                tcp_bind: "0.0.0.0:53".to_string(),
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
        assert_eq!(config.dns.udp_bind, "0.0.0.0:53");
        assert_eq!(config.dns.tcp_bind, "0.0.0.0:53");
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
        assert_eq!(deserialized.dns.udp_bind, config.dns.udp_bind);
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
  udp_bind: "0.0.0.0:53"
  tcp_bind: "0.0.0.0:53"
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
}
