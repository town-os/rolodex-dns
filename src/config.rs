use serde::{Deserialize, Serialize};

/// Configuration for the rolodex DNS server.
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

impl Default for Config {
    fn default() -> Self {
        Self {
            dns: DnsConfig {
                udp_bind: "0.0.0.0:53".to_string(),
                tcp_bind: "0.0.0.0:53".to_string(),
            },
            grpc: GrpcConfig {
                tcp_bind: "127.0.0.1:50051".to_string(),
                unix_socket: "/var/run/rolodex.sock".to_string(),
                shared_secret: String::new(),
            },
            forwarders: vec!["8.8.8.8:53".to_string(), "8.8.4.4:53".to_string()],
            database_path: "rolodex.db".to_string(),
            rbl: RblSettings {
                enabled: false,
                providers: default_rbl_providers(),
            },
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
}
