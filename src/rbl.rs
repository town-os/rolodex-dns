use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// A cached RBL lookup result.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Whether the IP is listed in this RBL.
    listed: bool,
    /// When the entry expires.
    expires_at: Instant,
}

/// An RBL provider configuration used at runtime.
#[derive(Debug, Clone)]
pub struct RblProvider {
    /// The DNSBL zone (e.g. "zen.spamhaus.org").
    pub zone: String,
    /// Whether this provider is enabled.
    pub enabled: bool,
}

/// Trait for performing RBL DNS lookups, enabling mock testing.
/// Uses async_trait for dyn-compatibility.
#[async_trait::async_trait]
pub trait RblResolver: Send + Sync {
    /// Looks up whether the given query name resolves to an A record.
    /// Returns Ok(Some(ttl)) if listed, Ok(None) if not listed.
    async fn lookup_rbl(&self, query: &str) -> Result<Option<u32>, anyhow::Error>;
}

/// Default RBL resolver using hickory-resolver.
pub struct HickoryRblResolver {
    resolver: hickory_resolver::TokioResolver,
}

impl HickoryRblResolver {
    pub fn new() -> Self {
        let resolver = hickory_resolver::TokioResolver::builder_tokio()
            .expect("failed to create system resolver")
            .build();
        Self { resolver }
    }
}

#[async_trait::async_trait]
impl RblResolver for HickoryRblResolver {
    async fn lookup_rbl(&self, query: &str) -> Result<Option<u32>, anyhow::Error> {
        match self.resolver.lookup_ip(query).await {
            Ok(response) => {
                if response.iter().next().is_some() {
                    // Use the TTL from the lookup, default to 300 seconds
                    let ttl = response
                        .as_lookup()
                        .records()
                        .first()
                        .map(|r| r.ttl())
                        .unwrap_or(300);
                    Ok(Some(ttl))
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                // On any error (including NXDOMAIN), treat as not listed
                // to avoid false positives
                debug!("RBL lookup for {}: {}", query, e);
                Ok(None)
            }
        }
    }
}

/// The RBL checker performs DNS-based blackhole list lookups.
///
/// It checks IP addresses against configured RBL providers by performing
/// DNS lookups in the format `<reversed-ip>.<rbl-zone>`. If the lookup
/// returns a result, the IP is considered listed (blacklisted).
///
/// Results are cached in memory for the TTL duration returned by the RBL.
pub struct RblChecker {
    /// Whether RBL checking is globally enabled.
    enabled: Arc<RwLock<bool>>,
    /// Configured RBL providers.
    providers: Arc<RwLock<Vec<RblProvider>>>,
    /// Cache of RBL lookup results keyed by "<ip>/<zone>".
    cache: Arc<DashMap<String, CacheEntry>>,
    /// DNS resolver for RBL lookups.
    resolver: Arc<dyn RblResolver>,
}

impl RblChecker {
    /// Creates a new RBL checker with the default hickory resolver.
    pub fn new(enabled: bool, providers: Vec<RblProvider>) -> Self {
        Self::with_resolver(enabled, providers, Arc::new(HickoryRblResolver::new()))
    }

    /// Creates a new RBL checker with a custom resolver (for testing).
    pub fn with_resolver(
        enabled: bool,
        providers: Vec<RblProvider>,
        resolver: Arc<dyn RblResolver>,
    ) -> Self {
        Self {
            enabled: Arc::new(RwLock::new(enabled)),
            providers: Arc::new(RwLock::new(providers)),
            cache: Arc::new(DashMap::new()),
            resolver,
        }
    }

    /// Checks if an IP address is listed in any enabled RBL.
    /// Returns true if the IP is blacklisted and should be blocked (NXDOMAIN).
    pub async fn is_listed(&self, ip: &IpAddr) -> bool {
        if !*self.enabled.read().await {
            return false;
        }

        let providers = self.providers.read().await.clone();
        for provider in &providers {
            if !provider.enabled {
                continue;
            }

            let query = build_rbl_query(ip, &provider.zone);
            let cache_key = format!("{}/{}", ip, provider.zone);

            // Check cache first
            if let Some(entry) = self.cache.get(&cache_key) {
                if entry.expires_at > Instant::now() {
                    if entry.listed {
                        debug!("RBL cache hit: {} is listed in {}", ip, provider.zone);
                        return true;
                    }
                    continue;
                }
                // Expired, drop the reference before removing
                drop(entry);
                self.cache.remove(&cache_key);
            }

            // Perform DNS lookup
            match self.resolver.lookup_rbl(&query).await {
                Ok(Some(ttl)) => {
                    debug!("RBL hit: {} listed in {} (TTL: {})", ip, provider.zone, ttl);
                    self.cache.insert(
                        cache_key,
                        CacheEntry {
                            listed: true,
                            expires_at: Instant::now() + Duration::from_secs(ttl as u64),
                        },
                    );
                    return true;
                }
                Ok(None) => {
                    debug!("RBL miss: {} not listed in {}", ip, provider.zone);
                    // Cache negative results for 5 minutes
                    self.cache.insert(
                        cache_key,
                        CacheEntry {
                            listed: false,
                            expires_at: Instant::now() + Duration::from_secs(300),
                        },
                    );
                }
                Err(e) => {
                    warn!("RBL lookup failed for {} in {}: {}", ip, provider.zone, e);
                }
            }
        }

        false
    }

    /// Updates the RBL configuration.
    pub async fn set_config(&self, enabled: bool, providers: Vec<RblProvider>) {
        *self.enabled.write().await = enabled;
        *self.providers.write().await = providers;
    }

    /// Returns the current RBL configuration.
    pub async fn get_config(&self) -> (bool, Vec<RblProvider>) {
        let enabled = *self.enabled.read().await;
        let providers = self.providers.read().await.clone();
        (enabled, providers)
    }

    /// Flushes the RBL cache.
    pub async fn flush_cache(&self) {
        self.cache.clear();
    }

    /// Returns whether RBL checking is enabled.
    pub async fn is_enabled(&self) -> bool {
        *self.enabled.read().await
    }
}

/// Builds an RBL DNS query for an IP address.
///
/// For IPv4: reverses the octets and appends the zone.
///   e.g., 192.168.1.1 + zen.spamhaus.org -> 1.1.168.192.zen.spamhaus.org
///
/// For IPv6: expands and reverses the nibbles and appends the zone.
///   e.g., ::1 + zen.spamhaus.org -> 1.0.0.0...0.0.0.0.zen.spamhaus.org
pub fn build_rbl_query(ip: &IpAddr, zone: &str) -> String {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            format!(
                "{}.{}.{}.{}.{}",
                octets[3], octets[2], octets[1], octets[0], zone
            )
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.octets();
            let nibbles: Vec<String> = segments
                .iter()
                .rev()
                .flat_map(|byte| {
                    vec![
                        format!("{:x}", byte & 0x0f),
                        format!("{:x}", (byte >> 4) & 0x0f),
                    ]
                })
                .collect();
            format!("{}.{}", nibbles.join("."), zone)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_build_rbl_query_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let query = build_rbl_query(&ip, "zen.spamhaus.org");
        assert_eq!(query, "100.1.168.192.zen.spamhaus.org");
    }

    #[test]
    fn test_build_rbl_query_ipv4_simple() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let query = build_rbl_query(&ip, "bl.spamcop.net");
        assert_eq!(query, "4.3.2.1.bl.spamcop.net");
    }

    #[test]
    fn test_build_rbl_query_ipv6_loopback() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let query = build_rbl_query(&ip, "zen.spamhaus.org");
        assert!(query.starts_with("1.0.0.0.0.0.0.0"));
        assert!(query.ends_with("zen.spamhaus.org"));
    }

    #[test]
    fn test_build_rbl_query_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        let query = build_rbl_query(&ip, "test.rbl");
        assert!(query.ends_with(".test.rbl"));
        assert!(query.starts_with("1.0.0.0.0.0.0.0"));
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
    impl RblResolver for MockResolver {
        async fn lookup_rbl(&self, _query: &str) -> Result<Option<u32>, anyhow::Error> {
            if self.listed {
                Ok(Some(300))
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
    impl RblResolver for CountingResolver {
        async fn lookup_rbl(&self, _query: &str) -> Result<Option<u32>, anyhow::Error> {
            self.count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.listed {
                Ok(Some(300))
            } else {
                Ok(None)
            }
        }
    }

    #[tokio::test]
    async fn test_rbl_checker_disabled() {
        let checker = RblChecker::with_resolver(
            false,
            vec![RblProvider {
                zone: "test.rbl".to_string(),
                enabled: true,
            }],
            Arc::new(MockResolver::new(false)),
        );
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(!checker.is_listed(&ip).await);
    }

    #[tokio::test]
    async fn test_rbl_checker_listed() {
        let checker = RblChecker::with_resolver(
            true,
            vec![RblProvider {
                zone: "test.rbl".to_string(),
                enabled: true,
            }],
            Arc::new(MockResolver::new(true)),
        );
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(checker.is_listed(&ip).await);
    }

    #[tokio::test]
    async fn test_rbl_checker_not_listed() {
        let checker = RblChecker::with_resolver(
            true,
            vec![RblProvider {
                zone: "test.rbl".to_string(),
                enabled: true,
            }],
            Arc::new(MockResolver::new(false)),
        );
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(!checker.is_listed(&ip).await);
    }

    #[tokio::test]
    async fn test_rbl_checker_caching() {
        let resolver = Arc::new(CountingResolver::new(true));
        let checker = RblChecker::with_resolver(
            true,
            vec![RblProvider {
                zone: "test.rbl".to_string(),
                enabled: true,
            }],
            resolver.clone(),
        );
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // First lookup should hit the resolver
        assert!(checker.is_listed(&ip).await);
        assert_eq!(resolver.count(), 1);

        // Second lookup should be cached
        assert!(checker.is_listed(&ip).await);
        assert_eq!(resolver.count(), 1);
    }

    #[tokio::test]
    async fn test_rbl_checker_flush_cache() {
        let resolver = Arc::new(CountingResolver::new(true));
        let checker = RblChecker::with_resolver(
            true,
            vec![RblProvider {
                zone: "test.rbl".to_string(),
                enabled: true,
            }],
            resolver.clone(),
        );
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        assert!(checker.is_listed(&ip).await);
        assert_eq!(resolver.count(), 1);

        checker.flush_cache().await;

        assert!(checker.is_listed(&ip).await);
        assert_eq!(resolver.count(), 2);
    }

    #[tokio::test]
    async fn test_rbl_set_config() {
        let checker = RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(MockResolver::new(true)),
        );

        let (enabled, providers) = checker.get_config().await;
        assert!(!enabled);
        assert!(providers.is_empty());

        checker
            .set_config(
                true,
                vec![RblProvider {
                    zone: "new.rbl".to_string(),
                    enabled: true,
                }],
            )
            .await;

        let (enabled, providers) = checker.get_config().await;
        assert!(enabled);
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].zone, "new.rbl");
    }

    #[tokio::test]
    async fn test_rbl_disabled_provider() {
        let resolver = Arc::new(CountingResolver::new(true));
        let checker = RblChecker::with_resolver(
            true,
            vec![RblProvider {
                zone: "test.rbl".to_string(),
                enabled: false,
            }],
            resolver.clone(),
        );
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(!checker.is_listed(&ip).await);
        assert_eq!(resolver.count(), 0);
    }
}
