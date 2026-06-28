use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
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

impl Default for HickoryRblResolver {
    fn default() -> Self {
        Self::new()
    }
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
    enabled: AtomicBool,
    /// Configured RBL providers (IP blocklists, queried with a reversed IP).
    providers: ArcSwap<Vec<RblProvider>>,
    /// Whether DNSBL (domain blocklist) checking is globally enabled.
    dnsbl_enabled: AtomicBool,
    /// Configured DNSBL providers (domain blocklists, queried with the name
    /// prepended to the zone). These are kept separate from `providers` because
    /// the two query forms are different and a zone is one or the other.
    dnsbl_providers: ArcSwap<Vec<RblProvider>>,
    /// Cache of RBL/DNSBL lookup results keyed by "<ip-or-name>/<zone>".
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
    ///
    /// DNSBL checking starts disabled with no providers; configure it via
    /// [`set_dnsbl_config`](Self::set_dnsbl_config).
    pub fn with_resolver(
        enabled: bool,
        providers: Vec<RblProvider>,
        resolver: Arc<dyn RblResolver>,
    ) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            providers: ArcSwap::from_pointee(providers),
            dnsbl_enabled: AtomicBool::new(false),
            dnsbl_providers: ArcSwap::from_pointee(Vec::new()),
            cache: Arc::new(DashMap::new()),
            resolver,
        }
    }

    /// Checks if an IP address is listed in any enabled RBL.
    /// Returns true if the IP is blacklisted and should be blocked (NXDOMAIN).
    pub async fn is_listed(&self, ip: &IpAddr) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return false;
        }

        let providers = self.providers.load();
        for provider in providers.iter() {
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
        if !self.dnsbl_enabled.load(Ordering::Relaxed) {
            return false;
        }

        let normalized = normalize_rbl_name(name);
        if normalized.is_empty() {
            return false;
        }

        let providers = self.dnsbl_providers.load();
        for provider in providers.iter() {
            if !provider.enabled {
                continue;
            }
            if self.provider_lists_name(&normalized, &provider.zone).await {
                return true;
            }
        }

        false
    }

    /// Checks a single provider for a domain-name listing, using and populating
    /// the same result cache as the IP-based path (keyed by `<name>/<zone>`).
    async fn provider_lists_name(&self, normalized_name: &str, zone: &str) -> bool {
        let query = format!("{normalized_name}.{zone}");
        let cache_key = format!("{normalized_name}/{zone}");

        // Check cache first
        if let Some(entry) = self.cache.get(&cache_key) {
            if entry.expires_at > Instant::now() {
                if entry.listed {
                    debug!("RBL cache hit: {} is listed in {}", normalized_name, zone);
                }
                return entry.listed;
            }
            // Expired, drop the reference before removing
            drop(entry);
            self.cache.remove(&cache_key);
        }

        match self.resolver.lookup_rbl(&query).await {
            Ok(Some(ttl)) => {
                debug!(
                    "RBL hit: {} listed in {} (TTL: {})",
                    normalized_name, zone, ttl
                );
                self.cache.insert(
                    cache_key,
                    CacheEntry {
                        listed: true,
                        expires_at: Instant::now() + Duration::from_secs(ttl as u64),
                    },
                );
                true
            }
            Ok(None) => {
                debug!("RBL miss: {} not listed in {}", normalized_name, zone);
                // Cache negative results for 5 minutes
                self.cache.insert(
                    cache_key,
                    CacheEntry {
                        listed: false,
                        expires_at: Instant::now() + Duration::from_secs(300),
                    },
                );
                false
            }
            Err(e) => {
                warn!(
                    "RBL name lookup failed for {} in {}: {}",
                    normalized_name, zone, e
                );
                false
            }
        }
    }

    /// Updates the RBL configuration.
    pub async fn set_config(&self, enabled: bool, providers: Vec<RblProvider>) {
        self.enabled.store(enabled, Ordering::Relaxed);
        self.providers.store(Arc::new(providers));
    }

    /// Returns the current RBL configuration.
    pub async fn get_config(&self) -> (bool, Vec<RblProvider>) {
        let enabled = self.enabled.load(Ordering::Relaxed);
        let providers = self.providers.load();
        (enabled, providers.as_ref().clone())
    }

    /// Updates the DNSBL (domain blocklist) configuration. The shared result
    /// cache is flushed so that newly added/removed providers take effect
    /// immediately rather than serving a stale not-listed verdict.
    pub async fn set_dnsbl_config(&self, enabled: bool, providers: Vec<RblProvider>) {
        self.dnsbl_enabled.store(enabled, Ordering::Relaxed);
        self.dnsbl_providers.store(Arc::new(providers));
        self.cache.clear();
    }

    /// Returns the current DNSBL configuration.
    pub async fn get_dnsbl_config(&self) -> (bool, Vec<RblProvider>) {
        let enabled = self.dnsbl_enabled.load(Ordering::Relaxed);
        let providers = self.dnsbl_providers.load();
        (enabled, providers.as_ref().clone())
    }

    /// Returns whether DNSBL checking is enabled.
    pub async fn is_dnsbl_enabled(&self) -> bool {
        self.dnsbl_enabled.load(Ordering::Relaxed)
    }

    /// Flushes the RBL cache.
    pub async fn flush_cache(&self) {
        self.cache.clear();
    }

    /// Returns whether RBL checking is enabled.
    pub async fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Checks if an IP address is listed in any enabled global RBL
    /// or in the provided extra per-scope RBL providers.
    pub async fn is_listed_with_extra_providers(&self, ip: &IpAddr, extra: &[RblProvider]) -> bool {
        // Check global providers first
        if self.is_listed(ip).await {
            return true;
        }

        // Check extra per-scope providers
        for provider in extra {
            if !provider.enabled {
                continue;
            }

            let query = build_rbl_query(ip, &provider.zone);
            let cache_key = format!("{}/{}", ip, provider.zone);

            // Check cache
            if let Some(entry) = self.cache.get(&cache_key) {
                if entry.expires_at > Instant::now() {
                    if entry.listed {
                        debug!("Scope RBL cache hit: {} is listed in {}", ip, provider.zone);
                        return true;
                    }
                    continue;
                }
                drop(entry);
                self.cache.remove(&cache_key);
            }

            match self.resolver.lookup_rbl(&query).await {
                Ok(Some(ttl)) => {
                    debug!(
                        "Scope RBL hit: {} listed in {} (TTL: {})",
                        ip, provider.zone, ttl
                    );
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
                    self.cache.insert(
                        cache_key,
                        CacheEntry {
                            listed: false,
                            expires_at: Instant::now() + Duration::from_secs(300),
                        },
                    );
                }
                Err(e) => {
                    warn!(
                        "Scope RBL lookup failed for {} in {}: {}",
                        ip, provider.zone, e
                    );
                }
            }
        }

        false
    }
}

/// Normalizes a domain name for RBL lookups: lowercased with the trailing
/// dot stripped, so that `GoogleAdServices.com.` and `googleadservices.com`
/// produce the same query and cache key.
pub fn normalize_rbl_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
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
            let octets = ipv6.octets();
            // 32 nibbles * 2 chars each (nibble + dot) + zone length
            let mut result = String::with_capacity(64 + zone.len());
            for &byte in octets.iter().rev() {
                let lo = byte & 0x0f;
                let hi = (byte >> 4) & 0x0f;
                result.push(char::from(b"0123456789abcdef"[lo as usize]));
                result.push('.');
                result.push(char::from(b"0123456789abcdef"[hi as usize]));
                result.push('.');
            }
            // String already ends with '.', just append the zone
            result.push_str(zone);
            result
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
            if self.listed { Ok(Some(300)) } else { Ok(None) }
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
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.listed { Ok(Some(300)) } else { Ok(None) }
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
        let checker = RblChecker::with_resolver(false, vec![], Arc::new(MockResolver::new(true)));

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

    #[test]
    fn test_normalize_rbl_name() {
        assert_eq!(normalize_rbl_name("Example.COM."), "example.com");
        assert_eq!(normalize_rbl_name("example.com"), "example.com");
        assert_eq!(normalize_rbl_name("."), "");
    }

    /// Builds a checker with DNSBL enabled and a single `dbl.test` provider.
    async fn dnsbl_checker(resolver: Arc<dyn RblResolver>) -> RblChecker {
        let checker = RblChecker::with_resolver(false, vec![], resolver);
        checker
            .set_dnsbl_config(
                true,
                vec![RblProvider {
                    zone: "dbl.test".to_string(),
                    enabled: true,
                }],
            )
            .await;
        checker
    }

    #[tokio::test]
    async fn test_is_name_listed_listed() {
        let checker = dnsbl_checker(Arc::new(MockResolver::new(true))).await;
        assert!(checker.is_name_listed("googleadservices.com.").await);
    }

    #[tokio::test]
    async fn test_is_name_listed_not_listed() {
        let checker = dnsbl_checker(Arc::new(MockResolver::new(false))).await;
        assert!(!checker.is_name_listed("example.com.").await);
    }

    #[tokio::test]
    async fn test_is_name_listed_disabled() {
        // DNSBL globally disabled: even a listed name is not reported.
        let checker = RblChecker::with_resolver(false, vec![], Arc::new(MockResolver::new(true)));
        checker
            .set_dnsbl_config(
                false,
                vec![RblProvider {
                    zone: "dbl.test".to_string(),
                    enabled: true,
                }],
            )
            .await;
        assert!(!checker.is_name_listed("googleadservices.com.").await);
    }

    #[tokio::test]
    async fn test_is_name_listed_independent_of_rbl() {
        // RBL is enabled but DNSBL is not configured: domain checks must not
        // fall back to the IP-based RBL provider list.
        let checker = RblChecker::with_resolver(
            true,
            vec![RblProvider {
                zone: "test.rbl".to_string(),
                enabled: true,
            }],
            Arc::new(MockResolver::new(true)),
        );
        assert!(!checker.is_name_listed("googleadservices.com.").await);
    }

    #[tokio::test]
    async fn test_is_name_listed_caches() {
        let resolver = Arc::new(CountingResolver::new(true));
        let checker = dnsbl_checker(resolver.clone()).await;
        // Trailing-dot and case differences normalize to the same cache key.
        assert!(checker.is_name_listed("Ads.Example.com.").await);
        assert_eq!(resolver.count(), 1);
        assert!(checker.is_name_listed("ads.example.com").await);
        assert_eq!(resolver.count(), 1);
    }

    #[tokio::test]
    async fn test_enabled_but_empty_rbl_is_noop() {
        // RBL globally enabled with no providers: nothing is queried and the
        // resolver is never consulted, so no IP is listed.
        let resolver = Arc::new(CountingResolver::new(true));
        let checker = RblChecker::with_resolver(true, vec![], resolver.clone());
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(!checker.is_listed(&ip).await);
        assert_eq!(resolver.count(), 0);
    }

    #[tokio::test]
    async fn test_enabled_but_empty_dnsbl_is_noop() {
        // DNSBL globally enabled with no providers: nothing is queried.
        let resolver = Arc::new(CountingResolver::new(true));
        let checker = RblChecker::with_resolver(false, vec![], resolver.clone());
        checker.set_dnsbl_config(true, vec![]).await;
        assert!(!checker.is_name_listed("googleadservices.com.").await);
        assert_eq!(resolver.count(), 0);
    }

    #[tokio::test]
    async fn test_dnsbl_get_set_config() {
        let checker = RblChecker::with_resolver(false, vec![], Arc::new(MockResolver::new(true)));

        let (enabled, providers) = checker.get_dnsbl_config().await;
        assert!(!enabled);
        assert!(providers.is_empty());
        assert!(!checker.is_dnsbl_enabled().await);

        checker
            .set_dnsbl_config(
                true,
                vec![RblProvider {
                    zone: "dbl.spamhaus.org".to_string(),
                    enabled: true,
                }],
            )
            .await;

        let (enabled, providers) = checker.get_dnsbl_config().await;
        assert!(enabled);
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].zone, "dbl.spamhaus.org");
        assert!(checker.is_dnsbl_enabled().await);

        // DNSBL config is independent of the IP-based RBL config.
        let (rbl_enabled, rbl_providers) = checker.get_config().await;
        assert!(!rbl_enabled);
        assert!(rbl_providers.is_empty());
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
