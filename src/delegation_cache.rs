//! Delegation cache: zone -> nameserver addresses.
//!
//! The iterative resolver used to start every single resolution at the root
//! hints, because the only cache in the system ([`crate::dns_cache::DnsCache`])
//! sits *above* it and caches final answers. The `com.` NS set was therefore
//! never retained, and every cache-cold name re-walked root -> TLD ->
//! authoritative from scratch — hammering one root server with a query for
//! every name ever looked up (which earns a rate-limit, which turns each query
//! into a multi-second timeout-then-failover).
//!
//! This cache closes that hole. It is consulted by
//! [`crate::resolver::IterativeResolver`] before falling back to the root
//! hints, and populated from every delegation referral seen along the way, so a
//! warm `.com` lookup skips the root hop entirely.
//!
//! TTLs are honoured, clamped into [`MIN_DELEGATION_TTL`]..=[`MAX_DELEGATION_TTL`]:
//! the floor stops a pathologically small TTL from reintroducing per-query root
//! walks, the ceiling stops a delegation being pinned indefinitely.
//!
//! Entries whose TTL exceeds a configurable threshold (default 5m) are persisted
//! to SQLite and reloaded at boot, so a restart comes back warm rather than
//! re-walking the roots. Root and TLD NS sets carry multi-day TTLs, so in
//! practice exactly the entries worth keeping are the ones that survive.

use anyhow::Result;
use dashmap::DashMap;
use hickory_proto::rr::Name;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::db::Database;

/// Upper bound on a cached delegation's lifetime (7 days). Purely an absurdity
/// cap — there is deliberately **no lower bound**: a TTL that is present is
/// honoured exactly as the zone published it. A floor would silently override what
/// the zone asked for, which is the one thing a TTL is for.
pub const MAX_DELEGATION_TTL: u32 = 604_800;
/// Maximum number of zones held in memory before expired entries are reaped.
pub const MAX_DELEGATION_ENTRIES: usize = 10_000;
/// Default minimum TTL for a delegation to be worth persisting to disk.
pub const DEFAULT_PERSIST_MIN_TTL: u32 = 300;

/// A cached delegation: the addresses of a zone's nameservers, and when the
/// entry stops being usable.
#[derive(Debug, Clone)]
struct CachedDelegation {
    servers: Vec<IpAddr>,
    expires_at: Instant,
}

/// A write queued for the SQLite persistence worker.
#[derive(Debug)]
struct DelegationWriteRequest {
    zone: String,
    servers: Vec<String>,
    ttl: u32,
}

/// Zone -> nameserver addresses, TTL-respecting, optionally persisted.
pub struct DelegationCache {
    memory: DashMap<String, CachedDelegation>,
    db: Option<Database>,
    persist_tx: Option<tokio::sync::mpsc::Sender<DelegationWriteRequest>>,
    /// Delegations with a TTL above this are persisted; shorter ones stay in memory.
    persist_min_ttl: u32,
    /// Lifetime applied to a delegation that arrives with a zero TTL.
    default_ttl: u32,
}

// `Database` is not `Debug`, so this is hand-rolled to keep `IterativeResolver`
// (which holds the cache) derivable.
impl std::fmt::Debug for DelegationCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegationCache")
            .field("zones", &self.memory.len())
            .field("persistent", &self.db.is_some())
            .field("persist_min_ttl", &self.persist_min_ttl)
            .finish()
    }
}

impl Default for DelegationCache {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl DelegationCache {
    /// An in-memory-only cache (no persistence). Used when no database is
    /// available — tests, and the resolver's `with_defaults` constructor.
    pub fn in_memory() -> Self {
        Self {
            memory: DashMap::new(),
            db: None,
            persist_tx: None,
            persist_min_ttl: DEFAULT_PERSIST_MIN_TTL,
            default_ttl: crate::resolver::DEFAULT_TTL,
        }
    }

    /// Sets the lifetime applied to a delegation that arrives with a zero TTL.
    pub fn with_default_ttl(mut self, default_ttl: u32) -> Self {
        self.default_ttl = default_ttl;
        self
    }

    /// A persistent cache. Spawns the write-behind worker and loads any
    /// non-expired delegations from the previous run.
    ///
    /// Requires a Tokio runtime (same as [`crate::dns_cache::DnsCache::new`]).
    pub fn with_db(db: Database, persist_min_ttl: u32) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        tokio::spawn(Self::persist_worker(db.clone(), rx));

        let cache = Self {
            memory: DashMap::new(),
            db: Some(db),
            persist_tx: Some(tx),
            persist_min_ttl,
            default_ttl: crate::resolver::DEFAULT_TTL,
        };
        cache.load_from_disk();
        cache
    }

    /// Drains queued writes onto SQLite off the query path.
    async fn persist_worker(
        db: Database,
        mut rx: tokio::sync::mpsc::Receiver<DelegationWriteRequest>,
    ) {
        while let Some(req) = rx.recv().await {
            if let Err(e) = db.delegation_replace(&req.zone, &req.servers, req.ttl) {
                warn!("failed to persist delegation for {}: {}", req.zone, e);
            }
        }
    }

    /// Repopulates the in-memory map from the non-expired rows on disk, using
    /// each row's *remaining* lifetime rather than a fabricated one.
    fn load_from_disk(&self) {
        let Some(ref db) = self.db else { return };
        let rows = match db.delegation_load_all() {
            Ok(rows) => rows,
            Err(e) => {
                warn!("failed to load delegation cache: {}", e);
                return;
            }
        };

        let mut loaded = 0usize;
        for (zone, ips, remaining_ttl) in rows {
            let servers: Vec<IpAddr> = ips.iter().filter_map(|s| s.parse().ok()).collect();
            if servers.is_empty() {
                continue;
            }
            self.memory.insert(
                zone,
                CachedDelegation {
                    servers,
                    expires_at: Instant::now() + Duration::from_secs(remaining_ttl as u64),
                },
            );
            loaded += 1;
        }
        debug!("delegation cache loaded ({} zones)", loaded);
    }

    /// The lifetime to honour for a delegation.
    ///
    /// A TTL that is present is honoured **as sent** — no floor. A zero TTL carries
    /// no lifetime at all, so [`Self::default_ttl`] applies rather than the
    /// delegation being dropped (which would send the next lookup back to the
    /// roots) or kept forever.
    fn lifetime(&self, ttl: u32) -> u32 {
        if ttl == 0 {
            return self.default_ttl;
        }
        ttl.min(MAX_DELEGATION_TTL)
    }

    /// Records the nameserver addresses for `zone`.
    ///
    /// The root zone (`.`) is cached like any other — that is what root priming
    /// populates, so the compiled-in hints become a bootstrap rather than the only
    /// root servers we ever know about.
    pub fn insert(&self, zone: &Name, servers: Vec<IpAddr>, ttl: u32) {
        if servers.is_empty() {
            return;
        }
        let key = zone_key(zone);
        let ttl = self.lifetime(ttl);

        self.reap_if_full();
        self.memory.insert(
            key.clone(),
            CachedDelegation {
                servers: servers.clone(),
                expires_at: Instant::now() + Duration::from_secs(ttl as u64),
            },
        );

        // Only long-lived delegations are worth a disk write.
        if ttl <= self.persist_min_ttl {
            return;
        }
        if let Some(ref tx) = self.persist_tx {
            let req = DelegationWriteRequest {
                zone: key,
                servers: servers.iter().map(|ip| ip.to_string()).collect(),
                ttl,
            };
            if tx.try_send(req).is_err() {
                debug!(
                    "delegation persist queue full; keeping {} in memory only",
                    zone
                );
            }
        }
    }

    /// Returns the deepest non-expired delegation covering `name`, along with the
    /// zone it was found under.
    ///
    /// This is the whole point of the cache: for `x.example.com` it prefers a
    /// cached `example.com.` over a cached `com.`, so a warm lookup starts as far
    /// down the delegation chain as possible — often skipping the root and TLD
    /// hops entirely. Expired entries are dropped as they are encountered.
    pub fn best_match(&self, name: &Name) -> Option<(String, Vec<IpAddr>)> {
        let now = Instant::now();
        let mut current = name.clone();

        loop {
            let key = zone_key(&current);
            let hit = self.memory.get(&key).map(|e| e.value().clone());
            if let Some(entry) = hit {
                if entry.expires_at > now {
                    return Some((key, entry.servers));
                }
                self.memory.remove(&key);
            }
            if current.is_root() {
                return None;
            }
            current = current.base_name();
        }
    }

    /// Drops a zone's delegation (used when a cached delegation turns out to be
    /// unusable, so the next attempt re-learns it from the roots).
    pub fn invalidate(&self, zone: &str) {
        self.memory.remove(zone);
        if let Some(ref db) = self.db
            && let Err(e) = db.delegation_replace(zone, &[], 0)
        {
            debug!("failed to clear persisted delegation for {}: {}", zone, e);
        }
    }

    /// Clears every delegation, in memory and on disk.
    ///
    /// Called when the `auto` chain switches upstream tiers — delegations learned
    /// while talking to one tier must not steer queries on another. It is
    /// deliberately *not* wired into [`crate::dns_server::DnsServer::flush_cache`],
    /// which local record mutations call on every zone/record/scope change.
    pub fn flush(&self) {
        self.memory.clear();
        if let Some(ref db) = self.db
            && let Err(e) = db.delegation_flush()
        {
            warn!("failed to flush persisted delegation cache: {}", e);
        }
    }

    pub fn len(&self) -> usize {
        self.memory.len()
    }

    pub fn is_empty(&self) -> bool {
        self.memory.is_empty()
    }

    /// Reaps expired entries once the map hits its bound, then evicts
    /// arbitrarily if everything is still live.
    fn reap_if_full(&self) {
        if self.memory.len() < MAX_DELEGATION_ENTRIES {
            return;
        }
        let now = Instant::now();
        self.memory.retain(|_, v| v.expires_at > now);

        while self.memory.len() >= MAX_DELEGATION_ENTRIES {
            let victim = self.memory.iter().next().map(|e| e.key().clone());
            match victim {
                Some(k) => {
                    self.memory.remove(&k);
                }
                None => break,
            }
        }
    }

    /// Persisted-row count (test/observability helper).
    pub fn persisted_count(&self) -> Result<u64> {
        match self.db {
            Some(ref db) => db.delegation_count(),
            None => Ok(0),
        }
    }
}

/// Canonical cache key for a zone: lowercase ASCII, trailing dot.
fn zone_key(name: &Name) -> String {
    name.to_ascii().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn best_match_returns_deepest_ancestor() {
        let cache = DelegationCache::in_memory();
        cache.insert(&name("com."), vec![ip(1)], 3600);
        cache.insert(&name("example.com."), vec![ip(2)], 3600);

        let (zone, servers) = cache
            .best_match(&name("www.example.com."))
            .expect("should match");
        assert_eq!(zone, "example.com.");
        assert_eq!(servers, vec![ip(2)]);
    }

    #[test]
    fn best_match_falls_back_to_shallower_zone() {
        let cache = DelegationCache::in_memory();
        cache.insert(&name("com."), vec![ip(1)], 3600);

        let (zone, _) = cache
            .best_match(&name("www.example.com."))
            .expect("should match com.");
        assert_eq!(zone, "com.");
    }

    #[test]
    fn best_match_is_none_when_empty() {
        let cache = DelegationCache::in_memory();
        assert!(cache.best_match(&name("www.example.com.")).is_none());
    }

    #[test]
    fn best_match_is_case_insensitive() {
        let cache = DelegationCache::in_memory();
        cache.insert(&name("Example.COM."), vec![ip(2)], 3600);
        assert!(cache.best_match(&name("WWW.example.com.")).is_some());
    }

    #[test]
    fn expired_entry_is_not_served_and_is_evicted() {
        let cache = DelegationCache::in_memory();
        // Force an already-expired entry (insert() clamps TTL up to the floor,
        // so build it directly).
        cache.memory.insert(
            "com.".to_string(),
            CachedDelegation {
                servers: vec![ip(1)],
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );

        assert!(cache.best_match(&name("www.example.com.")).is_none());
        assert_eq!(cache.len(), 0, "expired entry should be evicted on lookup");
    }

    #[test]
    fn a_present_ttl_is_honoured_exactly_as_sent() {
        let cache = DelegationCache::in_memory();
        // No floor: a zone that publishes a 1s TTL gets 1s. Rounding it up to some
        // minimum would silently override what the zone actually asked for.
        assert_eq!(cache.lifetime(1), 1);
        assert_eq!(cache.lifetime(30), 30);
        assert_eq!(cache.lifetime(3600), 3600);
        assert_eq!(cache.lifetime(172_800), 172_800);
    }

    #[test]
    fn a_zero_ttl_falls_back_to_the_default() {
        let cache = DelegationCache::in_memory();
        // Zero carries no lifetime to honour, so the configured default applies —
        // rather than dropping the delegation (sending the next lookup back to the
        // roots) or keeping it forever.
        assert_eq!(cache.lifetime(0), crate::resolver::DEFAULT_TTL);

        let cache = DelegationCache::in_memory().with_default_ttl(42);
        assert_eq!(cache.lifetime(0), 42, "the default is configurable");
    }

    #[test]
    fn absurd_ttls_are_capped() {
        let cache = DelegationCache::in_memory();
        assert_eq!(
            cache.lifetime(30 * 86_400),
            MAX_DELEGATION_TTL,
            "a 30d TTL is capped at the 7d ceiling"
        );
    }

    #[test]
    fn root_zone_is_cached() {
        let cache = DelegationCache::in_memory();
        // Root priming stores the live root NS set here, which is what demotes the
        // compiled-in hints to a bootstrap rather than the only roots we ever know.
        cache.insert(&Name::root(), vec![ip(1)], 518_400);
        let (zone, servers) = cache
            .best_match(&name("example.com."))
            .expect("the primed root delegation must be reachable");
        assert_eq!(zone, ".");
        assert_eq!(servers, vec![ip(1)]);
    }

    #[test]
    fn empty_server_set_is_not_cached() {
        let cache = DelegationCache::in_memory();
        cache.insert(&name("com."), vec![], 3600);
        assert!(cache.is_empty());
    }

    #[test]
    fn invalidate_drops_the_zone() {
        let cache = DelegationCache::in_memory();
        cache.insert(&name("com."), vec![ip(1)], 3600);
        cache.invalidate("com.");
        assert!(cache.best_match(&name("x.com.")).is_none());
    }

    #[test]
    fn flush_clears_everything() {
        let cache = DelegationCache::in_memory();
        cache.insert(&name("com."), vec![ip(1)], 3600);
        cache.insert(&name("org."), vec![ip(2)], 3600);
        cache.flush();
        assert!(cache.is_empty());
    }

    #[test]
    fn zones_are_isolated_from_each_other() {
        let cache = DelegationCache::in_memory();
        cache.insert(&name("com."), vec![ip(1)], 3600);
        assert!(cache.best_match(&name("example.org.")).is_none());
    }
}
