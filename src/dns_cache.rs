/// Privacy-first DNS response cache.
///
/// Rolodex caches DNS responses locally. Once cached, queries are answered
/// without contacting upstream resolvers. This is a deliberate design to
/// prevent DNS query leakage to upstream providers.
///
/// Set forwarders to empty to operate as a purely authoritative server
/// with no upstream resolution.
use crate::db::{Database, DnsRecord, RecordKind};
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// A cached DNS record with expiration time.
#[derive(Debug, Clone)]
struct CachedEntry {
    records: Arc<Vec<DnsRecord>>,
    expires_at: Instant,
    /// When true, records come from the local DB — TTL is returned as-is (no decay)
    /// and entries are not persisted to the SQLite cache table.
    local: bool,
}

/// A request to persist a cache entry to disk.
struct CacheWriteRequest {
    name: String,
    rt_str: Option<String>,
    records: Arc<Vec<DnsRecord>>,
    ttl: u32,
}

/// In-memory DNS cache backed by SQLite for persistence across restarts.
pub struct DnsCache {
    /// In-memory cache: key = "name:type" or "name:*"
    memory: Arc<DashMap<String, CachedEntry>>,
    /// Database for persistent cache storage
    db: Database,
    /// Hit counter
    hits: AtomicU64,
    /// Miss counter
    misses: AtomicU64,
    /// Channel for batching disk writes
    persist_tx: tokio::sync::mpsc::Sender<CacheWriteRequest>,
}

impl DnsCache {
    pub fn new(db: Database) -> Self {
        let (persist_tx, persist_rx) = tokio::sync::mpsc::channel::<CacheWriteRequest>(1024);
        let persist_db = db.clone();
        tokio::spawn(Self::persist_worker(persist_db, persist_rx));

        let cache = Self {
            memory: Arc::new(DashMap::new()),
            db,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            persist_tx,
        };
        // Load non-expired entries from disk at boot time
        cache.load_from_disk();
        cache
    }

    /// Background worker that batches cache writes into SQLite transactions.
    async fn persist_worker(db: Database, mut rx: tokio::sync::mpsc::Receiver<CacheWriteRequest>) {
        let mut batch = Vec::with_capacity(64);
        loop {
            // Wait for at least one item, then drain up to 64
            match rx.recv().await {
                Some(first) => {
                    batch.push(first);
                    // Drain any additional pending items without blocking
                    while batch.len() < 64 {
                        match rx.try_recv() {
                            Ok(item) => batch.push(item),
                            Err(_) => break,
                        }
                    }
                }
                None => return, // Channel closed
            }

            // Write batch
            for req in &batch {
                for rec in req.records.iter() {
                    if let Err(e) = db.cache_insert(
                        &req.name,
                        req.rt_str.as_deref().unwrap_or(rec.record_type.as_str()),
                        &rec.value,
                        req.ttl,
                        req.ttl,
                        "upstream",
                    ) {
                        tracing::warn!("failed to persist cache entry for {}: {}", req.name, e);
                    }
                }
            }
            batch.clear();
        }
    }

    /// Looks up records in the cache.
    /// Returns empty vec on miss.
    pub fn lookup(&self, name: &str, record_type: Option<RecordKind>) -> Vec<DnsRecord> {
        let key = cache_key(name, record_type);
        if let Some(entry) = self.memory.get(&key) {
            let now = Instant::now();
            if entry.expires_at > now {
                self.hits.fetch_add(1, Ordering::Relaxed);
                if entry.local {
                    // Local records: return original TTL (no decay), zero-copy via Arc
                    return (*entry.records).clone();
                }
                // Upstream records: adjust TTL based on remaining cache time
                let remaining_secs = entry.expires_at.duration_since(now).as_secs() as u32;
                return entry
                    .records
                    .iter()
                    .map(|r| {
                        let mut rec = r.clone();
                        rec.ttl = remaining_secs.max(1);
                        rec
                    })
                    .collect();
            }
            // Expired, remove it
            drop(entry);
            self.memory.remove(&key);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        Vec::new()
    }

    /// Looks up records in the cache, but only returns a hit when the cached
    /// entry is a local (authoritative) record (inserted via
    /// [`insert_local`](Self::insert_local)). Upstream-cached entries are
    /// ignored. This lets the "local records first" stage of resolution use the
    /// cache without short-circuiting RBL precedence over externally-resolved
    /// answers — those are served later, after the RBL gate.
    pub fn lookup_local_only(&self, name: &str, record_type: Option<RecordKind>) -> Vec<DnsRecord> {
        let key = cache_key(name, record_type);
        if let Some(entry) = self.memory.get(&key) {
            if entry.expires_at > Instant::now() {
                if entry.local {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return (*entry.records).clone();
                }
                // Non-local hit: not eligible here, fall through to a miss
                // without disturbing the entry or the hit/miss counters.
                return Vec::new();
            }
            // Expired, remove it
            drop(entry);
            self.memory.remove(&key);
        }
        Vec::new()
    }

    /// Inserts records into the cache.
    pub fn insert(
        &self,
        name: &str,
        record_type: Option<RecordKind>,
        records: Vec<DnsRecord>,
        ttl: u32,
    ) {
        if records.is_empty() || ttl == 0 {
            return;
        }

        let key = cache_key(name, record_type);
        let expires_at = Instant::now() + std::time::Duration::from_secs(ttl as u64);
        let shared_records = Arc::new(records);

        self.memory.insert(
            key,
            CachedEntry {
                records: Arc::clone(&shared_records),
                expires_at,
                local: false,
            },
        );

        // Queue disk write via batching channel
        let req = CacheWriteRequest {
            name: name.to_string(),
            rt_str: record_type.map(|r| r.as_str().to_string()),
            records: shared_records,
            ttl,
        };
        if let Err(e) = self.persist_tx.try_send(req) {
            tracing::warn!(
                "cache persist channel full, dropping write for {}: {}",
                name,
                e
            );
        }
    }

    /// Inserts local (authoritative) records into the in-memory cache.
    ///
    /// Unlike `insert()`, this does NOT write to the persistent SQLite cache
    /// (local records already live in the main DB) and uses a long cache
    /// lifetime (1 day). The record's TTL is preserved as-is for clients;
    /// eviction happens via `flush()`, not TTL expiration.
    pub fn insert_local(
        &self,
        name: &str,
        record_type: Option<RecordKind>,
        records: Vec<DnsRecord>,
    ) {
        if records.is_empty() {
            return;
        }

        let key = cache_key(name, record_type);
        let expires_at = Instant::now() + std::time::Duration::from_secs(86400);

        self.memory.insert(
            key,
            CachedEntry {
                records: Arc::new(records),
                expires_at,
                local: true,
            },
        );
    }

    /// Flushes all cached entries.
    pub fn flush(&self) {
        self.memory.clear();
        if let Err(e) = self.db.cache_flush() {
            tracing::warn!("failed to flush persistent cache: {}", e);
        }
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
    }

    /// Returns cache statistics.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            total_entries: self.memory.len() as u64,
            hit_count: self.hits.load(Ordering::Relaxed),
            miss_count: self.misses.load(Ordering::Relaxed),
        }
    }

    /// Loads non-expired entries from disk at boot time.
    fn load_from_disk(&self) {
        // Load from the database cache table
        if let Ok(records) = self.db.cache_lookup("", None) {
            for rec in records {
                let key = cache_key(&rec.name, Some(rec.record_type));
                self.memory
                    .entry(key)
                    .and_modify(|entry| {
                        Arc::make_mut(&mut entry.records).push(rec.clone());
                    })
                    .or_insert(CachedEntry {
                        records: Arc::new(vec![rec]),
                        expires_at: Instant::now() + std::time::Duration::from_secs(300),
                        local: false,
                    });
            }
        }
    }
}

/// Cache statistics.
pub struct CacheStats {
    pub total_entries: u64,
    pub hit_count: u64,
    pub miss_count: u64,
}

/// Builds a cache key. Names are expected to already be normalized (lowercase
/// with trailing dot) by the DNS layer, so we skip the redundant
/// `to_lowercase()` call.
pub fn cache_key(name: &str, record_type: Option<RecordKind>) -> String {
    let rt_str = match record_type {
        Some(rt) => rt.as_str(),
        None => "*",
    };
    let mut key = String::with_capacity(name.len() + 1 + rt_str.len());
    key.push_str(name);
    key.push(':');
    key.push_str(rt_str);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cache() -> DnsCache {
        let db = Database::open_memory().unwrap();
        DnsCache::new(db)
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = test_cache();
        let result = cache.lookup("nonexistent.com.", Some(RecordKind::A));
        assert!(result.is_empty());
        assert_eq!(cache.stats().miss_count, 1);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let cache = test_cache();
        let records = vec![DnsRecord {
            id: None,
            name: "test.com.".to_string(),
            record_type: RecordKind::A,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            priority: 0,
        }];
        cache.insert("test.com.", Some(RecordKind::A), records, 300);

        let result = cache.lookup("test.com.", Some(RecordKind::A));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "1.2.3.4");
        assert_eq!(cache.stats().hit_count, 1);
    }

    #[tokio::test]
    async fn test_cache_flush() {
        let cache = test_cache();
        let records = vec![DnsRecord {
            id: None,
            name: "test.com.".to_string(),
            record_type: RecordKind::A,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            priority: 0,
        }];
        cache.insert("test.com.", Some(RecordKind::A), records, 300);
        assert_eq!(cache.stats().total_entries, 1);

        cache.flush();
        assert_eq!(cache.stats().total_entries, 0);

        let result = cache.lookup("test.com.", Some(RecordKind::A));
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = test_cache();
        let records = vec![DnsRecord {
            id: None,
            name: "expire.com.".to_string(),
            record_type: RecordKind::A,
            value: "1.2.3.4".to_string(),
            ttl: 0, // Zero TTL should not be cached
            priority: 0,
        }];
        cache.insert("expire.com.", Some(RecordKind::A), records, 0);

        let result = cache.lookup("expire.com.", Some(RecordKind::A));
        assert!(result.is_empty());
    }

    // ================================================================
    // cache_key tests
    // ================================================================

    #[test]
    fn test_cache_key_with_type() {
        let key = cache_key("example.com.", Some(RecordKind::A));
        assert_eq!(key, "example.com.:A");
    }

    #[test]
    fn test_cache_key_without_type() {
        let key = cache_key("example.com.", None);
        assert_eq!(key, "example.com.:*");
    }

    #[test]
    fn test_cache_key_various_types() {
        assert_eq!(cache_key("x.", Some(RecordKind::AAAA)), "x.:AAAA");
        assert_eq!(cache_key("x.", Some(RecordKind::CNAME)), "x.:CNAME");
        assert_eq!(cache_key("x.", Some(RecordKind::MX)), "x.:MX");
    }

    #[test]
    fn test_cache_key_consistency() {
        // Same inputs should produce same key
        let k1 = cache_key("test.com.", Some(RecordKind::A));
        let k2 = cache_key("test.com.", Some(RecordKind::A));
        assert_eq!(k1, k2);
    }

    // ================================================================
    // Arc-based insert/lookup tests
    // ================================================================

    #[tokio::test]
    async fn test_cache_insert_local_no_ttl_decay() {
        let cache = test_cache();
        let records = vec![DnsRecord {
            id: None,
            name: "local.com.".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.1".to_string(),
            ttl: 3600,
            priority: 0,
        }];
        cache.insert_local("local.com.", Some(RecordKind::A), records);

        let result = cache.lookup("local.com.", Some(RecordKind::A));
        assert_eq!(result.len(), 1);
        // Local records should preserve original TTL (no decay)
        assert_eq!(result[0].ttl, 3600);
    }

    #[tokio::test]
    async fn test_cache_insert_empty_vec_is_noop() {
        let cache = test_cache();
        cache.insert("empty.com.", Some(RecordKind::A), vec![], 300);
        assert_eq!(cache.stats().total_entries, 0);

        cache.insert_local("empty.com.", Some(RecordKind::A), vec![]);
        assert_eq!(cache.stats().total_entries, 0);
    }

    #[tokio::test]
    async fn test_cache_multiple_records_same_key() {
        let cache = test_cache();
        let records = vec![
            DnsRecord {
                id: None,
                name: "multi.com.".to_string(),
                record_type: RecordKind::A,
                value: "1.1.1.1".to_string(),
                ttl: 300,
                priority: 0,
            },
            DnsRecord {
                id: None,
                name: "multi.com.".to_string(),
                record_type: RecordKind::A,
                value: "2.2.2.2".to_string(),
                ttl: 300,
                priority: 0,
            },
        ];
        cache.insert("multi.com.", Some(RecordKind::A), records, 300);

        let result = cache.lookup("multi.com.", Some(RecordKind::A));
        assert_eq!(result.len(), 2);
    }
}
