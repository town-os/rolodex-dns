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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// A cached DNS record with expiration time.
#[derive(Debug, Clone)]
struct CachedEntry {
    records: Vec<DnsRecord>,
    expires_at: Instant,
    /// When true, records come from the local DB — TTL is returned as-is (no decay)
    /// and entries are not persisted to the SQLite cache table.
    local: bool,
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
}

impl DnsCache {
    pub fn new(db: Database) -> Self {
        let cache = Self {
            memory: Arc::new(DashMap::new()),
            db,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        };
        // Load non-expired entries from disk at boot time
        cache.load_from_disk();
        cache
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
                    // Local records: return original TTL (no decay)
                    return entry.records.clone();
                }
                // Upstream records: adjust TTL based on remaining cache time
                let remaining_secs = entry
                    .expires_at
                    .duration_since(now)
                    .as_secs() as u32;
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

    /// Inserts records into the cache.
    pub fn insert(&self, name: &str, record_type: Option<RecordKind>, records: Vec<DnsRecord>, ttl: u32) {
        if records.is_empty() || ttl == 0 {
            return;
        }

        let key = cache_key(name, record_type);
        let expires_at = Instant::now() + std::time::Duration::from_secs(ttl as u64);

        self.memory.insert(
            key,
            CachedEntry {
                records: records.clone(),
                expires_at,
                local: false,
            },
        );

        // Async write to disk
        let db = self.db.clone();
        let name = name.to_string();
        let rt_str = record_type.map(|r| r.as_str().to_string());
        tokio::spawn(async move {
            for rec in &records {
                let _ = db.cache_insert(
                    &name,
                    rt_str.as_deref().unwrap_or(rec.record_type.as_str()),
                    &rec.value,
                    ttl,
                    ttl,
                    "upstream",
                );
            }
        });
    }

    /// Inserts local (authoritative) records into the in-memory cache.
    ///
    /// Unlike `insert()`, this does NOT write to the persistent SQLite cache
    /// (local records already live in the main DB) and uses a long cache
    /// lifetime (1 day). The record's TTL is preserved as-is for clients;
    /// eviction happens via `flush()`, not TTL expiration.
    pub fn insert_local(&self, name: &str, record_type: Option<RecordKind>, records: Vec<DnsRecord>) {
        if records.is_empty() {
            return;
        }

        let key = cache_key(name, record_type);
        let expires_at = Instant::now() + std::time::Duration::from_secs(86400);

        self.memory.insert(
            key,
            CachedEntry {
                records,
                expires_at,
                local: true,
            },
        );
    }

    /// Flushes all cached entries.
    pub fn flush(&self) {
        self.memory.clear();
        let _ = self.db.cache_flush();
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
                        entry.records.push(rec.clone());
                    })
                    .or_insert(CachedEntry {
                        records: vec![rec.clone()],
                        expires_at: Instant::now()
                            + std::time::Duration::from_secs(rec.ttl as u64),
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

fn cache_key(name: &str, record_type: Option<RecordKind>) -> String {
    match record_type {
        Some(rt) => format!("{}:{}", name.to_lowercase(), rt.as_str()),
        None => format!("{}:*", name.to_lowercase()),
    }
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
}
