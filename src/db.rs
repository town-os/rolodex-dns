use anyhow::{Context, Result};
use dashmap::DashMap;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Represents a DNS record stored in the local database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub id: Option<i64>,
    pub name: String,
    pub record_type: RecordKind,
    pub value: String,
    pub ttl: u32,
    pub priority: u32,
}

/// Supported DNS record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
    SRV,
    PTR,
}

impl RecordKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordKind::A => "A",
            RecordKind::AAAA => "AAAA",
            RecordKind::CNAME => "CNAME",
            RecordKind::MX => "MX",
            RecordKind::TXT => "TXT",
            RecordKind::NS => "NS",
            RecordKind::SOA => "SOA",
            RecordKind::SRV => "SRV",
            RecordKind::PTR => "PTR",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(RecordKind::A),
            "AAAA" => Some(RecordKind::AAAA),
            "CNAME" => Some(RecordKind::CNAME),
            "MX" => Some(RecordKind::MX),
            "TXT" => Some(RecordKind::TXT),
            "NS" => Some(RecordKind::NS),
            "SOA" => Some(RecordKind::SOA),
            "SRV" => Some(RecordKind::SRV),
            "PTR" => Some(RecordKind::PTR),
            _ => None,
        }
    }

    pub fn to_proto_i32(&self) -> i32 {
        match self {
            RecordKind::A => 0,
            RecordKind::AAAA => 1,
            RecordKind::CNAME => 2,
            RecordKind::MX => 3,
            RecordKind::TXT => 4,
            RecordKind::NS => 5,
            RecordKind::SOA => 6,
            RecordKind::SRV => 7,
            RecordKind::PTR => 8,
        }
    }

    pub fn from_proto_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(RecordKind::A),
            1 => Some(RecordKind::AAAA),
            2 => Some(RecordKind::CNAME),
            3 => Some(RecordKind::MX),
            4 => Some(RecordKind::TXT),
            5 => Some(RecordKind::NS),
            6 => Some(RecordKind::SOA),
            7 => Some(RecordKind::SRV),
            8 => Some(RecordKind::PTR),
            _ => None,
        }
    }
}

/// Represents a network scope that defines a DNS view.
///
/// Each network scope has a unique name and a reserved `.home` domain
/// used as the default search domain for that network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkScope {
    /// Unique identifier for the network scope.
    pub name: String,
    /// The reserved `.home` domain for this network (e.g. "mynetwork.home.").
    /// Used as the default search domain for DHCP and similar services.
    pub home_domain: String,
}

/// Represents an association between a client IP address and a network scope.
///
/// Associations have a TTL and must be refreshed regularly. When an association
/// expires, the DNS server will stop resolving queries for that IP entirely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAssociation {
    /// The IP address of the client that has joined this network.
    pub ip_address: String,
    /// The name of the network scope this IP is associated with.
    pub scope_name: String,
    /// Time-to-live in seconds for this association.
    pub ttl_seconds: u64,
}

/// An in-memory cache entry for a network association, tracking its expiration.
#[derive(Debug, Clone)]
struct AssociationCacheEntry {
    scope_name: String,
    expires_at: Instant,
}

/// An in-memory cache for scoped DNS records, keyed by (scope_name, normalized_name, record_type).
#[derive(Debug, Clone)]
struct ScopedRecordCacheEntry {
    records: Vec<DnsRecord>,
}

/// Thread-safe handle to the DNS record database.
#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
    /// In-memory cache of network associations, keyed by IP address.
    /// Used for fast lookup during DNS resolution.
    association_cache: Arc<DashMap<String, AssociationCacheEntry>>,
    /// In-memory cache of scoped DNS records, keyed by "scope_name:name:record_type".
    /// Records are loaded from DB at boot and updated as they are entered.
    scoped_record_cache: Arc<DashMap<String, ScopedRecordCacheEntry>>,
}

impl Database {
    /// Opens or creates the database at the given path.
    /// Uses SQLite with WAL mode for concurrent read performance.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path).context("failed to open database")?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .context("failed to set pragmas")?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            association_cache: Arc::new(DashMap::new()),
            scoped_record_cache: Arc::new(DashMap::new()),
        };
        db.init_tables()?;
        db.load_scoped_records_into_cache()?;
        db.load_associations_into_cache()?;
        Ok(db)
    }

    /// Opens an in-memory database (useful for testing).
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("failed to open in-memory database")?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            association_cache: Arc::new(DashMap::new()),
            scoped_record_cache: Arc::new(DashMap::new()),
        };
        db.init_tables()?;
        Ok(db)
    }

    fn init_tables(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                record_type TEXT NOT NULL,
                value TEXT NOT NULL,
                ttl INTEGER NOT NULL DEFAULT 300,
                priority INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_dns_name ON dns_records(name);
            CREATE INDEX IF NOT EXISTS idx_dns_name_type ON dns_records(name, record_type);

            CREATE TABLE IF NOT EXISTS network_scopes (
                name TEXT PRIMARY KEY NOT NULL,
                home_domain TEXT NOT NULL UNIQUE
            );

            CREATE TABLE IF NOT EXISTS scoped_dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope_name TEXT NOT NULL,
                name TEXT NOT NULL,
                record_type TEXT NOT NULL,
                value TEXT NOT NULL,
                ttl INTEGER NOT NULL DEFAULT 300,
                priority INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (scope_name) REFERENCES network_scopes(name) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_scoped_dns_scope ON scoped_dns_records(scope_name);
            CREATE INDEX IF NOT EXISTS idx_scoped_dns_name ON scoped_dns_records(scope_name, name);
            CREATE INDEX IF NOT EXISTS idx_scoped_dns_name_type ON scoped_dns_records(scope_name, name, record_type);

            CREATE TABLE IF NOT EXISTS network_associations (
                ip_address TEXT PRIMARY KEY NOT NULL,
                scope_name TEXT NOT NULL,
                ttl_seconds INTEGER NOT NULL DEFAULT 300,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (scope_name) REFERENCES network_scopes(name) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_assoc_scope ON network_associations(scope_name);",
        )
        .context("failed to create tables")?;
        Ok(())
    }

    /// Loads all scoped DNS records from the database into the in-memory cache.
    /// Called at boot time.
    fn load_scoped_records_into_cache(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT scope_name, name, record_type, value, ttl, priority FROM scoped_dns_records",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                DnsRecord {
                    id: None,
                    name: row.get(1)?,
                    record_type: RecordKind::from_str(&row.get::<_, String>(2)?).unwrap_or(RecordKind::A),
                    value: row.get(3)?,
                    ttl: row.get(4)?,
                    priority: row.get(5)?,
                },
            ))
        })?;

        for row in rows {
            let (scope_name, record) = row?;
            let cache_key = scoped_record_cache_key(&scope_name, &record.name, Some(record.record_type));
            self.scoped_record_cache
                .entry(cache_key)
                .and_modify(|entry| entry.records.push(record.clone()))
                .or_insert(ScopedRecordCacheEntry {
                    records: vec![record],
                });
        }

        Ok(())
    }

    /// Loads all non-expired network associations from the database into the in-memory cache.
    /// Called at boot time.
    fn load_associations_into_cache(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut stmt = conn.prepare(
            "SELECT ip_address, scope_name, ttl_seconds, created_at FROM network_associations",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;

        for row in rows {
            let (ip, scope, ttl, created_at) = row?;
            let elapsed = now - created_at;
            if elapsed < ttl {
                let remaining = (ttl - elapsed) as u64;
                self.association_cache.insert(
                    ip,
                    AssociationCacheEntry {
                        scope_name: scope,
                        expires_at: Instant::now() + Duration::from_secs(remaining),
                    },
                );
            }
        }

        Ok(())
    }

    /// Adds a DNS record to the database. Returns the row ID.
    pub fn add_record(&self, record: &DnsRecord) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO dns_records (name, record_type, value, ttl, priority) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                normalize_name(&record.name),
                record.record_type.as_str(),
                record.value,
                record.ttl,
                record.priority,
            ],
        )
        .context("failed to insert record")?;
        Ok(conn.last_insert_rowid())
    }

    /// Removes records matching the given criteria.
    /// If `record_type` is None, removes all records for the name.
    /// If `value` is non-empty, only removes the exact match.
    /// Returns the number of records removed.
    pub fn remove_records(
        &self,
        name: &str,
        record_type: Option<RecordKind>,
        value: &str,
    ) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let normalized = normalize_name(name);

        let count = if let Some(rt) = record_type {
            if value.is_empty() {
                conn.execute(
                    "DELETE FROM dns_records WHERE name = ?1 AND record_type = ?2",
                    params![normalized, rt.as_str()],
                )?
            } else {
                conn.execute(
                    "DELETE FROM dns_records WHERE name = ?1 AND record_type = ?2 AND value = ?3",
                    params![normalized, rt.as_str(), value],
                )?
            }
        } else if value.is_empty() {
            conn.execute(
                "DELETE FROM dns_records WHERE name = ?1",
                params![normalized],
            )?
        } else {
            conn.execute(
                "DELETE FROM dns_records WHERE name = ?1 AND value = ?2",
                params![normalized, value],
            )?
        };

        Ok(count)
    }

    /// Looks up all records for a given name and optional type.
    pub fn lookup(&self, name: &str, record_type: Option<RecordKind>) -> Result<Vec<DnsRecord>> {
        let conn = self.conn.lock().unwrap();
        let normalized = normalize_name(name);

        let mut records = Vec::new();

        if let Some(rt) = record_type {
            let mut stmt = conn.prepare(
                "SELECT id, name, record_type, value, ttl, priority FROM dns_records WHERE name = ?1 AND record_type = ?2",
            )?;
            let rows = stmt.query_map(params![normalized, rt.as_str()], |row| {
                Ok(DnsRecord {
                    id: Some(row.get(0)?),
                    name: row.get(1)?,
                    record_type: RecordKind::from_str(&row.get::<_, String>(2)?).unwrap_or(RecordKind::A),
                    value: row.get(3)?,
                    ttl: row.get(4)?,
                    priority: row.get(5)?,
                })
            })?;
            for row in rows {
                records.push(row?);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, name, record_type, value, ttl, priority FROM dns_records WHERE name = ?1",
            )?;
            let rows = stmt.query_map(params![normalized], |row| {
                Ok(DnsRecord {
                    id: Some(row.get(0)?),
                    name: row.get(1)?,
                    record_type: RecordKind::from_str(&row.get::<_, String>(2)?).unwrap_or(RecordKind::A),
                    value: row.get(3)?,
                    ttl: row.get(4)?,
                    priority: row.get(5)?,
                })
            })?;
            for row in rows {
                records.push(row?);
            }
        }

        Ok(records)
    }

    /// Lists all records, optionally filtered by name pattern and type.
    /// The name filter supports a wildcard prefix "*." to match all subdomains.
    pub fn list_records(
        &self,
        name_filter: &str,
        record_type: Option<RecordKind>,
    ) -> Result<Vec<DnsRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut records = Vec::new();

        let (sql, filter_params) = build_list_query(name_filter, record_type);
        let mut stmt = conn.prepare(&sql)?;

        let rows = match filter_params {
            FilterParams::None => stmt.query_map([], row_mapper)?,
            FilterParams::Name(ref n) => stmt.query_map(params![n], row_mapper)?,
            FilterParams::NameLike(ref n) => stmt.query_map(params![n], row_mapper)?,
            FilterParams::Type(ref t) => stmt.query_map(params![t], row_mapper)?,
            FilterParams::NameAndType(ref n, ref t) => stmt.query_map(params![n, t], row_mapper)?,
            FilterParams::NameLikeAndType(ref n, ref t) => {
                stmt.query_map(params![n, t], row_mapper)?
            }
        };

        for row in rows {
            records.push(row?);
        }

        Ok(records)
    }

    /// Returns all unique TLDs/domains in the database.
    pub fn get_managed_zones(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT name FROM dns_records",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut zones = std::collections::HashSet::new();
        for row in rows {
            let name = row?;
            // Extract the TLD or zone from the FQDN
            let parts: Vec<&str> = name.trim_end_matches('.').split('.').collect();
            if parts.len() >= 2 {
                // Register the domain (last two parts) as a managed zone
                let zone = format!(
                    "{}.",
                    parts[parts.len() - 2..].join(".")
                );
                zones.insert(zone);
            } else if parts.len() == 1 && !parts[0].is_empty() {
                // TLD-level record
                zones.insert(format!("{}.", parts[0]));
            }
        }
        Ok(zones.into_iter().collect())
    }

    // ================================================================
    // Network Scope Management
    // ================================================================

    /// Creates a new network scope.
    ///
    /// Each scope has a unique name and a reserved `.home` domain that serves
    /// as the default search domain for DNS clients in that network.
    /// The home domain is automatically derived as `<name>.home.` if not explicitly provided.
    pub fn create_network_scope(&self, scope: &NetworkScope) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO network_scopes (name, home_domain) VALUES (?1, ?2)",
            params![scope.name, normalize_name(&scope.home_domain)],
        )
        .context("failed to create network scope")?;
        Ok(())
    }

    /// Deletes a network scope and all associated records and associations.
    /// Returns true if a scope was deleted, false if it didn't exist.
    pub fn delete_network_scope(&self, name: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        // Delete associated records first (due to foreign keys)
        conn.execute(
            "DELETE FROM scoped_dns_records WHERE scope_name = ?1",
            params![name],
        )?;
        conn.execute(
            "DELETE FROM network_associations WHERE scope_name = ?1",
            params![name],
        )?;
        let count = conn.execute(
            "DELETE FROM network_scopes WHERE name = ?1",
            params![name],
        )?;

        // Clear caches for this scope
        self.scoped_record_cache.retain(|key, _| !key.starts_with(&format!("{}:", name)));
        self.association_cache.retain(|_, entry| entry.scope_name != name);

        Ok(count > 0)
    }

    /// Lists all network scopes.
    pub fn list_network_scopes(&self) -> Result<Vec<NetworkScope>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT name, home_domain FROM network_scopes")?;
        let rows = stmt.query_map([], |row| {
            Ok(NetworkScope {
                name: row.get(0)?,
                home_domain: row.get(1)?,
            })
        })?;
        let mut scopes = Vec::new();
        for row in rows {
            scopes.push(row?);
        }
        Ok(scopes)
    }

    /// Gets a network scope by name.
    pub fn get_network_scope(&self, name: &str) -> Result<Option<NetworkScope>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT name, home_domain FROM network_scopes WHERE name = ?1")?;
        let mut rows = stmt.query_map(params![name], |row| {
            Ok(NetworkScope {
                name: row.get(0)?,
                home_domain: row.get(1)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    // ================================================================
    // Network Association Management
    // ================================================================

    /// Associates an IP address with a network scope ("joins the network").
    ///
    /// The association has a TTL which must be refreshed regularly to maintain
    /// DNS resolution capability. If the TTL expires, the DNS server will stop
    /// responding to queries from this IP.
    ///
    /// If the IP is already associated with a scope, the association is updated.
    pub fn join_network(&self, assoc: &NetworkAssociation) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        conn.execute(
            "INSERT OR REPLACE INTO network_associations (ip_address, scope_name, ttl_seconds, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![assoc.ip_address, assoc.scope_name, assoc.ttl_seconds as i64, now],
        )
        .context("failed to join network")?;

        // Update in-memory cache
        self.association_cache.insert(
            assoc.ip_address.clone(),
            AssociationCacheEntry {
                scope_name: assoc.scope_name.clone(),
                expires_at: Instant::now() + Duration::from_secs(assoc.ttl_seconds),
            },
        );

        Ok(())
    }

    /// Removes an IP address's association with any network scope ("leaves the network").
    /// Returns true if an association was removed.
    pub fn leave_network(&self, ip_address: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count = conn.execute(
            "DELETE FROM network_associations WHERE ip_address = ?1",
            params![ip_address],
        )?;

        // Remove from cache
        self.association_cache.remove(ip_address);

        Ok(count > 0)
    }

    /// Lists all network associations, optionally filtered by scope name.
    pub fn list_network_associations(&self, scope_name: Option<&str>) -> Result<Vec<NetworkAssociation>> {
        let conn = self.conn.lock().unwrap();
        let mut assocs = Vec::new();

        if let Some(scope) = scope_name {
            let mut stmt = conn.prepare(
                "SELECT ip_address, scope_name, ttl_seconds FROM network_associations WHERE scope_name = ?1",
            )?;
            let rows = stmt.query_map(params![scope], |row| {
                Ok(NetworkAssociation {
                    ip_address: row.get(0)?,
                    scope_name: row.get(1)?,
                    ttl_seconds: row.get::<_, i64>(2)? as u64,
                })
            })?;
            for row in rows {
                assocs.push(row?);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT ip_address, scope_name, ttl_seconds FROM network_associations",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(NetworkAssociation {
                    ip_address: row.get(0)?,
                    scope_name: row.get(1)?,
                    ttl_seconds: row.get::<_, i64>(2)? as u64,
                })
            })?;
            for row in rows {
                assocs.push(row?);
            }
        }

        Ok(assocs)
    }

    /// Looks up the network scope for a given IP address from the in-memory cache.
    ///
    /// Returns None if the IP is not associated with any scope or if the
    /// association has expired (TTL exceeded).
    pub fn get_scope_for_ip(&self, ip_address: &str) -> Option<String> {
        if let Some(entry) = self.association_cache.get(ip_address) {
            if entry.expires_at > Instant::now() {
                return Some(entry.scope_name.clone());
            }
            // Expired - remove from cache
            drop(entry);
            self.association_cache.remove(ip_address);
        }
        None
    }

    /// Forcibly expires a cached network association for testing.
    /// Sets the entry's expiration to the past so the next lookup returns None.
    #[cfg(test)]
    pub fn expire_association(&self, ip_address: &str) {
        if self.association_cache.contains_key(ip_address) {
            self.association_cache.insert(
                ip_address.to_string(),
                AssociationCacheEntry {
                    scope_name: String::new(),
                    expires_at: Instant::now() - Duration::from_secs(1),
                },
            );
        }
    }

    // ================================================================
    // Scoped DNS Record Management
    // ================================================================

    /// Adds a DNS record scoped to a specific network scope.
    /// The record is stored in SQL and also cached in memory.
    pub fn add_scoped_record(&self, scope_name: &str, record: &DnsRecord) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let normalized = normalize_name(&record.name);
        conn.execute(
            "INSERT INTO scoped_dns_records (scope_name, name, record_type, value, ttl, priority)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                scope_name,
                normalized,
                record.record_type.as_str(),
                record.value,
                record.ttl,
                record.priority,
            ],
        )
        .context("failed to insert scoped record")?;
        let id = conn.last_insert_rowid();

        // Update in-memory cache
        let cached_record = DnsRecord {
            id: Some(id),
            name: normalized.clone(),
            record_type: record.record_type,
            value: record.value.clone(),
            ttl: record.ttl,
            priority: record.priority,
        };
        let cache_key = scoped_record_cache_key(scope_name, &normalized, Some(record.record_type));
        self.scoped_record_cache
            .entry(cache_key)
            .and_modify(|entry| entry.records.push(cached_record.clone()))
            .or_insert(ScopedRecordCacheEntry {
                records: vec![cached_record],
            });

        Ok(id)
    }

    /// Removes scoped DNS records matching the given criteria.
    /// Returns the number of records removed.
    pub fn remove_scoped_records(
        &self,
        scope_name: &str,
        name: &str,
        record_type: Option<RecordKind>,
        value: &str,
    ) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let normalized = normalize_name(name);

        let count = if let Some(rt) = record_type {
            if value.is_empty() {
                conn.execute(
                    "DELETE FROM scoped_dns_records WHERE scope_name = ?1 AND name = ?2 AND record_type = ?3",
                    params![scope_name, normalized, rt.as_str()],
                )?
            } else {
                conn.execute(
                    "DELETE FROM scoped_dns_records WHERE scope_name = ?1 AND name = ?2 AND record_type = ?3 AND value = ?4",
                    params![scope_name, normalized, rt.as_str(), value],
                )?
            }
        } else if value.is_empty() {
            conn.execute(
                "DELETE FROM scoped_dns_records WHERE scope_name = ?1 AND name = ?2",
                params![scope_name, normalized],
            )?
        } else {
            conn.execute(
                "DELETE FROM scoped_dns_records WHERE scope_name = ?1 AND name = ?2 AND value = ?3",
                params![scope_name, normalized, value],
            )?
        };

        // Invalidate cache entries for this scope and name
        self.scoped_record_cache.retain(|key, _| {
            !key.starts_with(&format!("{}:{}", scope_name, normalized))
        });

        Ok(count)
    }

    /// Looks up scoped DNS records from the in-memory cache.
    ///
    /// This is the primary lookup path for DNS resolution within a network scope.
    /// Records are served from cache for performance, with the cache being
    /// populated at boot from the database and updated on each write.
    pub fn lookup_scoped(
        &self,
        scope_name: &str,
        name: &str,
        record_type: Option<RecordKind>,
    ) -> Vec<DnsRecord> {
        let normalized = normalize_name(name);

        if let Some(rt) = record_type {
            let cache_key = scoped_record_cache_key(scope_name, &normalized, Some(rt));
            if let Some(entry) = self.scoped_record_cache.get(&cache_key) {
                return entry.records.clone();
            }
        } else {
            // Without a type filter, we need to collect all record types for this name
            let mut records = Vec::new();
            let prefix = format!("{}:{}:", scope_name, normalized);
            for entry in self.scoped_record_cache.iter() {
                if entry.key().starts_with(&prefix) {
                    records.extend(entry.records.clone());
                }
            }
            return records;
        }

        Vec::new()
    }

    /// Lists scoped DNS records from the database with optional filters.
    pub fn list_scoped_records(
        &self,
        scope_name: &str,
        name_filter: &str,
        record_type: Option<RecordKind>,
    ) -> Result<Vec<DnsRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut records = Vec::new();

        if name_filter.is_empty() && record_type.is_none() {
            let mut stmt = conn.prepare(
                "SELECT id, name, record_type, value, ttl, priority FROM scoped_dns_records WHERE scope_name = ?1",
            )?;
            let rows = stmt.query_map(params![scope_name], row_mapper)?;
            for row in rows {
                records.push(row?);
            }
        } else if name_filter.is_empty() {
            let rt = record_type.unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, name, record_type, value, ttl, priority FROM scoped_dns_records WHERE scope_name = ?1 AND record_type = ?2",
            )?;
            let rows = stmt.query_map(params![scope_name, rt.as_str()], row_mapper)?;
            for row in rows {
                records.push(row?);
            }
        } else if record_type.is_none() {
            if let Some(suffix) = name_filter.strip_prefix("*.") {
                let like = format!("%{}", normalize_name(suffix));
                let mut stmt = conn.prepare(
                    "SELECT id, name, record_type, value, ttl, priority FROM scoped_dns_records WHERE scope_name = ?1 AND name LIKE ?2",
                )?;
                let rows = stmt.query_map(params![scope_name, like], row_mapper)?;
                for row in rows {
                    records.push(row?);
                }
            } else {
                let normalized = normalize_name(name_filter);
                let mut stmt = conn.prepare(
                    "SELECT id, name, record_type, value, ttl, priority FROM scoped_dns_records WHERE scope_name = ?1 AND name = ?2",
                )?;
                let rows = stmt.query_map(params![scope_name, normalized], row_mapper)?;
                for row in rows {
                    records.push(row?);
                }
            }
        } else {
            let rt = record_type.unwrap();
            if let Some(suffix) = name_filter.strip_prefix("*.") {
                let like = format!("%{}", normalize_name(suffix));
                let mut stmt = conn.prepare(
                    "SELECT id, name, record_type, value, ttl, priority FROM scoped_dns_records WHERE scope_name = ?1 AND name LIKE ?2 AND record_type = ?3",
                )?;
                let rows = stmt.query_map(params![scope_name, like, rt.as_str()], row_mapper)?;
                for row in rows {
                    records.push(row?);
                }
            } else {
                let normalized = normalize_name(name_filter);
                let mut stmt = conn.prepare(
                    "SELECT id, name, record_type, value, ttl, priority FROM scoped_dns_records WHERE scope_name = ?1 AND name = ?2 AND record_type = ?3",
                )?;
                let rows = stmt.query_map(params![scope_name, normalized, rt.as_str()], row_mapper)?;
                for row in rows {
                    records.push(row?);
                }
            }
        }

        Ok(records)
    }

    /// Returns the managed zones for a specific scope (from scoped records).
    pub fn get_scoped_managed_zones(&self, scope_name: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT name FROM scoped_dns_records WHERE scope_name = ?1",
        )?;
        let rows = stmt.query_map(params![scope_name], |row| row.get::<_, String>(0))?;
        let mut zones = std::collections::HashSet::new();
        for row in rows {
            let name = row?;
            let parts: Vec<&str> = name.trim_end_matches('.').split('.').collect();
            if parts.len() >= 2 {
                let zone = format!("{}.", parts[parts.len() - 2..].join("."));
                zones.insert(zone);
            } else if parts.len() == 1 && !parts[0].is_empty() {
                zones.insert(format!("{}.", parts[0]));
            }
        }
        Ok(zones.into_iter().collect())
    }

    /// Returns the search domains for a given IP address.
    ///
    /// If the IP is associated with a network scope, returns that scope's
    /// `.home` domain as the search domain. This is useful for DHCP servers
    /// that need to set the search domain for clients.
    pub fn get_search_domains(&self, ip_address: &str) -> Result<Vec<String>> {
        let scope_name = match self.get_scope_for_ip(ip_address) {
            Some(name) => name,
            None => return Ok(Vec::new()),
        };
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT home_domain FROM network_scopes WHERE name = ?1",
        )?;
        let mut rows = stmt.query_map(params![scope_name], |row| row.get::<_, String>(0))?;
        match rows.next() {
            Some(row) => Ok(vec![row?]),
            None => Ok(Vec::new()),
        }
    }
}

fn row_mapper(row: &rusqlite::Row) -> rusqlite::Result<DnsRecord> {
    Ok(DnsRecord {
        id: Some(row.get(0)?),
        name: row.get(1)?,
        record_type: RecordKind::from_str(&row.get::<_, String>(2)?).unwrap_or(RecordKind::A),
        value: row.get(3)?,
        ttl: row.get(4)?,
        priority: row.get(5)?,
    })
}

enum FilterParams {
    None,
    Name(String),
    NameLike(String),
    Type(String),
    NameAndType(String, String),
    NameLikeAndType(String, String),
}

fn build_list_query(name_filter: &str, record_type: Option<RecordKind>) -> (String, FilterParams) {
    let base = "SELECT id, name, record_type, value, ttl, priority FROM dns_records";

    if name_filter.is_empty() && record_type.is_none() {
        return (base.to_string(), FilterParams::None);
    }

    let mut conditions = Vec::new();
    let filter_params;

    if !name_filter.is_empty() {
        if let Some(suffix) = name_filter.strip_prefix("*.") {
            let like = format!("%{}", normalize_name(suffix));
            if let Some(rt) = record_type {
                conditions.push("name LIKE ?1".to_string());
                conditions.push("record_type = ?2".to_string());
                filter_params = FilterParams::NameLikeAndType(like, rt.as_str().to_string());
            } else {
                conditions.push("name LIKE ?1".to_string());
                filter_params = FilterParams::NameLike(like);
            }
        } else {
            let normalized = normalize_name(name_filter);
            if let Some(rt) = record_type {
                conditions.push("name = ?1".to_string());
                conditions.push("record_type = ?2".to_string());
                filter_params = FilterParams::NameAndType(normalized, rt.as_str().to_string());
            } else {
                conditions.push("name = ?1".to_string());
                filter_params = FilterParams::Name(normalized);
            }
        }
    } else if let Some(rt) = record_type {
        conditions.push("record_type = ?1".to_string());
        filter_params = FilterParams::Type(rt.as_str().to_string());
    } else {
        filter_params = FilterParams::None;
    }

    let sql = if conditions.is_empty() {
        base.to_string()
    } else {
        format!("{} WHERE {}", base, conditions.join(" AND "))
    };

    (sql, filter_params)
}

/// Generates a cache key for scoped record lookups.
fn scoped_record_cache_key(scope_name: &str, normalized_name: &str, record_type: Option<RecordKind>) -> String {
    match record_type {
        Some(rt) => format!("{}:{}:{}", scope_name, normalized_name, rt.as_str()),
        None => format!("{}:{}:*", scope_name, normalized_name),
    }
}

/// Normalizes a DNS name to lowercase with a trailing dot.
pub fn normalize_name(name: &str) -> String {
    let lower = name.to_lowercase();
    if lower.ends_with('.') {
        lower
    } else {
        format!("{}.", lower)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Database {
        Database::open_memory().unwrap()
    }

    #[test]
    fn test_normalize_name() {
        assert_eq!(normalize_name("example.com"), "example.com.");
        assert_eq!(normalize_name("example.com."), "example.com.");
        assert_eq!(normalize_name("Example.COM"), "example.com.");
    }

    #[test]
    fn test_add_and_lookup() {
        let db = test_db();
        let record = DnsRecord {
            id: None,
            name: "test.example.com".to_string(),
            record_type: RecordKind::A,
            value: "192.168.1.1".to_string(),
            ttl: 300,
            priority: 0,
        };
        let id = db.add_record(&record).unwrap();
        assert!(id > 0);

        let results = db.lookup("test.example.com", Some(RecordKind::A)).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "192.168.1.1");
        assert_eq!(results[0].ttl, 300);
    }

    #[test]
    fn test_lookup_case_insensitive() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "Test.Example.COM".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.1".to_string(),
            ttl: 60,
            priority: 0,
        })
        .unwrap();

        let results = db.lookup("test.example.com", None).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_remove_by_name() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "rm.example.com".to_string(),
            record_type: RecordKind::A,
            value: "1.1.1.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "rm.example.com".to_string(),
            record_type: RecordKind::AAAA,
            value: "::1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let removed = db.remove_records("rm.example.com", None, "").unwrap();
        assert_eq!(removed, 2);

        let results = db.lookup("rm.example.com", None).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_remove_by_type() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "multi.example.com".to_string(),
            record_type: RecordKind::A,
            value: "1.1.1.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "multi.example.com".to_string(),
            record_type: RecordKind::AAAA,
            value: "::1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let removed = db
            .remove_records("multi.example.com", Some(RecordKind::A), "")
            .unwrap();
        assert_eq!(removed, 1);

        let results = db.lookup("multi.example.com", None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].record_type, RecordKind::AAAA);
    }

    #[test]
    fn test_remove_by_value() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "val.example.com".to_string(),
            record_type: RecordKind::A,
            value: "1.1.1.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "val.example.com".to_string(),
            record_type: RecordKind::A,
            value: "2.2.2.2".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let removed = db
            .remove_records("val.example.com", Some(RecordKind::A), "1.1.1.1")
            .unwrap();
        assert_eq!(removed, 1);

        let results = db.lookup("val.example.com", Some(RecordKind::A)).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "2.2.2.2");
    }

    #[test]
    fn test_list_all() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "a.example.com".to_string(),
            record_type: RecordKind::A,
            value: "1.1.1.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "b.example.com".to_string(),
            record_type: RecordKind::AAAA,
            value: "::1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let results = db.list_records("", None).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_list_with_wildcard() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "sub.example.com".to_string(),
            record_type: RecordKind::A,
            value: "1.1.1.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "other.test.com".to_string(),
            record_type: RecordKind::A,
            value: "2.2.2.2".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let results = db.list_records("*.example.com", None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "sub.example.com.");
    }

    #[test]
    fn test_list_with_type_filter() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "mixed.example.com".to_string(),
            record_type: RecordKind::A,
            value: "1.1.1.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "mixed.example.com".to_string(),
            record_type: RecordKind::MX,
            value: "mail.example.com".to_string(),
            ttl: 300,
            priority: 10,
        })
        .unwrap();

        let results = db.list_records("", Some(RecordKind::MX)).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].record_type, RecordKind::MX);
    }

    #[test]
    fn test_get_managed_zones() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "a.example.com".to_string(),
            record_type: RecordKind::A,
            value: "1.1.1.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "b.test.org".to_string(),
            record_type: RecordKind::A,
            value: "2.2.2.2".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let zones = db.get_managed_zones().unwrap();
        assert_eq!(zones.len(), 2);
        assert!(zones.contains(&"example.com.".to_string()));
        assert!(zones.contains(&"test.org.".to_string()));
    }

    #[test]
    fn test_record_kind_conversions() {
        for kind in &[
            RecordKind::A,
            RecordKind::AAAA,
            RecordKind::CNAME,
            RecordKind::MX,
            RecordKind::TXT,
            RecordKind::NS,
            RecordKind::SOA,
            RecordKind::SRV,
            RecordKind::PTR,
        ] {
            let s = kind.as_str();
            assert_eq!(RecordKind::from_str(s), Some(*kind));
            let i = kind.to_proto_i32();
            assert_eq!(RecordKind::from_proto_i32(i), Some(*kind));
        }
    }

    #[test]
    fn test_record_kind_from_str_case_insensitive() {
        assert_eq!(RecordKind::from_str("a"), Some(RecordKind::A));
        assert_eq!(RecordKind::from_str("aaaa"), Some(RecordKind::AAAA));
        assert_eq!(RecordKind::from_str("cname"), Some(RecordKind::CNAME));
    }

    #[test]
    fn test_record_kind_from_str_invalid() {
        assert_eq!(RecordKind::from_str("INVALID"), None);
    }

    #[test]
    fn test_record_kind_from_proto_invalid() {
        assert_eq!(RecordKind::from_proto_i32(99), None);
    }

    // ================================================================
    // Network Scope Tests
    // ================================================================

    #[test]
    fn test_create_and_list_network_scopes() {
        let db = test_db();
        let scope = NetworkScope {
            name: "office".to_string(),
            home_domain: "office.home".to_string(),
        };
        db.create_network_scope(&scope).unwrap();

        let scopes = db.list_network_scopes().unwrap();
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0].name, "office");
        assert_eq!(scopes[0].home_domain, "office.home.");
    }

    #[test]
    fn test_get_network_scope() {
        let db = test_db();
        let scope = NetworkScope {
            name: "lab".to_string(),
            home_domain: "lab.home".to_string(),
        };
        db.create_network_scope(&scope).unwrap();

        let found = db.get_network_scope("lab").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "lab");

        let not_found = db.get_network_scope("nonexistent").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_delete_network_scope() {
        let db = test_db();
        let scope = NetworkScope {
            name: "temp".to_string(),
            home_domain: "temp.home".to_string(),
        };
        db.create_network_scope(&scope).unwrap();

        // Add a scoped record
        db.add_scoped_record("temp", &DnsRecord {
            id: None,
            name: "host.temp.home".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        }).unwrap();

        // Add an association
        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.1".to_string(),
            scope_name: "temp".to_string(),
            ttl_seconds: 3600,
        }).unwrap();

        let deleted = db.delete_network_scope("temp").unwrap();
        assert!(deleted);

        let scopes = db.list_network_scopes().unwrap();
        assert!(scopes.is_empty());

        // Records and associations should be gone
        let records = db.lookup_scoped("temp", "host.temp.home", Some(RecordKind::A));
        assert!(records.is_empty());
        assert!(db.get_scope_for_ip("192.168.1.1").is_none());
    }

    #[test]
    fn test_delete_nonexistent_scope() {
        let db = test_db();
        let deleted = db.delete_network_scope("nonexistent").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_duplicate_scope_name_fails() {
        let db = test_db();
        let scope = NetworkScope {
            name: "dup".to_string(),
            home_domain: "dup.home".to_string(),
        };
        db.create_network_scope(&scope).unwrap();
        assert!(db.create_network_scope(&scope).is_err());
    }

    // ================================================================
    // Network Association Tests
    // ================================================================

    #[test]
    fn test_join_and_get_scope_for_ip() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "net1".to_string(),
            home_domain: "net1.home".to_string(),
        }).unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "10.0.0.5".to_string(),
            scope_name: "net1".to_string(),
            ttl_seconds: 3600,
        }).unwrap();

        let scope = db.get_scope_for_ip("10.0.0.5");
        assert_eq!(scope, Some("net1".to_string()));
    }

    #[test]
    fn test_unassociated_ip_returns_none() {
        let db = test_db();
        assert!(db.get_scope_for_ip("10.0.0.99").is_none());
    }

    #[test]
    fn test_leave_network() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "net2".to_string(),
            home_domain: "net2.home".to_string(),
        }).unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "10.0.0.10".to_string(),
            scope_name: "net2".to_string(),
            ttl_seconds: 3600,
        }).unwrap();

        let left = db.leave_network("10.0.0.10").unwrap();
        assert!(left);
        assert!(db.get_scope_for_ip("10.0.0.10").is_none());
    }

    #[test]
    fn test_leave_network_not_found() {
        let db = test_db();
        let left = db.leave_network("10.0.0.99").unwrap();
        assert!(!left);
    }

    #[test]
    fn test_list_associations() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "netA".to_string(),
            home_domain: "netA.home".to_string(),
        }).unwrap();
        db.create_network_scope(&NetworkScope {
            name: "netB".to_string(),
            home_domain: "netB.home".to_string(),
        }).unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "10.1.0.1".to_string(),
            scope_name: "netA".to_string(),
            ttl_seconds: 300,
        }).unwrap();
        db.join_network(&NetworkAssociation {
            ip_address: "10.2.0.1".to_string(),
            scope_name: "netB".to_string(),
            ttl_seconds: 300,
        }).unwrap();

        let all = db.list_network_associations(None).unwrap();
        assert_eq!(all.len(), 2);

        let net_a_only = db.list_network_associations(Some("netA")).unwrap();
        assert_eq!(net_a_only.len(), 1);
        assert_eq!(net_a_only[0].ip_address, "10.1.0.1");
    }

    #[test]
    fn test_join_network_updates_existing() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "update-net".to_string(),
            home_domain: "update.home".to_string(),
        }).unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "10.5.0.1".to_string(),
            scope_name: "update-net".to_string(),
            ttl_seconds: 100,
        }).unwrap();

        // Re-join with new TTL (refresh)
        db.join_network(&NetworkAssociation {
            ip_address: "10.5.0.1".to_string(),
            scope_name: "update-net".to_string(),
            ttl_seconds: 3600,
        }).unwrap();

        let assocs = db.list_network_associations(Some("update-net")).unwrap();
        assert_eq!(assocs.len(), 1);
        assert_eq!(assocs[0].ttl_seconds, 3600);
    }

    // ================================================================
    // Scoped DNS Record Tests
    // ================================================================

    #[test]
    fn test_add_and_lookup_scoped_record() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "scopeA".to_string(),
            home_domain: "scopeA.home".to_string(),
        }).unwrap();

        db.add_scoped_record("scopeA", &DnsRecord {
            id: None,
            name: "host1.scopeA.home".to_string(),
            record_type: RecordKind::A,
            value: "10.10.0.1".to_string(),
            ttl: 300,
            priority: 0,
        }).unwrap();

        let records = db.lookup_scoped("scopeA", "host1.scopeA.home", Some(RecordKind::A));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "10.10.0.1");
    }

    #[test]
    fn test_scoped_records_isolated_between_scopes() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "scope1".to_string(),
            home_domain: "scope1.home".to_string(),
        }).unwrap();
        db.create_network_scope(&NetworkScope {
            name: "scope2".to_string(),
            home_domain: "scope2.home".to_string(),
        }).unwrap();

        db.add_scoped_record("scope1", &DnsRecord {
            id: None,
            name: "shared.internal".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        }).unwrap();

        db.add_scoped_record("scope2", &DnsRecord {
            id: None,
            name: "shared.internal".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.2".to_string(),
            ttl: 300,
            priority: 0,
        }).unwrap();

        let s1_records = db.lookup_scoped("scope1", "shared.internal", Some(RecordKind::A));
        assert_eq!(s1_records.len(), 1);
        assert_eq!(s1_records[0].value, "10.0.0.1");

        let s2_records = db.lookup_scoped("scope2", "shared.internal", Some(RecordKind::A));
        assert_eq!(s2_records.len(), 1);
        assert_eq!(s2_records[0].value, "10.0.0.2");
    }

    #[test]
    fn test_remove_scoped_records() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "rmscope".to_string(),
            home_domain: "rmscope.home".to_string(),
        }).unwrap();

        db.add_scoped_record("rmscope", &DnsRecord {
            id: None,
            name: "remove-me.rmscope.home".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        }).unwrap();

        let removed = db.remove_scoped_records("rmscope", "remove-me.rmscope.home", Some(RecordKind::A), "").unwrap();
        assert_eq!(removed, 1);

        let records = db.lookup_scoped("rmscope", "remove-me.rmscope.home", Some(RecordKind::A));
        assert!(records.is_empty());
    }

    #[test]
    fn test_list_scoped_records() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "listscope".to_string(),
            home_domain: "listscope.home".to_string(),
        }).unwrap();

        db.add_scoped_record("listscope", &DnsRecord {
            id: None,
            name: "a.listscope.home".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        }).unwrap();
        db.add_scoped_record("listscope", &DnsRecord {
            id: None,
            name: "b.listscope.home".to_string(),
            record_type: RecordKind::AAAA,
            value: "::1".to_string(),
            ttl: 300,
            priority: 0,
        }).unwrap();

        let all = db.list_scoped_records("listscope", "", None).unwrap();
        assert_eq!(all.len(), 2);

        let a_only = db.list_scoped_records("listscope", "", Some(RecordKind::A)).unwrap();
        assert_eq!(a_only.len(), 1);
    }

    #[test]
    fn test_get_search_domains() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "search-net".to_string(),
            home_domain: "search.home".to_string(),
        }).unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "192.168.0.50".to_string(),
            scope_name: "search-net".to_string(),
            ttl_seconds: 3600,
        }).unwrap();

        let domains = db.get_search_domains("192.168.0.50").unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "search.home.");

        // Unassociated IP should get no search domains
        let empty = db.get_search_domains("192.168.0.99").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_lookup_scoped_without_type() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "alltype".to_string(),
            home_domain: "alltype.home".to_string(),
        }).unwrap();

        db.add_scoped_record("alltype", &DnsRecord {
            id: None,
            name: "multi.alltype.home".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        }).unwrap();
        db.add_scoped_record("alltype", &DnsRecord {
            id: None,
            name: "multi.alltype.home".to_string(),
            record_type: RecordKind::AAAA,
            value: "::1".to_string(),
            ttl: 300,
            priority: 0,
        }).unwrap();

        let all = db.lookup_scoped("alltype", "multi.alltype.home", None);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_association_ttl_expiration() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "expire-net".to_string(),
            home_domain: "expire.home".to_string(),
        }).unwrap();

        // Join with a very short TTL
        db.join_network(&NetworkAssociation {
            ip_address: "10.99.0.1".to_string(),
            scope_name: "expire-net".to_string(),
            ttl_seconds: 3600,
        }).unwrap();

        // Should be associated initially
        assert_eq!(db.get_scope_for_ip("10.99.0.1"), Some("expire-net".to_string()));

        // Manually expire the cache entry by setting expires_at to the past
        db.association_cache.insert(
            "10.99.0.1".to_string(),
            AssociationCacheEntry {
                scope_name: "expire-net".to_string(),
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );

        // Should return None for expired association
        assert!(db.get_scope_for_ip("10.99.0.1").is_none());

        // The expired entry should have been removed from the cache
        assert!(!db.association_cache.contains_key("10.99.0.1"));
    }

    #[test]
    fn test_database_persistence_with_scoped_data() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("scoped-test.db");

        // Create and populate database with scoped data
        {
            let db = Database::open(&db_path).unwrap();

            db.create_network_scope(&NetworkScope {
                name: "persist-scope".to_string(),
                home_domain: "persist.home".to_string(),
            }).unwrap();

            db.add_scoped_record("persist-scope", &DnsRecord {
                id: None,
                name: "host1.persist.home".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            }).unwrap();

            db.join_network(&NetworkAssociation {
                ip_address: "192.168.5.1".to_string(),
                scope_name: "persist-scope".to_string(),
                ttl_seconds: 86400,
            }).unwrap();
        }

        // Reopen and verify caches are populated from database
        {
            let db = Database::open(&db_path).unwrap();

            // Scoped records should be loaded into cache
            let records = db.lookup_scoped("persist-scope", "host1.persist.home", Some(RecordKind::A));
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].value, "10.0.0.1");

            // Association should be loaded into cache
            let scope = db.get_scope_for_ip("192.168.5.1");
            assert_eq!(scope, Some("persist-scope".to_string()));

            // Scope itself should still exist
            let scopes = db.list_network_scopes().unwrap();
            assert_eq!(scopes.len(), 1);
            assert_eq!(scopes[0].name, "persist-scope");
        }
    }

    #[test]
    fn test_scoped_managed_zones() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "zones".to_string(),
            home_domain: "zones.home".to_string(),
        }).unwrap();

        db.add_scoped_record("zones", &DnsRecord {
            id: None,
            name: "host.zones.home".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        }).unwrap();
        db.add_scoped_record("zones", &DnsRecord {
            id: None,
            name: "host.other.net".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.2".to_string(),
            ttl: 300,
            priority: 0,
        }).unwrap();

        let zones = db.get_scoped_managed_zones("zones").unwrap();
        assert_eq!(zones.len(), 2);
        assert!(zones.contains(&"zones.home.".to_string()));
        assert!(zones.contains(&"other.net.".to_string()));
    }
}
