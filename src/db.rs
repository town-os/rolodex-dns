use anyhow::{Context, Result, anyhow};
use dashmap::{DashMap, DashSet};
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Parameters for storing a DNSSEC key.
pub struct DnssecKeyParams<'a> {
    pub zone: &'a str,
    pub scope: &'a str,
    pub algorithm: &'a str,
    pub key_type: &'a str,
    pub private_key: &'a [u8],
    pub public_key: &'a [u8],
    pub key_tag: u16,
}

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
    URI,
    SSHFP,
    DNAME,
    ANAME,
    ZONEMD,
    TLSA,
    DNSKEY,
    DS,
    RRSIG,
    NSEC,
    NSEC3,
    NSEC3PARAM,
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
            RecordKind::URI => "URI",
            RecordKind::SSHFP => "SSHFP",
            RecordKind::DNAME => "DNAME",
            RecordKind::ANAME => "ANAME",
            RecordKind::ZONEMD => "ZONEMD",
            RecordKind::TLSA => "TLSA",
            RecordKind::DNSKEY => "DNSKEY",
            RecordKind::DS => "DS",
            RecordKind::RRSIG => "RRSIG",
            RecordKind::NSEC => "NSEC",
            RecordKind::NSEC3 => "NSEC3",
            RecordKind::NSEC3PARAM => "NSEC3PARAM",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
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
            "URI" => Some(RecordKind::URI),
            "SSHFP" => Some(RecordKind::SSHFP),
            "DNAME" => Some(RecordKind::DNAME),
            "ANAME" => Some(RecordKind::ANAME),
            "ZONEMD" => Some(RecordKind::ZONEMD),
            "TLSA" => Some(RecordKind::TLSA),
            "DNSKEY" => Some(RecordKind::DNSKEY),
            "DS" => Some(RecordKind::DS),
            "RRSIG" => Some(RecordKind::RRSIG),
            "NSEC" => Some(RecordKind::NSEC),
            "NSEC3" => Some(RecordKind::NSEC3),
            "NSEC3PARAM" => Some(RecordKind::NSEC3PARAM),
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
            RecordKind::URI => 9,
            RecordKind::SSHFP => 10,
            RecordKind::DNAME => 11,
            RecordKind::ANAME => 12,
            RecordKind::ZONEMD => 13,
            RecordKind::TLSA => 14,
            RecordKind::DNSKEY => 15,
            RecordKind::DS => 16,
            RecordKind::RRSIG => 17,
            RecordKind::NSEC => 18,
            RecordKind::NSEC3 => 19,
            RecordKind::NSEC3PARAM => 20,
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
            9 => Some(RecordKind::URI),
            10 => Some(RecordKind::SSHFP),
            11 => Some(RecordKind::DNAME),
            12 => Some(RecordKind::ANAME),
            13 => Some(RecordKind::ZONEMD),
            14 => Some(RecordKind::TLSA),
            15 => Some(RecordKind::DNSKEY),
            16 => Some(RecordKind::DS),
            17 => Some(RecordKind::RRSIG),
            18 => Some(RecordKind::NSEC),
            19 => Some(RecordKind::NSEC3),
            20 => Some(RecordKind::NSEC3PARAM),
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

/// Represents a DNSSEC key stored in the database.
#[derive(Debug, Clone)]
pub struct DnssecKeyRow {
    pub id: i64,
    pub zone: String,
    pub scope_name: String,
    pub algorithm: String,
    pub key_type: String,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub key_tag: u16,
    pub created_at: i64,
    pub active: bool,
}

/// Represents an ACME certificate stored in the database.
#[derive(Debug, Clone)]
pub struct AcmeCertRow {
    pub id: i64,
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub chain_pem: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// DHCP address pool for a network scope.
#[derive(Debug, Clone)]
pub struct DhcpPool {
    pub id: i64,
    pub scope_name: String,
    pub range_start: String,
    pub range_end: String,
    pub gateway: Option<String>,
    pub subnet_mask: String,
    pub dns_servers: Option<String>,
}

/// DHCP lease record tracking MAC→IP bindings.
#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub mac: String,
    pub ip: String,
    pub scope_name: String,
    pub hostname: Option<String>,
    pub lease_start: i64,
    pub lease_duration: i64,
    pub state: String,
}

/// Per-scope RBL provider configuration.
#[derive(Debug, Clone)]
pub struct ScopeRblProvider {
    pub scope_name: String,
    pub zone: String,
    pub enabled: bool,
}

/// DHCP certificate option delivered to clients.
#[derive(Debug, Clone)]
pub struct DhcpCertOption {
    pub scope_name: String,
    pub option_code: u32,
    pub cert_data: Vec<u8>,
    pub description: Option<String>,
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
    /// Count of network scopes — avoids SQL query on every DNS query.
    scope_count: Arc<AtomicUsize>,
    /// In-memory cache of local RBL entries for fast lookup.
    local_rbl_cache: Arc<DashSet<String>>,
    /// In-memory cache of authoritative zones.
    authoritative_zones_cache: Arc<DashSet<String>>,
    /// In-memory cache of managed zones (derived from dns_records names).
    managed_zones_cache: Arc<DashSet<String>>,
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
            scope_count: Arc::new(AtomicUsize::new(0)),
            local_rbl_cache: Arc::new(DashSet::new()),
            authoritative_zones_cache: Arc::new(DashSet::new()),
            managed_zones_cache: Arc::new(DashSet::new()),
        };
        db.init_tables()?;
        db.load_scoped_records_into_cache()?;
        db.load_associations_into_cache()?;
        db.load_caches_at_boot()?;
        Ok(db)
    }

    /// Opens an in-memory database (useful for testing).
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("failed to open in-memory database")?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            association_cache: Arc::new(DashMap::new()),
            scoped_record_cache: Arc::new(DashMap::new()),
            scope_count: Arc::new(AtomicUsize::new(0)),
            local_rbl_cache: Arc::new(DashSet::new()),
            authoritative_zones_cache: Arc::new(DashSet::new()),
            managed_zones_cache: Arc::new(DashSet::new()),
        };
        db.init_tables()?;
        Ok(db)
    }

    /// Returns the raw database connection (for test use).
    pub fn conn(&self) -> &Arc<Mutex<Connection>> {
        &self.conn
    }

    /// Acquires the database lock.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|e| anyhow!("database lock poisoned: {}", e))
    }

    fn init_tables(&self) -> Result<()> {
        let conn = self.lock()?;
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
            CREATE INDEX IF NOT EXISTS idx_assoc_scope ON network_associations(scope_name);

            CREATE TABLE IF NOT EXISTS authoritative_zones (
                zone TEXT PRIMARY KEY NOT NULL
            );

            CREATE TABLE IF NOT EXISTS dns_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                record_type TEXT NOT NULL,
                value TEXT NOT NULL,
                ttl INTEGER NOT NULL,
                original_ttl INTEGER NOT NULL,
                cached_at INTEGER NOT NULL,
                source TEXT NOT NULL DEFAULT 'upstream'
            );
            CREATE INDEX IF NOT EXISTS idx_cache_name ON dns_cache(name);
            CREATE INDEX IF NOT EXISTS idx_cache_name_type ON dns_cache(name, record_type);
            CREATE INDEX IF NOT EXISTS idx_cache_expiry ON dns_cache(cached_at, ttl);

            CREATE TABLE IF NOT EXISTS local_rbl_entries (
                name TEXT PRIMARY KEY NOT NULL,
                reason TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS query_latency_stats (
                server TEXT PRIMARY KEY NOT NULL,
                avg_latency_ms REAL NOT NULL DEFAULT 0.0,
                query_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS dnssec_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                zone TEXT NOT NULL,
                scope_name TEXT,
                algorithm TEXT NOT NULL,
                key_type TEXT NOT NULL,
                private_key BLOB NOT NULL,
                public_key BLOB NOT NULL,
                key_tag INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                active BOOLEAN NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS acme_accounts (
                id INTEGER PRIMARY KEY,
                provider_url TEXT NOT NULL,
                account_key BLOB NOT NULL,
                account_url TEXT,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS acme_certificates (
                id INTEGER PRIMARY KEY,
                domain TEXT NOT NULL,
                cert_pem TEXT NOT NULL,
                key_pem TEXT NOT NULL,
                chain_pem TEXT,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS dane_root_cas (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                cert_pem TEXT NOT NULL,
                key_pem TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS dhcp_pools (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope_name TEXT NOT NULL,
                range_start TEXT NOT NULL,
                range_end TEXT NOT NULL,
                gateway TEXT,
                subnet_mask TEXT NOT NULL DEFAULT '255.255.255.0',
                dns_servers TEXT,
                FOREIGN KEY (scope_name) REFERENCES network_scopes(name) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_dhcp_pools_scope ON dhcp_pools(scope_name);

            CREATE TABLE IF NOT EXISTS dhcp_leases (
                mac TEXT PRIMARY KEY NOT NULL,
                ip TEXT NOT NULL UNIQUE,
                scope_name TEXT NOT NULL,
                hostname TEXT,
                lease_start INTEGER NOT NULL,
                lease_duration INTEGER NOT NULL,
                state TEXT NOT NULL DEFAULT 'active',
                FOREIGN KEY (scope_name) REFERENCES network_scopes(name) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_dhcp_leases_scope ON dhcp_leases(scope_name);
            CREATE INDEX IF NOT EXISTS idx_dhcp_leases_ip ON dhcp_leases(ip);

            CREATE TABLE IF NOT EXISTS scope_rbl_providers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope_name TEXT NOT NULL,
                zone TEXT NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT 1,
                FOREIGN KEY (scope_name) REFERENCES network_scopes(name) ON DELETE CASCADE,
                UNIQUE(scope_name, zone)
            );
            CREATE INDEX IF NOT EXISTS idx_scope_rbl_scope ON scope_rbl_providers(scope_name);

            CREATE TABLE IF NOT EXISTS dhcp_cert_options (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope_name TEXT NOT NULL,
                option_code INTEGER NOT NULL,
                cert_data BLOB NOT NULL,
                description TEXT,
                FOREIGN KEY (scope_name) REFERENCES network_scopes(name) ON DELETE CASCADE,
                UNIQUE(scope_name, option_code)
            );",
        )
        .context("failed to create tables")?;
        Ok(())
    }

    /// Loads all scoped DNS records from the database into the in-memory cache.
    /// Called at boot time.
    fn load_scoped_records_into_cache(&self) -> Result<()> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT scope_name, name, record_type, value, ttl, priority FROM scoped_dns_records",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                DnsRecord {
                    id: None,
                    name: row.get(1)?,
                    record_type: RecordKind::parse(&row.get::<_, String>(2)?)
                        .unwrap_or(RecordKind::A),
                    value: row.get(3)?,
                    ttl: row.get(4)?,
                    priority: row.get(5)?,
                },
            ))
        })?;

        for row in rows {
            let (scope_name, record) = row?;
            let cache_key =
                scoped_record_cache_key(&scope_name, &record.name, Some(record.record_type));
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
        let conn = self.lock()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs() as i64;

        let mut stmt = conn.prepare_cached(
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

    /// Loads scope_count, local_rbl_cache, authoritative_zones_cache, and
    /// managed_zones_cache from the database at boot time.
    fn load_caches_at_boot(&self) -> Result<()> {
        let conn = self.lock()?;

        // Scope count
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM network_scopes", [], |row| row.get(0))?;
        self.scope_count.store(count as usize, Ordering::Relaxed);

        // Local RBL entries
        let mut stmt = conn.prepare_cached("SELECT name FROM local_rbl_entries")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            self.local_rbl_cache.insert(row?);
        }

        // Authoritative zones
        let mut stmt = conn.prepare_cached("SELECT zone FROM authoritative_zones")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            self.authoritative_zones_cache.insert(row?);
        }

        // Managed zones (derived from dns_records names)
        let mut stmt = conn.prepare_cached("SELECT DISTINCT name FROM dns_records")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            let name = row?;
            if let Some(zone) = extract_zone_from_name(&name) {
                self.managed_zones_cache.insert(zone);
            }
        }

        Ok(())
    }

    /// Returns whether any network scopes are defined.
    pub fn has_scopes(&self) -> bool {
        self.scope_count.load(Ordering::Relaxed) > 0
    }

    /// Adds a DNS record to the database. Returns the row ID.
    pub fn add_record(&self, record: &DnsRecord) -> Result<i64> {
        let conn = self.lock()?;
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
        let id = conn.last_insert_rowid();
        // Update managed zones cache
        let normalized = normalize_name(&record.name);
        if let Some(zone) = extract_zone_from_name(&normalized) {
            self.managed_zones_cache.insert(zone);
        }
        Ok(id)
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
        let conn = self.lock()?;
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
        let conn = self.lock()?;
        let normalized = normalize_name(name);

        let records = Self::lookup_exact(&conn, &normalized, record_type)?;

        // RFC 4592: If exact match fails, try wildcard (replace first label with *)
        if records.is_empty()
            && let Some(wildcard_name) = make_wildcard_name(&normalized)
        {
            let wildcard_records = Self::lookup_exact(&conn, &wildcard_name, record_type)?;
            if !wildcard_records.is_empty() {
                // Return wildcard results with the original qname substituted
                return Ok(wildcard_records
                    .into_iter()
                    .map(|mut r| {
                        r.name = normalized.clone();
                        r
                    })
                    .collect());
            }
        }

        Ok(records)
    }

    fn lookup_exact(
        conn: &Connection,
        normalized: &str,
        record_type: Option<RecordKind>,
    ) -> Result<Vec<DnsRecord>> {
        let mut records = Vec::new();

        if let Some(rt) = record_type {
            let mut stmt = conn.prepare_cached(
                "SELECT id, name, record_type, value, ttl, priority FROM dns_records WHERE name = ?1 AND record_type = ?2",
            )?;
            let rows = stmt.query_map(params![normalized, rt.as_str()], |row| {
                Ok(DnsRecord {
                    id: Some(row.get(0)?),
                    name: row.get(1)?,
                    record_type: RecordKind::parse(&row.get::<_, String>(2)?)
                        .unwrap_or(RecordKind::A),
                    value: row.get(3)?,
                    ttl: row.get(4)?,
                    priority: row.get(5)?,
                })
            })?;
            for row in rows {
                records.push(row?);
            }
        } else {
            let mut stmt = conn.prepare_cached(
                "SELECT id, name, record_type, value, ttl, priority FROM dns_records WHERE name = ?1",
            )?;
            let rows = stmt.query_map(params![normalized], |row| {
                Ok(DnsRecord {
                    id: Some(row.get(0)?),
                    name: row.get(1)?,
                    record_type: RecordKind::parse(&row.get::<_, String>(2)?)
                        .unwrap_or(RecordKind::A),
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
        let conn = self.lock()?;
        let mut records = Vec::new();

        let (sql, filter_params) = build_list_query(name_filter, record_type);
        let mut stmt = conn.prepare_cached(&sql)?;

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
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached("SELECT DISTINCT name FROM dns_records")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut zones = std::collections::HashSet::new();
        for row in rows {
            let name = row?;
            // Extract the TLD or zone from the FQDN
            let parts: Vec<&str> = name.trim_end_matches('.').split('.').collect();
            if parts.len() >= 2 {
                // Register the domain (last two parts) as a managed zone
                let zone = format!("{}.", parts[parts.len() - 2..].join("."));
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
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO network_scopes (name, home_domain) VALUES (?1, ?2)",
            params![scope.name, normalize_name(&scope.home_domain)],
        )
        .context("failed to create network scope")?;
        self.scope_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Deletes a network scope and all associated records and associations.
    /// Returns true if a scope was deleted, false if it didn't exist.
    pub fn delete_network_scope(&self, name: &str) -> Result<bool> {
        let conn = self.lock()?;
        // Delete associated records first (due to foreign keys)
        conn.execute(
            "DELETE FROM scoped_dns_records WHERE scope_name = ?1",
            params![name],
        )?;
        conn.execute(
            "DELETE FROM network_associations WHERE scope_name = ?1",
            params![name],
        )?;
        let count = conn.execute("DELETE FROM network_scopes WHERE name = ?1", params![name])?;

        // Clear caches for this scope
        self.scoped_record_cache
            .retain(|key, _| !key.starts_with(&format!("{}:", name)));
        self.association_cache
            .retain(|_, entry| entry.scope_name != name);

        if count > 0 {
            self.scope_count.fetch_sub(1, Ordering::Relaxed);
        }
        Ok(count > 0)
    }

    /// Lists all network scopes.
    pub fn list_network_scopes(&self) -> Result<Vec<NetworkScope>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached("SELECT name, home_domain FROM network_scopes")?;
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
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare_cached("SELECT name, home_domain FROM network_scopes WHERE name = ?1")?;
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
        let conn = self.lock()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
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
        let conn = self.lock()?;
        let count = conn.execute(
            "DELETE FROM network_associations WHERE ip_address = ?1",
            params![ip_address],
        )?;

        // Remove from cache
        self.association_cache.remove(ip_address);

        Ok(count > 0)
    }

    /// Lists all network associations, optionally filtered by scope name.
    pub fn list_network_associations(
        &self,
        scope_name: Option<&str>,
    ) -> Result<Vec<NetworkAssociation>> {
        let conn = self.lock()?;
        let mut assocs = Vec::new();

        if let Some(scope) = scope_name {
            let mut stmt = conn.prepare_cached(
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
            let mut stmt = conn.prepare_cached(
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
        let conn = self.lock()?;
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
        let conn = self.lock()?;
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
        self.scoped_record_cache
            .retain(|key, _| !key.starts_with(&format!("{}:{}", scope_name, normalized)));

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

        let records = self.lookup_scoped_exact(scope_name, &normalized, record_type);

        // RFC 4592: If exact match fails, try wildcard
        if records.is_empty()
            && let Some(wildcard_name) = make_wildcard_name(&normalized)
        {
            let wildcard_records =
                self.lookup_scoped_exact(scope_name, &wildcard_name, record_type);
            if !wildcard_records.is_empty() {
                return wildcard_records
                    .into_iter()
                    .map(|mut r| {
                        r.name = normalized.clone();
                        r
                    })
                    .collect();
            }
        }

        records
    }

    fn lookup_scoped_exact(
        &self,
        scope_name: &str,
        normalized: &str,
        record_type: Option<RecordKind>,
    ) -> Vec<DnsRecord> {
        if let Some(rt) = record_type {
            let cache_key = scoped_record_cache_key(scope_name, normalized, Some(rt));
            if let Some(entry) = self.scoped_record_cache.get(&cache_key) {
                return entry.records.clone();
            }
        } else {
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
        let conn = self.lock()?;
        let mut records = Vec::new();

        if name_filter.is_empty() && record_type.is_none() {
            let mut stmt = conn.prepare_cached(
                "SELECT id, name, record_type, value, ttl, priority FROM scoped_dns_records WHERE scope_name = ?1",
            )?;
            let rows = stmt.query_map(params![scope_name], row_mapper)?;
            for row in rows {
                records.push(row?);
            }
        } else if let (true, Some(rt)) = (name_filter.is_empty(), record_type) {
            let mut stmt = conn.prepare_cached(
                "SELECT id, name, record_type, value, ttl, priority FROM scoped_dns_records WHERE scope_name = ?1 AND record_type = ?2",
            )?;
            let rows = stmt.query_map(params![scope_name, rt.as_str()], row_mapper)?;
            for row in rows {
                records.push(row?);
            }
        } else if record_type.is_none() {
            if let Some(suffix) = name_filter.strip_prefix("*.") {
                let like = format!("%{}", normalize_name(suffix));
                let mut stmt = conn.prepare_cached(
                    "SELECT id, name, record_type, value, ttl, priority FROM scoped_dns_records WHERE scope_name = ?1 AND name LIKE ?2",
                )?;
                let rows = stmt.query_map(params![scope_name, like], row_mapper)?;
                for row in rows {
                    records.push(row?);
                }
            } else {
                let normalized = normalize_name(name_filter);
                let mut stmt = conn.prepare_cached(
                    "SELECT id, name, record_type, value, ttl, priority FROM scoped_dns_records WHERE scope_name = ?1 AND name = ?2",
                )?;
                let rows = stmt.query_map(params![scope_name, normalized], row_mapper)?;
                for row in rows {
                    records.push(row?);
                }
            }
        } else if let Some(rt) = record_type {
            if let Some(suffix) = name_filter.strip_prefix("*.") {
                let like = format!("%{}", normalize_name(suffix));
                let mut stmt = conn.prepare_cached(
                    "SELECT id, name, record_type, value, ttl, priority FROM scoped_dns_records WHERE scope_name = ?1 AND name LIKE ?2 AND record_type = ?3",
                )?;
                let rows = stmt.query_map(params![scope_name, like, rt.as_str()], row_mapper)?;
                for row in rows {
                    records.push(row?);
                }
            } else {
                let normalized = normalize_name(name_filter);
                let mut stmt = conn.prepare_cached(
                    "SELECT id, name, record_type, value, ttl, priority FROM scoped_dns_records WHERE scope_name = ?1 AND name = ?2 AND record_type = ?3",
                )?;
                let rows =
                    stmt.query_map(params![scope_name, normalized, rt.as_str()], row_mapper)?;
                for row in rows {
                    records.push(row?);
                }
            }
        }

        Ok(records)
    }

    /// Returns the managed zones for a specific scope (from scoped records).
    pub fn get_scoped_managed_zones(&self, scope_name: &str) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached("SELECT DISTINCT name FROM scoped_dns_records WHERE scope_name = ?1")?;
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
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare_cached("SELECT home_domain FROM network_scopes WHERE name = ?1")?;
        let mut rows = stmt.query_map(params![scope_name], |row| row.get::<_, String>(0))?;
        match rows.next() {
            Some(row) => Ok(vec![row?]),
            None => Ok(Vec::new()),
        }
    }

    // ================================================================
    // Authoritative Zone Management
    // ================================================================

    pub fn add_authoritative_zone(&self, zone: &str) -> Result<()> {
        let conn = self.lock()?;
        let normalized = normalize_name(zone);
        conn.execute(
            "INSERT OR IGNORE INTO authoritative_zones (zone) VALUES (?1)",
            params![normalized],
        )
        .context("failed to add authoritative zone")?;
        self.authoritative_zones_cache.insert(normalized);
        Ok(())
    }

    pub fn remove_authoritative_zone(&self, zone: &str) -> Result<bool> {
        let conn = self.lock()?;
        let normalized = normalize_name(zone);
        let count = conn
            .execute(
                "DELETE FROM authoritative_zones WHERE zone = ?1",
                params![normalized],
            )
            .context("failed to remove authoritative zone")?;
        if count > 0 {
            self.authoritative_zones_cache.remove(&normalized);
        }
        Ok(count > 0)
    }

    pub fn list_authoritative_zones(&self) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached("SELECT zone FROM authoritative_zones")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut zones = Vec::new();
        for row in rows {
            zones.push(row?);
        }
        Ok(zones)
    }

    /// Returns authoritative zones from the in-memory cache (no SQL).
    pub fn list_authoritative_zones_cached(&self) -> Vec<String> {
        self.authoritative_zones_cache
            .iter()
            .map(|r| r.key().clone())
            .collect()
    }

    /// Returns managed zones from the in-memory cache (no SQL).
    pub fn get_managed_zones_cached(&self) -> Vec<String> {
        self.managed_zones_cache
            .iter()
            .map(|r| r.key().clone())
            .collect()
    }

    pub fn is_authoritative_zone(&self, name: &str) -> bool {
        let normalized = normalize_name(name);
        // Check explicit authoritative zones (from cache)
        for zone in self.authoritative_zones_cache.iter() {
            if normalized.ends_with(zone.key().as_str()) || normalized == *zone.key() {
                return true;
            }
        }
        // Also check managed zones (from cache)
        for zone in self.managed_zones_cache.iter() {
            if normalized.ends_with(zone.key().as_str()) || normalized == *zone.key() {
                return true;
            }
        }
        false
    }

    // ================================================================
    // Local RBL Management
    // ================================================================

    pub fn add_local_rbl_entry(&self, name: &str, reason: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO local_rbl_entries (name, reason) VALUES (?1, ?2)",
            params![name, reason],
        )
        .context("failed to add local RBL entry")?;
        self.local_rbl_cache.insert(name.to_string());
        Ok(())
    }

    pub fn remove_local_rbl_entry(&self, name: &str) -> Result<bool> {
        let conn = self.lock()?;
        let count = conn
            .execute(
                "DELETE FROM local_rbl_entries WHERE name = ?1",
                params![name],
            )
            .context("failed to remove local RBL entry")?;
        if count > 0 {
            self.local_rbl_cache.remove(name);
        }
        Ok(count > 0)
    }

    pub fn list_local_rbl_entries(&self) -> Result<Vec<(String, String)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached("SELECT name, reason FROM local_rbl_entries")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    pub fn lookup_local_rbl(&self, name: &str) -> bool {
        self.local_rbl_cache.contains(name)
    }

    // ================================================================
    // Latency Stats
    // ================================================================

    pub fn update_latency_stat(
        &self,
        server: &str,
        avg_latency_ms: f64,
        query_count: u64,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO query_latency_stats (server, avg_latency_ms, query_count) VALUES (?1, ?2, ?3)",
            params![server, avg_latency_ms, query_count as i64],
        )
        .context("failed to update latency stat")?;
        Ok(())
    }

    pub fn get_latency_stats(&self) -> Result<Vec<(String, f64, u64)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT server, avg_latency_ms, query_count FROM query_latency_stats",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, f64>(1)?,
                row.get::<_, i64>(2)? as u64,
            ))
        })?;
        let mut stats = Vec::new();
        for row in rows {
            stats.push(row?);
        }
        Ok(stats)
    }

    // ================================================================
    // DNS Cache (database-backed)
    // ================================================================

    pub fn cache_insert(
        &self,
        name: &str,
        record_type: &str,
        value: &str,
        ttl: u32,
        original_ttl: u32,
        source: &str,
    ) -> Result<()> {
        let conn = self.lock()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs() as i64;
        conn.execute(
            "INSERT INTO dns_cache (name, record_type, value, ttl, original_ttl, cached_at, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![name, record_type, value, ttl as i64, original_ttl as i64, now, source],
        )
        .context("failed to insert cache entry")?;
        Ok(())
    }

    pub fn cache_lookup(&self, name: &str, record_type: Option<&str>) -> Result<Vec<DnsRecord>> {
        let conn = self.lock()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs() as i64;
        let mut records = Vec::new();

        if let Some(rt) = record_type {
            let mut stmt = conn.prepare_cached(
                "SELECT name, record_type, value, ttl, cached_at FROM dns_cache WHERE name = ?1 AND record_type = ?2",
            )?;
            let rows = stmt.query_map(params![name, rt], |row| {
                let ttl: i64 = row.get(3)?;
                let cached_at: i64 = row.get(4)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    ttl,
                    cached_at,
                ))
            })?;
            for row in rows {
                let (n, rt_str, val, ttl, cached_at) = row?;
                let elapsed = now - cached_at;
                if elapsed < ttl {
                    let remaining_ttl = (ttl - elapsed) as u32;
                    records.push(DnsRecord {
                        id: None,
                        name: n,
                        record_type: RecordKind::parse(&rt_str).unwrap_or(RecordKind::A),
                        value: val,
                        ttl: remaining_ttl,
                        priority: 0,
                    });
                }
            }
        } else {
            let mut stmt = conn.prepare_cached(
                "SELECT name, record_type, value, ttl, cached_at FROM dns_cache WHERE name = ?1",
            )?;
            let rows = stmt.query_map(params![name], |row| {
                let ttl: i64 = row.get(3)?;
                let cached_at: i64 = row.get(4)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    ttl,
                    cached_at,
                ))
            })?;
            for row in rows {
                let (n, rt_str, val, ttl, cached_at) = row?;
                let elapsed = now - cached_at;
                if elapsed < ttl {
                    let remaining_ttl = (ttl - elapsed) as u32;
                    records.push(DnsRecord {
                        id: None,
                        name: n,
                        record_type: RecordKind::parse(&rt_str).unwrap_or(RecordKind::A),
                        value: val,
                        ttl: remaining_ttl,
                        priority: 0,
                    });
                }
            }
        }

        Ok(records)
    }

    pub fn cache_flush(&self) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM dns_cache", [])
            .context("failed to flush DNS cache")?;
        Ok(())
    }

    pub fn cache_count(&self) -> Result<u64> {
        let conn = self.lock()?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM dns_cache", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    // ================================================================
    // DNSSEC Key Management
    // ================================================================

    /// Stores a DNSSEC key in the database.
    pub fn store_dnssec_key(&self, params: &DnssecKeyParams<'_>) -> Result<i64> {
        let zone = params.zone;
        let scope = params.scope;
        let algorithm = params.algorithm;
        let key_type = params.key_type;
        let private_key = params.private_key;
        let public_key = params.public_key;
        let key_tag = params.key_tag;
        let conn = self.lock()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs() as i64;
        let scope_val = if scope.is_empty() {
            None
        } else {
            Some(scope.to_string())
        };
        conn.execute(
            "INSERT INTO dnssec_keys (zone, scope_name, algorithm, key_type, private_key, public_key, key_tag, created_at, active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
            params![
                normalize_name(zone),
                scope_val,
                algorithm,
                key_type,
                private_key,
                public_key,
                key_tag as i64,
                now,
            ],
        )
        .context("failed to store DNSSEC key")?;
        Ok(conn.last_insert_rowid())
    }

    /// Lists all DNSSEC keys for a zone.
    pub fn list_dnssec_keys(&self, zone: &str) -> Result<Vec<DnssecKeyRow>> {
        let conn = self.lock()?;
        let normalized = normalize_name(zone);
        let mut stmt = conn.prepare_cached(
            "SELECT id, zone, scope_name, algorithm, key_type, private_key, public_key, key_tag, created_at, active
             FROM dnssec_keys WHERE zone = ?1",
        )?;
        let rows = stmt.query_map(params![normalized], |row| {
            Ok(DnssecKeyRow {
                id: row.get(0)?,
                zone: row.get(1)?,
                scope_name: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                algorithm: row.get(3)?,
                key_type: row.get(4)?,
                private_key: row.get(5)?,
                public_key: row.get(6)?,
                key_tag: row.get::<_, i64>(7)? as u16,
                created_at: row.get(8)?,
                active: row.get(9)?,
            })
        })?;
        let mut keys = Vec::new();
        for row in rows {
            keys.push(row?);
        }
        Ok(keys)
    }

    /// Deletes a DNSSEC key by ID. Returns true if a key was deleted.
    pub fn delete_dnssec_key(&self, id: i64) -> Result<bool> {
        let conn = self.lock()?;
        let count = conn.execute("DELETE FROM dnssec_keys WHERE id = ?1", params![id])?;
        Ok(count > 0)
    }

    /// Gets active keys for a zone filtered by key type (KSK or ZSK).
    pub fn get_active_keys(&self, zone: &str, key_type: &str) -> Result<Vec<DnssecKeyRow>> {
        let conn = self.lock()?;
        let normalized = normalize_name(zone);
        let mut stmt = conn.prepare_cached(
            "SELECT id, zone, scope_name, algorithm, key_type, private_key, public_key, key_tag, created_at, active
             FROM dnssec_keys WHERE zone = ?1 AND key_type = ?2 AND active = 1",
        )?;
        let rows = stmt.query_map(params![normalized, key_type], |row| {
            Ok(DnssecKeyRow {
                id: row.get(0)?,
                zone: row.get(1)?,
                scope_name: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                algorithm: row.get(3)?,
                key_type: row.get(4)?,
                private_key: row.get(5)?,
                public_key: row.get(6)?,
                key_tag: row.get::<_, i64>(7)? as u16,
                created_at: row.get(8)?,
                active: row.get(9)?,
            })
        })?;
        let mut keys = Vec::new();
        for row in rows {
            keys.push(row?);
        }
        Ok(keys)
    }

    // ================================================================
    // DANE Root CA Management
    // ================================================================

    /// Stores a DANE root CA certificate.
    pub fn store_dane_root_ca(&self, name: &str, cert_pem: &str, key_pem: &str) -> Result<i64> {
        let conn = self.lock()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs() as i64;
        conn.execute(
            "INSERT INTO dane_root_cas (name, cert_pem, key_pem, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![name, cert_pem, key_pem, now],
        )
        .context("failed to store DANE root CA")?;
        Ok(conn.last_insert_rowid())
    }

    /// Gets a DANE root CA by name.
    pub fn get_dane_root_ca(&self, name: &str) -> Result<Option<(i64, String, String, String)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, name, cert_pem, key_pem FROM dane_root_cas WHERE name = ?1",
        )?;
        let mut rows = stmt.query_map(params![name], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    // ================================================================
    // ACME Certificate Management
    // ================================================================

    /// Stores an ACME certificate.
    pub fn store_acme_certificate(
        &self,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
        chain_pem: &str,
        expires_at: i64,
    ) -> Result<i64> {
        let conn = self.lock()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs() as i64;
        conn.execute(
            "INSERT INTO acme_certificates (domain, cert_pem, key_pem, chain_pem, issued_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![domain, cert_pem, key_pem, chain_pem, now, expires_at],
        )
        .context("failed to store ACME certificate")?;
        Ok(conn.last_insert_rowid())
    }

    /// Gets the latest ACME certificate for a domain.
    pub fn get_acme_certificate(&self, domain: &str) -> Result<Option<AcmeCertRow>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, domain, cert_pem, key_pem, chain_pem, issued_at, expires_at
             FROM acme_certificates WHERE domain = ?1 ORDER BY issued_at DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![domain], |row| {
            Ok(AcmeCertRow {
                id: row.get(0)?,
                domain: row.get(1)?,
                cert_pem: row.get(2)?,
                key_pem: row.get(3)?,
                chain_pem: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                issued_at: row.get(5)?,
                expires_at: row.get(6)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    // ================================================================
    // DHCP Pool Management
    // ================================================================

    /// Adds a DHCP address pool for a network scope. Returns the pool ID.
    pub fn add_dhcp_pool(&self, pool: &DhcpPool) -> Result<i64> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO dhcp_pools (scope_name, range_start, range_end, gateway, subnet_mask, dns_servers)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                pool.scope_name,
                pool.range_start,
                pool.range_end,
                pool.gateway,
                pool.subnet_mask,
                pool.dns_servers,
            ],
        )
        .context("failed to insert DHCP pool")?;
        Ok(conn.last_insert_rowid())
    }

    /// Removes a DHCP pool by ID. Returns whether anything was deleted.
    pub fn remove_dhcp_pool(&self, id: i64) -> Result<bool> {
        let conn = self.lock()?;
        let count = conn.execute("DELETE FROM dhcp_pools WHERE id = ?1", params![id])?;
        Ok(count > 0)
    }

    /// Lists DHCP pools, optionally filtered by scope name.
    pub fn list_dhcp_pools(&self, scope_name: Option<&str>) -> Result<Vec<DhcpPool>> {
        let conn = self.lock()?;
        let mut pools = Vec::new();

        if let Some(scope) = scope_name {
            let mut stmt = conn.prepare_cached(
                "SELECT id, scope_name, range_start, range_end, gateway, subnet_mask, dns_servers
                 FROM dhcp_pools WHERE scope_name = ?1",
            )?;
            let rows = stmt.query_map(params![scope], |row| {
                Ok(DhcpPool {
                    id: row.get(0)?,
                    scope_name: row.get(1)?,
                    range_start: row.get(2)?,
                    range_end: row.get(3)?,
                    gateway: row.get(4)?,
                    subnet_mask: row.get(5)?,
                    dns_servers: row.get(6)?,
                })
            })?;
            for row in rows {
                pools.push(row?);
            }
        } else {
            let mut stmt = conn.prepare_cached(
                "SELECT id, scope_name, range_start, range_end, gateway, subnet_mask, dns_servers
                 FROM dhcp_pools",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(DhcpPool {
                    id: row.get(0)?,
                    scope_name: row.get(1)?,
                    range_start: row.get(2)?,
                    range_end: row.get(3)?,
                    gateway: row.get(4)?,
                    subnet_mask: row.get(5)?,
                    dns_servers: row.get(6)?,
                })
            })?;
            for row in rows {
                pools.push(row?);
            }
        }

        Ok(pools)
    }

    // ================================================================
    // DHCP Lease Management
    // ================================================================

    /// Creates or replaces a DHCP lease.
    pub fn create_lease(&self, lease: &DhcpLease) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO dhcp_leases (mac, ip, scope_name, hostname, lease_start, lease_duration, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                lease.mac,
                lease.ip,
                lease.scope_name,
                lease.hostname,
                lease.lease_start,
                lease.lease_duration,
                lease.state,
            ],
        )
        .context("failed to create DHCP lease")?;
        Ok(())
    }

    /// Renews a lease by updating its lease_start and lease_duration.
    /// Returns whether a lease was found and updated.
    pub fn renew_lease(&self, mac: &str, lease_duration: i64) -> Result<bool> {
        let conn = self.lock()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs() as i64;
        let count = conn.execute(
            "UPDATE dhcp_leases SET lease_start = ?1, lease_duration = ?2 WHERE mac = ?3",
            params![now, lease_duration, mac],
        )?;
        Ok(count > 0)
    }

    /// Releases a lease by setting its state to 'released'. Returns the lease if found.
    pub fn release_lease(&self, mac: &str) -> Result<Option<DhcpLease>> {
        let conn = self.lock()?;
        let count = conn.execute(
            "UPDATE dhcp_leases SET state = 'released' WHERE mac = ?1",
            params![mac],
        )?;
        if count == 0 {
            return Ok(None);
        }
        let mut stmt = conn.prepare_cached(
            "SELECT mac, ip, scope_name, hostname, lease_start, lease_duration, state
             FROM dhcp_leases WHERE mac = ?1",
        )?;
        let mut rows = stmt.query_map(params![mac], dhcp_lease_row_mapper)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Gets a lease by MAC address.
    pub fn get_lease_by_mac(&self, mac: &str) -> Result<Option<DhcpLease>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT mac, ip, scope_name, hostname, lease_start, lease_duration, state
             FROM dhcp_leases WHERE mac = ?1",
        )?;
        let mut rows = stmt.query_map(params![mac], dhcp_lease_row_mapper)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Gets a lease by IP address.
    pub fn get_lease_by_ip(&self, ip: &str) -> Result<Option<DhcpLease>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT mac, ip, scope_name, hostname, lease_start, lease_duration, state
             FROM dhcp_leases WHERE ip = ?1",
        )?;
        let mut rows = stmt.query_map(params![ip], dhcp_lease_row_mapper)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Lists DHCP leases, optionally filtered by scope name.
    pub fn list_leases(&self, scope_name: Option<&str>) -> Result<Vec<DhcpLease>> {
        let conn = self.lock()?;
        let mut leases = Vec::new();

        if let Some(scope) = scope_name {
            let mut stmt = conn.prepare_cached(
                "SELECT mac, ip, scope_name, hostname, lease_start, lease_duration, state
                 FROM dhcp_leases WHERE scope_name = ?1",
            )?;
            let rows = stmt.query_map(params![scope], dhcp_lease_row_mapper)?;
            for row in rows {
                leases.push(row?);
            }
        } else {
            let mut stmt = conn.prepare_cached(
                "SELECT mac, ip, scope_name, hostname, lease_start, lease_duration, state
                 FROM dhcp_leases",
            )?;
            let rows = stmt.query_map([], dhcp_lease_row_mapper)?;
            for row in rows {
                leases.push(row?);
            }
        }

        Ok(leases)
    }

    /// Deletes a lease by MAC address. Returns whether anything was deleted.
    pub fn delete_lease(&self, mac: &str) -> Result<bool> {
        let conn = self.lock()?;
        let count = conn.execute("DELETE FROM dhcp_leases WHERE mac = ?1", params![mac])?;
        Ok(count > 0)
    }

    /// Allocates the next available IP in a scope's pools for the given MAC.
    ///
    /// If the MAC already has an active lease, returns the same IP (sticky binding).
    /// Otherwise iterates through the scope's pool ranges to find the first
    /// unoccupied address.
    pub fn allocate_ip(&self, scope_name: &str, mac: &str) -> Result<Option<String>> {
        let conn = self.lock()?;

        // Check for sticky binding: if MAC already has a lease, return same IP
        {
            let mut stmt = conn.prepare_cached("SELECT ip FROM dhcp_leases WHERE mac = ?1")?;
            let mut rows = stmt.query_map(params![mac], |row| row.get::<_, String>(0))?;
            if let Some(row) = rows.next() {
                return Ok(Some(row?));
            }
        }

        // Get all pools for the scope
        let pools: Vec<(String, String)> = {
            let mut stmt = conn.prepare_cached(
                "SELECT range_start, range_end FROM dhcp_pools WHERE scope_name = ?1",
            )?;
            let rows = stmt.query_map(params![scope_name], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut p = Vec::new();
            for row in rows {
                p.push(row?);
            }
            p
        };

        // Get all currently leased IPs in this scope
        let leased_ips: std::collections::HashSet<String> = {
            let mut stmt =
                conn.prepare_cached("SELECT ip FROM dhcp_leases WHERE scope_name = ?1")?;
            let rows = stmt.query_map(params![scope_name], |row| row.get::<_, String>(0))?;
            let mut set = std::collections::HashSet::new();
            for row in rows {
                set.insert(row?);
            }
            set
        };

        // Iterate through pools to find first available IP
        for (start_str, end_str) in &pools {
            let start: std::net::Ipv4Addr =
                start_str.parse().context("invalid pool range_start IP")?;
            let end: std::net::Ipv4Addr = end_str.parse().context("invalid pool range_end IP")?;

            let mut current = start;
            loop {
                let ip_str = current.to_string();
                if !leased_ips.contains(&ip_str) {
                    return Ok(Some(ip_str));
                }
                if current == end {
                    break;
                }
                let n: u32 = current.into();
                match n.checked_add(1) {
                    Some(next) => current = std::net::Ipv4Addr::from(next),
                    None => break,
                }
            }
        }

        Ok(None)
    }

    /// Sweeps expired leases.
    ///
    /// 1. Finds active leases whose (lease_start + lease_duration) < now and sets
    ///    their state to 'expired'.
    /// 2. Finds leases in 'expired' or 'released' state whose
    ///    (lease_start + lease_duration + reclaim_timeout) < now, deletes them,
    ///    and returns the deleted leases.
    pub fn sweep_expired_leases(&self, reclaim_timeout_secs: u64) -> Result<Vec<DhcpLease>> {
        let conn = self.lock()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs() as i64;

        // Mark active leases as expired
        conn.execute(
            "UPDATE dhcp_leases SET state = 'expired'
             WHERE state = 'active' AND (lease_start + lease_duration) < ?1",
            params![now],
        )?;

        // Collect reclaimable leases
        let reclaim_timeout = reclaim_timeout_secs as i64;
        let mut stmt = conn.prepare_cached(
            "SELECT mac, ip, scope_name, hostname, lease_start, lease_duration, state
             FROM dhcp_leases
             WHERE state IN ('expired', 'released')
               AND (lease_start + lease_duration + ?1) < ?2",
        )?;
        let rows = stmt.query_map(params![reclaim_timeout, now], dhcp_lease_row_mapper)?;
        let mut reclaimed = Vec::new();
        for row in rows {
            reclaimed.push(row?);
        }

        // Delete the reclaimable leases
        conn.execute(
            "DELETE FROM dhcp_leases
             WHERE state IN ('expired', 'released')
               AND (lease_start + lease_duration + ?1) < ?2",
            params![reclaim_timeout, now],
        )?;

        Ok(reclaimed)
    }

    // ================================================================
    // Scope RBL Provider Management
    // ================================================================

    /// Adds or replaces a per-scope RBL provider.
    pub fn add_scope_rbl_provider(&self, provider: &ScopeRblProvider) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO scope_rbl_providers (scope_name, zone, enabled)
             VALUES (?1, ?2, ?3)",
            params![provider.scope_name, provider.zone, provider.enabled],
        )
        .context("failed to add scope RBL provider")?;
        Ok(())
    }

    /// Removes a per-scope RBL provider. Returns whether anything was deleted.
    pub fn remove_scope_rbl_provider(&self, scope_name: &str, zone: &str) -> Result<bool> {
        let conn = self.lock()?;
        let count = conn.execute(
            "DELETE FROM scope_rbl_providers WHERE scope_name = ?1 AND zone = ?2",
            params![scope_name, zone],
        )?;
        Ok(count > 0)
    }

    /// Lists per-scope RBL providers for a given scope.
    pub fn list_scope_rbl_providers(&self, scope_name: &str) -> Result<Vec<ScopeRblProvider>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT scope_name, zone, enabled FROM scope_rbl_providers WHERE scope_name = ?1",
        )?;
        let rows = stmt.query_map(params![scope_name], |row| {
            Ok(ScopeRblProvider {
                scope_name: row.get(0)?,
                zone: row.get(1)?,
                enabled: row.get(2)?,
            })
        })?;
        let mut providers = Vec::new();
        for row in rows {
            providers.push(row?);
        }
        Ok(providers)
    }

    // ================================================================
    // DHCP Certificate Option Management
    // ================================================================

    /// Sets (inserts or replaces) a DHCP certificate option for a scope.
    pub fn set_dhcp_cert_option(&self, opt: &DhcpCertOption) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO dhcp_cert_options (scope_name, option_code, cert_data, description)
             VALUES (?1, ?2, ?3, ?4)",
            params![opt.scope_name, opt.option_code, opt.cert_data, opt.description],
        )
        .context("failed to set DHCP cert option")?;
        Ok(())
    }

    /// Removes a DHCP certificate option. Returns whether anything was deleted.
    pub fn remove_dhcp_cert_option(&self, scope_name: &str, option_code: u32) -> Result<bool> {
        let conn = self.lock()?;
        let count = conn.execute(
            "DELETE FROM dhcp_cert_options WHERE scope_name = ?1 AND option_code = ?2",
            params![scope_name, option_code],
        )?;
        Ok(count > 0)
    }

    /// Lists DHCP certificate options for a scope.
    pub fn list_dhcp_cert_options(&self, scope_name: &str) -> Result<Vec<DhcpCertOption>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT scope_name, option_code, cert_data, description
             FROM dhcp_cert_options WHERE scope_name = ?1",
        )?;
        let rows = stmt.query_map(params![scope_name], |row| {
            Ok(DhcpCertOption {
                scope_name: row.get(0)?,
                option_code: row.get(1)?,
                cert_data: row.get(2)?,
                description: row.get(3)?,
            })
        })?;
        let mut options = Vec::new();
        for row in rows {
            options.push(row?);
        }
        Ok(options)
    }
}

fn row_mapper(row: &rusqlite::Row) -> rusqlite::Result<DnsRecord> {
    Ok(DnsRecord {
        id: Some(row.get(0)?),
        name: row.get(1)?,
        record_type: RecordKind::parse(&row.get::<_, String>(2)?).unwrap_or(RecordKind::A),
        value: row.get(3)?,
        ttl: row.get(4)?,
        priority: row.get(5)?,
    })
}

fn dhcp_lease_row_mapper(row: &rusqlite::Row) -> rusqlite::Result<DhcpLease> {
    Ok(DhcpLease {
        mac: row.get(0)?,
        ip: row.get(1)?,
        scope_name: row.get(2)?,
        hostname: row.get(3)?,
        lease_start: row.get(4)?,
        lease_duration: row.get(5)?,
        state: row.get(6)?,
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
fn scoped_record_cache_key(
    scope_name: &str,
    normalized_name: &str,
    record_type: Option<RecordKind>,
) -> String {
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

/// Constructs a wildcard name by replacing the first label with "*".
/// E.g. "foo.example.com." -> "*.example.com."
/// Returns None if there's no parent domain (single-label or empty).
pub fn make_wildcard_name(normalized: &str) -> Option<String> {
    let trimmed = normalized.trim_end_matches('.');
    trimmed
        .find('.')
        .map(|dot_pos| format!("*.{}.", &trimmed[dot_pos + 1..]))
}

/// Extracts the zone (last two labels + trailing dot) from a DNS name.
/// E.g. "sub.example.com." -> Some("example.com.")
///      "tld." -> Some("tld.")
fn extract_zone_from_name(name: &str) -> Option<String> {
    let parts: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    if parts.len() >= 2 {
        Some(format!("{}.", parts[parts.len() - 2..].join(".")))
    } else if parts.len() == 1 && !parts[0].is_empty() {
        Some(format!("{}.", parts[0]))
    } else {
        None
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
            assert_eq!(RecordKind::parse(s), Some(*kind));
            let i = kind.to_proto_i32();
            assert_eq!(RecordKind::from_proto_i32(i), Some(*kind));
        }
    }

    #[test]
    fn test_record_kind_from_str_case_insensitive() {
        assert_eq!(RecordKind::parse("a"), Some(RecordKind::A));
        assert_eq!(RecordKind::parse("aaaa"), Some(RecordKind::AAAA));
        assert_eq!(RecordKind::parse("cname"), Some(RecordKind::CNAME));
    }

    #[test]
    fn test_record_kind_from_str_invalid() {
        assert_eq!(RecordKind::parse("INVALID"), None);
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
        db.add_scoped_record(
            "temp",
            &DnsRecord {
                id: None,
                name: "host.temp.home".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        // Add an association
        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.1".to_string(),
            scope_name: "temp".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

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
        })
        .unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "10.0.0.5".to_string(),
            scope_name: "net1".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

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
        })
        .unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "10.0.0.10".to_string(),
            scope_name: "net2".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

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
        })
        .unwrap();
        db.create_network_scope(&NetworkScope {
            name: "netB".to_string(),
            home_domain: "netB.home".to_string(),
        })
        .unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "10.1.0.1".to_string(),
            scope_name: "netA".to_string(),
            ttl_seconds: 300,
        })
        .unwrap();
        db.join_network(&NetworkAssociation {
            ip_address: "10.2.0.1".to_string(),
            scope_name: "netB".to_string(),
            ttl_seconds: 300,
        })
        .unwrap();

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
        })
        .unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "10.5.0.1".to_string(),
            scope_name: "update-net".to_string(),
            ttl_seconds: 100,
        })
        .unwrap();

        // Re-join with new TTL (refresh)
        db.join_network(&NetworkAssociation {
            ip_address: "10.5.0.1".to_string(),
            scope_name: "update-net".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

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
        })
        .unwrap();

        db.add_scoped_record(
            "scopeA",
            &DnsRecord {
                id: None,
                name: "host1.scopeA.home".to_string(),
                record_type: RecordKind::A,
                value: "10.10.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

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
        })
        .unwrap();
        db.create_network_scope(&NetworkScope {
            name: "scope2".to_string(),
            home_domain: "scope2.home".to_string(),
        })
        .unwrap();

        db.add_scoped_record(
            "scope1",
            &DnsRecord {
                id: None,
                name: "shared.internal".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        db.add_scoped_record(
            "scope2",
            &DnsRecord {
                id: None,
                name: "shared.internal".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.2".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

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
        })
        .unwrap();

        db.add_scoped_record(
            "rmscope",
            &DnsRecord {
                id: None,
                name: "remove-me.rmscope.home".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        let removed = db
            .remove_scoped_records("rmscope", "remove-me.rmscope.home", Some(RecordKind::A), "")
            .unwrap();
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
        })
        .unwrap();

        db.add_scoped_record(
            "listscope",
            &DnsRecord {
                id: None,
                name: "a.listscope.home".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();
        db.add_scoped_record(
            "listscope",
            &DnsRecord {
                id: None,
                name: "b.listscope.home".to_string(),
                record_type: RecordKind::AAAA,
                value: "::1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        let all = db.list_scoped_records("listscope", "", None).unwrap();
        assert_eq!(all.len(), 2);

        let a_only = db
            .list_scoped_records("listscope", "", Some(RecordKind::A))
            .unwrap();
        assert_eq!(a_only.len(), 1);
    }

    #[test]
    fn test_get_search_domains() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "search-net".to_string(),
            home_domain: "search.home".to_string(),
        })
        .unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "192.168.0.50".to_string(),
            scope_name: "search-net".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

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
        })
        .unwrap();

        db.add_scoped_record(
            "alltype",
            &DnsRecord {
                id: None,
                name: "multi.alltype.home".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();
        db.add_scoped_record(
            "alltype",
            &DnsRecord {
                id: None,
                name: "multi.alltype.home".to_string(),
                record_type: RecordKind::AAAA,
                value: "::1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        let all = db.lookup_scoped("alltype", "multi.alltype.home", None);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_association_ttl_expiration() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "expire-net".to_string(),
            home_domain: "expire.home".to_string(),
        })
        .unwrap();

        // Join with a very short TTL
        db.join_network(&NetworkAssociation {
            ip_address: "10.99.0.1".to_string(),
            scope_name: "expire-net".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        // Should be associated initially
        assert_eq!(
            db.get_scope_for_ip("10.99.0.1"),
            Some("expire-net".to_string())
        );

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
            })
            .unwrap();

            db.add_scoped_record(
                "persist-scope",
                &DnsRecord {
                    id: None,
                    name: "host1.persist.home".to_string(),
                    record_type: RecordKind::A,
                    value: "10.0.0.1".to_string(),
                    ttl: 300,
                    priority: 0,
                },
            )
            .unwrap();

            db.join_network(&NetworkAssociation {
                ip_address: "192.168.5.1".to_string(),
                scope_name: "persist-scope".to_string(),
                ttl_seconds: 86400,
            })
            .unwrap();
        }

        // Reopen and verify caches are populated from database
        {
            let db = Database::open(&db_path).unwrap();

            // Scoped records should be loaded into cache
            let records =
                db.lookup_scoped("persist-scope", "host1.persist.home", Some(RecordKind::A));
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
        })
        .unwrap();

        db.add_scoped_record(
            "zones",
            &DnsRecord {
                id: None,
                name: "host.zones.home".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();
        db.add_scoped_record(
            "zones",
            &DnsRecord {
                id: None,
                name: "host.other.net".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.2".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        let zones = db.get_scoped_managed_zones("zones").unwrap();
        assert_eq!(zones.len(), 2);
        assert!(zones.contains(&"zones.home.".to_string()));
        assert!(zones.contains(&"other.net.".to_string()));
    }

    // ================================================================
    // DHCP Pool Tests
    // ================================================================

    #[test]
    fn test_dhcp_pool_crud() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "pool-scope".to_string(),
            home_domain: "pool.home".to_string(),
        })
        .unwrap();

        let pool = DhcpPool {
            id: 0,
            scope_name: "pool-scope".to_string(),
            range_start: "10.0.0.10".to_string(),
            range_end: "10.0.0.20".to_string(),
            gateway: Some("10.0.0.1".to_string()),
            subnet_mask: "255.255.255.0".to_string(),
            dns_servers: Some("10.0.0.1".to_string()),
        };
        let id = db.add_dhcp_pool(&pool).unwrap();
        assert!(id > 0);

        // List all pools
        let pools = db.list_dhcp_pools(None).unwrap();
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].range_start, "10.0.0.10");
        assert_eq!(pools[0].range_end, "10.0.0.20");
        assert_eq!(pools[0].gateway, Some("10.0.0.1".to_string()));
        assert_eq!(pools[0].subnet_mask, "255.255.255.0");
        assert_eq!(pools[0].dns_servers, Some("10.0.0.1".to_string()));

        // List by scope
        let scoped = db.list_dhcp_pools(Some("pool-scope")).unwrap();
        assert_eq!(scoped.len(), 1);

        let empty = db.list_dhcp_pools(Some("nonexistent")).unwrap();
        assert!(empty.is_empty());

        // Remove
        let removed = db.remove_dhcp_pool(id).unwrap();
        assert!(removed);

        let removed_again = db.remove_dhcp_pool(id).unwrap();
        assert!(!removed_again);

        let pools = db.list_dhcp_pools(None).unwrap();
        assert!(pools.is_empty());
    }

    // ================================================================
    // DHCP Lease Tests
    // ================================================================

    #[test]
    fn test_dhcp_lease_lifecycle() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "lease-scope".to_string(),
            home_domain: "lease.home".to_string(),
        })
        .unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs() as i64;

        let lease = DhcpLease {
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            ip: "10.0.0.50".to_string(),
            scope_name: "lease-scope".to_string(),
            hostname: Some("myhost".to_string()),
            lease_start: now,
            lease_duration: 3600,
            state: "active".to_string(),
        };
        db.create_lease(&lease).unwrap();

        // Get by MAC
        let found = db.get_lease_by_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.ip, "10.0.0.50");
        assert_eq!(found.hostname, Some("myhost".to_string()));
        assert_eq!(found.state, "active");

        // Get by IP
        let by_ip = db.get_lease_by_ip("10.0.0.50").unwrap();
        assert!(by_ip.is_some());
        assert_eq!(by_ip.unwrap().mac, "aa:bb:cc:dd:ee:ff");

        // Renew
        let renewed = db.renew_lease("aa:bb:cc:dd:ee:ff", 7200).unwrap();
        assert!(renewed);
        let after_renew = db.get_lease_by_mac("aa:bb:cc:dd:ee:ff").unwrap().unwrap();
        assert_eq!(after_renew.lease_duration, 7200);

        // Renew nonexistent
        let no_renew = db.renew_lease("00:00:00:00:00:00", 100).unwrap();
        assert!(!no_renew);

        // Release
        let released = db.release_lease("aa:bb:cc:dd:ee:ff").unwrap();
        assert!(released.is_some());
        assert_eq!(released.unwrap().state, "released");

        // Release nonexistent
        let no_release = db.release_lease("00:00:00:00:00:00").unwrap();
        assert!(no_release.is_none());

        // List
        let all = db.list_leases(None).unwrap();
        assert_eq!(all.len(), 1);

        let scoped = db.list_leases(Some("lease-scope")).unwrap();
        assert_eq!(scoped.len(), 1);

        let empty = db.list_leases(Some("nonexistent")).unwrap();
        assert!(empty.is_empty());

        // Delete
        let deleted = db.delete_lease("aa:bb:cc:dd:ee:ff").unwrap();
        assert!(deleted);

        let deleted_again = db.delete_lease("aa:bb:cc:dd:ee:ff").unwrap();
        assert!(!deleted_again);

        let all = db.list_leases(None).unwrap();
        assert!(all.is_empty());
    }

    // ================================================================
    // DHCP IP Allocation Tests
    // ================================================================

    #[test]
    fn test_dhcp_ip_allocation() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "alloc-scope".to_string(),
            home_domain: "alloc.home".to_string(),
        })
        .unwrap();

        let pool = DhcpPool {
            id: 0,
            scope_name: "alloc-scope".to_string(),
            range_start: "10.0.0.10".to_string(),
            range_end: "10.0.0.12".to_string(),
            gateway: None,
            subnet_mask: "255.255.255.0".to_string(),
            dns_servers: None,
        };
        db.add_dhcp_pool(&pool).unwrap();

        // Allocate first IP
        let ip1 = db.allocate_ip("alloc-scope", "aa:aa:aa:aa:aa:01").unwrap();
        assert_eq!(ip1, Some("10.0.0.10".to_string()));

        // Create the lease so the IP is occupied
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs() as i64;
        db.create_lease(&DhcpLease {
            mac: "aa:aa:aa:aa:aa:01".to_string(),
            ip: "10.0.0.10".to_string(),
            scope_name: "alloc-scope".to_string(),
            hostname: None,
            lease_start: now,
            lease_duration: 3600,
            state: "active".to_string(),
        })
        .unwrap();

        // Sticky binding: same MAC should get same IP
        let ip1_again = db.allocate_ip("alloc-scope", "aa:aa:aa:aa:aa:01").unwrap();
        assert_eq!(ip1_again, Some("10.0.0.10".to_string()));

        // New MAC should get next available IP
        let ip2 = db.allocate_ip("alloc-scope", "aa:aa:aa:aa:aa:02").unwrap();
        assert_eq!(ip2, Some("10.0.0.11".to_string()));

        // Create lease for second MAC
        db.create_lease(&DhcpLease {
            mac: "aa:aa:aa:aa:aa:02".to_string(),
            ip: "10.0.0.11".to_string(),
            scope_name: "alloc-scope".to_string(),
            hostname: None,
            lease_start: now,
            lease_duration: 3600,
            state: "active".to_string(),
        })
        .unwrap();

        // Third MAC gets last IP
        let ip3 = db.allocate_ip("alloc-scope", "aa:aa:aa:aa:aa:03").unwrap();
        assert_eq!(ip3, Some("10.0.0.12".to_string()));

        // Create lease for third MAC
        db.create_lease(&DhcpLease {
            mac: "aa:aa:aa:aa:aa:03".to_string(),
            ip: "10.0.0.12".to_string(),
            scope_name: "alloc-scope".to_string(),
            hostname: None,
            lease_start: now,
            lease_duration: 3600,
            state: "active".to_string(),
        })
        .unwrap();

        // Pool exhausted
        let ip4 = db.allocate_ip("alloc-scope", "aa:aa:aa:aa:aa:04").unwrap();
        assert!(ip4.is_none());
    }

    // ================================================================
    // DHCP Lease Sweep Tests
    // ================================================================

    #[test]
    fn test_dhcp_lease_sweep() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "sweep-scope".to_string(),
            home_domain: "sweep.home".to_string(),
        })
        .unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs() as i64;

        // Create an already-expired lease (started 200s ago, duration 100s)
        db.create_lease(&DhcpLease {
            mac: "bb:bb:bb:bb:bb:01".to_string(),
            ip: "10.0.0.100".to_string(),
            scope_name: "sweep-scope".to_string(),
            hostname: None,
            lease_start: now - 200,
            lease_duration: 100,
            state: "active".to_string(),
        })
        .unwrap();

        // Create a still-active lease
        db.create_lease(&DhcpLease {
            mac: "bb:bb:bb:bb:bb:02".to_string(),
            ip: "10.0.0.101".to_string(),
            scope_name: "sweep-scope".to_string(),
            hostname: None,
            lease_start: now,
            lease_duration: 3600,
            state: "active".to_string(),
        })
        .unwrap();

        // Sweep with a short reclaim timeout (50s)
        // The expired lease started 200s ago, duration 100, so expired 100s ago.
        // reclaim_timeout=50 means it's reclaimable since 100 > 50.
        let reclaimed = db.sweep_expired_leases(50).unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].mac, "bb:bb:bb:bb:bb:01");

        // The reclaimed lease should be deleted
        let gone = db.get_lease_by_mac("bb:bb:bb:bb:bb:01").unwrap();
        assert!(gone.is_none());

        // The active lease should still be there
        let still_active = db.get_lease_by_mac("bb:bb:bb:bb:bb:02").unwrap();
        assert!(still_active.is_some());
        assert_eq!(still_active.unwrap().state, "active");
    }

    // ================================================================
    // Scope RBL Provider Tests
    // ================================================================

    #[test]
    fn test_scope_rbl_crud() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "rbl-scope".to_string(),
            home_domain: "rbl.home".to_string(),
        })
        .unwrap();

        // Add providers
        db.add_scope_rbl_provider(&ScopeRblProvider {
            scope_name: "rbl-scope".to_string(),
            zone: "zen.spamhaus.org".to_string(),
            enabled: true,
        })
        .unwrap();
        db.add_scope_rbl_provider(&ScopeRblProvider {
            scope_name: "rbl-scope".to_string(),
            zone: "bl.spamcop.net".to_string(),
            enabled: false,
        })
        .unwrap();

        // List
        let providers = db.list_scope_rbl_providers("rbl-scope").unwrap();
        assert_eq!(providers.len(), 2);

        let spamhaus = providers
            .iter()
            .find(|p| p.zone == "zen.spamhaus.org")
            .unwrap();
        assert!(spamhaus.enabled);

        let spamcop = providers
            .iter()
            .find(|p| p.zone == "bl.spamcop.net")
            .unwrap();
        assert!(!spamcop.enabled);

        // Update (replace)
        db.add_scope_rbl_provider(&ScopeRblProvider {
            scope_name: "rbl-scope".to_string(),
            zone: "bl.spamcop.net".to_string(),
            enabled: true,
        })
        .unwrap();
        let updated = db.list_scope_rbl_providers("rbl-scope").unwrap();
        let spamcop_updated = updated.iter().find(|p| p.zone == "bl.spamcop.net").unwrap();
        assert!(spamcop_updated.enabled);

        // Remove
        let removed = db
            .remove_scope_rbl_provider("rbl-scope", "zen.spamhaus.org")
            .unwrap();
        assert!(removed);

        let removed_again = db
            .remove_scope_rbl_provider("rbl-scope", "zen.spamhaus.org")
            .unwrap();
        assert!(!removed_again);

        let remaining = db.list_scope_rbl_providers("rbl-scope").unwrap();
        assert_eq!(remaining.len(), 1);

        // Empty scope
        let empty = db.list_scope_rbl_providers("nonexistent").unwrap();
        assert!(empty.is_empty());
    }

    // ================================================================
    // DHCP Cert Option Tests
    // ================================================================

    #[test]
    fn test_dhcp_cert_option_crud() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "cert-scope".to_string(),
            home_domain: "cert.home".to_string(),
        })
        .unwrap();

        // Set option
        db.set_dhcp_cert_option(&DhcpCertOption {
            scope_name: "cert-scope".to_string(),
            option_code: 224,
            cert_data: vec![0x30, 0x82, 0x01, 0x22],
            description: Some("Root CA cert".to_string()),
        })
        .unwrap();

        // List
        let options = db.list_dhcp_cert_options("cert-scope").unwrap();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].option_code, 224);
        assert_eq!(options[0].cert_data, vec![0x30, 0x82, 0x01, 0x22]);
        assert_eq!(options[0].description, Some("Root CA cert".to_string()));

        // Update (replace)
        db.set_dhcp_cert_option(&DhcpCertOption {
            scope_name: "cert-scope".to_string(),
            option_code: 224,
            cert_data: vec![0xFF, 0xFE],
            description: Some("Updated cert".to_string()),
        })
        .unwrap();
        let updated = db.list_dhcp_cert_options("cert-scope").unwrap();
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].cert_data, vec![0xFF, 0xFE]);
        assert_eq!(updated[0].description, Some("Updated cert".to_string()));

        // Add a second option
        db.set_dhcp_cert_option(&DhcpCertOption {
            scope_name: "cert-scope".to_string(),
            option_code: 225,
            cert_data: vec![0xAB],
            description: None,
        })
        .unwrap();
        let all = db.list_dhcp_cert_options("cert-scope").unwrap();
        assert_eq!(all.len(), 2);

        // Remove
        let removed = db.remove_dhcp_cert_option("cert-scope", 224).unwrap();
        assert!(removed);

        let removed_again = db.remove_dhcp_cert_option("cert-scope", 224).unwrap();
        assert!(!removed_again);

        let remaining = db.list_dhcp_cert_options("cert-scope").unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].option_code, 225);

        // Empty scope
        let empty = db.list_dhcp_cert_options("nonexistent").unwrap();
        assert!(empty.is_empty());
    }

    // ================================================================
    // IPAM Unit Tests
    // ================================================================

    #[test]
    fn test_ipam_allocation_exhaustion() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "exhaust-scope".to_string(),
            home_domain: "exhaust.home".to_string(),
        })
        .unwrap();

        // Single pool with 3 IPs
        db.add_dhcp_pool(&DhcpPool {
            id: 0,
            scope_name: "exhaust-scope".to_string(),
            range_start: "10.0.0.10".to_string(),
            range_end: "10.0.0.12".to_string(),
            gateway: None,
            subnet_mask: "255.255.255.0".to_string(),
            dns_servers: None,
        })
        .unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs() as i64;

        // Allocate all 3 IPs sequentially
        for i in 0..3u8 {
            let mac = format!("aa:aa:aa:aa:00:{:02x}", i);
            let ip = db.allocate_ip("exhaust-scope", &mac).unwrap().unwrap();
            assert_eq!(ip, format!("10.0.0.{}", 10 + i));
            db.create_lease(&DhcpLease {
                mac,
                ip,
                scope_name: "exhaust-scope".to_string(),
                hostname: None,
                lease_start: now,
                lease_duration: 3600,
                state: "active".to_string(),
            })
            .unwrap();
        }

        // Pool exhausted — no more IPs
        let none = db
            .allocate_ip("exhaust-scope", "aa:aa:aa:aa:00:03")
            .unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn test_ipam_allocation_after_lease_deletion() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "reuse-scope".to_string(),
            home_domain: "reuse.home".to_string(),
        })
        .unwrap();

        db.add_dhcp_pool(&DhcpPool {
            id: 0,
            scope_name: "reuse-scope".to_string(),
            range_start: "10.0.0.10".to_string(),
            range_end: "10.0.0.10".to_string(),
            gateway: None,
            subnet_mask: "255.255.255.0".to_string(),
            dns_servers: None,
        })
        .unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs() as i64;

        // Allocate the only IP
        let ip = db.allocate_ip("reuse-scope", "aa:bb:cc:00:00:01").unwrap();
        assert_eq!(ip, Some("10.0.0.10".to_string()));
        db.create_lease(&DhcpLease {
            mac: "aa:bb:cc:00:00:01".to_string(),
            ip: "10.0.0.10".to_string(),
            scope_name: "reuse-scope".to_string(),
            hostname: None,
            lease_start: now,
            lease_duration: 3600,
            state: "active".to_string(),
        })
        .unwrap();

        // Pool is full
        let none = db.allocate_ip("reuse-scope", "aa:bb:cc:00:00:02").unwrap();
        assert!(none.is_none());

        // Delete the lease — IP should become available again
        db.delete_lease("aa:bb:cc:00:00:01").unwrap();

        let reused = db.allocate_ip("reuse-scope", "aa:bb:cc:00:00:02").unwrap();
        assert_eq!(reused, Some("10.0.0.10".to_string()));
    }

    #[test]
    fn test_ipam_scope_isolation() {
        let db = test_db();

        db.create_network_scope(&NetworkScope {
            name: "scope-a".to_string(),
            home_domain: "a.home".to_string(),
        })
        .unwrap();
        db.create_network_scope(&NetworkScope {
            name: "scope-b".to_string(),
            home_domain: "b.home".to_string(),
        })
        .unwrap();

        // Same IP range in both scopes
        for scope in &["scope-a", "scope-b"] {
            db.add_dhcp_pool(&DhcpPool {
                id: 0,
                scope_name: scope.to_string(),
                range_start: "10.0.0.10".to_string(),
                range_end: "10.0.0.11".to_string(),
                gateway: None,
                subnet_mask: "255.255.255.0".to_string(),
                dns_servers: None,
            })
            .unwrap();
        }

        // Allocate in scope-a
        let ip_a = db.allocate_ip("scope-a", "aa:00:00:00:00:01").unwrap();
        assert_eq!(ip_a, Some("10.0.0.10".to_string()));

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs() as i64;
        db.create_lease(&DhcpLease {
            mac: "aa:00:00:00:00:01".to_string(),
            ip: "10.0.0.10".to_string(),
            scope_name: "scope-a".to_string(),
            hostname: None,
            lease_start: now,
            lease_duration: 3600,
            state: "active".to_string(),
        })
        .unwrap();

        // Allocate in scope-b — should also get .10 since scopes are isolated
        let ip_b = db.allocate_ip("scope-b", "bb:00:00:00:00:01").unwrap();
        assert_eq!(ip_b, Some("10.0.0.10".to_string()));
    }

    #[test]
    fn test_ipam_sticky_binding_survives_release() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "sticky-scope".to_string(),
            home_domain: "sticky.home".to_string(),
        })
        .unwrap();

        db.add_dhcp_pool(&DhcpPool {
            id: 0,
            scope_name: "sticky-scope".to_string(),
            range_start: "10.0.0.10".to_string(),
            range_end: "10.0.0.20".to_string(),
            gateway: None,
            subnet_mask: "255.255.255.0".to_string(),
            dns_servers: None,
        })
        .unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs() as i64;

        // Allocate and create lease
        let ip = db.allocate_ip("sticky-scope", "cc:cc:cc:00:00:01").unwrap();
        assert_eq!(ip, Some("10.0.0.10".to_string()));
        db.create_lease(&DhcpLease {
            mac: "cc:cc:cc:00:00:01".to_string(),
            ip: "10.0.0.10".to_string(),
            scope_name: "sticky-scope".to_string(),
            hostname: None,
            lease_start: now,
            lease_duration: 3600,
            state: "active".to_string(),
        })
        .unwrap();

        // Release the lease
        db.release_lease("cc:cc:cc:00:00:01").unwrap();

        // Allocate again with same MAC — sticky binding should return same IP
        let ip_again = db.allocate_ip("sticky-scope", "cc:cc:cc:00:00:01").unwrap();
        assert_eq!(ip_again, Some("10.0.0.10".to_string()));
    }

    #[test]
    fn test_ipam_single_ip_pool() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "single-scope".to_string(),
            home_domain: "single.home".to_string(),
        })
        .unwrap();

        db.add_dhcp_pool(&DhcpPool {
            id: 0,
            scope_name: "single-scope".to_string(),
            range_start: "10.0.0.99".to_string(),
            range_end: "10.0.0.99".to_string(),
            gateway: None,
            subnet_mask: "255.255.255.0".to_string(),
            dns_servers: None,
        })
        .unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs() as i64;

        let ip = db.allocate_ip("single-scope", "dd:dd:dd:00:00:01").unwrap();
        assert_eq!(ip, Some("10.0.0.99".to_string()));

        db.create_lease(&DhcpLease {
            mac: "dd:dd:dd:00:00:01".to_string(),
            ip: "10.0.0.99".to_string(),
            scope_name: "single-scope".to_string(),
            hostname: None,
            lease_start: now,
            lease_duration: 3600,
            state: "active".to_string(),
        })
        .unwrap();

        // Second MAC should get nothing
        let none = db.allocate_ip("single-scope", "dd:dd:dd:00:00:02").unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn test_ipam_lease_replace_same_mac() {
        let db = test_db();
        db.create_network_scope(&NetworkScope {
            name: "replace-scope".to_string(),
            home_domain: "replace.home".to_string(),
        })
        .unwrap();

        db.add_dhcp_pool(&DhcpPool {
            id: 0,
            scope_name: "replace-scope".to_string(),
            range_start: "10.0.0.50".to_string(),
            range_end: "10.0.0.60".to_string(),
            gateway: None,
            subnet_mask: "255.255.255.0".to_string(),
            dns_servers: None,
        })
        .unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs() as i64;

        let mac = "ee:ee:ee:00:00:01";

        // First allocation
        let ip1 = db.allocate_ip("replace-scope", mac).unwrap();
        assert_eq!(ip1, Some("10.0.0.50".to_string()));

        // Create lease
        db.create_lease(&DhcpLease {
            mac: mac.to_string(),
            ip: "10.0.0.50".to_string(),
            scope_name: "replace-scope".to_string(),
            hostname: Some("host1".to_string()),
            lease_start: now,
            lease_duration: 3600,
            state: "active".to_string(),
        })
        .unwrap();

        // Release and re-create lease (simulating a renewal/rebind)
        db.release_lease(mac).unwrap();
        db.create_lease(&DhcpLease {
            mac: mac.to_string(),
            ip: "10.0.0.50".to_string(),
            scope_name: "replace-scope".to_string(),
            hostname: Some("host2".to_string()),
            lease_start: now,
            lease_duration: 7200,
            state: "active".to_string(),
        })
        .unwrap();

        // Sticky binding: allocate_ip should still return the same IP
        let ip2 = db.allocate_ip("replace-scope", mac).unwrap();
        assert_eq!(ip2, Some("10.0.0.50".to_string()));

        // Should only have one lease for this MAC
        let all = db.list_leases(None).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].ip, "10.0.0.50");
        assert_eq!(all[0].hostname, Some("host2".to_string()));
        assert_eq!(all[0].lease_duration, 7200);
    }
}
