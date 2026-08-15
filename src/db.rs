use anyhow::{Context, Result, anyhow};
use dashmap::{DashMap, DashSet};
use rusqlite::{Connection, OptionalExtension, params};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::warn;

/// Error returned when a TLD is already owned by a different network scope.
/// Owned TLDs (a scope's `home_domain` plus any additional registered TLDs) are
/// globally unique so a name resolves within exactly one network partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TldConflict {
    /// The normalized TLD that was requested.
    pub tld: String,
    /// The scope that already owns it.
    pub owner: String,
}

impl std::fmt::Display for TldConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tld '{}' is already owned by scope '{}'",
            self.tld, self.owner
        )
    }
}

impl std::error::Error for TldConflict {}

/// Builds the composite key used by `tld_forwarder_cache` for a (scope, tld)
/// pair. The NUL separator can never appear in a scope name or DNS name.
fn tld_fwd_key(scope: &str, tld_norm: &str) -> String {
    format!("{scope}\u{0}{tld_norm}")
}

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

/// Result of a combined lookup with fallback chain (exact, wildcard, CNAME, ANAME).
#[derive(Debug, Default)]
pub struct LookupResult {
    pub exact: Vec<DnsRecord>,
    pub wildcard: Vec<DnsRecord>,
    pub cname: Vec<DnsRecord>,
    pub aname: Vec<DnsRecord>,
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
    CERT,
    SVCB,
    HTTPS,
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
            RecordKind::CERT => "CERT",
            RecordKind::SVCB => "SVCB",
            RecordKind::HTTPS => "HTTPS",
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
            "CERT" => Some(RecordKind::CERT),
            "SVCB" => Some(RecordKind::SVCB),
            "HTTPS" => Some(RecordKind::HTTPS),
            _ => None,
        }
    }

    /// The IANA DNS type code for this record kind.
    ///
    /// Distinct from [`Self::to_proto_i32`], which is the protobuf enum's
    /// ordinal and has nothing to do with the wire. DNSSEC signing needs the
    /// real code: it goes into the RRSIG `type_covered` field and into each
    /// signed RR, where a wrong value produces a signature no validator can
    /// reproduce.
    pub fn wire_type(&self) -> u16 {
        match self {
            RecordKind::A => 1,
            RecordKind::NS => 2,
            RecordKind::CNAME => 5,
            RecordKind::SOA => 6,
            RecordKind::PTR => 12,
            RecordKind::MX => 15,
            RecordKind::TXT => 16,
            RecordKind::AAAA => 28,
            RecordKind::SRV => 33,
            RecordKind::CERT => 37,
            RecordKind::DNAME => 39,
            RecordKind::DS => 43,
            RecordKind::SSHFP => 44,
            RecordKind::RRSIG => 46,
            RecordKind::NSEC => 47,
            RecordKind::DNSKEY => 48,
            RecordKind::NSEC3 => 50,
            RecordKind::NSEC3PARAM => 51,
            RecordKind::TLSA => 52,
            RecordKind::ZONEMD => 63,
            RecordKind::SVCB => 64,
            RecordKind::HTTPS => 65,
            RecordKind::URI => 256,
            // ANAME has no assigned code; this is the value hickory uses for the
            // draft type, matched here so the two agree.
            RecordKind::ANAME => 65305,
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
            RecordKind::CERT => 21,
            RecordKind::SVCB => 22,
            RecordKind::HTTPS => 23,
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
            21 => Some(RecordKind::CERT),
            22 => Some(RecordKind::SVCB),
            23 => Some(RecordKind::HTTPS),
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

/// An ACME server account (RFC 8555), keyed by an opaque account id (the `kid` tail).
#[derive(Debug, Clone)]
pub struct AcmeAccount {
    pub account_id: String,
    /// The client's account public key as a JWK JSON string.
    pub jwk: String,
    /// Base64url SHA-256 JWK thumbprint (RFC 7638).
    pub thumbprint: String,
    pub contacts: Option<String>,
    pub status: String,
    pub eab_kid: Option<String>,
    /// Zone this account is scoped to (from its EAB), if any.
    pub zone: Option<String>,
}

/// An External Account Binding credential (kid + HMAC secret).
#[derive(Debug, Clone)]
pub struct AcmeEab {
    pub kid: String,
    pub hmac_key: Vec<u8>,
    pub zone: Option<String>,
    pub used: bool,
}

/// An ACME order.
#[derive(Debug, Clone)]
pub struct AcmeOrder {
    pub id: String,
    pub account_id: String,
    pub status: String,
    /// JSON array of DNS identifier names.
    pub identifiers: String,
    /// JSON array of authorization ids.
    pub authorizations: String,
    pub cert_id: Option<i64>,
    pub expires_at: i64,
}

/// An ACME authorization for a single identifier.
#[derive(Debug, Clone)]
pub struct AcmeAuthorization {
    pub id: String,
    pub order_id: String,
    pub account_id: String,
    pub identifier: String,
    pub status: String,
    pub expires_at: i64,
}

/// An ACME challenge belonging to an authorization.
#[derive(Debug, Clone)]
pub struct AcmeChallenge {
    pub id: String,
    pub authz_id: String,
    pub challenge_type: String,
    pub token: String,
    pub status: String,
    pub validated_at: Option<i64>,
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
    /// In-memory cache of local blocklist entries for fast lookup.
    local_blocklist_cache: Arc<DashSet<String>>,
    /// In-memory cache of DNSBL allowlist entries — names exempted from the
    /// name-based blocklist check. Held normalized (lowercase, trailing dot) so
    /// the hot path can suffix-match in O(labels), which is what makes an entry
    /// cover the name *and* everything under it.
    dnsbl_allowlist_cache: Arc<DashSet<String>>,
    /// In-memory cache of authoritative zones.
    authoritative_zones_cache: Arc<DashSet<String>>,
    /// In-memory cache of managed zones (derived from dns_records names).
    managed_zones_cache: Arc<DashSet<String>>,
    /// Maps a normalized owned TLD/zone ("office.") to the name of the scope that
    /// owns it. Populated from each scope's `home_domain` (implicit primary TLD)
    /// and the `scope_tlds` table. Drives the per-network resolution partition
    /// and enforces global TLD uniqueness. O(labels) suffix lookup on the hot path.
    tld_owner_cache: Arc<DashMap<String, String>>,
    /// Per-(scope, TLD) peer forwarder addresses, keyed by `tld_fwd_key`. These
    /// are the overlay rolodex servers of other members of the same network,
    /// consulted only for names under the owning scope's TLD.
    tld_forwarder_cache: Arc<DashMap<String, Vec<SocketAddr>>>,
    /// Ingress listener IP per owned TLD, keyed by the normalized TLD. When a
    /// query for a programmed name under this TLD arrives on the matching local
    /// listener IP, its A/AAAA answer is rewritten to this IP (the network's
    /// ingress controller). O(1) hot-path lookup by TLD.
    tld_ingress_cache: Arc<DashMap<String, IpAddr>>,
}

impl Database {
    /// Opens or creates the database at the given path.
    /// Uses SQLite with WAL mode for concurrent read performance.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let conn = Connection::open(path).context("failed to open database")?;
        // Tighten before enabling WAL, not after. This file is the keystore —
        // the root CA private key, every per-zone intermediate key, the DNSSEC
        // private keys, and the EAB HMAC secrets are plain rows in it — and
        // SQLite creates it under the bare umask, typically 0644, so any local
        // user could read the root key and forge a certificate for any name
        // every enrolled client trusts. SQLite copies the main file's mode onto
        // the `-wal`/`-shm` sidecars it creates, so restricting first means they
        // are born restricted rather than fixed up in a window where they are
        // not.
        restrict_to_owner(path).context("failed to restrict database permissions")?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .context("failed to set pragmas")?;
        // Belt and braces: a sidecar that already existed (from a previous run
        // under a looser umask, or a crash) keeps its old mode above.
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
            if sidecar.exists()
                && let Err(e) = restrict_to_owner(&sidecar)
            {
                warn!("failed to restrict permissions on {:?}: {}", sidecar, e);
            }
        }
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            association_cache: Arc::new(DashMap::new()),
            scoped_record_cache: Arc::new(DashMap::new()),
            scope_count: Arc::new(AtomicUsize::new(0)),
            local_blocklist_cache: Arc::new(DashSet::new()),
            dnsbl_allowlist_cache: Arc::new(DashSet::new()),
            authoritative_zones_cache: Arc::new(DashSet::new()),
            managed_zones_cache: Arc::new(DashSet::new()),
            tld_owner_cache: Arc::new(DashMap::new()),
            tld_forwarder_cache: Arc::new(DashMap::new()),
            tld_ingress_cache: Arc::new(DashMap::new()),
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
            local_blocklist_cache: Arc::new(DashSet::new()),
            dnsbl_allowlist_cache: Arc::new(DashSet::new()),
            authoritative_zones_cache: Arc::new(DashSet::new()),
            managed_zones_cache: Arc::new(DashSet::new()),
            tld_owner_cache: Arc::new(DashMap::new()),
            tld_forwarder_cache: Arc::new(DashMap::new()),
            tld_ingress_cache: Arc::new(DashMap::new()),
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

            CREATE TABLE IF NOT EXISTS tracked_tlds (
                tld TEXT PRIMARY KEY NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scope_tlds (
                scope_name TEXT NOT NULL,
                tld TEXT NOT NULL,
                PRIMARY KEY (scope_name, tld),
                FOREIGN KEY (scope_name) REFERENCES network_scopes(name) ON DELETE CASCADE
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_scope_tlds_tld ON scope_tlds(tld);
            CREATE INDEX IF NOT EXISTS idx_scope_tlds_scope ON scope_tlds(scope_name);

            CREATE TABLE IF NOT EXISTS scope_tld_forwarders (
                scope_name TEXT NOT NULL,
                tld TEXT NOT NULL,
                forwarder_addr TEXT NOT NULL,
                PRIMARY KEY (scope_name, tld, forwarder_addr),
                FOREIGN KEY (scope_name) REFERENCES network_scopes(name) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_scope_tld_fwd ON scope_tld_forwarders(scope_name, tld);

            CREATE TABLE IF NOT EXISTS tld_listeners (
                scope_name TEXT NOT NULL,
                tld TEXT NOT NULL,
                listen_ip TEXT NOT NULL,
                PRIMARY KEY (scope_name, tld),
                FOREIGN KEY (scope_name) REFERENCES network_scopes(name) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_tld_listeners_ip ON tld_listeners(listen_ip);

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

            -- dns_cache historically had no uniqueness constraint and cache_insert
            -- was a bare INSERT, so re-caching a name appended a duplicate row every
            -- time and nothing but a full flush ever pruned them. Collapse any
            -- accumulated duplicates, then enforce uniqueness so cache_insert can
            -- upsert. Both are no-ops once the index exists.
            DELETE FROM dns_cache WHERE id NOT IN (
                SELECT MAX(id) FROM dns_cache GROUP BY name, record_type, value
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_cache_unique
                ON dns_cache(name, record_type, value);

            -- Cached delegations (zone -> nameserver addresses), so the iterative
            -- resolver does not re-walk root -> TLD for every cold name. Long-lived
            -- entries (root/TLD NS sets carry multi-day TTLs) are persisted so a
            -- restart comes back warm.
            CREATE TABLE IF NOT EXISTS delegation_cache (
                zone       TEXT NOT NULL,
                ns_ip      TEXT NOT NULL,
                ttl        INTEGER NOT NULL,
                cached_at  INTEGER NOT NULL,
                PRIMARY KEY (zone, ns_ip)
            );
            CREATE INDEX IF NOT EXISTS idx_delegation_expiry
                ON delegation_cache(cached_at, ttl);

            CREATE TABLE IF NOT EXISTS local_blocklist_entries (
                name TEXT PRIMARY KEY NOT NULL,
                reason TEXT NOT NULL DEFAULT ''
            );

            -- Names exempted from the name-based blocklist check (DNSBL
            -- providers and local blocklist entries). Stored normalized, and
            -- matched as a suffix so an entry covers its subdomains too.
            CREATE TABLE IF NOT EXISTS dnsbl_allowlist (
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

            -- Per-zone intermediate CAs (signed by the Rolodex root CA).
            CREATE TABLE IF NOT EXISTS zone_cas (
                zone TEXT PRIMARY KEY,
                cert_pem TEXT NOT NULL,
                key_pem TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            -- ACME server accounts (RFC 8555): one per client account key.
            CREATE TABLE IF NOT EXISTS acme_server_accounts (
                account_id TEXT PRIMARY KEY,
                jwk TEXT NOT NULL,
                thumbprint TEXT NOT NULL,
                contacts TEXT,
                status TEXT NOT NULL DEFAULT 'valid',
                eab_kid TEXT,
                zone TEXT,
                created_at INTEGER NOT NULL
            );

            -- External Account Binding credentials (kid + HMAC secret).
            CREATE TABLE IF NOT EXISTS acme_eab (
                kid TEXT PRIMARY KEY,
                hmac_key BLOB NOT NULL,
                zone TEXT,
                used INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            -- ACME orders, authorizations, and challenges.
            CREATE TABLE IF NOT EXISTS acme_orders (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                status TEXT NOT NULL,
                identifiers TEXT NOT NULL,
                authorizations TEXT NOT NULL,
                cert_id INTEGER,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_acme_orders_account ON acme_orders(account_id);

            CREATE TABLE IF NOT EXISTS acme_authorizations (
                id TEXT PRIMARY KEY,
                order_id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                identifier TEXT NOT NULL,
                status TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_acme_authz_order ON acme_authorizations(order_id);

            CREATE TABLE IF NOT EXISTS acme_challenges (
                id TEXT PRIMARY KEY,
                authz_id TEXT NOT NULL,
                challenge_type TEXT NOT NULL,
                token TEXT NOT NULL,
                status TEXT NOT NULL,
                validated_at INTEGER,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_acme_chal_authz ON acme_challenges(authz_id);

            -- Anti-replay nonces issued to ACME clients.
            CREATE TABLE IF NOT EXISTS acme_nonces (
                nonce TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL
            );
            -- Both the TTL prune and the size cap order by created_at.
            CREATE INDEX IF NOT EXISTS idx_acme_nonces_created ON acme_nonces(created_at);

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
        drop(conn);
        self.migrate_retired_rbl_tables()?;
        self.migrate_columns()?;
        Ok(())
    }

    /// Carries a database created before the RBL feature was removed onto the
    /// current schema.
    ///
    /// Two things happened to it. The local blocklist was renamed
    /// (`local_rbl_entries` -> `local_blocklist_entries`): the entries are an
    /// operator's own list and must survive, so they are moved rather than left
    /// behind an old name nothing reads — a box whose blocklist silently emptied
    /// on upgrade would look like the blocklist simply not working. The
    /// per-scope provider table is dropped outright, because the lookups it
    /// configured no longer exist and its rows would be unreachable data
    /// referencing a feature that is gone.
    ///
    /// `CREATE TABLE IF NOT EXISTS` above has already created the new table, so
    /// the move is an INSERT rather than a rename; `OR IGNORE` keeps a name
    /// present in both (an upgrade interrupted halfway) from failing the boot.
    fn migrate_retired_rbl_tables(&self) -> Result<()> {
        let conn = self.lock()?;
        let legacy: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'local_rbl_entries'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if legacy {
            conn.execute_batch(
                "INSERT OR IGNORE INTO local_blocklist_entries (name, reason)
                     SELECT name, reason FROM local_blocklist_entries;
                 DROP TABLE local_rbl_entries;",
            )
            .context("failed to move the local blocklist off its RBL-era table")?;
        }
        conn.execute_batch("DROP TABLE IF EXISTS scope_rbl_providers;")
            .context("failed to drop the retired per-scope RBL provider table")?;
        Ok(())
    }

    /// Adds columns introduced after a table shipped.
    ///
    /// `CREATE TABLE IF NOT EXISTS` is a no-op against a database created by an
    /// older build, so a column added to the statement above exists only on
    /// databases created fresh. Every entry here must therefore carry a
    /// `DEFAULT`, so the existing rows have a defined value the moment the
    /// column appears.
    fn migrate_columns(&self) -> Result<()> {
        const ADDED_COLUMNS: &[(&str, &str, &str)] = &[];

        let conn = self.lock()?;
        for (table, column, decl) in ADDED_COLUMNS {
            let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
            let existing: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<std::result::Result<_, _>>()?;
            if existing.iter().any(|c| c == column) {
                continue;
            }
            drop(stmt);
            conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))
                .with_context(|| format!("failed to add column {table}.{column}"))?;
        }
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

    /// Loads scope_count, local_blocklist_cache, dnsbl_allowlist_cache,
    /// authoritative_zones_cache, and managed_zones_cache from the database at
    /// boot time.
    fn load_caches_at_boot(&self) -> Result<()> {
        let conn = self.lock()?;

        // Scope count
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM network_scopes", [], |row| row.get(0))?;
        self.scope_count.store(count as usize, Ordering::Relaxed);

        // Local blocklist entries
        let mut stmt = conn.prepare_cached("SELECT name FROM local_blocklist_entries")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            self.local_blocklist_cache.insert(row?);
        }

        // DNSBL allowlist entries
        let mut stmt = conn.prepare_cached("SELECT name FROM dnsbl_allowlist")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            self.dnsbl_allowlist_cache.insert(row?);
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

        // Owned TLDs: each scope's home_domain (implicit primary TLD) ...
        let mut stmt = conn.prepare_cached("SELECT name, home_domain FROM network_scopes")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (scope, home_domain) = row?;
            self.tld_owner_cache
                .insert(normalize_name(&home_domain), scope);
        }
        // ... plus additional registered TLDs.
        let mut stmt = conn.prepare_cached("SELECT scope_name, tld FROM scope_tlds")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (scope, tld) = row?;
            self.tld_owner_cache.insert(normalize_name(&tld), scope);
        }

        // Per-TLD peer forwarders.
        let mut stmt = conn
            .prepare_cached("SELECT scope_name, tld, forwarder_addr FROM scope_tld_forwarders")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (scope, tld, addr) = row?;
            if let Ok(sa) = addr.parse::<SocketAddr>() {
                self.tld_forwarder_cache
                    .entry(tld_fwd_key(&scope, &normalize_name(&tld)))
                    .or_default()
                    .push(sa);
            }
        }

        // Per-TLD ingress listener IPs.
        let mut stmt = conn.prepare_cached("SELECT tld, listen_ip FROM tld_listeners")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (tld, ip) = row?;
            if let Ok(parsed) = ip.parse::<IpAddr>() {
                self.tld_ingress_cache.insert(normalize_name(&tld), parsed);
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

        // Keep the managed-zone cache honest. This is the only path that deletes
        // global records, so it is the only place the cache can go stale — and a
        // stale entry is not harmless: `find_managed_zone` is what turns a miss
        // into an *authoritative* NXDOMAIN, so a zone whose last record was
        // deleted would keep swallowing every name under it instead of letting
        // them resolve upstream.
        //
        // Off the hot path by construction: removal is a control-plane
        // operation, so paying a query here is what lets the query path trust
        // the cache without one.
        if count > 0
            && let Some(zone) = extract_zone_from_name(&normalized)
            && !Self::zone_has_records_conn(&conn, &zone)?
        {
            self.managed_zones_cache.remove(&zone);
        }

        Ok(count)
    }

    /// Whether any record remains at or beneath `zone`.
    ///
    /// "Beneath" is the operative word. The obvious spelling — look up the zone
    /// apex — asks a different and much narrower question, because a zone
    /// commonly has records only at subdomains: storing `www.example.com` with
    /// nothing at `example.com` is the normal case, not an edge case.
    pub fn zone_has_records(&self, zone: &str) -> Result<bool> {
        let conn = self.lock()?;
        Self::zone_has_records_conn(&conn, &normalize_name(zone))
    }

    /// [`Self::zone_has_records`] against a connection the caller already holds.
    fn zone_has_records_conn(conn: &rusqlite::Connection, zone: &str) -> Result<bool> {
        // `LIKE '%.<zone>'` cannot use the index, but it stops at the first row
        // (`LIMIT 1`), so a zone that still has records costs almost nothing.
        // Only a genuinely empty zone pays a scan, and that is the case where
        // the entry is about to be dropped anyway.
        //
        // The pattern is escaped because `_` is a LIKE wildcard *and* a legal
        // DNS label character (`_tcp`, `_acme-challenge`). Unescaped, `_x.test.`
        // would match `ax.test.` and the zone would look occupied when it is
        // not — leaving the stale entry this function exists to remove.
        let pattern = format!(".{}", like_escape(zone));
        let mut stmt = conn.prepare_cached(
            "SELECT 1 FROM dns_records WHERE name = ?1 OR name LIKE '%' || ?2 ESCAPE '\\' LIMIT 1",
        )?;
        let found = stmt.exists(params![zone, pattern])?;
        Ok(found)
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

    /// Looks up records with fallback chain in a single SQL query.
    ///
    /// Combines exact match, wildcard, CNAME, and ANAME lookups into one
    /// UNION ALL query, reducing lock acquisitions from 4+ to 1. Results are
    /// tagged with a source discriminator so callers can apply priority order:
    /// exact > wildcard > CNAME > ANAME.
    pub fn lookup_with_fallbacks(
        &self,
        name: &str,
        record_type: RecordKind,
    ) -> Result<LookupResult> {
        let conn = self.lock()?;
        let normalized = normalize_name(name);
        let wildcard_name = make_wildcard_name(&normalized).unwrap_or_default();
        let rt_str = record_type.as_str();

        let mut stmt = conn.prepare_cached(
            "SELECT id, name, record_type, value, ttl, priority, 'exact' as source \
               FROM dns_records WHERE name = ?1 AND record_type = ?2 \
             UNION ALL \
             SELECT id, name, record_type, value, ttl, priority, 'wildcard' as source \
               FROM dns_records WHERE name = ?3 AND record_type = ?2 \
             UNION ALL \
             SELECT id, name, record_type, value, ttl, priority, 'cname' as source \
               FROM dns_records WHERE name = ?1 AND record_type = 'CNAME' \
             UNION ALL \
             SELECT id, name, record_type, value, ttl, priority, 'aname' as source \
               FROM dns_records WHERE name = ?1 AND record_type = 'ANAME'",
        )?;

        let rows = stmt.query_map(params![normalized, rt_str, wildcard_name], |row| {
            let source: String = row.get(6)?;
            Ok((
                DnsRecord {
                    id: Some(row.get(0)?),
                    name: row.get(1)?,
                    record_type: RecordKind::parse(&row.get::<_, String>(2)?)
                        .unwrap_or(RecordKind::A),
                    value: row.get(3)?,
                    ttl: row.get(4)?,
                    priority: row.get(5)?,
                },
                source,
            ))
        })?;

        let mut exact = Vec::new();
        let mut wildcard = Vec::new();
        let mut cname = Vec::new();
        let mut aname = Vec::new();

        for row in rows {
            let (record, source) = row?;
            match source.as_str() {
                "exact" => exact.push(record),
                "wildcard" => wildcard.push(record),
                "cname" => cname.push(record),
                "aname" => aname.push(record),
                _ => {}
            }
        }

        // Fixup wildcard records: substitute the original qname
        if !wildcard.is_empty() {
            for r in &mut wildcard {
                r.name = normalized.clone();
            }
        }

        Ok(LookupResult {
            exact,
            wildcard,
            cname,
            aname,
        })
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
        let home_domain = normalize_name(&scope.home_domain);
        // A scope's home_domain is its implicit primary owned TLD, so it must be
        // globally unique across all owned TLDs (home_domains + additional TLDs).
        if let Some(existing) = self.tld_owner_cache.get(&home_domain)
            && existing.value() != &scope.name
        {
            return Err(TldConflict {
                tld: home_domain,
                owner: existing.value().clone(),
            }
            .into());
        }
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO network_scopes (name, home_domain) VALUES (?1, ?2)",
            params![scope.name, home_domain],
        )
        .context("failed to create network scope")?;
        drop(conn);
        self.scope_count.fetch_add(1, Ordering::Relaxed);
        self.tld_owner_cache.insert(home_domain, scope.name.clone());
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
        // Foreign keys are not enforced at runtime (no PRAGMA foreign_keys=ON),
        // so cascade the owned-TLD tables manually.
        conn.execute(
            "DELETE FROM scope_tld_forwarders WHERE scope_name = ?1",
            params![name],
        )?;
        conn.execute(
            "DELETE FROM scope_tlds WHERE scope_name = ?1",
            params![name],
        )?;
        let count = conn.execute("DELETE FROM network_scopes WHERE name = ?1", params![name])?;

        // Clear caches for this scope
        self.scoped_record_cache
            .retain(|key, _| !key.starts_with(&format!("{}:", name)));
        self.association_cache
            .retain(|_, entry| entry.scope_name != name);
        // Drop this scope's owned TLDs (home_domain + additional) and their
        // forwarders. Done unconditionally so caches never outlive the rows.
        self.tld_owner_cache.retain(|_tld, owner| owner != name);
        let fwd_prefix = format!("{name}\u{0}");
        self.tld_forwarder_cache
            .retain(|key, _| !key.starts_with(&fwd_prefix));

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
    /// `.home` domain (the implicit primary TLD) followed by any additional
    /// owned TLDs. This is useful for DHCP servers that need to set the search
    /// domain for clients.
    pub fn get_search_domains(&self, ip_address: &str) -> Result<Vec<String>> {
        let scope_name = match self.get_scope_for_ip(ip_address) {
            Some(name) => name,
            None => return Ok(Vec::new()),
        };
        let mut domains = Vec::new();
        {
            let conn = self.lock()?;
            let mut stmt =
                conn.prepare_cached("SELECT home_domain FROM network_scopes WHERE name = ?1")?;
            let mut rows = stmt.query_map(params![scope_name], |row| row.get::<_, String>(0))?;
            if let Some(row) = rows.next() {
                domains.push(row?);
            } else {
                return Ok(Vec::new());
            }
        }
        for tld in self.list_scope_tlds(&scope_name)? {
            if !domains.contains(&tld) {
                domains.push(tld);
            }
        }
        Ok(domains)
    }

    // ================================================================
    // Scope TLDs (per-network owned zones, partitioned across networks)
    // ================================================================

    /// Registers an additional TLD (owned zone) for a scope. The TLD is
    /// normalized to lowercase with a trailing dot. Owned TLDs are globally
    /// unique: if the TLD is already owned by any scope (including via a
    /// `home_domain`), returns a `TldConflict`.
    pub fn add_scope_tld(&self, scope_name: &str, tld: &str) -> Result<()> {
        let normalized = normalize_name(tld);
        if normalized.is_empty() || normalized == "." {
            return Err(anyhow!("tld must not be empty"));
        }
        if let Some(existing) = self.tld_owner_cache.get(&normalized)
            && existing.value() != scope_name
        {
            return Err(TldConflict {
                tld: normalized,
                owner: existing.value().clone(),
            }
            .into());
        }
        // Guard against registering a TLD for a nonexistent scope (there is no
        // enforced foreign key at runtime).
        if self.get_network_scope(scope_name)?.is_none() {
            return Err(anyhow!("scope '{}' does not exist", scope_name));
        }
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO scope_tlds (scope_name, tld) VALUES (?1, ?2)",
            params![scope_name, normalized],
        )
        .context("failed to add scope tld")?;
        drop(conn);
        self.tld_owner_cache
            .insert(normalized, scope_name.to_string());
        Ok(())
    }

    /// Removes an additional owned TLD from a scope. A scope's `home_domain`
    /// (the implicit primary TLD) cannot be removed this way. Returns whether a
    /// row was removed.
    pub fn remove_scope_tld(&self, scope_name: &str, tld: &str) -> Result<bool> {
        let normalized = normalize_name(tld);
        if let Some(scope) = self.get_network_scope(scope_name)?
            && normalize_name(&scope.home_domain) == normalized
        {
            return Err(anyhow!(
                "cannot remove '{}': it is the home_domain (primary TLD) of scope '{}'",
                normalized,
                scope_name
            ));
        }
        let conn = self.lock()?;
        let count = conn.execute(
            "DELETE FROM scope_tlds WHERE scope_name = ?1 AND tld = ?2",
            params![scope_name, normalized],
        )?;
        conn.execute(
            "DELETE FROM scope_tld_forwarders WHERE scope_name = ?1 AND tld = ?2",
            params![scope_name, normalized],
        )?;
        conn.execute(
            "DELETE FROM tld_listeners WHERE scope_name = ?1 AND tld = ?2",
            params![scope_name, normalized],
        )?;
        drop(conn);
        if count > 0 {
            self.tld_owner_cache.remove(&normalized);
            self.tld_forwarder_cache
                .remove(&tld_fwd_key(scope_name, &normalized));
            self.tld_ingress_cache.remove(&normalized);
        }
        Ok(count > 0)
    }

    /// Sets (or replaces) the ingress listener IP for an owned TLD. The TLD must
    /// already be owned by `scope_name` (via `add_scope_tld` or as the scope's
    /// `home_domain`). Programmed A/AAAA names under this TLD, queried on the
    /// matching local listener, resolve to `listen_ip`. Updates the database and
    /// the hot-path `tld_ingress_cache`.
    pub fn set_tld_listener(&self, scope_name: &str, tld: &str, listen_ip: IpAddr) -> Result<()> {
        let normalized = normalize_name(tld);
        match self.tld_owner_cache.get(&normalized) {
            Some(owner) if owner.value() == scope_name => {}
            Some(owner) => {
                return Err(anyhow!(
                    "tld '{}' is owned by scope '{}', not '{}'",
                    normalized,
                    owner.value(),
                    scope_name
                ));
            }
            None => {
                return Err(anyhow!(
                    "tld '{}' is not owned by scope '{}'; register it first",
                    normalized,
                    scope_name
                ));
            }
        }
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO tld_listeners (scope_name, tld, listen_ip) VALUES (?1, ?2, ?3)
             ON CONFLICT(scope_name, tld) DO UPDATE SET listen_ip = excluded.listen_ip",
            params![scope_name, normalized, listen_ip.to_string()],
        )
        .context("failed to set tld listener")?;
        drop(conn);
        self.tld_ingress_cache.insert(normalized, listen_ip);
        Ok(())
    }

    /// Removes the ingress listener for an owned TLD (the TLD ownership itself is
    /// unaffected). Returns whether a row was removed.
    pub fn remove_tld_listener(&self, scope_name: &str, tld: &str) -> Result<bool> {
        let normalized = normalize_name(tld);
        let conn = self.lock()?;
        let count = conn.execute(
            "DELETE FROM tld_listeners WHERE scope_name = ?1 AND tld = ?2",
            params![scope_name, normalized],
        )?;
        drop(conn);
        if count > 0 {
            self.tld_ingress_cache.remove(&normalized);
        }
        Ok(count > 0)
    }

    /// Returns the ingress listener IP for a normalized TLD, if one is set.
    /// Cache-only, O(1) — safe on the DNS hot path.
    pub fn get_tld_ingress(&self, tld: &str) -> Option<IpAddr> {
        self.tld_ingress_cache
            .get(&normalize_name(tld))
            .map(|e| *e.value())
    }

    /// Reverse of `get_tld_ingress`: the scope that owns a TLD whose ingress
    /// listener is bound to `ip`, if any.
    ///
    /// This associates a query with its network scope by the LISTENER it
    /// arrived on rather than by the queried name, so an ingress listener acts
    /// as its network's dedicated resolver for the *whole* namespace: owned-TLD
    /// names are partitioned/rewritten as before, and every other name
    /// (`google.com`, …) falls through to global resolution and forwarding
    /// instead of being refused as an unassociated overlay peer. Cache-only,
    /// safe on the DNS hot path. If several TLDs share the ingress IP (all
    /// belonging to the same network in practice) the first owner found wins.
    pub fn scope_for_ingress_ip(&self, ip: IpAddr) -> Option<String> {
        for entry in self.tld_ingress_cache.iter() {
            if *entry.value() == ip
                && let Some(owner) = self.tld_owner_cache.get(entry.key())
            {
                return Some(owner.value().clone());
            }
        }
        None
    }

    /// Lists the ingress listeners for a scope's TLDs as `(tld, listen_ip)`.
    pub fn list_tld_listeners(&self, scope_name: &str) -> Result<Vec<(String, IpAddr)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT tld, listen_ip FROM tld_listeners WHERE scope_name = ?1 ORDER BY tld",
        )?;
        let rows = stmt.query_map(params![scope_name], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (tld, ip) = row?;
            if let Ok(parsed) = ip.parse::<IpAddr>() {
                out.push((tld, parsed));
            }
        }
        Ok(out)
    }

    /// Returns the distinct set of ingress listener IPs across all scopes. Used
    /// at boot to (re-)create the ingress DNS listeners, and to decide whether a
    /// listener IP is still referenced after a TLD is removed.
    pub fn list_all_tld_ingress_ips(&self) -> Vec<IpAddr> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for entry in self.tld_ingress_cache.iter() {
            let ip = *entry.value();
            if seen.insert(ip) {
                out.push(ip);
            }
        }
        out
    }

    /// Lists a scope's additional owned TLDs (from `scope_tlds`, not including
    /// the implicit `home_domain`).
    pub fn list_scope_tlds(&self, scope_name: &str) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare_cached("SELECT tld FROM scope_tlds WHERE scope_name = ?1 ORDER BY tld")?;
        let rows = stmt.query_map(params![scope_name], |row| row.get::<_, String>(0))?;
        let mut tlds = Vec::new();
        for row in rows {
            tlds.push(row?);
        }
        Ok(tlds)
    }

    /// Lists all TLDs a scope owns: its `home_domain` (first) followed by any
    /// additional registered TLDs.
    pub fn list_all_owned_tlds(&self, scope_name: &str) -> Result<Vec<String>> {
        let mut tlds = Vec::new();
        if let Some(scope) = self.get_network_scope(scope_name)? {
            tlds.push(normalize_name(&scope.home_domain));
        }
        for tld in self.list_scope_tlds(scope_name)? {
            if !tlds.contains(&tld) {
                tlds.push(tld);
            }
        }
        Ok(tlds)
    }

    /// Finds the scope that owns a covering TLD for `qname`, if any. Walks the
    /// qname's suffixes (most specific first) against the owned-TLD cache,
    /// returning `(owning_scope, matched_tld)`. O(labels), cache-only — safe on
    /// the DNS hot path.
    pub fn find_tld_owner(&self, qname: &str) -> Option<(String, String)> {
        let normalized = normalize_name(qname);
        if let Some(owner) = self.tld_owner_cache.get(&normalized) {
            return Some((owner.value().clone(), normalized));
        }
        let trimmed = normalized.trim_end_matches('.');
        let mut start = 0;
        while let Some(dot_pos) = trimmed[start..].find('.') {
            let suffix_start = start + dot_pos + 1;
            if suffix_start >= trimmed.len() {
                break;
            }
            let mut suffix = String::with_capacity(trimmed.len() - suffix_start + 1);
            suffix.push_str(&trimmed[suffix_start..]);
            suffix.push('.');
            if let Some(owner) = self.tld_owner_cache.get(&suffix) {
                return Some((owner.value().clone(), suffix));
            }
            start = suffix_start;
        }
        None
    }

    /// Replaces the peer forwarder set for a scope's TLD. Each forwarder is an
    /// "ip:port" address of another network member's rolodex server. Invalid
    /// addresses are rejected. Updates both the database and the hot-path cache.
    pub fn set_scope_tld_forwarders(
        &self,
        scope_name: &str,
        tld: &str,
        forwarders: &[String],
    ) -> Result<()> {
        let normalized = normalize_name(tld);
        // Validate + parse all addresses up front so the hot path never re-parses.
        let mut parsed = Vec::with_capacity(forwarders.len());
        for addr in forwarders {
            let sa: SocketAddr = addr
                .parse()
                .with_context(|| format!("invalid forwarder address '{addr}'"))?;
            parsed.push(sa);
        }
        // Ownership sanity: the TLD should be owned by this scope. Not fatal to
        // resolution (the hot path keys forwarders by scope+tld), but reject the
        // obvious misconfiguration of setting forwarders for another scope's TLD.
        if let Some(owner) = self.tld_owner_cache.get(&normalized)
            && owner.value() != scope_name
        {
            return Err(TldConflict {
                tld: normalized,
                owner: owner.value().clone(),
            }
            .into());
        }
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM scope_tld_forwarders WHERE scope_name = ?1 AND tld = ?2",
            params![scope_name, normalized],
        )?;
        for addr in forwarders {
            conn.execute(
                "INSERT OR IGNORE INTO scope_tld_forwarders (scope_name, tld, forwarder_addr) VALUES (?1, ?2, ?3)",
                params![scope_name, normalized, addr],
            )?;
        }
        drop(conn);
        let key = tld_fwd_key(scope_name, &normalized);
        if parsed.is_empty() {
            self.tld_forwarder_cache.remove(&key);
        } else {
            self.tld_forwarder_cache.insert(key, parsed);
        }
        Ok(())
    }

    /// Lists the configured peer forwarder addresses for a scope's TLD (from the
    /// database, as "ip:port" strings).
    pub fn list_scope_tld_forwarders(&self, scope_name: &str, tld: &str) -> Result<Vec<String>> {
        let normalized = normalize_name(tld);
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT forwarder_addr FROM scope_tld_forwarders WHERE scope_name = ?1 AND tld = ?2 ORDER BY forwarder_addr",
        )?;
        let rows = stmt.query_map(params![scope_name, normalized], |row| {
            row.get::<_, String>(0)
        })?;
        let mut addrs = Vec::new();
        for row in rows {
            addrs.push(row?);
        }
        Ok(addrs)
    }

    /// Returns the parsed peer forwarders for a (scope, TLD) from the in-memory
    /// cache. Hot-path helper for the resolver; empty if none configured.
    pub fn get_tld_forwarders_cached(&self, scope_name: &str, tld: &str) -> Vec<SocketAddr> {
        self.tld_forwarder_cache
            .get(&tld_fwd_key(scope_name, tld))
            .map(|entry| entry.value().clone())
            .unwrap_or_default()
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

    /// Replaces the operator's tracked-TLD list — the Prometheus `tld` label
    /// dimension's opt-in set, over and above the owned TLDs that are tracked
    /// automatically.
    ///
    /// The magic `common` entry is stored verbatim rather than expanded here, so
    /// a read-back reports what the operator actually asked for and a later
    /// change to [`crate::metrics::COMMON_TLDS`] takes effect without every
    /// deployment having to re-issue the call. Expansion happens in
    /// [`crate::metrics::Metrics::set_tracked_tlds`].
    ///
    /// Replace-not-merge, matching `SetForwarders` and `SetDnsblConfig`: a setter
    /// that only ever accumulates gives an operator no way to remove an entry.
    pub fn set_tracked_tlds(&self, tlds: &[String]) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM tracked_tlds", [])?;
        {
            let mut stmt = tx.prepare("INSERT OR IGNORE INTO tracked_tlds (tld) VALUES (?1)")?;
            for tld in tlds {
                let trimmed = tld.trim();
                if trimmed.is_empty() {
                    continue;
                }
                // `common` is a keyword, not a name: keep it unqualified so the
                // expander recognizes it. Everything else is normalized on the
                // way in, so `Example.COM`, `example.com` and `example.com.` are
                // one entry.
                let stored = if trimmed.eq_ignore_ascii_case("common") {
                    "common".to_string()
                } else {
                    normalize_name(trimmed)
                };
                stmt.execute(params![stored])?;
            }
        }
        tx.commit().context("failed to set tracked TLDs")?;
        Ok(())
    }

    /// The operator's stored tracked-TLD list, sorted for a stable read-back.
    pub fn list_tracked_tlds(&self) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached("SELECT tld FROM tracked_tlds ORDER BY tld")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut tlds = Vec::new();
        for row in rows {
            tlds.push(row?);
        }
        Ok(tlds)
    }

    /// Every TLD owned by a network scope, including each scope's implicit
    /// `.home` domain.
    ///
    /// Read from the in-memory ownership cache rather than `scope_tlds`, because
    /// this is called on the metrics refresh path and the cache is already the
    /// authority the DNS hot path consults — going to SQLite here would take the
    /// database lock to learn something already in memory.
    pub fn owned_tlds(&self) -> Vec<String> {
        self.tld_owner_cache
            .iter()
            .map(|e| e.key().clone())
            .collect()
    }

    /// Number of implicitly-managed zones, read straight off the in-memory
    /// cache. Unlike [`Self::get_managed_zones_cached`] this clones nothing,
    /// which matters on the scrape path where only the count is wanted.
    pub fn managed_zone_count(&self) -> usize {
        self.managed_zones_cache.len()
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
        // Check all suffix zones of the name against the caches (O(labels) instead of O(zones))
        self.matches_zone_suffix(&normalized, &self.authoritative_zones_cache)
            || self.matches_zone_suffix(&normalized, &self.managed_zones_cache)
    }

    /// Checks if any suffix of a DNS name matches an entry in the zone set.
    /// Walks up from the full name (e.g. "sub.example.com.") checking each
    /// parent zone ("example.com.", "com.") against the set.
    pub fn matches_zone_suffix(&self, normalized: &str, zones: &DashSet<String>) -> bool {
        if zones.contains(normalized) {
            return true;
        }
        let trimmed = normalized.trim_end_matches('.');
        let mut start = 0;
        while let Some(dot_pos) = trimmed[start..].find('.') {
            let suffix_start = start + dot_pos + 1;
            if suffix_start >= trimmed.len() {
                break;
            }
            let mut suffix = String::with_capacity(trimmed.len() - suffix_start + 1);
            suffix.push_str(&trimmed[suffix_start..]);
            suffix.push('.');
            if zones.contains(&suffix) {
                return true;
            }
            start = suffix_start;
        }
        false
    }

    /// Returns the matching managed zone for a qname, if any.
    pub fn find_managed_zone(&self, name: &str) -> Option<String> {
        let normalized = normalize_name(name);
        if self.managed_zones_cache.contains(&normalized) {
            return Some(normalized);
        }
        let trimmed = normalized.trim_end_matches('.');
        let mut start = 0;
        while let Some(dot_pos) = trimmed[start..].find('.') {
            let suffix_start = start + dot_pos + 1;
            if suffix_start >= trimmed.len() {
                break;
            }
            let mut suffix = String::with_capacity(trimmed.len() - suffix_start + 1);
            suffix.push_str(&trimmed[suffix_start..]);
            suffix.push('.');
            if self.managed_zones_cache.contains(&suffix) {
                return Some(suffix);
            }
            start = suffix_start;
        }
        None
    }

    /// Returns the matching authoritative zone for a qname, if any.
    pub fn find_authoritative_zone(&self, name: &str) -> Option<String> {
        let normalized = normalize_name(name);
        if self.authoritative_zones_cache.contains(&normalized) {
            return Some(normalized);
        }
        let trimmed = normalized.trim_end_matches('.');
        let mut start = 0;
        while let Some(dot_pos) = trimmed[start..].find('.') {
            let suffix_start = start + dot_pos + 1;
            if suffix_start >= trimmed.len() {
                break;
            }
            let mut suffix = String::with_capacity(trimmed.len() - suffix_start + 1);
            suffix.push_str(&trimmed[suffix_start..]);
            suffix.push('.');
            if self.authoritative_zones_cache.contains(&suffix) {
                return Some(suffix);
            }
            start = suffix_start;
        }
        None
    }

    // ================================================================
    // Local blocklist management
    // ================================================================

    pub fn add_local_blocklist_entry(&self, name: &str, reason: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO local_blocklist_entries (name, reason) VALUES (?1, ?2)",
            params![name, reason],
        )
        .context("failed to add local blocklist entry")?;
        self.local_blocklist_cache.insert(name.to_string());
        Ok(())
    }

    pub fn remove_local_blocklist_entry(&self, name: &str) -> Result<bool> {
        let conn = self.lock()?;
        let count = conn
            .execute(
                "DELETE FROM local_blocklist_entries WHERE name = ?1",
                params![name],
            )
            .context("failed to remove local blocklist entry")?;
        if count > 0 {
            self.local_blocklist_cache.remove(name);
        }
        Ok(count > 0)
    }

    pub fn list_local_blocklist_entries(&self) -> Result<Vec<(String, String)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached("SELECT name, reason FROM local_blocklist_entries")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    pub fn lookup_local_blocklist(&self, name: &str) -> bool {
        self.local_blocklist_cache.contains(name)
    }

    // ================================================================
    // DNSBL Allowlist Management
    // ================================================================

    /// Adds a name to the DNSBL allowlist, exempting it (and everything under
    /// it) from the name-based blocklist check. The name is normalized on the
    /// way in so that `Example.COM`, `example.com`, and `example.com.` are one
    /// entry rather than three.
    pub fn add_dnsbl_allowlist_entry(&self, name: &str, reason: &str) -> Result<()> {
        let normalized = normalize_name(name.trim());
        if normalized.is_empty() || normalized == "." {
            anyhow::bail!("DNSBL allowlist entry name must not be empty");
        }
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO dnsbl_allowlist (name, reason) VALUES (?1, ?2)",
            params![normalized, reason],
        )
        .context("failed to add DNSBL allowlist entry")?;
        self.dnsbl_allowlist_cache.insert(normalized);
        Ok(())
    }

    /// Removes a name from the DNSBL allowlist. Returns whether an entry was
    /// removed.
    pub fn remove_dnsbl_allowlist_entry(&self, name: &str) -> Result<bool> {
        let normalized = normalize_name(name.trim());
        let conn = self.lock()?;
        let count = conn
            .execute(
                "DELETE FROM dnsbl_allowlist WHERE name = ?1",
                params![normalized],
            )
            .context("failed to remove DNSBL allowlist entry")?;
        if count > 0 {
            self.dnsbl_allowlist_cache.remove(&normalized);
        }
        Ok(count > 0)
    }

    /// Returns every DNSBL allowlist entry as `(name, reason)`.
    pub fn list_dnsbl_allowlist_entries(&self) -> Result<Vec<(String, String)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached("SELECT name, reason FROM dnsbl_allowlist")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Whether `name` is exempt from the name-based blocklist check. Matches the
    /// allowlisted name itself and any name beneath it, so one entry for a
    /// domain covers its whole subtree.
    pub fn is_dnsbl_allowlisted(&self, name: &str) -> bool {
        if self.dnsbl_allowlist_cache.is_empty() {
            return false;
        }
        let normalized = normalize_name(name);
        self.matches_zone_suffix(&normalized, &self.dnsbl_allowlist_cache)
    }

    /// Whether `literal` is allowlisted as an **exact** entry, with no subtree
    /// match. This is the form used for IP literals, which is how the local
    /// blocklist blocks an address (`lookup_local_blocklist` is given
    /// `ip.to_string()`), so it is
    /// the form an exemption for that address has to take.
    ///
    /// Suffix matching is meaningless on an address: an IPv4 literal is written
    /// most-significant-octet first, so `1.100` is not a parent of
    /// `192.168.1.100` the way `example.com` is a parent of `www.example.com` —
    /// treating it as one would exempt addresses the operator never named. The
    /// reverse *name* (`100.1.168.192.in-addr.arpa.`) is a real DNS name and is
    /// matched by [`is_dnsbl_allowlisted`](Self::is_dnsbl_allowlisted) as usual.
    pub fn is_dnsbl_allowlisted_exact(&self, literal: &str) -> bool {
        if self.dnsbl_allowlist_cache.is_empty() {
            return false;
        }
        self.dnsbl_allowlist_cache
            .contains(&normalize_name(literal))
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
            "INSERT INTO dns_cache (name, record_type, value, ttl, original_ttl, cached_at, source) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT(name, record_type, value) DO UPDATE SET \
                 ttl = excluded.ttl, \
                 original_ttl = excluded.original_ttl, \
                 cached_at = excluded.cached_at, \
                 source = excluded.source",
            params![name, record_type, value, ttl as i64, original_ttl as i64, now, source],
        )
        .context("failed to insert cache entry")?;
        Ok(())
    }

    /// Loads every non-expired cache row, with each record's TTL rewritten to the
    /// remaining lifetime.
    ///
    /// `cache_lookup` filters on `WHERE name = ?1`, so the boot-load path used to
    /// call it with an empty name and silently load nothing on every start (hence
    /// the perennial "DNS cache loaded (0 entries)"). This is the query it should
    /// have been making.
    pub fn cache_load_all(&self) -> Result<Vec<(DnsRecord, u32)>> {
        let conn = self.lock()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs() as i64;

        let mut stmt = conn.prepare_cached(
            "SELECT name, record_type, value, ttl, cached_at FROM dns_cache WHERE cached_at + ttl > ?1",
        )?;
        let rows = stmt.query_map(params![now], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (name, rt_str, value, ttl, cached_at) = row?;
            let remaining = ttl - (now - cached_at);
            if remaining <= 0 {
                continue;
            }
            let remaining = remaining as u32;
            out.push((
                DnsRecord {
                    id: None,
                    name,
                    record_type: RecordKind::parse(&rt_str).unwrap_or(RecordKind::A),
                    value,
                    ttl: remaining,
                    priority: 0,
                },
                remaining,
            ));
        }
        Ok(out)
    }

    // ================================================================
    // Delegation cache (zone -> nameserver addresses)
    // ================================================================

    /// Upserts one nameserver address for `zone`. Keyed on (zone, ns_ip), so
    /// re-learning a delegation refreshes it in place instead of appending.
    pub fn delegation_insert(&self, zone: &str, ns_ip: &str, ttl: u32) -> Result<()> {
        let conn = self.lock()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs() as i64;
        conn.execute(
            "INSERT INTO delegation_cache (zone, ns_ip, ttl, cached_at) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(zone, ns_ip) DO UPDATE SET ttl = excluded.ttl, cached_at = excluded.cached_at",
            params![zone, ns_ip, ttl as i64, now],
        )
        .context("failed to insert delegation")?;
        Ok(())
    }

    /// Replaces the full nameserver set for `zone` in one transaction, so a
    /// shrinking NS set does not leave stale addresses behind.
    pub fn delegation_replace(&self, zone: &str, ns_ips: &[String], ttl: u32) -> Result<()> {
        let mut conn = self.lock()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs() as i64;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM delegation_cache WHERE zone = ?1",
            params![zone],
        )?;
        for ip in ns_ips {
            tx.execute(
                "INSERT INTO delegation_cache (zone, ns_ip, ttl, cached_at) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(zone, ns_ip) DO UPDATE SET ttl = excluded.ttl, cached_at = excluded.cached_at",
                params![zone, ip, ttl as i64, now],
            )?;
        }
        tx.commit().context("failed to replace delegation")?;
        Ok(())
    }

    /// Loads every non-expired delegation, grouped by zone, with the remaining TTL.
    pub fn delegation_load_all(&self) -> Result<Vec<(String, Vec<String>, u32)>> {
        let conn = self.lock()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs() as i64;

        let mut stmt = conn.prepare_cached(
            "SELECT zone, ns_ip, ttl, cached_at FROM delegation_cache WHERE cached_at + ttl > ?1 ORDER BY zone",
        )?;
        let rows = stmt.query_map(params![now], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;

        let mut grouped: Vec<(String, Vec<String>, u32)> = Vec::new();
        for row in rows {
            let (zone, ns_ip, ttl, cached_at) = row?;
            let remaining = ttl - (now - cached_at);
            if remaining <= 0 {
                continue;
            }
            let remaining = remaining as u32;
            match grouped.last_mut() {
                Some((z, ips, rem)) if *z == zone => {
                    ips.push(ns_ip);
                    *rem = (*rem).min(remaining);
                }
                _ => grouped.push((zone, vec![ns_ip], remaining)),
            }
        }
        Ok(grouped)
    }

    pub fn delegation_flush(&self) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM delegation_cache", [])
            .context("failed to flush delegation cache")?;
        Ok(())
    }

    pub fn delegation_count(&self) -> Result<u64> {
        let conn = self.lock()?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM delegation_cache", [], |row| {
            row.get(0)
        })?;
        Ok(count as u64)
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

    /// Gets an ACME certificate by its row id (used by the ACME cert download URL).
    pub fn get_acme_certificate_by_id(&self, id: i64) -> Result<Option<AcmeCertRow>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, domain, cert_pem, key_pem, chain_pem, issued_at, expires_at
             FROM acme_certificates WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
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

    /// Lists all ACME certificates, newest first, optionally filtered by zone suffix.
    pub fn list_acme_certificates(&self, zone: Option<&str>) -> Result<Vec<AcmeCertRow>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, domain, cert_pem, key_pem, chain_pem, issued_at, expires_at
             FROM acme_certificates ORDER BY issued_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
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
        // Label-boundary matching, not `ends_with`: an operator auditing
        // `example.com` must not be shown a certificate for `notexample.com`,
        // which is somebody else's name.
        let suffix = zone.map(normalize_name);
        let mut out = Vec::new();
        for row in rows {
            let row = row?;
            match &suffix {
                Some(s) if !name_in_zone(&row.domain, s) => continue,
                _ => out.push(row),
            }
        }
        Ok(out)
    }

    // ================================================================
    // Per-Zone Intermediate CA Management
    // ================================================================

    /// Stores (or replaces) a per-zone intermediate CA.
    pub fn store_zone_ca(&self, zone: &str, cert_pem: &str, key_pem: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO zone_cas (zone, cert_pem, key_pem, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![normalize_name(zone), cert_pem, key_pem, now_secs()?],
        )
        .context("failed to store zone CA")?;
        Ok(())
    }

    /// Gets a per-zone intermediate CA `(cert_pem, key_pem)`.
    pub fn get_zone_ca(&self, zone: &str) -> Result<Option<(String, String)>> {
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare_cached("SELECT cert_pem, key_pem FROM zone_cas WHERE zone = ?1")?;
        let mut rows = stmt.query_map(params![normalize_name(zone)], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Lists the zones that have an intermediate CA.
    pub fn list_zone_cas(&self) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached("SELECT zone FROM zone_cas ORDER BY zone")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    // ================================================================
    // ACME Server Accounts, EAB, Orders, Authorizations, Challenges
    // ================================================================

    /// Creates an ACME server account.
    pub fn create_acme_account(&self, account: &AcmeAccount) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO acme_server_accounts
                (account_id, jwk, thumbprint, contacts, status, eab_kid, zone, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                account.account_id,
                account.jwk,
                account.thumbprint,
                account.contacts,
                account.status,
                account.eab_kid,
                account.zone,
                now_secs()?,
            ],
        )
        .context("failed to create ACME account")?;
        Ok(())
    }

    /// Gets an ACME account by its account id.
    pub fn get_acme_account(&self, account_id: &str) -> Result<Option<AcmeAccount>> {
        self.query_acme_account("account_id", account_id)
    }

    /// Gets an ACME account by its JWK thumbprint (for account key reuse on newAccount).
    pub fn get_acme_account_by_thumbprint(&self, thumbprint: &str) -> Result<Option<AcmeAccount>> {
        self.query_acme_account("thumbprint", thumbprint)
    }

    fn query_acme_account(&self, column: &str, value: &str) -> Result<Option<AcmeAccount>> {
        let conn = self.lock()?;
        // `column` is a fixed internal literal, never user input.
        let sql = format!(
            "SELECT account_id, jwk, thumbprint, contacts, status, eab_kid, zone
             FROM acme_server_accounts WHERE {} = ?1",
            column
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query_map(params![value], |row| {
            Ok(AcmeAccount {
                account_id: row.get(0)?,
                jwk: row.get(1)?,
                thumbprint: row.get(2)?,
                contacts: row.get(3)?,
                status: row.get(4)?,
                eab_kid: row.get(5)?,
                zone: row.get(6)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Lists all ACME server accounts.
    pub fn list_acme_accounts(&self) -> Result<Vec<AcmeAccount>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT account_id, jwk, thumbprint, contacts, status, eab_kid, zone
             FROM acme_server_accounts ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(AcmeAccount {
                account_id: row.get(0)?,
                jwk: row.get(1)?,
                thumbprint: row.get(2)?,
                contacts: row.get(3)?,
                status: row.get(4)?,
                eab_kid: row.get(5)?,
                zone: row.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Creates an EAB credential.
    pub fn create_eab(&self, kid: &str, hmac_key: &[u8], zone: Option<&str>) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO acme_eab (kid, hmac_key, zone, used, created_at) VALUES (?1, ?2, ?3, 0, ?4)",
            params![kid, hmac_key, zone, now_secs()?],
        )
        .context("failed to create EAB credential")?;
        Ok(())
    }

    /// Gets an EAB credential by kid.
    pub fn get_eab(&self, kid: &str) -> Result<Option<AcmeEab>> {
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare_cached("SELECT kid, hmac_key, zone, used FROM acme_eab WHERE kid = ?1")?;
        let mut rows = stmt.query_map(params![kid], |row| {
            Ok(AcmeEab {
                kid: row.get(0)?,
                hmac_key: row.get(1)?,
                zone: row.get(2)?,
                used: row.get::<_, i64>(3)? != 0,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Marks an EAB credential as used (one-time binding).
    pub fn mark_eab_used(&self, kid: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("UPDATE acme_eab SET used = 1 WHERE kid = ?1", params![kid])
            .context("failed to mark EAB used")?;
        Ok(())
    }

    /// Removes an EAB credential by kid. Returns true if a row was removed.
    pub fn remove_eab(&self, kid: &str) -> Result<bool> {
        let conn = self.lock()?;
        let n = conn
            .execute("DELETE FROM acme_eab WHERE kid = ?1", params![kid])
            .context("failed to remove EAB credential")?;
        Ok(n > 0)
    }

    /// How long an unused anti-replay nonce stays valid.
    ///
    /// A nonce is minted on *every* ACME response, including unauthenticated
    /// `GET /acme/directory`, and only the ones a client actually spends are
    /// removed by [`consume_nonce`]. Without an expiry the table grew by a row
    /// per request forever — an unauthenticated remote client could fill the
    /// disk, contending all the while on the mutex the DNS hot path uses.
    ///
    /// An hour is far longer than the seconds a real client holds a nonce for,
    /// and it also gives anti-replay an actual time bound.
    pub const NONCE_TTL_SECS: i64 = 3600;

    /// Hard ceiling on outstanding (unconsumed) nonces.
    ///
    /// The TTL alone does not bound the table: a burst arriving inside one
    /// second is all within the window, so a flood still grows it without limit.
    /// The cap is what makes the bound real. Eviction is oldest-first, which
    /// costs an attacker their own older nonces long before it costs a
    /// legitimate client, since a real client spends its nonce immediately.
    pub const MAX_OUTSTANDING_NONCES: i64 = 1024;

    /// Stores a freshly issued anti-replay nonce, then enforces both bounds.
    ///
    /// Pruning rides along with minting so no separate sweep task is needed: the
    /// table can only grow on the same path that trims it.
    pub fn store_nonce(&self, nonce: &str) -> Result<()> {
        let now = now_secs()?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO acme_nonces (nonce, created_at) VALUES (?1, ?2)",
            params![nonce, now],
        )
        .context("failed to store nonce")?;
        conn.execute(
            "DELETE FROM acme_nonces WHERE created_at < ?1",
            params![now - Self::NONCE_TTL_SECS],
        )
        .context("failed to prune expired nonces")?;
        // Keep only the newest MAX_OUTSTANDING_NONCES rows. `LIMIT -1 OFFSET n`
        // is SQLite's "everything after the first n".
        conn.execute(
            "DELETE FROM acme_nonces WHERE nonce IN (
                 SELECT nonce FROM acme_nonces
                 ORDER BY created_at DESC, rowid DESC
                 LIMIT -1 OFFSET ?1
             )",
            params![Self::MAX_OUTSTANDING_NONCES],
        )
        .context("failed to cap the nonce table")?;
        Ok(())
    }

    /// Consumes a nonce, returning true if it existed, is not expired, and is
    /// now removed. An expired nonce is deleted but reported as unusable.
    pub fn consume_nonce(&self, nonce: &str) -> Result<bool> {
        let cutoff = now_secs()? - Self::NONCE_TTL_SECS;
        let conn = self.lock()?;
        let n = conn
            .execute(
                "DELETE FROM acme_nonces WHERE nonce = ?1 AND created_at >= ?2",
                params![nonce, cutoff],
            )
            .context("failed to consume nonce")?;
        Ok(n > 0)
    }

    /// The number of outstanding (unconsumed) nonces. Used by tests to prove the
    /// table stays bounded.
    pub fn count_nonces(&self) -> Result<i64> {
        let conn = self.lock()?;
        let count = conn
            .query_row("SELECT COUNT(*) FROM acme_nonces", [], |row| row.get(0))
            .context("failed to count nonces")?;
        Ok(count)
    }

    /// Creates an ACME order.
    pub fn create_order(&self, order: &AcmeOrder) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO acme_orders
                (id, account_id, status, identifiers, authorizations, cert_id, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                order.id,
                order.account_id,
                order.status,
                order.identifiers,
                order.authorizations,
                order.cert_id,
                order.expires_at,
                now_secs()?,
            ],
        )
        .context("failed to create ACME order")?;
        Ok(())
    }

    /// Gets an ACME order by id.
    pub fn get_order(&self, id: &str) -> Result<Option<AcmeOrder>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, account_id, status, identifiers, authorizations, cert_id, expires_at
             FROM acme_orders WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(AcmeOrder {
                id: row.get(0)?,
                account_id: row.get(1)?,
                status: row.get(2)?,
                identifiers: row.get(3)?,
                authorizations: row.get(4)?,
                cert_id: row.get(5)?,
                expires_at: row.get(6)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Finds the order that a certificate was issued under.
    ///
    /// Certificates are addressed by a sequential rowid, so the ACME
    /// certificate-download endpoint needs a way to tell whose certificate a
    /// given id refers to. The issuing order carries the account.
    pub fn get_order_by_cert_id(&self, cert_id: i64) -> Result<Option<AcmeOrder>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, account_id, status, identifiers, authorizations, cert_id, expires_at
             FROM acme_orders WHERE cert_id = ?1",
        )?;
        let mut rows = stmt.query_map(params![cert_id], |row| {
            Ok(AcmeOrder {
                id: row.get(0)?,
                account_id: row.get(1)?,
                status: row.get(2)?,
                identifiers: row.get(3)?,
                authorizations: row.get(4)?,
                cert_id: row.get(5)?,
                expires_at: row.get(6)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Updates an order's status and (optionally) the issued certificate id.
    pub fn update_order(&self, id: &str, status: &str, cert_id: Option<i64>) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE acme_orders SET status = ?2, cert_id = ?3 WHERE id = ?1",
            params![id, status, cert_id],
        )
        .context("failed to update ACME order")?;
        Ok(())
    }

    /// Creates an authorization.
    pub fn create_authorization(&self, authz: &AcmeAuthorization) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO acme_authorizations
                (id, order_id, account_id, identifier, status, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                authz.id,
                authz.order_id,
                authz.account_id,
                authz.identifier,
                authz.status,
                authz.expires_at,
                now_secs()?,
            ],
        )
        .context("failed to create authorization")?;
        Ok(())
    }

    /// Gets an authorization by id.
    pub fn get_authorization(&self, id: &str) -> Result<Option<AcmeAuthorization>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, order_id, account_id, identifier, status, expires_at
             FROM acme_authorizations WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(AcmeAuthorization {
                id: row.get(0)?,
                order_id: row.get(1)?,
                account_id: row.get(2)?,
                identifier: row.get(3)?,
                status: row.get(4)?,
                expires_at: row.get(5)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Updates an authorization's status.
    pub fn update_authorization_status(&self, id: &str, status: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE acme_authorizations SET status = ?2 WHERE id = ?1",
            params![id, status],
        )
        .context("failed to update authorization")?;
        Ok(())
    }

    /// Creates a challenge.
    pub fn create_challenge(&self, chal: &AcmeChallenge) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO acme_challenges
                (id, authz_id, challenge_type, token, status, validated_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                chal.id,
                chal.authz_id,
                chal.challenge_type,
                chal.token,
                chal.status,
                chal.validated_at,
                now_secs()?,
            ],
        )
        .context("failed to create challenge")?;
        Ok(())
    }

    /// Gets a challenge by id.
    pub fn get_challenge(&self, id: &str) -> Result<Option<AcmeChallenge>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, authz_id, challenge_type, token, status, validated_at
             FROM acme_challenges WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(AcmeChallenge {
                id: row.get(0)?,
                authz_id: row.get(1)?,
                challenge_type: row.get(2)?,
                token: row.get(3)?,
                status: row.get(4)?,
                validated_at: row.get(5)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Lists challenges for an authorization.
    pub fn list_challenges_for_authz(&self, authz_id: &str) -> Result<Vec<AcmeChallenge>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, authz_id, challenge_type, token, status, validated_at
             FROM acme_challenges WHERE authz_id = ?1",
        )?;
        let rows = stmt.query_map(params![authz_id], |row| {
            Ok(AcmeChallenge {
                id: row.get(0)?,
                authz_id: row.get(1)?,
                challenge_type: row.get(2)?,
                token: row.get(3)?,
                status: row.get(4)?,
                validated_at: row.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Updates a challenge's status and validation timestamp.
    pub fn update_challenge_status(
        &self,
        id: &str,
        status: &str,
        validated_at: Option<i64>,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE acme_challenges SET status = ?2, validated_at = ?3 WHERE id = ?1",
            params![id, status, validated_at],
        )
        .context("failed to update challenge")?;
        Ok(())
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

    /// Collects every row count the Prometheus collector reports, in a single
    /// pass under one lock acquisition.
    ///
    /// The alternative — calling the various `list_*` methods at scrape time —
    /// would take and release the database mutex a dozen times and materialize
    /// every record in the zone just to call `.len()` on it. A scrape happens on
    /// someone else's schedule (typically every 15s, and nothing stops two
    /// Prometheus servers scraping at once), so it must not contend with the
    /// query path for the database lock.
    pub fn metrics_counts(&self) -> Result<MetricsCounts> {
        let conn = self.lock()?;
        let count = |sql: &str| -> Result<u64> {
            let mut stmt = conn.prepare_cached(sql)?;
            let n: i64 = stmt.query_row([], |row| row.get(0))?;
            Ok(n.max(0) as u64)
        };

        let mut counts = MetricsCounts {
            records: count("SELECT COUNT(*) FROM dns_records")?,
            scoped_records: count("SELECT COUNT(*) FROM scoped_dns_records")?,
            scopes: count("SELECT COUNT(*) FROM network_scopes")?,
            associations: count("SELECT COUNT(*) FROM network_associations")?,
            authoritative_zones: count("SELECT COUNT(*) FROM authoritative_zones")?,
            owned_tlds: count("SELECT COUNT(*) FROM scope_tlds")?,
            dhcp_pools: count("SELECT COUNT(*) FROM dhcp_pools")?,
            acme_accounts: count("SELECT COUNT(*) FROM acme_server_accounts")?,
            acme_certificates: count("SELECT COUNT(*) FROM acme_certificates")?,
            leases_by_state: Vec::new(),
        };

        let mut stmt =
            conn.prepare_cached("SELECT state, COUNT(*) FROM dhcp_leases GROUP BY state")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (state, n) = row?;
            counts.leases_by_state.push((state, n.max(0) as u64));
        }

        Ok(counts)
    }
}

/// Row counts sampled by the Prometheus collector; see
/// [`Database::metrics_counts`].
#[derive(Debug, Default)]
pub struct MetricsCounts {
    /// Rows in `dns_records` (the global, unscoped namespace).
    pub records: u64,
    /// Rows in `scoped_dns_records`, across every scope.
    pub scoped_records: u64,
    /// Configured network scopes.
    pub scopes: u64,
    /// Live IP-to-scope associations.
    pub associations: u64,
    /// Zones explicitly declared authoritative.
    pub authoritative_zones: u64,
    /// TLDs owned by a network scope.
    pub owned_tlds: u64,
    /// Configured DHCP address pools.
    pub dhcp_pools: u64,
    /// Registered ACME server accounts.
    pub acme_accounts: u64,
    /// Issued certificates on record.
    pub acme_certificates: u64,
    /// `(state, count)` pairs straight from the `dhcp_leases` table. States the
    /// collector does not recognize are simply not reported, so a future state
    /// value cannot land in the wrong series.
    pub leases_by_state: Vec<(String, u64)>,
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

/// Returns the current UNIX timestamp in seconds.
fn now_secs() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before UNIX epoch")?
        .as_secs() as i64)
}

/// Restricts `path` to `0600` — readable and writable by its owner only.
///
/// Used for files whose contents are secrets. Set explicitly rather than left to
/// the umask, because the umask is the operator's ambient preference and a
/// default one (0022) leaves a private key world-readable.
pub fn restrict_to_owner(path: &Path) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
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

/// Builds the reverse-DNS PTR owner name for an IP address.
///
/// IPv4 addresses produce `<reversed-octets>.in-addr.arpa.` and IPv6 addresses
/// produce the 32-nibble `<reversed-nibbles>.ip6.arpa.` form. The result always
/// carries a trailing dot. This is the inverse of the reverse-name parsing used
/// for reverse lookups, so a name built here round-trips back to the same address.
pub fn reverse_ptr_name(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        std::net::IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            // Emit nibbles least-significant first: for each byte (reading the
            // address from its last byte), push the low nibble then the high nibble.
            for byte in v6.octets().iter().rev() {
                s.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
                s.push('.');
                s.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
                s.push('.');
            }
            s.push_str("ip6.arpa.");
            s
        }
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

/// Whether `name` sits at or beneath `zone`, matching on label boundaries.
///
/// The naive spelling is `name.ends_with(zone)`, and it is wrong in a way that
/// reads as correct: `notexample.com.` ends with `example.com.` — the trailing
/// dot does not save it, because the mismatch is at the *front* of the zone
/// label. So the two names have to differ by a label separator, not merely by
/// text.
///
/// Every use of this is a place where the answer decides who owns a name: which
/// records a zone key signs, which certificates an operator is shown when they
/// audit a zone, and whether a miss inside a zone is an authoritative NXDOMAIN.
/// A false positive in any of them hands one party another party's names.
pub fn name_in_zone(name: &str, zone: &str) -> bool {
    let name = normalize_name(name);
    let zone = normalize_name(zone);
    if name == zone {
        return true;
    }
    // The root zone encloses everything.
    if zone == "." {
        return true;
    }
    name.ends_with(&format!(".{}", zone))
}

/// Escapes a string for use inside a SQL `LIKE` pattern with `ESCAPE '\'`.
///
/// `%` and `_` are LIKE wildcards, and `_` is also a perfectly legal DNS label
/// character — `_tcp`, `_acme-challenge` and every TLSA/SRV owner name uses it.
/// Interpolating one unescaped turns an exact suffix test into a fuzzy one.
fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// The reverse-DNS trees, where the last-two-labels heuristic does not name a
/// zone anyone could have delegated.
///
/// Deliberately *not* `arpa.` wholesale. `home.arpa.` (RFC 8375) is a
/// special-use domain for exactly the residential networks this server is built
/// for, and the heuristic handles it correctly — `foo.home.arpa.` yields
/// `home.arpa.`, which is the real zone. Excluding all of `arpa.` would stop a
/// miss under `home.arpa` being an authoritative NXDOMAIN and send it upstream,
/// where RFC 8375 §4 says it must never go.
const REVERSE_SUFFIXES: [&str; 2] = ["in-addr.arpa.", "ip6.arpa."];

/// Extracts the managed zone a stored record name implies — the last two labels
/// — or `None` where that heuristic does not describe a real zone.
///
/// E.g. "sub.example.com." -> Some("example.com.")
///      "tld." -> Some("tld.")
///
/// # Why the reverse trees are excluded
///
/// A managed zone makes this server *authoritative* for everything beneath it:
/// a miss inside one is an NXDOMAIN rather than a query passed upstream. For a
/// forward name that is the split-horizon bargain and the operator chose the
/// domain — storing `foo.example.com` claims `example.com`, which is a domain
/// they had in mind.
///
/// Under `in-addr.arpa` nobody chose anything. Reverse zones are delegated at
/// `1.168.192.in-addr.arpa` (a /24) or shorter, never at two labels, so the
/// heuristic always yields `in-addr.arpa.` itself — and registering *that* makes
/// one stored PTR turn this server into the authority for **the entire global
/// reverse tree**, NXDOMAINing every `in-addr.arpa` lookup on the internet. With
/// `dns.auto_ptr` enabled a single A record is enough to trigger it.
///
/// So the heuristic is not merely aggressive here, it is wrong: the zone it
/// derives is never the zone being managed. An operator who really does run a
/// reverse zone declares it with `AddAuthoritativeZone`, which matches on the
/// actual zone cut instead of guessing at it.
///
/// Note that the exclusion is the two reverse trees and not `arpa.` at large —
/// see [`REVERSE_SUFFIXES`].
///
/// # A note on the label arithmetic
///
/// "Last two labels" means a name that *is* two labels yields itself:
/// `host.example.` derives `host.example.`, not `example.`. That is why a
/// single stored record does not claim a whole TLD, and it is easy to get
/// backwards when reasoning about which names a stored record makes
/// authoritative.
fn extract_zone_from_name(name: &str) -> Option<String> {
    let normalized = normalize_name(name);
    if REVERSE_SUFFIXES
        .iter()
        .any(|suffix| name_in_zone(&normalized, suffix))
    {
        return None;
    }
    let parts: Vec<&str> = normalized.trim_end_matches('.').split('.').collect();
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
    fn opened_database_and_sidecars_are_owner_only() {
        // The database is the keystore (root CA key, zone intermediate keys,
        // DNSSEC private keys, EAB HMAC secrets), so it must not be created
        // under the bare umask.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rolodex-dns.db");
        let db = Database::open(&path).unwrap();
        // Force a write so the WAL sidecar definitely exists.
        db.add_record(&DnsRecord {
            id: None,
            name: "host.example.com.".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        for suffix in ["", "-wal", "-shm"] {
            let p = PathBuf::from(format!("{}{}", path.display(), suffix));
            if !p.exists() {
                continue;
            }
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode & 0o077,
                0,
                "{} is mode {:04o}; it must be readable by its owner only",
                p.display(),
                mode
            );
        }
    }

    #[test]
    fn test_reverse_ptr_name_ipv4() {
        let ip: std::net::IpAddr = "192.0.2.5".parse().unwrap();
        assert_eq!(reverse_ptr_name(ip), "5.2.0.192.in-addr.arpa.");
    }

    #[test]
    fn test_reverse_ptr_name_ipv6() {
        let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            reverse_ptr_name(ip),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
    }

    #[test]
    fn test_reverse_ptr_name_roundtrips_to_address() {
        // A name built here must parse back to the same IP via the reverse-name
        // parser used for RBL lookups (keeps both ends in lockstep).
        for raw in ["10.0.0.1", "255.254.253.252", "::1", "2001:db8:abcd::42"] {
            let ip: std::net::IpAddr = raw.parse().unwrap();
            let name = reverse_ptr_name(ip);
            let parsed = crate::dns_server::extract_ip_from_name(&name);
            assert_eq!(parsed, Some(ip), "round-trip failed for {raw}");
        }
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

    // ================================================================
    // lookup_with_fallbacks tests
    // ================================================================

    #[test]
    fn test_lookup_with_fallbacks_exact() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "host.example.com.".to_string(),
            record_type: RecordKind::A,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let result = db
            .lookup_with_fallbacks("host.example.com.", RecordKind::A)
            .unwrap();
        assert_eq!(result.exact.len(), 1);
        assert_eq!(result.exact[0].value, "1.2.3.4");
        assert!(result.wildcard.is_empty());
        assert!(result.cname.is_empty());
        assert!(result.aname.is_empty());
    }

    #[test]
    fn test_lookup_with_fallbacks_wildcard() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "*.example.com.".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let result = db
            .lookup_with_fallbacks("sub.example.com.", RecordKind::A)
            .unwrap();
        assert!(result.exact.is_empty());
        assert_eq!(result.wildcard.len(), 1);
        assert_eq!(result.wildcard[0].value, "10.0.0.1");
        // Wildcard should have qname substituted
        assert_eq!(result.wildcard[0].name, "sub.example.com.");
    }

    #[test]
    fn test_lookup_with_fallbacks_cname() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "alias.example.com.".to_string(),
            record_type: RecordKind::CNAME,
            value: "target.example.com.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let result = db
            .lookup_with_fallbacks("alias.example.com.", RecordKind::A)
            .unwrap();
        assert!(result.exact.is_empty());
        assert!(result.wildcard.is_empty());
        assert_eq!(result.cname.len(), 1);
        assert_eq!(result.cname[0].value, "target.example.com.");
    }

    #[test]
    fn test_lookup_with_fallbacks_aname() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "aname.example.com.".to_string(),
            record_type: RecordKind::ANAME,
            value: "target.example.com.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let result = db
            .lookup_with_fallbacks("aname.example.com.", RecordKind::A)
            .unwrap();
        assert!(result.exact.is_empty());
        assert!(result.wildcard.is_empty());
        assert!(result.cname.is_empty());
        assert_eq!(result.aname.len(), 1);
        assert_eq!(result.aname[0].value, "target.example.com.");
    }

    #[test]
    fn test_lookup_with_fallbacks_all_at_once() {
        let db = test_db();
        // Add exact, CNAME, and ANAME for the same name
        db.add_record(&DnsRecord {
            id: None,
            name: "multi.example.com.".to_string(),
            record_type: RecordKind::A,
            value: "1.1.1.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "multi.example.com.".to_string(),
            record_type: RecordKind::CNAME,
            value: "cname-target.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "multi.example.com.".to_string(),
            record_type: RecordKind::ANAME,
            value: "aname-target.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let result = db
            .lookup_with_fallbacks("multi.example.com.", RecordKind::A)
            .unwrap();
        assert_eq!(result.exact.len(), 1);
        assert_eq!(result.cname.len(), 1);
        assert_eq!(result.aname.len(), 1);
    }

    #[test]
    fn test_lookup_with_fallbacks_miss() {
        let db = test_db();
        let result = db
            .lookup_with_fallbacks("nonexistent.example.com.", RecordKind::A)
            .unwrap();
        assert!(result.exact.is_empty());
        assert!(result.wildcard.is_empty());
        assert!(result.cname.is_empty());
        assert!(result.aname.is_empty());
    }

    // ================================================================
    // matches_zone_suffix tests
    // ================================================================

    #[test]
    fn test_matches_zone_suffix_exact() {
        let db = test_db();
        db.add_authoritative_zone("example.com.").unwrap();
        assert!(db.matches_zone_suffix("example.com.", &db.authoritative_zones_cache));
    }

    #[test]
    fn test_matches_zone_suffix_subdomain() {
        let db = test_db();
        db.add_authoritative_zone("example.com.").unwrap();
        assert!(db.matches_zone_suffix("sub.example.com.", &db.authoritative_zones_cache));
        assert!(db.matches_zone_suffix("deep.sub.example.com.", &db.authoritative_zones_cache));
    }

    #[test]
    fn test_matches_zone_suffix_no_match() {
        let db = test_db();
        db.add_authoritative_zone("example.com.").unwrap();
        assert!(!db.matches_zone_suffix("other.org.", &db.authoritative_zones_cache));
        assert!(!db.matches_zone_suffix("notexample.com.", &db.authoritative_zones_cache));
    }

    #[test]
    fn test_matches_zone_suffix_empty_cache() {
        let db = test_db();
        assert!(!db.matches_zone_suffix("anything.com.", &db.authoritative_zones_cache));
    }

    // ================================================================
    // DNSBL allowlist tests
    // ================================================================

    #[test]
    fn test_dnsbl_allowlist_exact_and_subdomain() {
        let db = test_db();
        db.add_dnsbl_allowlist_entry("example.com", "false positive")
            .unwrap();
        // The entry covers the name itself...
        assert!(db.is_dnsbl_allowlisted("example.com."));
        // ... and everything under it.
        assert!(db.is_dnsbl_allowlisted("www.example.com."));
        assert!(db.is_dnsbl_allowlisted("deep.sub.example.com."));
        // But not a sibling that merely ends with the same characters.
        assert!(!db.is_dnsbl_allowlisted("notexample.com."));
        assert!(!db.is_dnsbl_allowlisted("example.org."));
    }

    #[test]
    fn test_dnsbl_allowlist_normalizes_name() {
        let db = test_db();
        // Stored with mixed case and no trailing dot; queried in every other
        // spelling — one entry, not three.
        db.add_dnsbl_allowlist_entry("  Example.COM  ", "").unwrap();
        assert!(db.is_dnsbl_allowlisted("example.com."));
        assert!(db.is_dnsbl_allowlisted("EXAMPLE.com"));
        let entries = db.list_dnsbl_allowlist_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "example.com.");
    }

    #[test]
    fn test_dnsbl_allowlist_empty_is_not_allowlisted() {
        let db = test_db();
        assert!(!db.is_dnsbl_allowlisted("example.com."));
    }

    /// The exact form matches the entry and nothing else. It exists for IP
    /// literals, where the suffix rule is not merely useless but wrong: octets
    /// run most-significant-first, so `1.100` is not a parent of `192.168.1.100`
    /// and must not exempt it.
    #[test]
    fn test_dnsbl_allowlist_exact_does_not_suffix_match() {
        let db = test_db();
        db.add_dnsbl_allowlist_entry("192.168.1.100", "mail host")
            .unwrap();
        assert!(db.is_dnsbl_allowlisted_exact("192.168.1.100"));
        assert!(db.is_dnsbl_allowlisted_exact("192.168.1.100."));

        db.add_dnsbl_allowlist_entry("1.100", "").unwrap();
        assert!(
            !db.is_dnsbl_allowlisted_exact("10.168.1.100"),
            "an exact match must not treat a trailing octet run as a parent"
        );
    }

    /// IPv6 literals carry no dots at all, so the exact form is the only one
    /// that can match them; normalization still folds case and trailing dot.
    #[test]
    fn test_dnsbl_allowlist_exact_matches_ipv6_literal() {
        let db = test_db();
        db.add_dnsbl_allowlist_entry("2001:DB8::1", "").unwrap();
        assert!(db.is_dnsbl_allowlisted_exact("2001:db8::1"));
        assert!(!db.is_dnsbl_allowlisted_exact("2001:db8::2"));
    }

    #[test]
    fn test_dnsbl_allowlist_exact_empty_is_not_allowlisted() {
        let db = test_db();
        assert!(!db.is_dnsbl_allowlisted_exact("192.168.1.100"));
    }

    #[test]
    fn test_dnsbl_allowlist_rejects_empty_and_root() {
        let db = test_db();
        // An empty or root entry would exempt the entire namespace.
        assert!(db.add_dnsbl_allowlist_entry("", "").is_err());
        assert!(db.add_dnsbl_allowlist_entry(".", "").is_err());
        assert!(db.list_dnsbl_allowlist_entries().unwrap().is_empty());
    }

    #[test]
    fn test_dnsbl_allowlist_remove() {
        let db = test_db();
        db.add_dnsbl_allowlist_entry("example.com", "temporary")
            .unwrap();
        assert!(db.is_dnsbl_allowlisted("www.example.com."));

        // Removal accepts any spelling of the name.
        assert!(db.remove_dnsbl_allowlist_entry("EXAMPLE.com.").unwrap());
        assert!(!db.is_dnsbl_allowlisted("www.example.com."));
        assert!(db.list_dnsbl_allowlist_entries().unwrap().is_empty());

        // Removing again reports that nothing was there.
        assert!(!db.remove_dnsbl_allowlist_entry("example.com").unwrap());
    }

    #[test]
    fn test_dnsbl_allowlist_list_returns_reason() {
        let db = test_db();
        db.add_dnsbl_allowlist_entry("cdn.example.com", "vendor CDN")
            .unwrap();
        db.add_dnsbl_allowlist_entry("mail.example.net", "")
            .unwrap();
        let mut entries = db.list_dnsbl_allowlist_entries().unwrap();
        entries.sort();
        assert_eq!(
            entries,
            vec![
                ("cdn.example.com.".to_string(), "vendor CDN".to_string()),
                ("mail.example.net.".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn test_dnsbl_allowlist_replaces_reason() {
        let db = test_db();
        db.add_dnsbl_allowlist_entry("example.com", "first")
            .unwrap();
        db.add_dnsbl_allowlist_entry("example.com.", "second")
            .unwrap();
        let entries = db.list_dnsbl_allowlist_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, "second");
    }

    #[test]
    fn test_dnsbl_allowlist_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist-boot.db");
        {
            let db = Database::open(&path).unwrap();
            db.add_dnsbl_allowlist_entry("example.com", "vendor")
                .unwrap();
        }
        // Reopen: the hot-path cache is rebuilt from disk in load_caches_at_boot,
        // so an allowlisted name is still exempt after a restart.
        let db = Database::open(&path).unwrap();
        assert!(db.is_dnsbl_allowlisted("www.example.com."));
        assert_eq!(db.list_dnsbl_allowlist_entries().unwrap().len(), 1);
    }

    #[test]
    fn test_matches_zone_suffix_tld() {
        let db = test_db();
        db.add_authoritative_zone("com.").unwrap();
        assert!(db.matches_zone_suffix("example.com.", &db.authoritative_zones_cache));
        assert!(db.matches_zone_suffix("sub.example.com.", &db.authoritative_zones_cache));
    }

    // ================================================================
    // find_managed_zone tests
    // ================================================================

    #[test]
    fn test_find_managed_zone_match() {
        let db = test_db();
        // Adding a record populates managed_zones_cache
        db.add_record(&DnsRecord {
            id: None,
            name: "host.example.com.".to_string(),
            record_type: RecordKind::A,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        assert_eq!(
            db.find_managed_zone("sub.example.com."),
            Some("example.com.".to_string())
        );
    }

    #[test]
    fn test_find_managed_zone_no_match() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "host.example.com.".to_string(),
            record_type: RecordKind::A,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        assert_eq!(db.find_managed_zone("other.org."), None);
    }

    fn a_record(name: &str, value: &str) -> DnsRecord {
        DnsRecord {
            id: None,
            name: name.to_string(),
            record_type: RecordKind::A,
            value: value.to_string(),
            ttl: 300,
            priority: 0,
        }
    }

    /// A zone is "has records" when anything lives *under* it, not only when its
    /// apex does. Storing `www.example.com` with nothing at `example.com` is the
    /// normal shape of a zone, and the query path turns this answer into an
    /// authoritative NXDOMAIN — so reading it as "the apex must have records"
    /// silently disables the whole managed-zone step for most real zones.
    #[test]
    fn zone_has_records_counts_names_beneath_the_apex() {
        let db = test_db();
        db.add_record(&a_record("www.example.com.", "192.0.2.1"))
            .unwrap();

        assert!(
            db.zone_has_records("example.com.").unwrap(),
            "a record under the zone must count"
        );
        assert!(
            !db.zone_has_records("other.org.").unwrap(),
            "an unrelated zone must not"
        );
    }

    /// Label-boundary matching: a zone name that merely shares a text suffix is
    /// a different zone.
    #[test]
    fn zone_has_records_matches_on_label_boundaries() {
        let db = test_db();
        db.add_record(&a_record("www.notexample.com.", "192.0.2.1"))
            .unwrap();
        assert!(!db.zone_has_records("example.com.").unwrap());
        assert!(db.zone_has_records("notexample.com.").unwrap());
    }

    /// `_` is a LIKE wildcard and a legal DNS label character. Unescaped, the
    /// suffix test would match any single character in its place and report a
    /// zone as occupied when it is empty — leaving a stale cache entry that
    /// NXDOMAINs a zone with nothing in it.
    #[test]
    fn zone_has_records_does_not_treat_underscores_as_wildcards() {
        let db = test_db();
        db.add_record(&a_record("host.ax.test.", "192.0.2.1"))
            .unwrap();
        assert!(
            !db.zone_has_records("_x.test.").unwrap(),
            "`_x.test.` must not be matched by `ax.test.`"
        );
    }

    /// The one that matters: `notexample.com.` genuinely *ends with*
    /// `example.com.`, so the trailing dot is not what makes a suffix test
    /// correct — the names must differ by a label separator.
    ///
    /// Every caller of this decides who owns a name: which records a zone key
    /// signs, which certificates an operator sees when auditing a zone, and
    /// whether a miss inside a zone is an authoritative NXDOMAIN. A false
    /// positive hands one party another party's names.
    #[test]
    fn name_in_zone_matches_on_label_boundaries() {
        assert!(name_in_zone("www.example.com.", "example.com."));
        assert!(name_in_zone("deep.sub.example.com.", "example.com."));
        assert!(name_in_zone("example.com.", "example.com."));

        assert!(
            !name_in_zone("notexample.com.", "example.com."),
            "a name sharing a text suffix is a different zone"
        );
        assert!(!name_in_zone("example.com.evil.test.", "example.com."));
        assert!(!name_in_zone("api.other.test.", "example.com."));
        assert!(!name_in_zone("com.", "example.com."));
    }

    #[test]
    fn name_in_zone_normalizes_case_and_trailing_dots() {
        assert!(name_in_zone("WWW.Example.COM", "example.com."));
        assert!(name_in_zone("www.example.com.", "EXAMPLE.com"));
    }

    /// The root encloses everything, which is what makes it usable as the signer
    /// zone for a root-zone signing run.
    #[test]
    fn name_in_zone_treats_the_root_as_enclosing_everything() {
        assert!(name_in_zone("anything.test.", "."));
        assert!(name_in_zone(".", "."));
    }

    /// A stored PTR must not make this server authoritative for the whole
    /// reverse tree.
    ///
    /// The last-two-labels heuristic yields `in-addr.arpa.` for every reverse
    /// name, so registering it as managed would NXDOMAIN every `in-addr.arpa`
    /// lookup on the internet — and with `dns.auto_ptr` enabled a single A
    /// record is enough to trigger it, because the PTR is created for you.
    #[test]
    fn a_stored_ptr_does_not_manage_the_whole_reverse_tree() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "100.1.168.192.in-addr.arpa.".to_string(),
            record_type: RecordKind::PTR,
            value: "host.local.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        assert_eq!(
            db.find_managed_zone("200.1.168.192.in-addr.arpa."),
            None,
            "another address in the same /24 must not be answered authoritatively"
        );
        assert_eq!(
            db.find_managed_zone("1.2.3.4.in-addr.arpa."),
            None,
            "an unrelated address must certainly not be"
        );
    }

    #[test]
    fn a_stored_ipv6_ptr_does_not_manage_ip6_arpa() {
        let db = test_db();
        db.add_record(&DnsRecord {
            id: None,
            name: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
                .to_string(),
            record_type: RecordKind::PTR,
            value: "host.local.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        assert_eq!(db.find_managed_zone("2.0.0.2.ip6.arpa."), None);
    }

    /// The exclusion is confined to the reverse trees: a forward name that
    /// merely *contains* "arpa" is an ordinary domain.
    #[test]
    fn the_reverse_exclusion_does_not_swallow_forward_names() {
        let db = test_db();
        db.add_record(&a_record("www.arpanet.example.", "192.0.2.1"))
            .unwrap();
        assert_eq!(
            db.find_managed_zone("other.arpanet.example."),
            Some("arpanet.example.".to_string())
        );

        // A single-label name is the only thing that derives a bare TLD as its
        // zone — "last two labels" makes a two-label name yield *itself*, so
        // `host.notarpa.` would derive `host.notarpa.`, not `notarpa.`.
        let db = test_db();
        db.add_record(&a_record("notarpa.", "192.0.2.1")).unwrap();
        assert_eq!(
            db.find_managed_zone("elsewhere.notarpa."),
            Some("notarpa.".to_string()),
            "`notarpa.` is not `arpa.`; the exclusion matches on label boundaries"
        );
    }

    /// `home.arpa.` (RFC 8375) is a special-use domain for residential networks —
    /// exactly what this server serves — and the last-two-labels heuristic gets
    /// it right: `foo.home.arpa.` derives `home.arpa.`, the real zone.
    ///
    /// It must therefore survive the reverse-tree exclusion. Excluding `arpa.`
    /// wholesale would send a miss under `home.arpa` upstream, which RFC 8375 §4
    /// says must never happen.
    #[test]
    fn home_arpa_is_still_a_managed_zone() {
        let db = test_db();
        db.add_record(&a_record("nas.home.arpa.", "192.0.2.1"))
            .unwrap();

        assert_eq!(
            db.find_managed_zone("absent.home.arpa."),
            Some("home.arpa.".to_string()),
            "home.arpa must stay locally authoritative, not be forwarded upstream"
        );
    }

    /// The label arithmetic itself, because it is easy to get backwards and it
    /// decides how much of the namespace one stored record claims.
    #[test]
    fn a_two_label_name_derives_itself_not_its_tld() {
        let db = test_db();
        db.add_record(&a_record("host.example.", "192.0.2.1"))
            .unwrap();

        assert_eq!(
            db.find_managed_zone("sub.host.example."),
            Some("host.example.".to_string()),
            "a name beneath the derived zone is covered"
        );
        assert_eq!(
            db.find_managed_zone("other.example."),
            None,
            "one two-label record must not claim the whole `example.` TLD"
        );
    }

    /// Deleting the last record in a zone must drop it from the managed-zone
    /// cache. A stale entry is not inert: `find_managed_zone` is what turns a
    /// miss into an *authoritative* NXDOMAIN, so a zone that no longer exists
    /// would keep swallowing every name under it instead of letting them resolve
    /// upstream.
    #[test]
    fn removing_the_last_record_unmanages_the_zone() {
        let db = test_db();
        db.add_record(&a_record("www.example.com.", "192.0.2.1"))
            .unwrap();
        db.add_record(&a_record("mail.example.com.", "192.0.2.2"))
            .unwrap();
        assert_eq!(
            db.find_managed_zone("absent.example.com."),
            Some("example.com.".to_string())
        );

        // One of two: the zone is still managed.
        db.remove_records("www.example.com.", None, "").unwrap();
        assert_eq!(
            db.find_managed_zone("absent.example.com."),
            Some("example.com.".to_string()),
            "a zone with records left must stay managed"
        );

        // The last one: the zone stops being managed.
        db.remove_records("mail.example.com.", None, "").unwrap();
        assert_eq!(
            db.find_managed_zone("absent.example.com."),
            None,
            "an emptied zone must stop being managed"
        );
    }

    // ================================================================
    // find_authoritative_zone tests
    // ================================================================

    #[test]
    fn test_find_authoritative_zone_match() {
        let db = test_db();
        db.add_authoritative_zone("auth.org.").unwrap();
        assert_eq!(
            db.find_authoritative_zone("sub.auth.org."),
            Some("auth.org.".to_string())
        );
    }

    #[test]
    fn test_find_authoritative_zone_exact() {
        let db = test_db();
        db.add_authoritative_zone("auth.org.").unwrap();
        assert_eq!(
            db.find_authoritative_zone("auth.org."),
            Some("auth.org.".to_string())
        );
    }

    #[test]
    fn test_find_authoritative_zone_no_match() {
        let db = test_db();
        db.add_authoritative_zone("auth.org.").unwrap();
        assert_eq!(db.find_authoritative_zone("other.com."), None);
    }

    // ================================================================
    // Scope TLDs (per-network owned zones, partitioned across networks)
    // ================================================================

    fn scope_with_tld(db: &Database, name: &str, home: &str) {
        db.create_network_scope(&NetworkScope {
            name: name.to_string(),
            home_domain: home.to_string(),
        })
        .unwrap();
    }

    #[test]
    fn test_add_and_find_scope_tld() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        db.add_scope_tld("office", "office").unwrap();

        // A single-label TLD is owned by the scope for any name under it.
        assert_eq!(
            db.find_tld_owner("gitea.town-os.office."),
            Some(("office".to_string(), "office.".to_string()))
        );
        // The home_domain is an implicit owned TLD too.
        assert_eq!(
            db.find_tld_owner("host.office.home."),
            Some(("office".to_string(), "office.home.".to_string()))
        );
        // Unrelated names are not owned.
        assert_eq!(db.find_tld_owner("www.google.com."), None);
    }

    #[test]
    fn test_add_scope_tld_normalizes() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        db.add_scope_tld("office", "Office").unwrap();
        let tlds = db.list_scope_tlds("office").unwrap();
        assert_eq!(tlds, vec!["office.".to_string()]);
    }

    #[test]
    fn test_scope_tld_global_uniqueness() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        scope_with_tld(&db, "lab", "lab.home");
        db.add_scope_tld("office", "shared").unwrap();

        // A different scope cannot claim the same TLD.
        let err = db.add_scope_tld("lab", "shared").unwrap_err();
        let conflict = err.downcast_ref::<TldConflict>().expect("TldConflict");
        assert_eq!(conflict.owner, "office");
        assert_eq!(conflict.tld, "shared.");

        // Re-adding to the SAME owning scope is idempotent, not a conflict.
        db.add_scope_tld("office", "shared").unwrap();
    }

    #[test]
    fn test_home_domain_uniqueness_across_scopes() {
        let db = test_db();
        scope_with_tld(&db, "office", "corp");
        // A second scope whose home_domain collides an existing owned TLD fails.
        let err = db
            .create_network_scope(&NetworkScope {
                name: "lab".to_string(),
                home_domain: "corp".to_string(),
            })
            .unwrap_err();
        assert!(err.downcast_ref::<TldConflict>().is_some());
    }

    #[test]
    fn test_scope_tld_conflicts_with_other_home_domain() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        scope_with_tld(&db, "lab", "lab.home");
        // Registering a TLD equal to another scope's home_domain is rejected.
        let err = db.add_scope_tld("office", "lab.home").unwrap_err();
        assert!(err.downcast_ref::<TldConflict>().is_some());
    }

    #[test]
    fn test_remove_scope_tld() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        db.add_scope_tld("office", "office").unwrap();
        assert!(db.remove_scope_tld("office", "office").unwrap());
        assert_eq!(db.find_tld_owner("x.office."), None);
        // Removing again returns false.
        assert!(!db.remove_scope_tld("office", "office").unwrap());
    }

    #[test]
    fn test_remove_scope_tld_refuses_home_domain() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        assert!(db.remove_scope_tld("office", "office.home").is_err());
        // home_domain remains owned.
        assert_eq!(
            db.find_tld_owner("office.home."),
            Some(("office".to_string(), "office.home.".to_string()))
        );
    }

    #[test]
    fn test_list_all_owned_tlds() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        db.add_scope_tld("office", "office").unwrap();
        db.add_scope_tld("office", "corp").unwrap();
        let all = db.list_all_owned_tlds("office").unwrap();
        // home_domain first.
        assert_eq!(all[0], "office.home.");
        assert!(all.contains(&"office.".to_string()));
        assert!(all.contains(&"corp.".to_string()));
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_find_tld_owner_most_specific_wins() {
        let db = test_db();
        scope_with_tld(&db, "a", "a.home");
        scope_with_tld(&db, "b", "b.home");
        db.add_scope_tld("a", "office").unwrap();
        db.add_scope_tld("b", "team.office").unwrap();
        // team.office. is more specific than office. and wins.
        assert_eq!(
            db.find_tld_owner("x.team.office."),
            Some(("b".to_string(), "team.office.".to_string()))
        );
        assert_eq!(
            db.find_tld_owner("x.office."),
            Some(("a".to_string(), "office.".to_string()))
        );
    }

    #[test]
    fn test_scope_tld_forwarders_crud() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        db.add_scope_tld("office", "office").unwrap();
        db.set_scope_tld_forwarders(
            "office",
            "office",
            &["10.90.12.2:53".to_string(), "10.90.12.3:53".to_string()],
        )
        .unwrap();

        let listed = db.list_scope_tld_forwarders("office", "office").unwrap();
        assert_eq!(listed.len(), 2);
        let cached = db.get_tld_forwarders_cached("office", "office.");
        assert_eq!(cached.len(), 2);
        assert!(cached.contains(&"10.90.12.2:53".parse().unwrap()));

        // Replace-all with a smaller set.
        db.set_scope_tld_forwarders("office", "office", &["10.90.12.9:53".to_string()])
            .unwrap();
        assert_eq!(db.get_tld_forwarders_cached("office", "office.").len(), 1);

        // Clearing empties the cache.
        db.set_scope_tld_forwarders("office", "office", &[])
            .unwrap();
        assert!(db.get_tld_forwarders_cached("office", "office.").is_empty());
    }

    #[test]
    fn test_scope_tld_forwarders_rejects_bad_address() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        db.add_scope_tld("office", "office").unwrap();
        assert!(
            db.set_scope_tld_forwarders("office", "office", &["not-an-addr".to_string()])
                .is_err()
        );
    }

    #[test]
    fn test_delete_scope_cascades_tlds_and_forwarders() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        db.add_scope_tld("office", "office").unwrap();
        db.set_scope_tld_forwarders("office", "office", &["10.90.12.2:53".to_string()])
            .unwrap();

        db.delete_network_scope("office").unwrap();

        // Owned TLDs (home + additional) and forwarders are gone from caches...
        assert_eq!(db.find_tld_owner("x.office."), None);
        assert_eq!(db.find_tld_owner("office.home."), None);
        assert!(db.get_tld_forwarders_cached("office", "office.").is_empty());
        // ... and from the database.
        assert!(db.list_scope_tlds("office").unwrap().is_empty());
        assert!(
            db.list_scope_tld_forwarders("office", "office")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn test_scope_tlds_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tld-boot.db");
        {
            let db = Database::open(&path).unwrap();
            scope_with_tld(&db, "office", "office.home");
            db.add_scope_tld("office", "office").unwrap();
            db.set_scope_tld_forwarders("office", "office", &["10.90.12.2:53".to_string()])
                .unwrap();
        }
        // Reopen: caches are rebuilt from disk in load_caches_at_boot.
        let db = Database::open(&path).unwrap();
        assert_eq!(
            db.find_tld_owner("host.office."),
            Some(("office".to_string(), "office.".to_string()))
        );
        assert_eq!(
            db.find_tld_owner("host.office.home."),
            Some(("office".to_string(), "office.home.".to_string()))
        );
        assert_eq!(db.get_tld_forwarders_cached("office", "office.").len(), 1);
    }

    #[test]
    fn test_tld_listener_crud() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        db.add_scope_tld("office", "office").unwrap();

        let ip: IpAddr = "127.0.0.9".parse().unwrap();
        db.set_tld_listener("office", "office", ip).unwrap();

        // Cache lookup tolerates the missing trailing dot.
        assert_eq!(db.get_tld_ingress("office"), Some(ip));
        assert_eq!(db.get_tld_ingress("office."), Some(ip));

        let listed = db.list_tld_listeners("office").unwrap();
        assert_eq!(listed, vec![("office.".to_string(), ip)]);
        assert_eq!(db.list_all_tld_ingress_ips(), vec![ip]);

        // Replacing the IP updates the cache.
        let ip2: IpAddr = "127.0.0.10".parse().unwrap();
        db.set_tld_listener("office", "office", ip2).unwrap();
        assert_eq!(db.get_tld_ingress("office."), Some(ip2));

        assert!(db.remove_tld_listener("office", "office").unwrap());
        assert_eq!(db.get_tld_ingress("office."), None);
        assert!(db.list_all_tld_ingress_ips().is_empty());
        // Removing again is a no-op.
        assert!(!db.remove_tld_listener("office", "office").unwrap());
    }

    #[test]
    fn test_set_tld_listener_requires_ownership() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        // "corp." is not owned by office → rejected.
        let ip: IpAddr = "127.0.0.9".parse().unwrap();
        assert!(db.set_tld_listener("office", "corp.", ip).is_err());

        // Owned by a different scope → rejected for the wrong owner.
        scope_with_tld(&db, "lab", "lab.home");
        db.add_scope_tld("lab", "lab").unwrap();
        assert!(db.set_tld_listener("office", "lab.", ip).is_err());
        // Correct owner works, including on the implicit home_domain TLD.
        db.set_tld_listener("office", "office.home", ip).unwrap();
        assert_eq!(db.get_tld_ingress("office.home."), Some(ip));
    }

    #[test]
    fn test_remove_scope_tld_clears_listener() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        db.add_scope_tld("office", "corp").unwrap();
        let ip: IpAddr = "127.0.0.9".parse().unwrap();
        db.set_tld_listener("office", "corp", ip).unwrap();
        assert_eq!(db.get_tld_ingress("corp."), Some(ip));

        assert!(db.remove_scope_tld("office", "corp").unwrap());
        // Removing the TLD ownership also drops its ingress listener row/cache.
        assert_eq!(db.get_tld_ingress("corp."), None);
        assert!(db.list_all_tld_ingress_ips().is_empty());
    }

    #[test]
    fn test_two_tlds_share_one_ingress_ip() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        db.add_scope_tld("office", "office").unwrap();
        db.add_scope_tld("office", "corp").unwrap();
        let ip: IpAddr = "127.0.0.9".parse().unwrap();
        db.set_tld_listener("office", "office", ip).unwrap();
        db.set_tld_listener("office", "corp", ip).unwrap();

        // Distinct ingress IPs de-duplicated for the boot/orphan check.
        assert_eq!(db.list_all_tld_ingress_ips(), vec![ip]);
        // Removing one TLD leaves the shared IP still referenced by the other.
        db.remove_scope_tld("office", "corp").unwrap();
        assert_eq!(db.list_all_tld_ingress_ips(), vec![ip]);
        db.remove_scope_tld("office", "office").unwrap();
        assert!(db.list_all_tld_ingress_ips().is_empty());
    }

    #[test]
    fn test_tld_listeners_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tld-listener-boot.db");
        let ip: IpAddr = "127.0.0.9".parse().unwrap();
        {
            let db = Database::open(&path).unwrap();
            scope_with_tld(&db, "office", "office.home");
            db.add_scope_tld("office", "office").unwrap();
            db.set_tld_listener("office", "office", ip).unwrap();
        }
        // Reopen: the ingress cache is rebuilt from disk in load_caches_at_boot.
        let db = Database::open(&path).unwrap();
        assert_eq!(db.get_tld_ingress("office."), Some(ip));
        assert_eq!(db.list_all_tld_ingress_ips(), vec![ip]);
    }

    #[test]
    fn test_get_search_domains_includes_tlds() {
        let db = test_db();
        scope_with_tld(&db, "office", "office.home");
        db.add_scope_tld("office", "corp").unwrap();
        db.join_network(&NetworkAssociation {
            ip_address: "10.0.0.5".to_string(),
            scope_name: "office".to_string(),
            ttl_seconds: 600,
        })
        .unwrap();
        let domains = db.get_search_domains("10.0.0.5").unwrap();
        assert_eq!(domains[0], "office.home.");
        assert!(domains.contains(&"corp.".to_string()));
    }
}
