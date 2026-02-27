use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex};

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

/// Thread-safe handle to the DNS record database.
#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
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
        };
        db.init_tables()?;
        Ok(db)
    }

    /// Opens an in-memory database (useful for testing).
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("failed to open in-memory database")?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
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
            CREATE INDEX IF NOT EXISTS idx_dns_name_type ON dns_records(name, record_type);",
        )
        .context("failed to create tables")?;
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
}
