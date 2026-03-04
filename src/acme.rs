/// ACME client for automated certificate management (RFC 8555).
///
/// Since Rolodex IS the DNS server, it can serve `_acme-challenge` TXT records
/// natively for DNS-01 challenge validation. This enables automated certificate
/// issuance without external DNS providers.
use anyhow::Result;
use crate::db::Database;

/// ACME certificate status.
#[derive(Debug, Clone)]
pub enum AcmeStatus {
    NotConfigured,
    Pending,
    Valid,
    Expired,
    Failed(String),
}

impl AcmeStatus {
    pub fn as_str(&self) -> &str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Pending => "pending",
            Self::Valid => "valid",
            Self::Expired => "expired",
            Self::Failed(_) => "failed",
        }
    }
}

/// Stores an ACME challenge TXT record in the DNS database.
pub fn set_acme_challenge(db: &Database, domain: &str, token: &str) -> Result<()> {
    let challenge_name = format!("_acme-challenge.{}", domain.trim_end_matches('.'));
    let record = crate::db::DnsRecord {
        id: None,
        name: challenge_name,
        record_type: crate::db::RecordKind::TXT,
        value: token.to_string(),
        ttl: 60,
        priority: 0,
    };
    db.add_record(&record)?;
    Ok(())
}

/// Removes an ACME challenge TXT record from the DNS database.
pub fn clear_acme_challenge(db: &Database, domain: &str) -> Result<()> {
    let challenge_name = format!("_acme-challenge.{}", domain.trim_end_matches('.'));
    db.remove_records(&challenge_name, Some(crate::db::RecordKind::TXT), "")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_status() {
        assert_eq!(AcmeStatus::NotConfigured.as_str(), "not_configured");
        assert_eq!(AcmeStatus::Valid.as_str(), "valid");
        assert_eq!(AcmeStatus::Pending.as_str(), "pending");
    }

    #[test]
    fn test_set_and_clear_acme_challenge() {
        let db = Database::open_memory().unwrap();
        set_acme_challenge(&db, "example.com.", "test-token-123").unwrap();

        let records = db
            .lookup("_acme-challenge.example.com.", Some(crate::db::RecordKind::TXT))
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "test-token-123");

        clear_acme_challenge(&db, "example.com.").unwrap();
        let records = db
            .lookup("_acme-challenge.example.com.", Some(crate::db::RecordKind::TXT))
            .unwrap();
        assert!(records.is_empty());
    }
}
