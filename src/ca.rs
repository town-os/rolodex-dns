//! Certificate Authority hierarchy for the built-in ACME issuer.
//!
//! Rolodex runs a single self-signed **root CA** and a **per-zone intermediate
//! CA**, all using Ed25519. The root signs the intermediates; each intermediate
//! signs the leaf certificates issued through the ACME endpoint.
//!
//! DANE publishes the *intermediate* as a trust anchor (`2 1 1`), so any leaf it
//! signs validates via DANE-TA as long as the server presents the
//! `leaf + intermediate` chain.
//!
//! CAs are persisted as PEM in the database and re-materialized at use time via
//! [`rcgen::CertificateParams::from_ca_cert_pem`] + [`rcgen::KeyPair::from_pem`].

use crate::db::{Database, normalize_name};
use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
};
use time::{Duration, OffsetDateTime};

/// Reserved name under which the Rolodex root CA is stored in `dane_root_cas`.
pub const ROOT_CA_NAME: &str = "__rolodex_root__";

const ROOT_VALIDITY_DAYS: i64 = 3650; // 10 years
const INTERMEDIATE_VALIDITY_DAYS: i64 = 1825; // 5 years

/// Generates a fresh Ed25519 key pair.
fn ed25519_key() -> Result<KeyPair> {
    KeyPair::generate_for(&PKCS_ED25519).context("failed to generate Ed25519 key pair")
}

/// Sets `not_before` to (a minute ago, to tolerate clock skew) and `not_after`
/// to `days` in the future.
fn set_validity(params: &mut CertificateParams, days: i64) -> Result<()> {
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::minutes(1);
    params.not_after = now
        .checked_add(Duration::days(days))
        .context("certificate validity overflow")?;
    Ok(())
}

/// Ensures the Rolodex root CA exists, creating it (Ed25519, self-signed) if not.
///
/// Idempotent: a no-op if the root already exists. Returns nothing; callers load
/// the root via [`load_root`].
pub fn ensure_root_ca(db: &Database, common_name: &str) -> Result<()> {
    if db.get_dane_root_ca(ROOT_CA_NAME)?.is_some() {
        return Ok(());
    }
    let key = ed25519_key()?;
    let mut params =
        CertificateParams::new(Vec::<String>::new()).context("failed to create root CA params")?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    set_validity(&mut params, ROOT_VALIDITY_DAYS)?;

    let cert = params
        .self_signed(&key)
        .context("failed to self-sign root CA")?;
    db.store_dane_root_ca(ROOT_CA_NAME, &cert.pem(), &key.serialize_pem())?;
    Ok(())
}

/// Loads the root CA as a re-materialized issuer `(Certificate, KeyPair)`.
fn load_root(db: &Database) -> Result<(Certificate, KeyPair)> {
    let (_, _, cert_pem, key_pem) = db
        .get_dane_root_ca(ROOT_CA_NAME)?
        .context("root CA not initialized")?;
    materialize_issuer(&cert_pem, &key_pem)
}

/// Re-materializes a CA `(Certificate, KeyPair)` from stored PEM so it can sign.
///
/// `from_ca_cert_pem` extracts the subject DN and CA attributes; pairing it with
/// the stored key reproduces a usable issuer for `signed_by`.
fn materialize_issuer(cert_pem: &str, key_pem: &str) -> Result<(Certificate, KeyPair)> {
    let key = KeyPair::from_pem(key_pem).context("failed to load CA key")?;
    let params =
        CertificateParams::from_ca_cert_pem(cert_pem).context("failed to parse CA certificate")?;
    let cert = params
        .self_signed(&key)
        .context("failed to re-materialize CA certificate")?;
    Ok((cert, key))
}

/// Ensures a per-zone intermediate CA exists, creating it (Ed25519, signed by the
/// root) if not. Idempotent. The root CA must already exist.
pub fn ensure_zone_intermediate(db: &Database, zone: &str) -> Result<()> {
    let zone = normalize_name(zone);
    if db.get_zone_ca(&zone)?.is_some() {
        return Ok(());
    }
    let (root_cert, root_key) = load_root(db)?;

    let key = ed25519_key()?;
    let mut params = CertificateParams::new(Vec::<String>::new())
        .context("failed to create intermediate CA params")?;
    // Path length 0: the intermediate may sign leaves but not further CAs.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(
        DnType::CommonName,
        format!("Rolodex Zone CA {}", zone.trim_end_matches('.')),
    );
    set_validity(&mut params, INTERMEDIATE_VALIDITY_DAYS)?;

    let cert = params
        .signed_by(&key, &root_cert, &root_key)
        .context("failed to sign intermediate CA")?;
    db.store_zone_ca(&zone, &cert.pem(), &key.serialize_pem())?;
    Ok(())
}

/// The outcome of issuing a leaf certificate.
pub struct IssuedLeaf {
    /// The leaf certificate alone, PEM.
    pub leaf_pem: String,
    /// The full chain the server should present: leaf followed by the
    /// per-zone intermediate, PEM.
    pub chain_pem: String,
    /// `not_after` of the leaf, as a UNIX timestamp.
    pub expires_at: i64,
}

/// Issues a leaf certificate by signing the supplied PKCS#10 CSR with the
/// intermediate CA for `zone`.
///
/// The CSR carries the subject public key and requested SANs; the issued leaf's
/// validity is `validity_days` from now. The intermediate must already exist.
pub fn issue_leaf(
    db: &Database,
    zone: &str,
    csr_pem: &str,
    validity_days: i64,
) -> Result<IssuedLeaf> {
    let zone = normalize_name(zone);
    let (int_cert_pem, int_key_pem) = db
        .get_zone_ca(&zone)?
        .with_context(|| format!("no intermediate CA for zone {}", zone))?;
    let (int_cert, int_key) = materialize_issuer(&int_cert_pem, &int_key_pem)?;

    let mut csr =
        CertificateSigningRequestParams::from_pem(csr_pem).context("failed to parse CSR")?;
    set_validity(&mut csr.params, validity_days)?;
    let expires_at = csr.params.not_after.unix_timestamp();

    let leaf = csr
        .signed_by(&int_cert, &int_key)
        .context("failed to sign leaf from CSR")?;
    let leaf_pem = leaf.pem();
    let chain_pem = format!("{}{}", leaf_pem, int_cert_pem);
    Ok(IssuedLeaf {
        leaf_pem,
        chain_pem,
        expires_at,
    })
}

/// Returns the DANE-TA TLSA RDATA (`2 1 1`) for a zone's intermediate CA.
///
/// Selector 1 (SPKI), matching type 1 (SHA-256), usage 2 (DANE-TA / trust anchor).
pub fn intermediate_tlsa(db: &Database, zone: &str) -> Result<String> {
    let (int_cert_pem, _) = db
        .get_zone_ca(&normalize_name(zone))?
        .with_context(|| format!("no intermediate CA for zone {}", zone))?;
    crate::dane::generate_tlsa_record(&int_cert_pem, 2, 1, 1)
}

/// Returns the PEM of the Rolodex root CA certificate (for clients to trust).
pub fn root_ca_pem(db: &Database) -> Result<String> {
    let (_, _, cert_pem, _) = db
        .get_dane_root_ca(ROOT_CA_NAME)?
        .context("root CA not initialized")?;
    Ok(cert_pem)
}

/// Returns the longest stored zone (by label count) that is a suffix of `name`,
/// i.e. the intermediate-backed zone responsible for `name`, if any.
pub fn responsible_zone(db: &Database, name: &str) -> Result<Option<String>> {
    let name = normalize_name(name);
    let mut best: Option<String> = None;
    for zone in db.list_zone_cas()? {
        let z = normalize_name(&zone);
        if name == z || name.ends_with(&format!(".{}", z)) {
            let better = match &best {
                Some(b) => z.matches('.').count() > b.matches('.').count(),
                None => true,
            };
            if better {
                best = Some(z);
            }
        }
    }
    Ok(best)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::CertificateDer;

    fn test_db() -> Database {
        let db = Database::open_memory().expect("open memory db");
        ensure_root_ca(&db, "Rolodex Test Root").expect("ensure root");
        db
    }

    /// Builds a CSR for `name` with an Ed25519 key, returning the CSR PEM.
    fn make_csr(name: &str) -> String {
        let key = ed25519_key().expect("key");
        let params = CertificateParams::new(vec![name.to_string()]).expect("params");
        let csr = params.serialize_request(&key).expect("csr");
        csr.pem().expect("csr pem")
    }

    #[test]
    fn root_ca_is_idempotent() {
        let db = test_db();
        // Second call must not create a second root or error.
        ensure_root_ca(&db, "Rolodex Test Root").expect("idempotent");
        assert!(db.get_dane_root_ca(ROOT_CA_NAME).unwrap().is_some());
        assert!(root_ca_pem(&db).unwrap().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn intermediate_is_created_and_idempotent() {
        let db = test_db();
        ensure_zone_intermediate(&db, "example.com").expect("intermediate");
        ensure_zone_intermediate(&db, "example.com").expect("idempotent");
        let (cert, _) = db.get_zone_ca("example.com.").unwrap().unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn issued_leaf_chains_to_root() {
        let db = test_db();
        ensure_zone_intermediate(&db, "example.com").expect("intermediate");
        let csr = make_csr("host.example.com");
        let issued = issue_leaf(&db, "example.com", &csr, 90).expect("issue");

        // The chain must contain two certificates: leaf + intermediate.
        let chain_certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut issued.chain_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .expect("parse chain");
        assert_eq!(chain_certs.len(), 2, "chain is leaf + intermediate");

        // Verify the leaf chains to the root via webpki path building.
        let root_pem = root_ca_pem(&db).unwrap();
        let root_der: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut root_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .expect("parse root");
        let anchors: Vec<_> = root_der
            .iter()
            .map(|d| webpki::anchor_from_trusted_cert(d).expect("anchor"))
            .collect();

        let ee = webpki::EndEntityCert::try_from(&chain_certs[0]).expect("ee cert");
        let intermediates = &chain_certs[1..];
        let now = rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            OffsetDateTime::now_utc().unix_timestamp() as u64,
        ));
        ee.verify_for_usage(
            &[webpki::ring::ED25519],
            &anchors,
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .expect("leaf must chain to the Rolodex root");
    }

    #[test]
    fn intermediate_tlsa_is_dane_ta() {
        let db = test_db();
        ensure_zone_intermediate(&db, "example.com").expect("intermediate");
        let tlsa = intermediate_tlsa(&db, "example.com").expect("tlsa");
        assert!(tlsa.starts_with("2 1 1 "));
        let parts: Vec<&str> = tlsa.split_whitespace().collect();
        assert_eq!(parts[3].len(), 64); // SHA-256 hex
    }

    #[test]
    fn responsible_zone_prefers_longest_suffix() {
        let db = test_db();
        ensure_zone_intermediate(&db, "example.com").expect("z1");
        ensure_zone_intermediate(&db, "lab.example.com").expect("z2");
        assert_eq!(
            responsible_zone(&db, "host.lab.example.com").unwrap(),
            Some("lab.example.com.".to_string())
        );
        assert_eq!(
            responsible_zone(&db, "host.example.com").unwrap(),
            Some("example.com.".to_string())
        );
        assert_eq!(responsible_zone(&db, "host.other.org").unwrap(), None);
    }
}
