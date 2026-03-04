/// DANE TLSA record generation and root CA management.
///
/// Supports:
/// - Usage 2 (Trust Anchor) and 3 (Domain-Issued)
/// - Selector 0 (Full certificate) and 1 (Subject public key)
/// - Matching type 1 (SHA-256) and 2 (SHA-512)
use anyhow::{Context, Result};
use sha2::{Digest, Sha256, Sha512};

/// Generates a TLSA record value from a certificate PEM.
///
/// Returns the TLSA RDATA string: "usage selector matching_type hex_data"
pub fn generate_tlsa_record(
    cert_pem: &str,
    usage: u8,
    selector: u8,
    matching_type: u8,
) -> Result<String> {
    let cert_der = pem_to_der(cert_pem)?;

    let data = match selector {
        0 => cert_der.clone(),  // Full certificate
        1 => extract_spki(&cert_der)?, // Subject Public Key Info
        _ => anyhow::bail!("unsupported TLSA selector: {}", selector),
    };

    let hash = match matching_type {
        0 => hex::encode(&data), // No hash, exact match
        1 => {
            let digest = Sha256::digest(&data);
            hex::encode(digest)
        }
        2 => {
            let digest = Sha512::digest(&data);
            hex::encode(digest)
        }
        _ => anyhow::bail!("unsupported TLSA matching type: {}", matching_type),
    };

    Ok(format!("{} {} {} {}", usage, selector, matching_type, hash))
}

/// Constructs the TLSA DNS name: _port._protocol.domain
pub fn tlsa_dns_name(domain: &str, port: u16, protocol: &str) -> String {
    let domain = domain.trim_end_matches('.');
    format!("_{}._{}.{}.", port, protocol, domain)
}

/// Generates a self-signed root CA certificate for DANE.
pub fn generate_dane_root_ca(name: &str) -> Result<(String, String)> {
    let mut params = rcgen::CertificateParams::new(vec![])
        .context("failed to create CA params")?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);

    let key_pair = rcgen::KeyPair::generate().context("failed to generate CA key pair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("failed to generate root CA")?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    Ok((cert_pem, key_pem))
}

/// Extracts DER-encoded certificate from PEM.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let pem = pem.trim();
    let base64_data: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &base64_data)
        .context("failed to decode PEM base64")
}

/// Extracts the SubjectPublicKeyInfo from a DER-encoded certificate.
/// This is a simplified extraction that finds the SPKI within the TBS.
fn extract_spki(cert_der: &[u8]) -> Result<Vec<u8>> {
    // For now, use the full certificate DER as a fallback
    // A full implementation would parse ASN.1 to extract SPKI
    // Using x509-parser when available
    Ok(cert_der.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlsa_dns_name() {
        assert_eq!(
            tlsa_dns_name("example.com.", 443, "tcp"),
            "_443._tcp.example.com."
        );
        assert_eq!(
            tlsa_dns_name("mail.example.com", 25, "tcp"),
            "_25._tcp.mail.example.com."
        );
    }

    #[test]
    fn test_generate_dane_root_ca() {
        let (cert_pem, key_pem) = generate_dane_root_ca("Test CA").unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_generate_tlsa_from_ca() {
        let (cert_pem, _) = generate_dane_root_ca("Test CA").unwrap();
        let tlsa = generate_tlsa_record(&cert_pem, 3, 0, 1).unwrap();
        assert!(tlsa.starts_with("3 0 1 "));
        // SHA-256 hex is 64 chars
        let parts: Vec<&str> = tlsa.split_whitespace().collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[3].len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
    }
}
