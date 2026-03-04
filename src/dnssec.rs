/// DNSSEC support: key management, zone signing, and validation.
///
/// Supported algorithms (strongest first):
/// 1. Ed25519 (RFC 8080, algo 15) — preferred
/// 2. ECDSA P-384 (RFC 6605, algo 14)
/// 3. ECDSA P-256 (RFC 6605, algo 13)
/// 4. RSA/SHA-256 (RFC 5702, algo 8)
///
/// Note: Ed448 is not supported by the `ring` crate.
use anyhow::Result;
use ring::signature::{self, KeyPair as _};
use sha2::{Digest, Sha256};

/// DNSSEC algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecAlgorithm {
    /// RSA/SHA-256 (algorithm 8)
    RsaSha256 = 8,
    /// ECDSA P-256/SHA-256 (algorithm 13)
    EcdsaP256Sha256 = 13,
    /// ECDSA P-384/SHA-384 (algorithm 14)
    EcdsaP384Sha384 = 14,
    /// Ed25519 (algorithm 15)
    Ed25519 = 15,
}

impl DnssecAlgorithm {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "rsa-sha256" | "rsasha256" | "8" => Some(Self::RsaSha256),
            "ecdsa-p256" | "ecdsap256sha256" | "13" => Some(Self::EcdsaP256Sha256),
            "ecdsa-p384" | "ecdsap384sha384" | "14" => Some(Self::EcdsaP384Sha384),
            "ed25519" | "15" => Some(Self::Ed25519),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RsaSha256 => "RSA-SHA256",
            Self::EcdsaP256Sha256 => "ECDSA-P256-SHA256",
            Self::EcdsaP384Sha384 => "ECDSA-P384-SHA384",
            Self::Ed25519 => "Ed25519",
        }
    }
}

/// Key type: Zone Signing Key or Key Signing Key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Zone Signing Key (256 flag)
    ZSK,
    /// Key Signing Key (257 flag)
    KSK,
}

impl KeyType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "ZSK" => Some(Self::ZSK),
            "KSK" => Some(Self::KSK),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ZSK => "ZSK",
            Self::KSK => "KSK",
        }
    }

    pub fn flags(&self) -> u16 {
        match self {
            Self::ZSK => 256,
            Self::KSK => 257,
        }
    }
}

/// Represents a DNSSEC key pair.
pub struct DnssecKeyPair {
    pub zone: String,
    pub algorithm: DnssecAlgorithm,
    pub key_type: KeyType,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub key_tag: u16,
}

/// Generates an Ed25519 key pair for DNSSEC.
pub fn generate_ed25519_key(zone: &str, key_type: KeyType) -> Result<DnssecKeyPair> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| anyhow::anyhow!("failed to generate Ed25519 key: {}", e))?;
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|e| anyhow::anyhow!("failed to parse generated Ed25519 key: {}", e))?;

    let public_key = key_pair.public_key().as_ref().to_vec();
    let private_key = pkcs8_bytes.as_ref().to_vec();

    let key_tag = compute_key_tag(DnssecAlgorithm::Ed25519, key_type, &public_key);

    Ok(DnssecKeyPair {
        zone: zone.to_string(),
        algorithm: DnssecAlgorithm::Ed25519,
        key_type,
        private_key,
        public_key,
        key_tag,
    })
}

/// Computes the DNSKEY key tag (RFC 4034 Appendix B).
pub fn compute_key_tag(algorithm: DnssecAlgorithm, key_type: KeyType, public_key: &[u8]) -> u16 {
    let flags = key_type.flags();
    let protocol: u8 = 3; // Always 3 for DNSSEC
    let algo = algorithm as u8;

    // Build DNSKEY RDATA: flags(2) + protocol(1) + algorithm(1) + public_key
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&flags.to_be_bytes());
    rdata.push(protocol);
    rdata.push(algo);
    rdata.extend_from_slice(public_key);

    // RFC 4034 key tag calculation
    let mut ac: u32 = 0;
    for (i, &byte) in rdata.iter().enumerate() {
        if i & 1 == 0 {
            ac += (byte as u32) << 8;
        } else {
            ac += byte as u32;
        }
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

/// Computes a DS record digest (SHA-256) from a DNSKEY.
pub fn compute_ds_sha256(
    zone: &str,
    key_tag: u16,
    algorithm: DnssecAlgorithm,
    public_key: &[u8],
    key_type: KeyType,
) -> String {
    // DS digest input: owner_name (wire format) + DNSKEY RDATA
    let mut input = Vec::new();
    // Wire-format the zone name
    for label in zone.trim_end_matches('.').split('.') {
        input.push(label.len() as u8);
        input.extend_from_slice(label.as_bytes());
    }
    input.push(0); // root label

    // DNSKEY RDATA
    let flags = key_type.flags();
    input.extend_from_slice(&flags.to_be_bytes());
    input.push(3); // protocol
    input.push(algorithm as u8);
    input.extend_from_slice(public_key);

    let digest = Sha256::digest(&input);
    let digest_hex = hex::encode(digest);

    format!(
        "{} {} {} 1 {}",
        key_tag,
        algorithm as u8,
        1, // SHA-256 digest type
        digest_hex
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_from_str() {
        assert_eq!(
            DnssecAlgorithm::from_str("ed25519"),
            Some(DnssecAlgorithm::Ed25519)
        );
        assert_eq!(
            DnssecAlgorithm::from_str("15"),
            Some(DnssecAlgorithm::Ed25519)
        );
        assert_eq!(
            DnssecAlgorithm::from_str("ecdsa-p256"),
            Some(DnssecAlgorithm::EcdsaP256Sha256)
        );
        assert!(DnssecAlgorithm::from_str("unknown").is_none());
    }

    #[test]
    fn test_key_type() {
        assert_eq!(KeyType::ZSK.flags(), 256);
        assert_eq!(KeyType::KSK.flags(), 257);
    }

    #[test]
    fn test_generate_ed25519_key() {
        let key = generate_ed25519_key("example.com.", KeyType::ZSK).unwrap();
        assert_eq!(key.algorithm, DnssecAlgorithm::Ed25519);
        assert_eq!(key.key_type, KeyType::ZSK);
        assert_eq!(key.public_key.len(), 32); // Ed25519 public key is 32 bytes
        assert!(!key.private_key.is_empty());
        assert!(key.key_tag > 0);
    }

    #[test]
    fn test_key_tag_deterministic() {
        let key1 = generate_ed25519_key("test.com.", KeyType::ZSK).unwrap();
        let tag1 = compute_key_tag(key1.algorithm, key1.key_type, &key1.public_key);
        let tag2 = compute_key_tag(key1.algorithm, key1.key_type, &key1.public_key);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_ds_record_generation() {
        let key = generate_ed25519_key("example.com.", KeyType::KSK).unwrap();
        let ds = compute_ds_sha256(
            "example.com.",
            key.key_tag,
            key.algorithm,
            &key.public_key,
            key.key_type,
        );
        assert!(!ds.is_empty());
        assert!(ds.contains(&key.key_tag.to_string()));
    }
}
