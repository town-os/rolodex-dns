//! DNSSEC support: key management and zone signing.
//!
//! Supported algorithms (strongest first):
//! 1. Ed25519 (RFC 8080, algo 15) — preferred
//! 2. ECDSA P-384/SHA-384 (RFC 6605, algo 14)
//! 3. ECDSA P-256/SHA-256 (RFC 6605, algo 13)
//!
//! RSA/SHA-256 (algo 8) is **not** supported: `ring` cannot generate RSA keys,
//! and a key we cannot generate is a key we cannot honestly advertise. Ed448 is
//! likewise absent from `ring`.
//!
//! Every algorithm here is one whose keys we actually generate and whose
//! signatures we actually produce. That invariant matters more than the length
//! of the list: a DNSKEY advertising algorithm 13 while carrying Ed25519 key
//! material is a zone that can never validate, and it fails at the resolver
//! rather than here, long after the operator has stopped looking.
//!
//! This module signs; it does not validate. Validation of upstream answers is
//! `crate::dnssec_validate`, which shares no code with this module on purpose —
//! see the DNSSEC sections of DESIGN.md.
use crate::db::{DnsRecord, RecordKind};
use anyhow::{Result, bail};
use ring::rand::SystemRandom;
use ring::signature::{self, KeyPair as _};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

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
    /// Parses an algorithm name or number.
    ///
    /// The spellings produced by [`Self::as_str`] must round-trip: that string
    /// is what gets written to the `dnssec_keys` table, so an algorithm whose
    /// stored name does not parse back is a key that silently becomes unusable
    /// the moment anything reads it again.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "rsa-sha256" | "rsasha256" | "8" => Some(Self::RsaSha256),
            "ecdsa-p256" | "ecdsap256sha256" | "ecdsa-p256-sha256" | "13" => {
                Some(Self::EcdsaP256Sha256)
            }
            "ecdsa-p384" | "ecdsap384sha384" | "ecdsa-p384-sha384" | "14" => {
                Some(Self::EcdsaP384Sha384)
            }
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

    /// Whether we can generate a key and produce signatures for this algorithm.
    ///
    /// `RsaSha256` parses — old rows carrying it must still be listable — but is
    /// not signable, because `ring` has no RSA key generation. Refusing here is
    /// the difference between an operator learning at `generate-dnssec-key` time
    /// and a resolver learning at validation time.
    pub fn signing_supported(&self) -> bool {
        !matches!(self, Self::RsaSha256)
    }

    /// The size, in bytes, of the DNSKEY public key this algorithm produces.
    ///
    /// Used to reject key material that does not match the algorithm it is
    /// stored under, which is how a mislabeled key is caught before it is signed
    /// with rather than after.
    fn public_key_len(&self) -> Option<usize> {
        match self {
            Self::Ed25519 => Some(32),
            // RFC 6605 §4: the DNSKEY RDATA is the raw uncompressed point with
            // the leading 0x04 octet stripped, i.e. X || Y.
            Self::EcdsaP256Sha256 => Some(64),
            Self::EcdsaP384Sha384 => Some(96),
            Self::RsaSha256 => None,
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
    pub fn parse(s: &str) -> Option<Self> {
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
    generate_key(zone, DnssecAlgorithm::Ed25519, key_type)
}

/// Generates a key pair for `algorithm`.
///
/// An unsupported algorithm is an error rather than a substitution. The previous
/// behaviour — generate Ed25519 and relabel it as whatever was asked for —
/// produced a DNSKEY whose advertised algorithm did not match its key material,
/// so the DS, the DNSKEY and every signature made with it disagreed with each
/// other and the zone was unvalidatable in a way nothing local would report.
pub fn generate_key(
    zone: &str,
    algorithm: DnssecAlgorithm,
    key_type: KeyType,
) -> Result<DnssecKeyPair> {
    if !algorithm.signing_supported() {
        bail!(
            "algorithm {} is not supported for key generation",
            algorithm.as_str()
        );
    }

    let rng = SystemRandom::new();
    let private_key = match algorithm {
        DnssecAlgorithm::Ed25519 => signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| anyhow::anyhow!("failed to generate Ed25519 key: {}", e))?
            .as_ref()
            .to_vec(),
        DnssecAlgorithm::EcdsaP256Sha256 | DnssecAlgorithm::EcdsaP384Sha384 => {
            signature::EcdsaKeyPair::generate_pkcs8(ecdsa_signing_alg(algorithm)?, &rng)
                .map_err(|e| anyhow::anyhow!("failed to generate ECDSA key: {}", e))?
                .as_ref()
                .to_vec()
        }
        DnssecAlgorithm::RsaSha256 => unreachable!("guarded by signing_supported above"),
    };

    // Round-trip the freshly generated PKCS#8 through the loader rather than
    // deriving the public key separately: the key that gets stored is then
    // provably the key that will later load and sign.
    let signing_key = SigningKey::from_pkcs8(algorithm, key_type, &private_key)?;
    let public_key = signing_key.public_key().to_vec();
    let key_tag = signing_key.key_tag;

    Ok(DnssecKeyPair {
        zone: zone.to_string(),
        algorithm,
        key_type,
        private_key,
        public_key,
        key_tag,
    })
}

fn ecdsa_signing_alg(
    algorithm: DnssecAlgorithm,
) -> Result<&'static signature::EcdsaSigningAlgorithm> {
    match algorithm {
        DnssecAlgorithm::EcdsaP256Sha256 => Ok(&signature::ECDSA_P256_SHA256_FIXED_SIGNING),
        DnssecAlgorithm::EcdsaP384Sha384 => Ok(&signature::ECDSA_P384_SHA384_FIXED_SIGNING),
        other => bail!("{} is not an ECDSA algorithm", other.as_str()),
    }
}

fn ecdsa_verification_alg(
    algorithm: DnssecAlgorithm,
) -> Result<&'static signature::EcdsaVerificationAlgorithm> {
    match algorithm {
        DnssecAlgorithm::EcdsaP256Sha256 => Ok(&signature::ECDSA_P256_SHA256_FIXED),
        DnssecAlgorithm::EcdsaP384Sha384 => Ok(&signature::ECDSA_P384_SHA384_FIXED),
        other => bail!("{} is not an ECDSA algorithm", other.as_str()),
    }
}

/// A private key loaded from storage and ready to sign.
///
/// Loading is where a key's stored algorithm label is checked against its actual
/// material: Ed25519 PKCS#8 does not parse as P-256, so a row mislabeled by the
/// old key generator fails here instead of yielding a signature that claims an
/// algorithm it was not made with.
pub struct SigningKey {
    pub algorithm: DnssecAlgorithm,
    pub key_type: KeyType,
    pub key_tag: u16,
    /// DNSKEY-form public key (ECDSA points already stripped of their 0x04).
    public_key: Vec<u8>,
    material: KeyMaterial,
}

enum KeyMaterial {
    Ed25519(Box<signature::Ed25519KeyPair>),
    Ecdsa(Box<signature::EcdsaKeyPair>),
}

impl SigningKey {
    /// Loads a PKCS#8 private key, verifying it really is the algorithm claimed.
    pub fn from_pkcs8(algorithm: DnssecAlgorithm, key_type: KeyType, pkcs8: &[u8]) -> Result<Self> {
        if !algorithm.signing_supported() {
            bail!("cannot sign with algorithm {}", algorithm.as_str());
        }

        let (material, public_key) = match algorithm {
            DnssecAlgorithm::Ed25519 => {
                let kp = signature::Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|e| {
                    anyhow::anyhow!("key material is not a valid Ed25519 PKCS#8 key: {}", e)
                })?;
                let public = kp.public_key().as_ref().to_vec();
                (KeyMaterial::Ed25519(Box::new(kp)), public)
            }
            DnssecAlgorithm::EcdsaP256Sha256 | DnssecAlgorithm::EcdsaP384Sha384 => {
                let rng = SystemRandom::new();
                let kp =
                    signature::EcdsaKeyPair::from_pkcs8(ecdsa_signing_alg(algorithm)?, pkcs8, &rng)
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "key material is not a valid {} PKCS#8 key: {}",
                                algorithm.as_str(),
                                e
                            )
                        })?;
                // RFC 6605 §4: DNSKEY carries X || Y, so drop the SEC1
                // uncompressed-point tag that `ring` hands back.
                let point = kp.public_key().as_ref();
                let public = match point.split_first() {
                    Some((0x04, xy)) => xy.to_vec(),
                    _ => bail!("ECDSA public key is not in uncompressed SEC1 form"),
                };
                (KeyMaterial::Ecdsa(Box::new(kp)), public)
            }
            DnssecAlgorithm::RsaSha256 => bail!("cannot sign with algorithm RSA-SHA256"),
        };

        if algorithm.public_key_len() != Some(public_key.len()) {
            bail!(
                "{} public key is {} bytes, expected {:?}",
                algorithm.as_str(),
                public_key.len(),
                algorithm.public_key_len()
            );
        }

        let key_tag = compute_key_tag(algorithm, key_type, &public_key);
        Ok(Self {
            algorithm,
            key_type,
            key_tag,
            public_key,
            material,
        })
    }

    /// The DNSKEY-form public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match &self.material {
            KeyMaterial::Ed25519(kp) => Ok(kp.sign(message).as_ref().to_vec()),
            KeyMaterial::Ecdsa(kp) => {
                let rng = SystemRandom::new();
                // FIXED (not ASN1) signing: RFC 6605 §4 wants the raw r || s
                // pair, not a DER-wrapped SEQUENCE.
                let sig = kp
                    .sign(&rng, message)
                    .map_err(|e| anyhow::anyhow!("ECDSA signing failed: {}", e))?;
                Ok(sig.as_ref().to_vec())
            }
        }
    }
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

/// Encodes a domain name in DNSSEC canonical form (RFC 4034 §6.1): fully
/// qualified, uncompressed, and lowercased.
///
/// Compression is not merely unnecessary here, it is forbidden — a pointer's
/// value depends on where in a message the name happened to land, so a
/// compressed name would make the signature depend on the packet layout of
/// whoever computed it.
fn canonical_name(name: &str) -> Option<Vec<u8>> {
    let lower = name.trim().to_lowercase();
    let trimmed = lower.trim_end_matches('.');
    let mut out = Vec::with_capacity(trimmed.len() + 2);
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    Some(out)
}

/// The label count for the RRSIG `labels` field (RFC 4034 §3.1.3): the root
/// label is not counted, and a leading wildcard label is not counted either, so
/// that a validator can tell a wildcard expansion from an exact match.
fn label_count(name: &str) -> u8 {
    let lower = name.trim().to_lowercase();
    let trimmed = lower.trim_end_matches('.');
    if trimmed.is_empty() {
        return 0;
    }
    let mut labels: Vec<&str> = trimmed.split('.').collect();
    if labels.first() == Some(&"*") {
        labels.remove(0);
    }
    labels.len().min(u8::MAX as usize) as u8
}

/// Splits a string into DNS character-strings (a length octet followed by up to
/// 255 bytes), as TXT-like RDATA requires.
fn character_strings(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() + bytes.len().div_ceil(255) + 1);
    if bytes.is_empty() {
        out.push(0);
        return out;
    }
    for chunk in bytes.chunks(255) {
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
    out
}

/// Encodes a stored record's value as canonical-form RDATA (RFC 4034 §6.2).
///
/// Returns `None` for a record whose stored value cannot be expressed as wire
/// RDATA — either because the type has no canonical encoding here (NSEC and
/// friends, which this server never generates) or because the value is
/// malformed. `None` means **skip**, never "sign something approximate": a
/// signature computed over a guess is worse than no signature, because it
/// validates as bogus rather than as unsigned.
pub fn canonical_rdata(record: &DnsRecord) -> Option<Vec<u8>> {
    let value = record.value.trim();
    let fields: Vec<&str> = value.split_whitespace().collect();
    let mut out = Vec::new();

    match record.record_type {
        RecordKind::A => {
            let ip: std::net::Ipv4Addr = value.parse().ok()?;
            out.extend_from_slice(&ip.octets());
        }
        RecordKind::AAAA => {
            let ip: std::net::Ipv6Addr = value.parse().ok()?;
            out.extend_from_slice(&ip.octets());
        }
        RecordKind::CNAME | RecordKind::NS | RecordKind::PTR | RecordKind::DNAME => {
            out.extend_from_slice(&canonical_name(value)?);
        }
        RecordKind::MX => {
            out.extend_from_slice(&(u16::try_from(record.priority).ok()?).to_be_bytes());
            out.extend_from_slice(&canonical_name(value)?);
        }
        RecordKind::TXT => out.extend_from_slice(&character_strings(value)),
        RecordKind::SOA => {
            // "mname rname serial refresh retry expire minimum"
            if fields.len() < 7 {
                return None;
            }
            out.extend_from_slice(&canonical_name(fields[0])?);
            out.extend_from_slice(&canonical_name(fields[1])?);
            for field in &fields[2..7] {
                out.extend_from_slice(&field.parse::<u32>().ok()?.to_be_bytes());
            }
        }
        RecordKind::SRV => {
            // "weight port target", with priority stored out-of-band.
            if fields.len() < 3 {
                return None;
            }
            out.extend_from_slice(&(u16::try_from(record.priority).ok()?).to_be_bytes());
            out.extend_from_slice(&fields[0].parse::<u16>().ok()?.to_be_bytes());
            out.extend_from_slice(&fields[1].parse::<u16>().ok()?.to_be_bytes());
            out.extend_from_slice(&canonical_name(fields[2])?);
        }
        RecordKind::SSHFP => {
            // "algorithm fp_type hex_fingerprint"
            if fields.len() < 3 {
                return None;
            }
            out.push(fields[0].parse::<u8>().ok()?);
            out.push(fields[1].parse::<u8>().ok()?);
            out.extend_from_slice(&hex::decode(fields[2]).ok()?);
        }
        RecordKind::TLSA => {
            // "usage selector matching_type hex_data"
            if fields.len() < 4 {
                return None;
            }
            out.push(fields[0].parse::<u8>().ok()?);
            out.push(fields[1].parse::<u8>().ok()?);
            out.push(fields[2].parse::<u8>().ok()?);
            out.extend_from_slice(&hex::decode(fields[3]).ok()?);
        }
        RecordKind::CERT => {
            // "cert_type key_tag algorithm base64_cert_data"
            if fields.len() < 4 {
                return None;
            }
            out.extend_from_slice(&fields[0].parse::<u16>().ok()?.to_be_bytes());
            out.extend_from_slice(&fields[1].parse::<u16>().ok()?.to_be_bytes());
            out.push(fields[2].parse::<u8>().ok()?);
            out.extend_from_slice(
                &base64::Engine::decode(&base64::engine::general_purpose::STANDARD, fields[3])
                    .ok()?,
            );
        }
        RecordKind::URI => {
            // "priority weight target_uri"; the target is the rest of the RDATA
            // with no length prefix (RFC 7553 §4.5).
            if fields.len() < 3 {
                return None;
            }
            out.extend_from_slice(&fields[0].parse::<u16>().ok()?.to_be_bytes());
            out.extend_from_slice(&fields[1].parse::<u16>().ok()?.to_be_bytes());
            let target_at = value.find(fields[2])?;
            out.extend_from_slice(value[target_at..].trim().as_bytes());
        }
        RecordKind::ZONEMD => {
            // "serial scheme hash_algorithm hex_digest"
            if fields.len() < 4 {
                return None;
            }
            out.extend_from_slice(&fields[0].parse::<u32>().ok()?.to_be_bytes());
            out.push(fields[1].parse::<u8>().ok()?);
            out.push(fields[2].parse::<u8>().ok()?);
            out.extend_from_slice(&hex::decode(fields[3]).ok()?);
        }
        RecordKind::DNSKEY => {
            // "flags protocol algorithm base64_public_key"
            if fields.len() < 4 {
                return None;
            }
            out.extend_from_slice(&fields[0].parse::<u16>().ok()?.to_be_bytes());
            out.push(fields[1].parse::<u8>().ok()?);
            out.push(fields[2].parse::<u8>().ok()?);
            out.extend_from_slice(
                &base64::Engine::decode(&base64::engine::general_purpose::STANDARD, fields[3])
                    .ok()?,
            );
        }
        RecordKind::DS => {
            // "key_tag algorithm digest_type hex_digest"
            if fields.len() < 4 {
                return None;
            }
            out.extend_from_slice(&fields[0].parse::<u16>().ok()?.to_be_bytes());
            out.push(fields[1].parse::<u8>().ok()?);
            out.push(fields[2].parse::<u8>().ok()?);
            out.extend_from_slice(&hex::decode(fields[3]).ok()?);
        }
        RecordKind::RRSIG => {
            let rrsig = Rrsig::parse(value).ok()?;
            out.extend_from_slice(&rrsig.rdata()?);
        }
        // ANAME is resolved at query time and never appears on the wire; NSEC,
        // NSEC3 and NSEC3PARAM are not generated by this server, so there is no
        // stored format to encode. Signing any of them would mean inventing one.
        RecordKind::ANAME | RecordKind::NSEC | RecordKind::NSEC3 | RecordKind::NSEC3PARAM => {
            return None;
        }
    }

    Some(out)
}

/// A parsed RRSIG.
///
/// Stored in the database as
/// `"<type_covered> <algorithm> <labels> <original_ttl> <expiration> <inception> <key_tag> <signer_name> <base64_signature>"`.
/// Expiration and inception are raw seconds since the Unix epoch rather than the
/// `YYYYMMDDHHmmSS` of zone-file presentation format, matching how every other
/// record type in this database stores its numeric fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rrsig {
    pub type_covered: RecordKind,
    pub algorithm: DnssecAlgorithm,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer_name: String,
    pub signature: Vec<u8>,
}

impl Rrsig {
    /// Renders the stored-value form.
    pub fn to_value(&self) -> String {
        format!(
            "{} {} {} {} {} {} {} {} {}",
            self.type_covered.as_str(),
            self.algorithm as u8,
            self.labels,
            self.original_ttl,
            self.expiration,
            self.inception,
            self.key_tag,
            self.signer_name,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.signature),
        )
    }

    /// Parses the stored-value form.
    pub fn parse(value: &str) -> Result<Self> {
        let fields: Vec<&str> = value.split_whitespace().collect();
        if fields.len() < 9 {
            bail!("RRSIG value has {} fields, expected 9", fields.len());
        }
        let type_covered = RecordKind::parse(fields[0])
            .ok_or_else(|| anyhow::anyhow!("unknown covered type {}", fields[0]))?;
        let algorithm = DnssecAlgorithm::parse(fields[1])
            .ok_or_else(|| anyhow::anyhow!("unknown algorithm {}", fields[1]))?;
        Ok(Self {
            type_covered,
            algorithm,
            labels: fields[2].parse()?,
            original_ttl: fields[3].parse()?,
            expiration: fields[4].parse()?,
            inception: fields[5].parse()?,
            key_tag: fields[6].parse()?,
            signer_name: fields[7].to_string(),
            signature: base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                fields[8],
            )?,
        })
    }

    /// The RRSIG RDATA fields that precede the signature — which is exactly the
    /// prefix that is itself signed (RFC 4034 §3.1.8.1).
    fn signed_prefix(&self) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(18 + self.signer_name.len());
        out.extend_from_slice(&self.type_covered.wire_type().to_be_bytes());
        out.push(self.algorithm as u8);
        out.push(self.labels);
        out.extend_from_slice(&self.original_ttl.to_be_bytes());
        out.extend_from_slice(&self.expiration.to_be_bytes());
        out.extend_from_slice(&self.inception.to_be_bytes());
        out.extend_from_slice(&self.key_tag.to_be_bytes());
        out.extend_from_slice(&canonical_name(&self.signer_name)?);
        Some(out)
    }

    /// The full wire RDATA: the signed prefix followed by the signature.
    fn rdata(&self) -> Option<Vec<u8>> {
        let mut out = self.signed_prefix()?;
        out.extend_from_slice(&self.signature);
        Some(out)
    }
}

/// The bytes a signature is computed over, per RFC 4034 §3.1.8.1:
/// the RRSIG RDATA up to but excluding the signature, then every RR in the
/// RRset in canonical form and canonical order.
fn signing_input(rrsig: &Rrsig, owner: &str, rrset: &[DnsRecord]) -> Result<Vec<u8>> {
    let mut rdatas: Vec<Vec<u8>> = Vec::with_capacity(rrset.len());
    for record in rrset {
        let rdata = canonical_rdata(record).ok_or_else(|| {
            anyhow::anyhow!(
                "cannot canonically encode {} record {:?}",
                record.record_type.as_str(),
                record.value
            )
        })?;
        rdatas.push(rdata);
    }

    // RFC 4034 §6.3: RRs sort by their RDATA treated as a left-justified
    // unsigned octet sequence, and duplicates are dropped. Both matter — a
    // validator re-derives this order from the wire, where the RRs may arrive
    // in any order at all.
    rdatas.sort_unstable();
    rdatas.dedup();

    let owner_wire =
        canonical_name(owner).ok_or_else(|| anyhow::anyhow!("invalid owner name {owner:?}"))?;
    let mut input = rrsig
        .signed_prefix()
        .ok_or_else(|| anyhow::anyhow!("invalid signer name {:?}", rrsig.signer_name))?;

    for rdata in &rdatas {
        input.extend_from_slice(&owner_wire);
        input.extend_from_slice(&rrsig.type_covered.wire_type().to_be_bytes());
        input.extend_from_slice(&1u16.to_be_bytes()); // class IN
        // The *original* TTL, not the record's current one: a cached RR's TTL
        // decays in transit, so signing the live value would invalidate the
        // signature the moment it passed through any cache.
        input.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        let len =
            u16::try_from(rdata.len()).map_err(|_| anyhow::anyhow!("RDATA exceeds 65535 bytes"))?;
        input.extend_from_slice(&len.to_be_bytes());
        input.extend_from_slice(rdata);
    }

    Ok(input)
}

/// How far an RRSIG is backdated, to tolerate clock skew between us and a
/// validator.
pub const RRSIG_INCEPTION_BACKDATE_SECS: u64 = 3600;
/// How long a generated RRSIG remains valid.
pub const RRSIG_VALIDITY_SECS: u64 = 30 * 86400;

/// One RRset to be signed, and the validity window to sign it under.
pub struct RrsetToSign<'a> {
    /// The zone whose key signs this, and so the RRSIG's signer name.
    pub signer_zone: &'a str,
    /// The owner name shared by every record in the set.
    pub owner: &'a str,
    pub type_covered: RecordKind,
    /// The RRset's TTL. Every RR in an RRset must share one TTL; callers that
    /// find a disagreement should resolve it before signing, since the value
    /// here is the one a validator will require.
    pub original_ttl: u32,
    pub rrset: &'a [DnsRecord],
    pub inception: u32,
    pub expiration: u32,
}

/// Signs one RRset — all records sharing an owner name and type — returning the
/// RRSIG in stored-value form.
pub fn sign_rrset(key: &SigningKey, set: &RrsetToSign<'_>) -> Result<String> {
    if set.rrset.is_empty() {
        bail!("cannot sign an empty RRset");
    }
    if set.type_covered == RecordKind::RRSIG {
        // RFC 4035 §2.2: an RRSIG RRset is never itself signed.
        bail!("RRSIG RRsets are not signed");
    }

    let mut rrsig = Rrsig {
        type_covered: set.type_covered,
        algorithm: key.algorithm,
        labels: label_count(set.owner),
        original_ttl: set.original_ttl,
        expiration: set.expiration,
        inception: set.inception,
        key_tag: key.key_tag,
        signer_name: crate::db::normalize_name(set.signer_zone),
        signature: Vec::new(),
    };

    let input = signing_input(&rrsig, set.owner, set.rrset)?;
    rrsig.signature = key.sign(&input)?;
    Ok(rrsig.to_value())
}

/// Verifies an RRSIG against an RRset and a DNSKEY-form public key.
///
/// This is the inverse of [`sign_rrset`] and exists so the signer can be checked
/// against something other than itself. It is deliberately not wired into the
/// resolution path: Rolodex does not validate upstream DNSSEC, and a verifier
/// that is only ever called on our own signatures must not be mistaken for one.
pub fn verify_rrsig(
    rrsig_value: &str,
    owner: &str,
    rrset: &[DnsRecord],
    public_key: &[u8],
) -> Result<()> {
    let rrsig = Rrsig::parse(rrsig_value)?;
    let input = signing_input(&rrsig, owner, rrset)?;

    match rrsig.algorithm {
        DnssecAlgorithm::Ed25519 => {
            signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
                .verify(&input, &rrsig.signature)
                .map_err(|_| anyhow::anyhow!("Ed25519 signature verification failed"))
        }
        DnssecAlgorithm::EcdsaP256Sha256 | DnssecAlgorithm::EcdsaP384Sha384 => {
            // Undo the RFC 6605 §4 stripping: `ring` wants the SEC1
            // uncompressed point that DNSKEY omits the tag octet from.
            let mut point = Vec::with_capacity(public_key.len() + 1);
            point.push(0x04);
            point.extend_from_slice(public_key);
            signature::UnparsedPublicKey::new(ecdsa_verification_alg(rrsig.algorithm)?, &point)
                .verify(&input, &rrsig.signature)
                .map_err(|_| anyhow::anyhow!("ECDSA signature verification failed"))
        }
        DnssecAlgorithm::RsaSha256 => bail!("RSA-SHA256 verification is not supported"),
    }
}

/// Current Unix time as the u32 seconds an RRSIG timestamp uses.
pub fn now_secs() -> Result<u32> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock is before the Unix epoch: {}", e))?
        .as_secs();
    u32::try_from(secs).map_err(|_| anyhow::anyhow!("system clock is past the u32 epoch limit"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, kind: RecordKind, value: &str) -> DnsRecord {
        DnsRecord {
            id: None,
            name: name.to_string(),
            record_type: kind,
            value: value.to_string(),
            ttl: 300,
            priority: 0,
        }
    }

    #[test]
    fn test_algorithm_from_str() {
        assert_eq!(
            DnssecAlgorithm::parse("ed25519"),
            Some(DnssecAlgorithm::Ed25519)
        );
        assert_eq!(DnssecAlgorithm::parse("15"), Some(DnssecAlgorithm::Ed25519));
        assert_eq!(
            DnssecAlgorithm::parse("ecdsa-p256"),
            Some(DnssecAlgorithm::EcdsaP256Sha256)
        );
        assert!(DnssecAlgorithm::parse("unknown").is_none());
    }

    /// `as_str` is what is written to the key table, so it must parse back.
    /// It did not for the ECDSA algorithms, which made every stored ECDSA key
    /// unreadable at signing time.
    #[test]
    fn algorithm_names_round_trip_through_storage() {
        for algorithm in [
            DnssecAlgorithm::Ed25519,
            DnssecAlgorithm::EcdsaP256Sha256,
            DnssecAlgorithm::EcdsaP384Sha384,
            DnssecAlgorithm::RsaSha256,
        ] {
            assert_eq!(
                DnssecAlgorithm::parse(algorithm.as_str()),
                Some(algorithm),
                "{} must parse back from its stored spelling",
                algorithm.as_str()
            );
        }
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

    /// RFC 4034 §6.1: canonical names are lowercased and fully qualified, and
    /// the three spellings of one name must produce identical bytes — otherwise
    /// a signature depends on how the operator happened to type the record.
    #[test]
    fn canonical_name_is_case_and_dot_insensitive() {
        let a = canonical_name("Example.COM.").expect("encode");
        let b = canonical_name("example.com").expect("encode");
        let c = canonical_name("EXAMPLE.com.").expect("encode");
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(a, b"\x07example\x03com\x00");
        assert_eq!(canonical_name(".").expect("root"), b"\x00");
    }

    #[test]
    fn canonical_name_rejects_malformed_labels() {
        assert!(canonical_name("a..b").is_none());
        assert!(canonical_name(&format!("{}.com", "x".repeat(64))).is_none());
    }

    /// RFC 4034 §3.1.3: the root label is not counted, and a leading wildcard
    /// is not counted either.
    #[test]
    fn label_count_excludes_root_and_wildcard() {
        assert_eq!(label_count("example.com."), 2);
        assert_eq!(label_count("www.example.com."), 3);
        assert_eq!(label_count("*.example.com."), 2);
        assert_eq!(label_count("."), 0);
    }

    #[test]
    fn character_strings_chunk_at_255_bytes() {
        let long = "a".repeat(300);
        let encoded = character_strings(&long);
        assert_eq!(encoded[0], 255);
        assert_eq!(encoded[256], 45);
        assert_eq!(encoded.len(), 1 + 255 + 1 + 45);
        assert_eq!(character_strings(""), vec![0u8]);
    }

    #[test]
    fn canonical_rdata_encodes_addresses() {
        let a = record("host.example.com.", RecordKind::A, "192.0.2.1");
        assert_eq!(canonical_rdata(&a).expect("A"), vec![192, 0, 2, 1]);

        let aaaa = record("host.example.com.", RecordKind::AAAA, "2001:db8::1");
        assert_eq!(canonical_rdata(&aaaa).expect("AAAA").len(), 16);
    }

    /// RFC 4034 §6.2: names embedded in the RDATA of these types are
    /// downcased for canonical form.
    #[test]
    fn canonical_rdata_downcases_embedded_names() {
        let upper = record("example.com.", RecordKind::CNAME, "Target.Example.COM.");
        let lower = record("example.com.", RecordKind::CNAME, "target.example.com.");
        assert_eq!(
            canonical_rdata(&upper).expect("upper"),
            canonical_rdata(&lower).expect("lower")
        );
    }

    #[test]
    fn canonical_rdata_encodes_mx_priority_from_the_column() {
        let mut mx = record("example.com.", RecordKind::MX, "mail.example.com.");
        mx.priority = 10;
        let encoded = canonical_rdata(&mx).expect("MX");
        assert_eq!(&encoded[..2], &10u16.to_be_bytes());
        assert_eq!(&encoded[2..], b"\x04mail\x07example\x03com\x00");
    }

    #[test]
    fn canonical_rdata_encodes_soa_fields() {
        let soa = record(
            "example.com.",
            RecordKind::SOA,
            "ns1.example.com. admin.example.com. 42 7200 3600 1209600 300",
        );
        let encoded = canonical_rdata(&soa).expect("SOA");
        // Two names, then five u32s.
        let names_len =
            b"\x03ns1\x07example\x03com\x00".len() + b"\x05admin\x07example\x03com\x00".len();
        assert_eq!(encoded.len(), names_len + 20);
        assert_eq!(&encoded[names_len..names_len + 4], &42u32.to_be_bytes());
    }

    /// The types this server never generates have no stored wire format, so
    /// they must be skipped rather than approximated.
    #[test]
    fn canonical_rdata_refuses_types_it_cannot_encode() {
        for kind in [
            RecordKind::NSEC,
            RecordKind::NSEC3,
            RecordKind::NSEC3PARAM,
            RecordKind::ANAME,
        ] {
            let rec = record("example.com.", kind, "whatever");
            assert!(
                canonical_rdata(&rec).is_none(),
                "{} must not be canonically encoded",
                kind.as_str()
            );
        }
    }

    #[test]
    fn canonical_rdata_refuses_malformed_values() {
        let bad_a = record("example.com.", RecordKind::A, "not-an-ip");
        assert!(canonical_rdata(&bad_a).is_none());
        let short_soa = record("example.com.", RecordKind::SOA, "ns1. admin. 1");
        assert!(canonical_rdata(&short_soa).is_none());
        let bad_tlsa = record("example.com.", RecordKind::TLSA, "3 1 1 nothex");
        assert!(canonical_rdata(&bad_tlsa).is_none());
    }

    #[test]
    fn rrsig_value_round_trips() {
        let rrsig = Rrsig {
            type_covered: RecordKind::A,
            algorithm: DnssecAlgorithm::Ed25519,
            labels: 2,
            original_ttl: 300,
            expiration: 1_800_000_000,
            inception: 1_700_000_000,
            key_tag: 12345,
            signer_name: "example.com.".to_string(),
            signature: vec![1, 2, 3, 4, 5],
        };
        let parsed = Rrsig::parse(&rrsig.to_value()).expect("parse");
        assert_eq!(parsed, rrsig);
    }

    #[test]
    fn rrsig_parse_rejects_short_and_unknown_values() {
        assert!(Rrsig::parse("A 15 2 300").is_err());
        assert!(Rrsig::parse("NOPE 15 2 300 1 2 3 example.com. AAAA").is_err());
    }

    /// Every algorithm we claim to support must actually produce a signature
    /// that verifies — the whole point of dropping the relabeling generator.
    #[test]
    fn sign_and_verify_round_trip_per_algorithm() {
        for algorithm in [
            DnssecAlgorithm::Ed25519,
            DnssecAlgorithm::EcdsaP256Sha256,
            DnssecAlgorithm::EcdsaP384Sha384,
        ] {
            let pair = generate_key("example.com.", algorithm, KeyType::ZSK).expect("generate key");
            let key = SigningKey::from_pkcs8(algorithm, KeyType::ZSK, &pair.private_key)
                .expect("load key");
            assert_eq!(key.public_key(), pair.public_key.as_slice());

            let rrset = vec![
                record("www.example.com.", RecordKind::A, "192.0.2.1"),
                record("www.example.com.", RecordKind::A, "192.0.2.2"),
            ];
            let value = sign_rrset(
                &key,
                &RrsetToSign {
                    signer_zone: "example.com.",
                    owner: "www.example.com.",
                    type_covered: RecordKind::A,
                    original_ttl: 300,
                    rrset: &rrset,
                    inception: 1_700_000_000,
                    expiration: 1_800_000_000,
                },
            )
            .expect("sign");

            verify_rrsig(&value, "www.example.com.", &rrset, key.public_key())
                .unwrap_or_else(|e| panic!("{} must verify: {e}", algorithm.as_str()));

            let parsed = Rrsig::parse(&value).expect("parse");
            assert_eq!(parsed.algorithm, algorithm);
            assert_eq!(parsed.key_tag, key.key_tag);
            assert_eq!(parsed.labels, 3);
            assert_eq!(parsed.type_covered, RecordKind::A);
        }
    }

    /// A signature must cover the data. If altering an RR does not break
    /// verification, the signature is decorative.
    #[test]
    fn verification_fails_when_the_rrset_changes() {
        let pair = generate_ed25519_key("example.com.", KeyType::ZSK).expect("generate");
        let key = SigningKey::from_pkcs8(DnssecAlgorithm::Ed25519, KeyType::ZSK, &pair.private_key)
            .expect("load");
        let rrset = vec![record("www.example.com.", RecordKind::A, "192.0.2.1")];
        let value = sign_rrset(
            &key,
            &RrsetToSign {
                signer_zone: "example.com.",
                owner: "www.example.com.",
                type_covered: RecordKind::A,
                original_ttl: 300,
                rrset: &rrset,
                inception: 1_700_000_000,
                expiration: 1_800_000_000,
            },
        )
        .expect("sign");

        let tampered = vec![record("www.example.com.", RecordKind::A, "198.51.100.9")];
        assert!(verify_rrsig(&value, "www.example.com.", &tampered, key.public_key()).is_err());

        // A different owner name is likewise a different signed message.
        assert!(verify_rrsig(&value, "other.example.com.", &rrset, key.public_key()).is_err());

        // As is a different key.
        let other = generate_ed25519_key("example.com.", KeyType::ZSK).expect("generate");
        assert!(verify_rrsig(&value, "www.example.com.", &rrset, &other.public_key).is_err());
    }

    /// RFC 4034 §6.3: the RRset is sorted into canonical order before signing,
    /// so the order records come out of the database in cannot matter.
    #[test]
    fn rrset_order_does_not_change_the_signature() {
        let pair = generate_ed25519_key("example.com.", KeyType::ZSK).expect("generate");
        let key = SigningKey::from_pkcs8(DnssecAlgorithm::Ed25519, KeyType::ZSK, &pair.private_key)
            .expect("load");
        let forward = vec![
            record("www.example.com.", RecordKind::A, "192.0.2.1"),
            record("www.example.com.", RecordKind::A, "192.0.2.2"),
        ];
        let reversed: Vec<DnsRecord> = forward.iter().rev().cloned().collect();

        let sign = |rrset: &[DnsRecord]| {
            sign_rrset(
                &key,
                &RrsetToSign {
                    signer_zone: "example.com.",
                    owner: "www.example.com.",
                    type_covered: RecordKind::A,
                    original_ttl: 300,
                    rrset,
                    inception: 1_700_000_000,
                    expiration: 1_800_000_000,
                },
            )
            .expect("sign")
        };

        // Ed25519 is deterministic, so identical input means an identical value.
        assert_eq!(sign(&forward), sign(&reversed));
        // And each verifies against the other's ordering.
        verify_rrsig(
            &sign(&forward),
            "www.example.com.",
            &reversed,
            key.public_key(),
        )
        .expect("verify");
    }

    /// A mislabeled key must fail to load rather than sign with an algorithm it
    /// is not. This is the failure the old "generate Ed25519, call it ECDSA"
    /// path produced, and it is invisible until a resolver rejects the zone.
    #[test]
    fn loading_rejects_key_material_that_contradicts_its_label() {
        let ed =
            generate_key("example.com.", DnssecAlgorithm::Ed25519, KeyType::ZSK).expect("generate");
        let err = SigningKey::from_pkcs8(
            DnssecAlgorithm::EcdsaP256Sha256,
            KeyType::ZSK,
            &ed.private_key,
        );
        assert!(err.is_err(), "Ed25519 material must not load as P-256");

        let p256 = generate_key(
            "example.com.",
            DnssecAlgorithm::EcdsaP256Sha256,
            KeyType::ZSK,
        )
        .expect("generate");
        assert!(
            SigningKey::from_pkcs8(DnssecAlgorithm::Ed25519, KeyType::ZSK, &p256.private_key)
                .is_err(),
            "P-256 material must not load as Ed25519"
        );
        assert!(
            SigningKey::from_pkcs8(
                DnssecAlgorithm::EcdsaP384Sha384,
                KeyType::ZSK,
                &p256.private_key
            )
            .is_err(),
            "P-256 material must not load as P-384"
        );
    }

    #[test]
    fn rsa_is_refused_rather_than_substituted() {
        assert!(!DnssecAlgorithm::RsaSha256.signing_supported());
        assert!(generate_key("example.com.", DnssecAlgorithm::RsaSha256, KeyType::ZSK).is_err());
        assert!(
            SigningKey::from_pkcs8(DnssecAlgorithm::RsaSha256, KeyType::ZSK, &[0u8; 32]).is_err()
        );
    }

    /// Generated key material must match the algorithm's published key size,
    /// which is also what makes the DNSKEY and DS records self-consistent.
    #[test]
    fn generated_public_keys_have_the_algorithms_size() {
        for (algorithm, len) in [
            (DnssecAlgorithm::Ed25519, 32),
            (DnssecAlgorithm::EcdsaP256Sha256, 64),
            (DnssecAlgorithm::EcdsaP384Sha384, 96),
        ] {
            let pair = generate_key("example.com.", algorithm, KeyType::KSK).expect("generate");
            assert_eq!(pair.public_key.len(), len, "{}", algorithm.as_str());
            assert_eq!(pair.algorithm, algorithm);
            assert_eq!(
                pair.key_tag,
                compute_key_tag(algorithm, KeyType::KSK, &pair.public_key)
            );
        }
    }

    #[test]
    fn rrsig_rrsets_are_never_signed() {
        let pair = generate_ed25519_key("example.com.", KeyType::ZSK).expect("generate");
        let key = SigningKey::from_pkcs8(DnssecAlgorithm::Ed25519, KeyType::ZSK, &pair.private_key)
            .expect("load");
        let rrset = vec![record("www.example.com.", RecordKind::RRSIG, "irrelevant")];
        assert!(
            sign_rrset(
                &key,
                &RrsetToSign {
                    signer_zone: "example.com.",
                    owner: "www.example.com.",
                    type_covered: RecordKind::RRSIG,
                    original_ttl: 300,
                    rrset: &rrset,
                    inception: 1,
                    expiration: 2,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn signing_an_empty_rrset_is_an_error() {
        let pair = generate_ed25519_key("example.com.", KeyType::ZSK).expect("generate");
        let key = SigningKey::from_pkcs8(DnssecAlgorithm::Ed25519, KeyType::ZSK, &pair.private_key)
            .expect("load");
        assert!(
            sign_rrset(
                &key,
                &RrsetToSign {
                    signer_zone: "example.com.",
                    owner: "www.example.com.",
                    type_covered: RecordKind::A,
                    original_ttl: 300,
                    rrset: &[],
                    inception: 1,
                    expiration: 2,
                },
            )
            .is_err()
        );
    }
}
