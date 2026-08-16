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
use std::cmp::Ordering;
use std::collections::BTreeMap;
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

/// Compares two owner names in DNSSEC canonical order (RFC 4034 §6.1).
///
/// Names sort as label sequences read **right to left**, each label compared as
/// unsigned bytes with ASCII case folded away. This is not the same as sorting
/// the strings: byte-wise, `a.example.com.` precedes `example.com.`, while
/// canonically the apex comes first because its label sequence is a suffix of
/// the other's. Getting this wrong does not fail loudly — it builds an NSEC
/// chain whose ranges do not tile the zone, so a validator finds no record
/// covering the name it asked about and calls a correct denial bogus.
pub fn canonical_name_cmp(a: &str, b: &str) -> Ordering {
    let a_labels: Vec<&str> = a.trim_end_matches('.').split('.').rev().collect();
    let b_labels: Vec<&str> = b.trim_end_matches('.').split('.').rev().collect();
    for (x, y) in a_labels.iter().zip(b_labels.iter()) {
        // The root's empty label sorts before everything, which falls out of
        // comparing an empty byte slice.
        let ord = x
            .bytes()
            .map(|c| c.to_ascii_lowercase())
            .cmp(y.bytes().map(|c| c.to_ascii_lowercase()));
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a_labels.len().cmp(&b_labels.len())
}

/// Encodes a set of RR type codes as an RFC 4034 §4.1.2 type bit map.
///
/// The wire form is a sequence of window blocks, each covering 256 type codes:
/// a one-byte window number (the code's high byte), a one-byte length, then that
/// many bytes of bitmap in which bit 0 of byte 0 is the window's lowest code.
/// Windows with no types set are omitted entirely, and each window's length is
/// trimmed to its highest set byte — a trailing zero byte would encode the same
/// set as different bytes, and the signature is over the bytes.
///
/// Windows must be emitted in increasing order, and this sorts to guarantee it:
/// a validator comparing our bitmap against its own reconstruction compares
/// bytes, so "same set, different order" is a verification failure.
pub fn encode_type_bitmap(types: &[u16]) -> Vec<u8> {
    let mut windows: BTreeMap<u8, [u8; 32]> = BTreeMap::new();
    for &code in types {
        let window = (code >> 8) as u8;
        let lo = (code & 0xff) as u8;
        let block = windows.entry(window).or_insert([0u8; 32]);
        // Bit 0 is the HIGH bit of the byte (RFC 4034 §4.1.2), not the low one.
        block[(lo / 8) as usize] |= 0x80 >> (lo % 8);
    }

    let mut out = Vec::new();
    for (window, block) in windows {
        let len = match block.iter().rposition(|b| *b != 0) {
            Some(last) => last + 1,
            None => continue,
        };
        out.push(window);
        // A window length is one byte and never exceeds 32 by construction.
        out.push(len as u8);
        out.extend_from_slice(&block[..len]);
    }
    out
}

/// The stored string form of an NSEC record: `"<next_owner> <TYPE> <TYPE> ..."`.
///
/// Types are stored by mnemonic rather than by code because every other stored
/// value in this database is human-legible and an operator reading a zone dump
/// should not have to decode `47` — and because [`RecordKind::parse`] already
/// round-trips the mnemonics, so nothing new has to be kept in step.
///
/// A type this server has no [`RecordKind`] for cannot appear here, which is
/// exactly right: the bitmap must list the types that exist at the name, and a
/// type it cannot store cannot exist at one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec {
    pub next_owner: String,
    pub types: Vec<RecordKind>,
}

impl Nsec {
    /// Renders the stored form. Types are emitted in ascending wire-code order
    /// so a chain rebuilt from the same zone is byte-identical to the last one —
    /// a re-sign that reordered the mnemonics would rewrite every NSEC RDATA and
    /// invalidate every NSEC signature for no reason.
    pub fn to_value(&self) -> String {
        let mut types = self.types.clone();
        types.sort_by_key(RecordKind::wire_type);
        types.dedup();
        let mut out = String::with_capacity(self.next_owner.len() + 8 * types.len());
        out.push_str(&self.next_owner);
        for t in types {
            out.push(' ');
            out.push_str(t.as_str());
        }
        out
    }

    /// Parses the stored form. An unrecognized mnemonic is an error rather than
    /// a skip: dropping it would silently narrow the bitmap, and a bitmap that
    /// omits a type present at the name is a *proof that the type is absent* —
    /// the validator would reject a perfectly good record as forged.
    pub fn parse(value: &str) -> Result<Self> {
        let mut fields = value.split_whitespace();
        let next_owner = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("NSEC value is empty"))?
            .to_string();
        let mut types = Vec::new();
        for field in fields {
            let kind = RecordKind::parse(field)
                .ok_or_else(|| anyhow::anyhow!("unknown type {} in NSEC bitmap", field))?;
            types.push(kind);
        }
        Ok(Self { next_owner, types })
    }

    /// Canonical RDATA: the uncompressed next owner name followed by the bitmap.
    fn rdata(&self) -> Option<Vec<u8>> {
        let mut types: Vec<u16> = self.types.iter().map(RecordKind::wire_type).collect();
        types.sort_unstable();
        types.dedup();
        let mut out = canonical_name(&self.next_owner)?;
        out.extend_from_slice(&encode_type_bitmap(&types));
        Some(out)
    }
}

/// Whether the NSEC at `owner`, pointing at `next`, proves `name` absent.
///
/// The range is the open interval `(owner, next)` in canonical order. The last
/// NSEC in a chain wraps — its next owner is the apex, which sorts *before* it —
/// and that entry covers everything after `owner` as well as everything before
/// `next`, which is how the ring closes with no gap.
///
/// A name equal to `owner` is deliberately **not** covered: that name exists,
/// and the record at it is a positive statement about it rather than a denial.
pub fn nsec_covers(owner: &str, next: &str, name: &str) -> bool {
    if canonical_name_cmp(next, owner) == Ordering::Greater {
        canonical_name_cmp(owner, name) == Ordering::Less
            && canonical_name_cmp(name, next) == Ordering::Less
    } else {
        // Wrapped: from `owner` to the end of the zone, and on from the apex.
        canonical_name_cmp(owner, name) == Ordering::Less
            || canonical_name_cmp(name, next) == Ordering::Less
    }
}

/// Builds the NSEC chain for a zone from the records it holds.
///
/// Returns one `(owner, Nsec)` per name that exists in the zone, in canonical
/// order, each pointing at the next — the last wrapping back to the apex so the
/// ranges tile the whole name space with no gap.
///
/// Three things this has to get right, none of them optional:
///
/// - **Empty non-terminals get no NSEC.** RFC 4035 §2.3 gives one to "each owner
///   name in the zone that has authoritative data or a delegation point NS
///   RRset", and an ENT has neither; the same section forbids an NSEC being "the
///   only RRset at any particular owner name", which is exactly what an ENT's
///   would be. RFC 4034 §4.1.1 says the same from the other end — the Next
///   Domain field names the next owner *with authoritative data*. Inserting ENTs
///   is an NSEC**3** rule (RFC 5155 §7.1), not an NSEC one, and doing it here
///   inflates every proof with links a validator is told to ignore. An ENT's
///   NODATA is proved by the NSEC that covers it instead.
/// - **Every NSEC bitmap includes NSEC and RRSIG**, because the chain adds both
///   to every name it covers. A bitmap that omits them denies the very records
///   carrying the denial.
/// - **The apex additionally lists SOA and DNSKEY** when they are present, which
///   they are by the time a zone is being signed. These fall out of reading the
///   real records rather than being special-cased.
///
/// RRSIG rows are ignored as *input* — they are signatures over the set, not
/// members of it — but RRSIG is still asserted in every bitmap, since signing
/// this chain is what puts one at each name. ANAME is dropped from the bitmap
/// too: it is a draft private-use code, and advertising it in a chain a
/// validator treats as exhaustive claims a type no resolver can ask for.
pub fn build_nsec_chain(zone: &str, records: &[DnsRecord]) -> Vec<(String, Nsec)> {
    let apex = crate::db::normalize_name(zone);

    // Types present at each name that actually holds records.
    let mut by_name: BTreeMap<String, Vec<RecordKind>> = BTreeMap::new();
    for record in records {
        let name = crate::db::normalize_name(&record.name);
        if !crate::db::name_in_zone(&name, &apex) {
            continue;
        }
        match record.record_type {
            // Not a member of any RRset it might be confused with, and never a
            // reason for a name to exist on its own.
            RecordKind::RRSIG | RecordKind::NSEC => {}
            // A draft private-use code with no wire presence. Claiming it in a
            // bitmap advertises a type nothing can query; the name still enters
            // the chain, because the ANAME is authoritative data.
            RecordKind::ANAME => {
                by_name.entry(name).or_default();
            }
            kind => by_name.entry(name).or_default().push(kind),
        }
    }

    // Only names with authoritative data are chained (RFC 4035 §2.3), so no
    // ancestor walk: an empty non-terminal is deliberately absent and is proved
    // by the link that covers it.
    let mut names = by_name;
    // The apex exists whether or not anything was stored at it.
    names.entry(apex.clone()).or_default();

    let mut ordered: Vec<String> = names.keys().cloned().collect();
    ordered.sort_by(|a, b| canonical_name_cmp(a, b));

    let mut chain = Vec::with_capacity(ordered.len());
    for (i, owner) in ordered.iter().enumerate() {
        // Wrap: the last name's next owner is the apex, closing the ring.
        let next_owner = ordered.get(i + 1).unwrap_or(&ordered[0]).clone();
        let mut types = names.get(owner).cloned().unwrap_or_default();
        types.push(RecordKind::NSEC);
        types.push(RecordKind::RRSIG);
        chain.push((owner.clone(), Nsec { next_owner, types }));
    }
    chain
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
        RecordKind::SVCB | RecordKind::HTTPS => {
            // Encoded by the same code that builds the served rdata, so the
            // bytes signed here and the bytes on the wire cannot disagree.
            out.extend_from_slice(&crate::svcb::canonical_rdata(value)?);
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
        RecordKind::NSEC => {
            let nsec = Nsec::parse(value).ok()?;
            out.extend_from_slice(&nsec.rdata()?);
        }
        // ANAME is resolved at query time and never appears on the wire. NSEC3
        // and NSEC3PARAM are not generated by this server — denial of existence
        // here is plain NSEC — so there is no stored format to encode, and
        // signing one would mean inventing it.
        RecordKind::ANAME | RecordKind::NSEC3 | RecordKind::NSEC3PARAM => {
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
///
/// Timed against
/// [`BLOCK_SITE_DNSSEC_SIGN`](crate::metrics::BLOCK_SITE_DNSSEC_SIGN). Signing
/// is not on the query path — it happens when a zone is signed or resigned —
/// but it is reached from the gRPC handlers, which are `async`, and re-signing a
/// zone is a loop of these on one worker thread.
pub fn sign_rrset(key: &SigningKey, set: &RrsetToSign<'_>) -> Result<String> {
    crate::metrics::time_blocking(crate::metrics::BLOCK_SITE_DNSSEC_SIGN, || {
        sign_rrset_inner(key, set)
    })
}

fn sign_rrset_inner(key: &SigningKey, set: &RrsetToSign<'_>) -> Result<String> {
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
    ///
    /// NSEC is deliberately absent from this list. It used to be here, and
    /// stopped belonging when the signer began building and signing the denial
    /// chain: a type the server now generates and must sign is a type it has to
    /// be able to encode. Keeping it would have asserted the property against
    /// the one member of the set that no longer has it.
    #[test]
    fn canonical_rdata_refuses_types_it_cannot_encode() {
        for kind in [RecordKind::NSEC3, RecordKind::NSEC3PARAM, RecordKind::ANAME] {
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

    // ================================================================
    // NSEC: bitmap, canonical ordering, chain
    //
    // Every expectation here is written out longhand rather than compared
    // against another encoder. A bitmap checked against the function that
    // produced it proves only that the function is deterministic; what has to
    // hold is that the bytes match RFC 4034, because a validator reconstructs
    // them independently and compares.
    // ================================================================

    /// RFC 4034 §4.1.2: window byte, length byte, then bitmap bytes in which
    /// bit 0 is the HIGH bit. A (RFC code 1) is window 0, byte 0, bit 1 → 0x40.
    #[test]
    fn type_bitmap_sets_the_high_bit_first() {
        assert_eq!(encode_type_bitmap(&[1]), vec![0x00, 0x01, 0x40]);
        // Type 0 would be bit 0 of byte 0 — the top bit.
        assert_eq!(encode_type_bitmap(&[0]), vec![0x00, 0x01, 0x80]);
        // A (1), NS (2) and SOA (6) share byte 0: 0100_0010 | 0000_0010 = 0x62.
        assert_eq!(encode_type_bitmap(&[1, 2, 6]), vec![0x00, 0x01, 0x62]);
    }

    /// The example from RFC 4034 §4.3: A, MX, RRSIG, NSEC — codes 1, 15, 46, 47.
    /// Byte 0 holds A; byte 1 holds MX (15 → bit 7 of byte 1 → 0x01); byte 5
    /// holds RRSIG (46 → bit 6) and NSEC (47 → bit 7) → 0x03.
    #[test]
    fn type_bitmap_matches_the_rfc_worked_example() {
        assert_eq!(
            encode_type_bitmap(&[1, 15, 46, 47]),
            vec![0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03],
        );
    }

    /// Windows with nothing set are omitted, high windows are emitted in
    /// ascending order, and each window is trimmed to its highest set byte.
    #[test]
    fn type_bitmap_omits_empty_windows_and_trims() {
        // URI is 256 → window 1, byte 0, bit 0 → 0x80. A is window 0.
        assert_eq!(
            encode_type_bitmap(&[256, 1]),
            vec![0x00, 0x01, 0x40, 0x01, 0x01, 0x80],
            "windows ascend regardless of input order, and neither is padded"
        );
        assert!(encode_type_bitmap(&[]).is_empty());
    }

    /// RFC 4034 §6.1 sorts label sequences right to left, so a zone apex
    /// precedes its own children — the reverse of a plain string sort, which is
    /// what the signing loop uses for reproducibility and what would build a
    /// chain whose ranges do not tile the zone.
    #[test]
    fn canonical_order_is_not_string_order() {
        let mut names = vec![
            "z.sub.example.com.".to_string(),
            "a.example.com.".to_string(),
            "example.com.".to_string(),
            "sub.example.com.".to_string(),
        ];
        names.sort_by(|a, b| canonical_name_cmp(a, b));
        assert_eq!(
            names,
            vec![
                "example.com.",
                "a.example.com.",
                "sub.example.com.",
                "z.sub.example.com.",
            ],
        );

        // The control: plain string order really does disagree, so this test is
        // not merely restating a sort that would have happened anyway.
        let mut byte_order = names.clone();
        byte_order.sort();
        assert_ne!(byte_order, names);
    }

    /// Case folds away, and a name is never equal to a different name.
    #[test]
    fn canonical_order_folds_case() {
        assert_eq!(
            canonical_name_cmp("WWW.Example.COM.", "www.example.com."),
            Ordering::Equal
        );
        assert_eq!(
            canonical_name_cmp("a.example.com.", "b.example.com."),
            Ordering::Less
        );
    }

    fn nsec_record(name: &str, kind: RecordKind) -> DnsRecord {
        record(name, kind, "192.0.2.1")
    }

    /// The chain covers every name, in canonical order, and the last entry wraps
    /// to the apex so the ranges tile the zone with no gap.
    #[test]
    fn nsec_chain_is_canonically_ordered_and_wraps() {
        let records = vec![
            nsec_record("example.com.", RecordKind::SOA),
            nsec_record("b.example.com.", RecordKind::A),
            nsec_record("a.example.com.", RecordKind::A),
        ];
        let chain = build_nsec_chain("example.com.", &records);
        let owners: Vec<&str> = chain.iter().map(|(o, _)| o.as_str()).collect();
        assert_eq!(
            owners,
            vec!["example.com.", "a.example.com.", "b.example.com."]
        );

        assert_eq!(chain[0].1.next_owner, "a.example.com.");
        assert_eq!(chain[1].1.next_owner, "b.example.com.");
        assert_eq!(
            chain[2].1.next_owner, "example.com.",
            "the last name wraps to the apex, closing the ring"
        );
    }

    /// Every bitmap asserts NSEC and RRSIG, because signing the chain puts both
    /// at every name it covers. A bitmap that omitted them would deny the very
    /// records carrying the denial.
    #[test]
    fn every_nsec_bitmap_claims_nsec_and_rrsig() {
        let records = vec![nsec_record("a.example.com.", RecordKind::A)];
        let chain = build_nsec_chain("example.com.", &records);
        for (owner, nsec) in &chain {
            assert!(
                nsec.types.contains(&RecordKind::NSEC),
                "{owner} bitmap omits NSEC"
            );
            assert!(
                nsec.types.contains(&RecordKind::RRSIG),
                "{owner} bitmap omits RRSIG"
            );
        }
        // The control: a type that is genuinely absent is not claimed.
        let a = chain
            .iter()
            .find(|(o, _)| o == "a.example.com.")
            .expect("a");
        assert!(a.1.types.contains(&RecordKind::A));
        assert!(!a.1.types.contains(&RecordKind::MX));
    }

    /// Empty non-terminals get **no** NSEC, and are still covered.
    ///
    /// RFC 4035 §2.3 gives an NSEC to "each owner name in the zone that has
    /// authoritative data or a delegation point NS RRset" — an ENT has neither —
    /// and forbids an NSEC being "the only RRset at any particular owner name",
    /// which is exactly what an ENT's would be. RFC 4034 §4.1.1 agrees from the
    /// other end: Next Domain names the next owner *with authoritative data*.
    /// Inserting ENTs is an NSEC**3** rule (RFC 5155 §7.1).
    ///
    /// The chain must still leave no hole: the ENT is covered by the link that
    /// spans it, which is what proves NODATA for it.
    #[test]
    fn empty_non_terminals_get_no_nsec_but_stay_covered() {
        let records = vec![nsec_record("_https._tcp.a.example.com.", RecordKind::TLSA)];
        let chain = build_nsec_chain("example.com.", &records);
        let owners: Vec<&str> = chain.iter().map(|(o, _)| o.as_str()).collect();
        assert_eq!(
            owners,
            vec!["example.com.", "_https._tcp.a.example.com."],
            "only names with authoritative data are chained"
        );

        // The ENTs are covered rather than chained — no gap, no link of their own.
        for ent in ["a.example.com.", "_tcp.a.example.com."] {
            let covering = chain
                .iter()
                .filter(|(owner, nsec)| nsec_covers(owner, &nsec.next_owner, ent))
                .count();
            assert_eq!(covering, 1, "{ent} must be covered by exactly one link");
        }
    }

    /// ANAME is a draft private-use code with no wire presence, so it is never
    /// claimed in a bitmap — a chain a validator treats as exhaustive must not
    /// advertise a type nothing can query. The name still enters the chain,
    /// because an ANAME is authoritative data.
    #[test]
    fn aname_is_chained_but_never_claimed_in_the_bitmap() {
        let records = vec![
            nsec_record("example.com.", RecordKind::SOA),
            record("www.example.com.", RecordKind::ANAME, "target.example.com."),
        ];
        let chain = build_nsec_chain("example.com.", &records);
        let www = chain
            .iter()
            .find(|(o, _)| o == "www.example.com.")
            .expect("the ANAME name is in the chain");
        assert!(!www.1.types.contains(&RecordKind::ANAME));

        // The control: a real type at the same name IS claimed.
        let records = vec![
            nsec_record("example.com.", RecordKind::SOA),
            nsec_record("www.example.com.", RecordKind::A),
        ];
        let chain = build_nsec_chain("example.com.", &records);
        let www = chain
            .iter()
            .find(|(o, _)| o == "www.example.com.")
            .expect("www");
        assert!(www.1.types.contains(&RecordKind::A));
    }

    /// Names outside the zone are not chained, and stored RRSIG/NSEC rows are not
    /// mistaken for reasons a name exists.
    #[test]
    fn nsec_chain_stops_at_the_zone_boundary() {
        let records = vec![
            nsec_record("a.example.com.", RecordKind::A),
            nsec_record("evil.notexample.com.", RecordKind::A),
            record(
                "a.example.com.",
                RecordKind::RRSIG,
                "A 15 3 300 2 1 1 example.com. AA==",
            ),
        ];
        let chain = build_nsec_chain("example.com.", &records);
        let owners: Vec<&str> = chain.iter().map(|(o, _)| o.as_str()).collect();
        assert_eq!(owners, vec!["example.com.", "a.example.com."]);

        let a = chain
            .iter()
            .find(|(o, _)| o == "a.example.com.")
            .expect("a");
        // RRSIG is claimed because the chain adds one, not because a row existed.
        assert!(a.1.types.contains(&RecordKind::A));
    }

    /// The stored form round-trips, and types are emitted in wire-code order so a
    /// rebuilt chain is byte-identical rather than merely equivalent.
    #[test]
    fn nsec_value_round_trips_in_wire_code_order() {
        let nsec = Nsec {
            next_owner: "b.example.com.".to_string(),
            types: vec![RecordKind::RRSIG, RecordKind::A, RecordKind::NSEC],
        };
        assert_eq!(nsec.to_value(), "b.example.com. A RRSIG NSEC");

        let parsed = Nsec::parse(&nsec.to_value()).expect("parse");
        assert_eq!(parsed.next_owner, "b.example.com.");
        assert_eq!(
            parsed.rdata(),
            nsec.rdata(),
            "the round trip is byte-identical, not merely equal as a set"
        );
    }

    /// An unknown mnemonic is refused rather than dropped. Dropping it would
    /// narrow the bitmap, and a narrowed bitmap is a signed proof that a type
    /// present at the name is absent — the validator rejects a good record.
    #[test]
    fn nsec_parse_refuses_an_unknown_type() {
        assert!(Nsec::parse("b.example.com. A WAT").is_err());
        assert!(Nsec::parse("b.example.com. A RRSIG").is_ok());
    }

    /// The covering range is open at both ends, and the wrapping entry closes
    /// the ring. Without the wrap arm, every name sorting after the zone's last
    /// name would be covered by nothing and its denial would be unprovable.
    #[test]
    fn nsec_covers_the_open_range_and_wraps() {
        // A normal link: (a, c) covers b but neither endpoint.
        assert!(nsec_covers(
            "a.example.com.",
            "c.example.com.",
            "b.example.com."
        ));
        assert!(!nsec_covers(
            "a.example.com.",
            "c.example.com.",
            "a.example.com."
        ));
        assert!(!nsec_covers(
            "a.example.com.",
            "c.example.com.",
            "c.example.com."
        ));
        assert!(!nsec_covers(
            "a.example.com.",
            "c.example.com.",
            "d.example.com."
        ));

        // The wrapping link: last name -> apex covers everything past the last.
        assert!(nsec_covers(
            "z.example.com.",
            "example.com.",
            "zz.example.com."
        ));
        // ...and NOT a name sorting between the apex and the last name.
        //
        // The apex is the first name in the zone's canonical ordering, so
        // nothing in-zone sorts before it and the wrap's range is "after the
        // last name" alone. RFC 4035 §2 defines coverage as *after the owner
        // and before the next owner*; reading the wrap as also covering
        // `a.example.com.` would have this link claim a name absent that the
        // apex's own link is responsible for, and a validator handed that proof
        // rejects the response rather than accepting a wider one.
        assert!(!nsec_covers(
            "z.example.com.",
            "example.com.",
            "a.example.com."
        ));
        // The link that really covers it — so the ring is shown to be tiled,
        // rather than this only asserting where the name is *not* proved.
        assert!(nsec_covers(
            "example.com.",
            "z.example.com.",
            "a.example.com."
        ));
        assert!(!nsec_covers(
            "z.example.com.",
            "example.com.",
            "example.com."
        ));
    }

    /// The chain a real zone produces actually tiles it: every name that does
    /// not exist is covered by exactly one link.
    ///
    /// This is the property the whole design turns on, and it is the one a
    /// hand-written `<` comparison silently breaks — so it is asserted over the
    /// generated chain rather than over hand-picked pairs.
    #[test]
    fn the_generated_chain_covers_every_absent_name() {
        let records = vec![
            nsec_record("example.com.", RecordKind::SOA),
            nsec_record("a.example.com.", RecordKind::A),
            nsec_record("m.example.com.", RecordKind::A),
            nsec_record("z.example.com.", RecordKind::A),
        ];
        let chain = build_nsec_chain("example.com.", &records);

        for absent in [
            "0.example.com.",
            "b.example.com.",
            "n.example.com.",
            "zz.example.com.",
            "deep.sub.example.com.",
        ] {
            let covering = chain
                .iter()
                .filter(|(owner, nsec)| nsec_covers(owner, &nsec.next_owner, absent))
                .count();
            assert_eq!(covering, 1, "{absent} must be covered by exactly one NSEC");
        }

        // The control: a name that DOES exist is covered by none of them, which
        // is what stops the chain proving a real name absent.
        for present in ["example.com.", "a.example.com.", "m.example.com."] {
            let covering = chain
                .iter()
                .filter(|(owner, nsec)| nsec_covers(owner, &nsec.next_owner, present))
                .count();
            assert_eq!(covering, 0, "{present} exists and must be covered by none");
        }
    }

    /// An NSEC can now be signed, which is the whole point of giving it a
    /// canonical encoding — `canonical_rdata` returning `None` is what used to
    /// make `sign_rrset` refuse it.
    #[test]
    fn an_nsec_record_is_now_canonically_encodable() {
        let nsec = record(
            "example.com.",
            RecordKind::NSEC,
            "a.example.com. A SOA RRSIG NSEC",
        );
        let encoded = canonical_rdata(&nsec).expect("NSEC must encode");
        let mut expected = canonical_name("a.example.com.").expect("name");
        expected.extend_from_slice(&encode_type_bitmap(&[1, 6, 46, 47]));
        assert_eq!(encoded, expected);

        // The control: NSEC3 still has no stored format and must stay refused.
        assert!(canonical_rdata(&record("example.com.", RecordKind::NSEC3, "whatever")).is_none());
    }
}
