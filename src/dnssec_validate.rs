//! DNSSEC validation of answers resolved from upstream.
//!
//! This is the *verifying* half of DNSSEC, and it is a different problem from
//! the signing half in [`crate::dnssec`]. The signer works on
//! [`crate::db::DnsRecord`] rows we wrote ourselves and controls every byte;
//! a validator works on whatever arrives on the wire, from a party whose
//! honesty is exactly the thing in question. So this module operates on hickory
//! wire records throughout and shares no code with the signer — the two must be
//! able to disagree, which is the entire point of `dnssec_signing_test`.
//!
//! Everything here is a pure function of records and the current time. There is
//! no I/O: fetching a DNSKEY or a DS is the resolver's job (`src/resolver.rs`),
//! deciding whether those records mean anything is this module's. Keeping the
//! split sharp is what makes the proofs testable against hand-built record sets
//! rather than only against a live network.
//!
//! # The three answers, and why "unsigned" is not "broken"
//!
//! RFC 4033 §5 gives four states, and conflating any two of them either breaks
//! the unsigned internet or silently accepts forgeries:
//!
//! - **Secure** — a chain of signatures ties the data to the trust anchor.
//! - **Insecure** — the chain *provably* stops: some delegation on the path has
//!   no DS, and the absence of that DS is itself signed. The data is unsigned
//!   and that is legitimate. Most of the DNS is here.
//! - **Bogus** — the data claims to be signed and the claim does not hold.
//!   This is the only state that must not be served.
//! - **Indeterminate** — we could not obtain what we needed to decide.
//!
//! The distinction that carries the security is Insecure vs. Bogus. "No
//! signature present" is *not* Insecure — an on-path attacker can strip
//! signatures from any response. It is Insecure only when a signed NSEC or
//! NSEC3 record proves the missing DS at the delegation above, which an
//! attacker cannot forge without the parent's key. That proof is the whole
//! reason the NSEC/NSEC3 machinery below exists, and skipping it would leave a
//! validator that any attacker can downgrade to no validator at all.
use hickory_proto::dnssec::rdata::{DNSKEY, DS, NSEC, NSEC3, RRSIG};
use hickory_proto::dnssec::{Algorithm, Nsec3HashAlgorithm, TrustAnchors, Verifier};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

/// RFC 9276 §3.2: a validator SHOULD treat NSEC3 with a high iteration count as
/// insecure rather than spend the CPU. The hashing is attacker-chosen work done
/// on our side of the wire, so an unbounded count is a remote CPU amplifier.
/// Zero extra iterations is the modern recommendation; 100 is the ceiling the
/// RFC names as still-tolerable, so that is where we stop.
pub const MAX_NSEC3_ITERATIONS: u16 = 100;

/// What validation concluded about a response.
///
/// `Bogus` and `Indeterminate` both end in SERVFAIL, but they are kept apart
/// because they mean opposite things operationally: `Bogus` is a zone (or an
/// attacker) producing data that contradicts its own signatures, and
/// `Indeterminate` is us failing to obtain something. Folding them together
/// would make a network problem indistinguishable from an attack in the
/// metrics, which is precisely when the difference matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Signed, and the signatures chain to the trust anchor.
    Secure,
    /// Provably unsigned: an insecure delegation was proven on the way down.
    Insecure,
    /// Claims to be signed, but the claim does not hold. Never served.
    Bogus(String),
    /// We could not reach a verdict.
    Indeterminate(String),
}

impl Verdict {
    /// The metrics label for this verdict.
    pub fn label(&self) -> &'static str {
        crate::metrics::DNSSEC_VERDICTS
            .get(self.index())
            .copied()
            .unwrap_or("indeterminate")
    }

    /// Index into [`crate::metrics::DNSSEC_VERDICTS`].
    pub fn index(&self) -> usize {
        match self {
            Self::Secure => 0,
            Self::Insecure => 1,
            Self::Bogus(_) => 2,
            Self::Indeterminate(_) => 3,
        }
    }

    /// Whether this verdict must not be served to a client.
    pub fn withholds_answer(&self) -> bool {
        matches!(self, Self::Bogus(_) | Self::Indeterminate(_))
    }

    /// The human-readable reason, for logs.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Bogus(r) | Self::Indeterminate(r) => Some(r),
            _ => None,
        }
    }

    /// The weaker of two verdicts, with `Bogus` dominating everything.
    ///
    /// A response is only as good as its worst part. In particular a Secure
    /// answer section alongside a Bogus authority section is Bogus: an attacker
    /// who can tamper with one section is not constrained to that section.
    pub fn merge(self, other: Self) -> Self {
        fn rank(v: &Verdict) -> u8 {
            match v {
                Verdict::Secure => 0,
                Verdict::Insecure => 1,
                Verdict::Indeterminate(_) => 2,
                Verdict::Bogus(_) => 3,
            }
        }
        if rank(&other) > rank(&self) {
            other
        } else {
            self
        }
    }
}

/// What a validated signature reveals about how the RRset was produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFacts {
    /// Set when the RRSIG covered fewer labels than the owner name has, which
    /// means the RRset was synthesized from a wildcard. The value is the
    /// closest encloser — the wildcard's parent.
    ///
    /// This is not bookkeeping: RFC 4035 §5.3.4 requires that a wildcard-derived
    /// answer also come with a denial proving the queried name does not exist
    /// on its own. Without that check, a signed `*.example.com` answer can be
    /// replayed as the answer for a name that *does* exist with different data.
    pub wildcard_closest_encloser: Option<Name>,
}

/// The configured trust anchors, wrapped so the resolver holding them can still
/// derive `Debug`.
///
/// hickory's `TrustAnchors` has no `Debug` impl, and dumping raw public-key
/// material into a log line would be the wrong thing to add anyway — the number
/// of anchors is the part an operator ever needs to see, and "0 anchors" is a
/// misconfiguration worth being able to spot.
#[derive(Clone)]
pub struct Anchors(std::sync::Arc<TrustAnchors>);

impl Anchors {
    pub fn new(anchors: std::sync::Arc<TrustAnchors>) -> Self {
        Self(anchors)
    }

    /// The IANA root keys compiled into hickory.
    pub fn iana_defaults() -> Self {
        Self(std::sync::Arc::new(TrustAnchors::default()))
    }

    /// Builds an anchor set from DNSKEY presentation strings —
    /// `"<flags> <protocol> <algorithm> <base64 key>"`.
    ///
    /// These are the four RDATA fields of a DNSKEY record in the order `dig
    /// DNSKEY <zone>` prints them, and the same spelling `crate::dnssec` stores
    /// one under, so an anchor can be lifted from a published root anchor file
    /// or from a `dig` of the zone itself with no second format to learn.
    /// (Not from `list-dnssec-keys`, which reports id, algorithm, type and key
    /// tag — it never prints key material, so there is nothing there to copy.)
    ///
    /// Every field is validated even though only the key bytes and the algorithm
    /// are retained, and they all fail for one reason: an anchor that cannot
    /// match a real DNSKEY makes *every* signed zone fail validation, with
    /// nothing in that failure pointing back at the anchor as the cause. Finding
    /// it at startup costs one error message; not finding it costs a resolver
    /// that appears to be validating and resolves nothing.
    ///
    /// - **Zone-key flag** (RFC 4034 §2.1.1, bit 7 = `0x0100`). Without it a
    ///   DNSKEY may not verify RRsets at all. Note that both `257` (KSK: zone
    ///   key + secure entry point) and `256` (ZSK: zone key alone) have it set —
    ///   `256` is a valid anchor, not a flag-less one.
    /// - **Protocol** must be 3; RFC 4034 §2.1.2 defines no other value.
    /// - **Algorithm** must be one this build can verify, since anchoring to an
    ///   algorithm we cannot check is anchoring to nothing.
    /// - **Key length** must match the algorithm where the algorithm fixes one
    ///   (see [`fixed_public_key_len`]). A truncated or mis-pasted key is the
    ///   likeliest of these mistakes and the least visible without the check.
    pub fn from_dnskey_strings<S: AsRef<str>>(entries: &[S]) -> Result<Self, String> {
        use hickory_proto::dnssec::PublicKeyBuf;

        let mut anchors = TrustAnchors::empty();
        for entry in entries {
            let entry = entry.as_ref().trim();
            let fields: Vec<&str> = entry.split_whitespace().collect();
            if fields.len() < 4 {
                return Err(format!(
                    "trust anchor {entry:?} has {} fields, expected \
                     \"<flags> <protocol> <algorithm> <base64 key>\"",
                    fields.len()
                ));
            }
            let flags: u16 = fields[0]
                .parse()
                .map_err(|_| format!("trust anchor {entry:?} has non-numeric flags"))?;
            // RFC 4034 §2.1.1, bit 7: without the zone-key flag a DNSKEY may not
            // verify RRsets at all, so it cannot serve as an anchor.
            if flags & 0x0100 == 0 {
                return Err(format!(
                    "trust anchor {entry:?} does not have the zone-key flag set"
                ));
            }
            let protocol: u8 = fields[1]
                .parse()
                .map_err(|_| format!("trust anchor {entry:?} has a non-numeric protocol"))?;
            if protocol != 3 {
                return Err(format!(
                    "trust anchor {entry:?} has protocol {protocol}, which must be 3"
                ));
            }
            let algorithm_num: u8 = fields[2]
                .parse()
                .map_err(|_| format!("trust anchor {entry:?} has a non-numeric algorithm"))?;
            let algorithm = Algorithm::from_u8(algorithm_num);
            if !algorithm.is_supported() {
                return Err(format!(
                    "trust anchor {entry:?} uses algorithm {algorithm_num}, which this build \
                     cannot verify — anchoring to it would make every signed zone fail"
                ));
            }
            let key = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                fields[3..].concat(),
            )
            .map_err(|e| format!("trust anchor {entry:?} has an undecodable key: {e}"))?;
            if key.is_empty() {
                return Err(format!("trust anchor {entry:?} has an empty key"));
            }
            // A key of the wrong size for its algorithm can never match a
            // DNSKEY, so anchoring to it means every signed zone fails with no
            // indication that the anchor is the problem. The algorithms with a
            // fixed public-key size are checked here; RSA's is variable
            // (exponent plus modulus), so there is nothing fixed to compare.
            if let Some(expected) = fixed_public_key_len(algorithm)
                && key.len() != expected
            {
                return Err(format!(
                    "trust anchor {entry:?} carries a {}-byte key, but algorithm {} needs {expected}",
                    key.len(),
                    algorithm_name(algorithm)
                ));
            }
            anchors.insert(&PublicKeyBuf::new(key, algorithm));
        }

        if anchors.is_empty() {
            return Err("no trust anchors were parsed".to_string());
        }
        Ok(Self(std::sync::Arc::new(anchors)))
    }

    pub fn get(&self) -> &TrustAnchors {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Anchors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Anchors({} key(s))", self.0.len())
    }
}

/// Where the keys that anchor a DNSKEY RRset come from.
pub enum KeySource<'a> {
    /// The top of the chain: the configured trust anchors.
    Anchors(&'a TrustAnchors),
    /// The parent zone's DS RRset, itself already validated.
    Ds(&'a [DS]),
}

/// Pulls the DNSKEY records out of a record slice, keeping only those usable as
/// zone keys at `zone`.
///
/// A DNSKEY with the zone-key flag clear (RFC 4034 §2.1.1) or a protocol other
/// than 3 is not a zone key and must not verify RRsets, so it is dropped here
/// rather than being allowed to match a key tag later.
pub fn zone_keys(records: &[Record], zone: &Name) -> Vec<DNSKEY> {
    records
        .iter()
        .filter(|r| r.name() == zone && r.record_type() == RecordType::DNSKEY)
        .filter_map(|r| r.data().as_dnssec()?.as_dnskey().cloned())
        .filter(|k| k.zone_key() && !k.revoke())
        .collect()
}

/// Pulls the DS records for `child` out of a record slice.
pub fn ds_records(records: &[Record], child: &Name) -> Vec<DS> {
    records
        .iter()
        .filter(|r| r.name() == child && r.record_type() == RecordType::DS)
        .filter_map(|r| r.data().as_dnssec()?.as_ds().cloned())
        .collect()
}

/// The DNSKEY public-key size an algorithm always uses, where it has one.
///
/// `None` for RSA, whose public key is an exponent plus a modulus and so varies
/// with the key size — there is no single length to check against.
fn fixed_public_key_len(algorithm: Algorithm) -> Option<usize> {
    match algorithm {
        Algorithm::ED25519 => Some(32),
        // RFC 6605 §4: DNSKEY carries the raw X || Y point with the SEC1
        // uncompressed-form tag octet stripped.
        Algorithm::ECDSAP256SHA256 => Some(64),
        Algorithm::ECDSAP384SHA384 => Some(96),
        _ => None,
    }
}

/// A displayable name for an algorithm, for error messages.
fn algorithm_name(algorithm: Algorithm) -> String {
    format!("{algorithm:?} ({})", u8::from(algorithm))
}

/// RFC 1982 §3.2 "less than" for the 32-bit serial space RRSIG timestamps live
/// in.
///
/// Plain `<` on the raw integers is wrong at exactly one moment — the 2106
/// wrap — and wrong in the worst direction: every live signature would read as
/// expired, and every expired one as valid. hickory's `SerialNumber` implements
/// this comparison but cannot be constructed outside the crate, so the two-line
/// version lives here rather than the current time being forced through a type
/// that will not accept it.
fn serial_lt(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < 0x8000_0000
}

/// Whether any DS in the set names an algorithm we can actually verify.
///
/// RFC 6840 §5.11: a delegation whose DS records all use algorithms the
/// validator does not implement is **insecure**, not bogus. Treating it as
/// bogus would mean a validator that cannot verify, say, GOST turns every zone
/// signed only with GOST into an outage — the resolver's ignorance is not the
/// zone's fault.
pub fn ds_algorithms_supported(ds: &[DS]) -> bool {
    ds.iter().any(|d| d.algorithm().is_supported())
}

/// Verifies one RRset against a zone's validated DNSKEY set.
///
/// `rrset` must be the records sharing `owner` and `rtype` with the RRSIGs
/// removed; `sigs` are the RRSIG records at `owner` (of any covered type — they
/// are filtered here).
///
/// Every check below is one an attacker gets to skip if it is missing, so none
/// of them are redundant with the signature check itself:
///
/// - **The signer must be the zone we are in.** The signature is only evidence
///   if it was made by a key we chained to. Accepting any signer name would let
///   an attacker sign `www.bank.example` with a key from a zone they own and
///   supply that zone's DS/DNSKEY, and the arithmetic would all check out.
/// - **The validity window.** A signature with no expiry check is a signature
///   that never stops being replayable, which is what the window is for.
/// - **The key must be a zone key whose tag and algorithm match.** The key tag
///   is a hint, not an identifier — collisions are legal — so every candidate
///   with a matching tag is tried and one success is enough.
pub fn verify_rrset(
    owner: &Name,
    rtype: RecordType,
    rrset: &[Record],
    sigs: &[Record],
    keys: &[DNSKEY],
    zone: &Name,
    now: u32,
) -> Result<SignatureFacts, String> {
    // Timed here rather than at the four call sites in the resolver, and around
    // the whole function rather than around each `verify_one`: what costs the
    // worker thread is the *set* of candidates tried, and a key-tag collision or
    // a rollover means several RSA-2048 verifications for one RRset. An RRset
    // that fails every candidate is the expensive case, and it is the one that
    // returns through the error path at the bottom.
    crate::metrics::time_blocking(crate::metrics::BLOCK_SITE_DNSSEC_VERIFY, || {
        verify_rrset_inner(owner, rtype, rrset, sigs, keys, zone, now)
    })
}

fn verify_rrset_inner(
    owner: &Name,
    rtype: RecordType,
    rrset: &[Record],
    sigs: &[Record],
    keys: &[DNSKEY],
    zone: &Name,
    now: u32,
) -> Result<SignatureFacts, String> {
    if rrset.is_empty() {
        return Err(format!("nothing to verify for {owner} {rtype}"));
    }
    if keys.is_empty() {
        return Err(format!("no DNSKEYs available for {zone}"));
    }

    let covering: Vec<&RRSIG> = sigs
        .iter()
        .filter(|r| r.name() == owner)
        .filter_map(|r| r.data().as_dnssec()?.as_rrsig())
        .filter(|s| s.type_covered() == rtype)
        .collect();
    if covering.is_empty() {
        return Err(format!("no RRSIG covers {owner} {rtype}"));
    }

    let mut last_reason = String::new();
    for sig in covering {
        match verify_one(owner, rtype, rrset, sig, keys, zone, now) {
            Ok(facts) => return Ok(facts),
            // Keep going: several RRSIGs over one RRset is normal during a key
            // rollover, and only one of them has to check out.
            Err(reason) => last_reason = reason,
        }
    }
    Err(format!("no RRSIG validated {owner} {rtype}: {last_reason}"))
}

/// One RRSIG against one RRset. See [`verify_rrset`] for why each check exists.
fn verify_one(
    owner: &Name,
    rtype: RecordType,
    rrset: &[Record],
    sig: &RRSIG,
    keys: &[DNSKEY],
    zone: &Name,
    now: u32,
) -> Result<SignatureFacts, String> {
    if sig.signer_name() != zone {
        return Err(format!(
            "RRSIG over {owner} {rtype} is signed by {}, which is not the zone {zone}",
            sig.signer_name()
        ));
    }

    // Serial-number arithmetic, not plain integer comparison: RFC 4034 §3.1.5
    // defines these fields to wrap, and 2106 is closer than the lifetime of a
    // resolver deployment.
    let inception = sig.sig_inception().get();
    let expiration = sig.sig_expiration().get();
    if serial_lt(now, inception) {
        return Err(format!(
            "RRSIG over {owner} {rtype} is not valid until {inception}"
        ));
    }
    if serial_lt(expiration, now) {
        return Err(format!(
            "RRSIG over {owner} {rtype} expired at {expiration}"
        ));
    }

    // A labels field longer than the owner name is nonsense, and it is the field
    // that decides whether the signed name is the owner or a wildcard — so a
    // value that cannot be honest is refused rather than clamped.
    let owner_labels = owner.num_labels();
    if sig.num_labels() > owner_labels {
        return Err(format!(
            "RRSIG over {owner} {rtype} claims {} labels, the name has {owner_labels}",
            sig.num_labels()
        ));
    }

    if !sig.algorithm().is_supported() {
        return Err(format!(
            "RRSIG over {owner} {rtype} uses unsupported algorithm {:?}",
            sig.algorithm()
        ));
    }

    let mut tried = 0usize;
    let mut last = String::from("no key matched the RRSIG's tag and algorithm");
    for key in keys {
        if key.algorithm() != sig.algorithm() {
            continue;
        }
        // A key tag is a checksum, not a name: two keys in one zone may share
        // one. Every candidate is tried and any success counts.
        match key.calculate_key_tag() {
            Ok(tag) if tag == sig.key_tag() => {}
            Ok(_) => continue,
            Err(e) => {
                last = format!("could not compute key tag: {e}");
                continue;
            }
        }
        tried += 1;
        match key.verify_rrsig(owner, DNSClass::IN, sig, rrset.iter()) {
            Ok(()) => {
                let wildcard = if sig.num_labels() < owner_labels {
                    Some(owner.trim_to(sig.num_labels() as usize))
                } else {
                    None
                };
                return Ok(SignatureFacts {
                    wildcard_closest_encloser: wildcard,
                });
            }
            Err(e) => last = format!("signature did not verify: {e}"),
        }
    }
    if tried == 0 {
        return Err(format!(
            "RRSIG over {owner} {rtype} names key tag {} algorithm {:?}, which is not in the {zone} DNSKEY RRset",
            sig.key_tag(),
            sig.algorithm()
        ));
    }
    Err(last)
}

/// Validates a zone's DNSKEY RRset and returns the keys that may then be used to
/// verify everything else in that zone.
///
/// Two things must hold, and both are load-bearing:
///
/// 1. **Some key in the set is anchored** — it matches a configured trust anchor
///    (at the root) or is covered by a DS record the parent signed (everywhere
///    else). This is the link in the chain.
/// 2. **That anchored key signed the DNSKEY RRset itself.** Without this, the
///    DS proves only that *one* key is legitimate, while the rest of the RRset —
///    including whatever key an attacker appended — would be trusted for free.
///    Self-signing is what extends trust from the anchored key to the set.
pub fn validate_dnskey_rrset(
    zone: &Name,
    records: &[Record],
    sigs: &[Record],
    source: &KeySource<'_>,
    now: u32,
) -> Result<Vec<DNSKEY>, String> {
    let keys = zone_keys(records, zone);
    if keys.is_empty() {
        return Err(format!("{zone} returned no usable DNSKEY records"));
    }

    let anchored: Vec<DNSKEY> = match source {
        KeySource::Anchors(anchors) => keys
            .iter()
            .filter(|k| anchors.contains(k.public_key()))
            .cloned()
            .collect(),
        KeySource::Ds(ds_set) => keys
            .iter()
            .filter(|k| {
                ds_set
                    .iter()
                    .any(|ds| ds.algorithm().is_supported() && ds.covers(zone, k).unwrap_or(false))
            })
            .cloned()
            .collect(),
    };

    if anchored.is_empty() {
        return Err(match source {
            KeySource::Anchors(_) => format!(
                "no DNSKEY at {zone} matches a configured trust anchor ({} key(s) offered)",
                keys.len()
            ),
            KeySource::Ds(ds_set) => format!(
                "no DNSKEY at {zone} is covered by any of the {} DS record(s) the parent published",
                ds_set.len()
            ),
        });
    }

    // The DNSKEY RRset must be self-signed by one of the anchored keys —
    // `anchored`, not `keys`, is the whole point.
    verify_rrset(
        zone,
        RecordType::DNSKEY,
        &records
            .iter()
            .filter(|r| r.name() == zone && r.record_type() == RecordType::DNSKEY)
            .cloned()
            .collect::<Vec<_>>(),
        sigs,
        &anchored,
        zone,
        now,
    )
    .map_err(|e| format!("{zone} DNSKEY RRset is not signed by an anchored key: {e}"))?;

    Ok(keys)
}

// ---------------------------------------------------------------------------
// Denial of existence
// ---------------------------------------------------------------------------

/// The NSEC and NSEC3 records from an authority section.
///
/// Callers build this **only from records whose RRSIGs already verified**. An
/// unverified NSEC is not evidence of anything — it is an attacker's assertion
/// that something does not exist, which is exactly the assertion these proofs
/// are supposed to make unforgeable.
#[derive(Debug, Default, Clone)]
pub struct Denial {
    pub nsec: Vec<(Name, NSEC)>,
    pub nsec3: Vec<(Name, NSEC3)>,
}

impl Denial {
    /// Collects the NSEC/NSEC3 records from an authority section.
    pub fn from_records(records: &[Record]) -> Self {
        let mut denial = Self::default();
        for record in records {
            let Some(dnssec) = record.data().as_dnssec() else {
                continue;
            };
            if let Some(nsec) = dnssec.as_nsec() {
                denial.nsec.push((record.name().clone(), nsec.clone()));
            } else if let Some(nsec3) = dnssec.as_nsec3() {
                denial.nsec3.push((record.name().clone(), nsec3.clone()));
            }
        }
        denial
    }

    pub fn is_empty(&self) -> bool {
        self.nsec.is_empty() && self.nsec3.is_empty()
    }
}

/// The outcome of a denial-of-existence proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// The denial is proven.
    Proven,
    /// NSEC3 opt-out applies, so the denial is only as strong as "this name was
    /// never signed for". RFC 5155 §6: an opt-out span may contain names the
    /// zone simply did not sign, so nothing under it can be proven absent —
    /// the correct downgrade is Insecure, not Secure and not Bogus.
    OptedOut,
}

/// Proves that a delegation to `child` carries no DS record, which is what makes
/// everything below it legitimately Insecure.
///
/// This is the single most security-critical proof in the module. Without it,
/// "the referral had no DS" is indistinguishable from "an attacker removed the
/// DS", and every signed zone on the internet can be downgraded to unsigned by
/// deleting two records from a packet.
pub fn prove_no_ds(child: &Name, denial: &Denial) -> Result<Denied, String> {
    if denial.is_empty() {
        return Err(format!(
            "the delegation to {child} carried neither a DS record nor any NSEC/NSEC3 \
             proving there is none"
        ));
    }

    // NSEC: the record at the delegation name itself. It must assert NS (this
    // really is a delegation point) and must not assert DS. SOA must be absent
    // too — an NSEC bearing SOA is the child zone's own apex record, which says
    // nothing about what the *parent* published.
    if let Some((_, nsec)) = denial.nsec.iter().find(|(owner, _)| owner == child) {
        let types: Vec<RecordType> = nsec.type_bit_maps().collect();
        if types.contains(&RecordType::DS) {
            return Err(format!(
                "the NSEC at {child} asserts a DS exists, but none was delivered"
            ));
        }
        if types.contains(&RecordType::SOA) {
            return Err(format!(
                "the NSEC at {child} is the child apex, not the parent's delegation point"
            ));
        }
        if !types.contains(&RecordType::NS) {
            return Err(format!("the NSEC at {child} does not assert a delegation"));
        }
        return Ok(Denied::Proven);
    }

    // NSEC3: same shape, against the hashed name.
    if !denial.nsec3.is_empty() {
        if let Some((_, nsec3)) = nsec3_matching(denial, child)? {
            let types: Vec<RecordType> = nsec3.type_bit_maps().collect();
            if types.contains(&RecordType::DS) {
                return Err(format!(
                    "the NSEC3 for {child} asserts a DS exists, but none was delivered"
                ));
            }
            if types.contains(&RecordType::SOA) {
                return Err(format!(
                    "the NSEC3 for {child} is the child apex, not the parent's delegation point"
                ));
            }
            if !types.contains(&RecordType::NS) {
                return Err(format!(
                    "the NSEC3 for {child} does not assert a delegation"
                ));
            }
            return Ok(Denied::Proven);
        }

        // Opt-out: there is no NSEC3 for the delegation at all, but the span
        // covering it is flagged opt-out, so the zone is entitled not to have
        // one. That proves nothing about a DS either way, which is why the
        // result is a downgrade rather than a proof.
        if let Some((ce, next_closer)) = closest_encloser(child, denial)?
            && let Some((_, nsec3)) = nsec3_covering(denial, &next_closer)?
        {
            if nsec3.opt_out() {
                return Ok(Denied::OptedOut);
            }
            return Err(format!(
                "the NSEC3 covering {next_closer} (closest encloser {ce}) is not opt-out, \
                 so {child} must have had an NSEC3 of its own"
            ));
        }
    }

    Err(format!(
        "no NSEC or NSEC3 record proves the delegation to {child} has no DS"
    ))
}

/// Proves that `qname` does not exist at all (NXDOMAIN).
pub fn prove_nxdomain(qname: &Name, zone: &Name, denial: &Denial) -> Result<Denied, String> {
    if !denial.nsec.is_empty() {
        // Two things must be shown: no NSEC asserts the name, and no wildcard
        // could have produced it. Skipping the wildcard half turns a real
        // wildcard answer into a forgeable NXDOMAIN.
        if denial.nsec.iter().any(|(owner, _)| owner == qname) {
            return Err(format!("an NSEC asserts {qname} exists"));
        }
        if !nsec_covers_name(denial, qname) {
            return Err(format!("no NSEC covers {qname}"));
        }
        let wildcard = wildcard_of(qname, zone);
        if !nsec_covers_name(denial, &wildcard) && !denial.nsec.iter().any(|(o, _)| o == &wildcard)
        {
            return Err(format!(
                "no NSEC rules out the wildcard {wildcard} that could have answered {qname}"
            ));
        }
        return Ok(Denied::Proven);
    }

    if !denial.nsec3.is_empty() {
        // RFC 5155 §8.4: closest encloser, next closer covered, wildcard at the
        // closest encloser covered.
        let Some((ce, next_closer)) = closest_encloser(qname, denial)? else {
            return Err(format!("no NSEC3 closest encloser found for {qname}"));
        };
        let Some((_, covering)) = nsec3_covering(denial, &next_closer)? else {
            return Err(format!(
                "no NSEC3 covers the next closer name {next_closer}"
            ));
        };
        let wildcard = prepend_wildcard(&ce);
        let wildcard_covered = nsec3_covering(denial, &wildcard)?.is_some();
        if !wildcard_covered && nsec3_matching(denial, &wildcard)?.is_none() {
            return Err(format!(
                "no NSEC3 rules out the wildcard {wildcard} that could have answered {qname}"
            ));
        }
        // An opt-out span may hold unsigned names, so it cannot prove absence.
        if covering.opt_out() {
            return Ok(Denied::OptedOut);
        }
        return Ok(Denied::Proven);
    }

    Err(format!(
        "no NSEC or NSEC3 record accompanies the NXDOMAIN for {qname}"
    ))
}

/// Proves that `qname` exists but has no records of `qtype` (NODATA).
pub fn prove_nodata(
    qname: &Name,
    qtype: RecordType,
    zone: &Name,
    denial: &Denial,
) -> Result<Denied, String> {
    if !denial.nsec.is_empty() {
        if let Some((_, nsec)) = denial.nsec.iter().find(|(owner, _)| owner == qname) {
            let types: Vec<RecordType> = nsec.type_bit_maps().collect();
            if types.contains(&qtype) {
                return Err(format!("the NSEC at {qname} asserts {qtype} exists"));
            }
            // A CNAME at the name would have been followed instead of producing
            // NODATA, so its presence contradicts the answer we were given.
            if types.contains(&RecordType::CNAME) {
                return Err(format!(
                    "the NSEC at {qname} asserts a CNAME, which should have been followed"
                ));
            }
            return Ok(Denied::Proven);
        }
        // NODATA at a name that does not exist itself is only legitimate for an
        // empty non-terminal or a wildcard-derived NODATA; both are covered by
        // showing the name is enclosed and the wildcard denies the type.
        let wildcard = wildcard_of(qname, zone);
        if let Some((_, nsec)) = denial.nsec.iter().find(|(owner, _)| owner == &wildcard) {
            let types: Vec<RecordType> = nsec.type_bit_maps().collect();
            if types.contains(&qtype) {
                return Err(format!(
                    "the wildcard NSEC at {wildcard} asserts {qtype} exists"
                ));
            }
            if !nsec_covers_name(denial, qname) {
                return Err(format!(
                    "the wildcard NSEC at {wildcard} denies {qtype}, but nothing shows {qname} \
                     does not exist in its own right"
                ));
            }
            return Ok(Denied::Proven);
        }
        return Err(format!("no NSEC at or covering {qname} denies {qtype}"));
    }

    if !denial.nsec3.is_empty() {
        // RFC 5155 §8.5: an NSEC3 matching the QNAME whose bitmap lacks the type.
        if let Some((_, nsec3)) = nsec3_matching(denial, qname)? {
            let types: Vec<RecordType> = nsec3.type_bit_maps().collect();
            if types.contains(&qtype) {
                return Err(format!("the NSEC3 for {qname} asserts {qtype} exists"));
            }
            if types.contains(&RecordType::CNAME) {
                return Err(format!(
                    "the NSEC3 for {qname} asserts a CNAME, which should have been followed"
                ));
            }
            return Ok(Denied::Proven);
        }
        // RFC 5155 §8.6/§8.7: wildcard NODATA, and the opt-out DS case.
        let Some((ce, next_closer)) = closest_encloser(qname, denial)? else {
            return Err(format!("no NSEC3 matches or encloses {qname}"));
        };
        let wildcard = prepend_wildcard(&ce);
        if let Some((_, nsec3)) = nsec3_matching(denial, &wildcard)? {
            let types: Vec<RecordType> = nsec3.type_bit_maps().collect();
            if types.contains(&qtype) {
                return Err(format!(
                    "the wildcard NSEC3 for {wildcard} asserts {qtype} exists"
                ));
            }
            return Ok(Denied::Proven);
        }
        if let Some((_, covering)) = nsec3_covering(denial, &next_closer)?
            && covering.opt_out()
        {
            return Ok(Denied::OptedOut);
        }
        return Err(format!("no NSEC3 denies {qtype} at {qname}"));
    }

    Err(format!(
        "no NSEC or NSEC3 record accompanies the NODATA for {qname}"
    ))
}

/// Proves that a wildcard-derived answer was legitimate: the queried name must
/// not exist in its own right, or the wildcard would not have applied.
///
/// RFC 4035 §5.3.4. An answer signed for `*.example.com` is a perfectly valid
/// signature for *every* name under `example.com`; the denial is what pins it to
/// the names the zone actually intended it for.
pub fn prove_wildcard_expansion(
    qname: &Name,
    closest_encloser: &Name,
    denial: &Denial,
) -> Result<Denied, String> {
    if denial.is_empty() {
        return Err(format!(
            "{qname} was answered from a wildcard under {closest_encloser} with no NSEC/NSEC3 \
             showing the name itself does not exist"
        ));
    }

    if !denial.nsec.is_empty() {
        if nsec_covers_name(denial, qname) {
            return Ok(Denied::Proven);
        }
        return Err(format!(
            "no NSEC shows {qname} is absent, so the wildcard answer under {closest_encloser} \
             is unsubstantiated"
        ));
    }

    // The next closer name is the one label below the closest encloser toward
    // the qname; covering it is what shows the qname has no exact match.
    let next_closer = next_closer_name(qname, closest_encloser)
        .ok_or_else(|| format!("{closest_encloser} does not enclose {qname}"))?;
    match nsec3_covering(denial, &next_closer)? {
        Some((_, nsec3)) if nsec3.opt_out() => Ok(Denied::OptedOut),
        Some(_) => Ok(Denied::Proven),
        None => Err(format!(
            "no NSEC3 covers the next closer name {next_closer}, so the wildcard answer for \
             {qname} is unsubstantiated"
        )),
    }
}

// ---------------------------------------------------------------------------
// NSEC / NSEC3 mechanics
// ---------------------------------------------------------------------------

/// Whether some NSEC's range covers `name`, i.e. the name falls strictly between
/// the NSEC's owner and its next name in canonical order.
///
/// The last NSEC in a zone wraps: its next name is the apex, which sorts before
/// its owner. That wrap is the case a naive `owner < name < next` misses, and
/// missing it rejects every legitimate denial past the last name in the zone.
fn nsec_covers_name(denial: &Denial, name: &Name) -> bool {
    denial.nsec.iter().any(|(owner, nsec)| {
        let next = nsec.next_domain_name();
        if next > owner {
            owner < name && name < next
        } else {
            // Wrapped: the range runs from the owner to the end of the zone and
            // continues from the apex.
            owner < name || name < next
        }
    })
}

/// The wildcard name that could have produced an answer for `qname` inside
/// `zone`: `*` prepended to the qname's parent, clamped to the zone apex.
fn wildcard_of(qname: &Name, zone: &Name) -> Name {
    let parent = qname.base_name();
    let base = if zone.zone_of(&parent) {
        parent
    } else {
        zone.clone()
    };
    prepend_wildcard(&base)
}

/// `*.name`.
fn prepend_wildcard(name: &Name) -> Name {
    Name::from_labels(vec![b"*".as_slice()])
        .ok()
        .and_then(|star| star.append_name(name).ok())
        .unwrap_or_else(|| name.clone())
}

/// The ancestor of `qname` that is exactly one label longer than `encloser`.
fn next_closer_name(qname: &Name, encloser: &Name) -> Option<Name> {
    let q = qname.num_labels() as usize;
    let e = encloser.num_labels() as usize;
    if e >= q {
        return None;
    }
    Some(qname.trim_to(e + 1))
}

/// Base32hex (RFC 4648 §7), unpadded — the encoding NSEC3 owner labels use.
///
/// Encoding rather than decoding is deliberate: the hash comparisons below are
/// all "is this computed hash equal to / between these owner labels", and
/// base32hex is order-preserving for equal-length inputs (that is the entire
/// reason NSEC3 uses the *hex* alphabet rather than ordinary base32). Since every
/// NSEC3 hash in a zone is the same length, comparing the encoded strings gives
/// exactly the same ordering as comparing the raw digests, and never needs a
/// decoder that could disagree with the encoder.
fn base32hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    for chunk in bytes.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let bits = (u64::from(buf[0]) << 32)
            | (u64::from(buf[1]) << 24)
            | (u64::from(buf[2]) << 16)
            | (u64::from(buf[3]) << 8)
            | u64::from(buf[4]);
        // 8 characters per 5 bytes, minus the ones that would encode only
        // padding for a short final chunk.
        let chars = match chunk.len() {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            _ => 8,
        };
        for i in 0..chars {
            let shift = 35 - i * 5;
            out.push(ALPHABET[((bits >> shift) & 0x1f) as usize] as char);
        }
    }
    out
}

/// The base32hex hash of `name` under one NSEC3 record's parameters.
fn hashed(nsec3: &NSEC3, name: &Name) -> Result<String, String> {
    if nsec3.iterations() > MAX_NSEC3_ITERATIONS {
        return Err(format!(
            "NSEC3 iteration count {} exceeds the {MAX_NSEC3_ITERATIONS} we are willing to \
             compute (RFC 9276)",
            nsec3.iterations()
        ));
    }
    let digest = Nsec3HashAlgorithm::from_u8(u8::from(nsec3.hash_algorithm()))
        .map_err(|e| format!("unsupported NSEC3 hash algorithm: {e}"))?
        .hash(nsec3.salt(), name, nsec3.iterations())
        .map_err(|e| format!("NSEC3 hashing failed for {name}: {e}"))?;
    Ok(base32hex(digest.as_ref()))
}

/// The owner label of an NSEC3 record, uppercased for comparison.
fn owner_hash(owner: &Name) -> Option<String> {
    owner
        .iter()
        .next()
        .map(|label| String::from_utf8_lossy(label).to_uppercase())
}

/// The NSEC3 record whose owner is the hash of `name`, if one is present.
fn nsec3_matching<'a>(
    denial: &'a Denial,
    name: &Name,
) -> Result<Option<&'a (Name, NSEC3)>, String> {
    for entry in &denial.nsec3 {
        let (owner, nsec3) = entry;
        let Some(owner_hash) = owner_hash(owner) else {
            continue;
        };
        if hashed(nsec3, name)? == owner_hash {
            return Ok(Some(entry));
        }
    }
    Ok(None)
}

/// The NSEC3 record whose range covers the hash of `name`.
///
/// "Covers" is strict on both ends (RFC 5155 §2.2): a hash equal to the owner
/// *matches* rather than being covered, and treating the ends as inclusive would
/// let a matching name masquerade as an absent one.
fn nsec3_covering<'a>(
    denial: &'a Denial,
    name: &Name,
) -> Result<Option<&'a (Name, NSEC3)>, String> {
    for entry in &denial.nsec3 {
        let (owner, nsec3) = entry;
        let Some(owner_hash) = owner_hash(owner) else {
            continue;
        };
        let next = base32hex(nsec3.next_hashed_owner_name());
        let target = hashed(nsec3, name)?;
        let covered = if next > owner_hash {
            owner_hash < target && target < next
        } else {
            // The last NSEC3 in the zone wraps around to the first.
            owner_hash < target || target < next
        };
        if covered {
            return Ok(Some(entry));
        }
    }
    Ok(None)
}

/// The closest encloser of `qname` — the longest ancestor for which an NSEC3
/// exists — together with the next closer name one label below it.
fn closest_encloser(qname: &Name, denial: &Denial) -> Result<Option<(Name, Name)>, String> {
    let labels = qname.num_labels() as usize;
    // Walk from the full name upward; the first ancestor with a matching NSEC3
    // is the closest encloser by definition. Starting at `labels` rather than
    // `labels - 1` matters for the no-DS case, where the delegation name itself
    // may be the encloser.
    for take in (0..=labels).rev() {
        let candidate = qname.trim_to(take);
        if nsec3_matching(denial, &candidate)?.is_some() {
            let Some(next_closer) = next_closer_name(qname, &candidate) else {
                // The qname itself matched, so there is no next closer name.
                return Ok(Some((candidate.clone(), candidate)));
            };
            return Ok(Some((candidate, next_closer)));
        }
    }
    Ok(None)
}

/// The algorithms present in a DNSKEY set, for reporting an all-unsupported zone.
pub fn dnskey_algorithms(keys: &[DNSKEY]) -> Vec<Algorithm> {
    let mut algorithms: Vec<Algorithm> = keys.iter().map(|k| k.algorithm()).collect();
    algorithms.sort_by_key(|a| u8::from(*a));
    algorithms.dedup();
    algorithms
}

/// An RRset as validation sees it: an owner name, a type, and every record
/// sharing both. One RRSIG covers exactly one of these.
pub type Rrset = (Name, RecordType, Vec<Record>);

/// Splits a record slice into the RRsets it contains, keyed by owner and type,
/// with RRSIGs held aside.
///
/// Validation is per-RRset — a signature covers one owner and one type — so any
/// caller holding a section has to perform this grouping before it can verify
/// anything.
pub fn group_rrsets(records: &[Record]) -> (Vec<Rrset>, Vec<Record>) {
    let mut sets: Vec<Rrset> = Vec::new();
    let mut sigs: Vec<Record> = Vec::new();
    for record in records {
        if record.record_type() == RecordType::RRSIG {
            sigs.push(record.clone());
            continue;
        }
        let rtype = record.record_type();
        match sets
            .iter_mut()
            .find(|(name, t, _)| *t == rtype && name == record.name())
        {
            Some((_, _, group)) => group.push(record.clone()),
            None => sets.push((record.name().clone(), rtype, vec![record.clone()])),
        }
    }
    (sets, sigs)
}

/// Whether a record is one of the DNSSEC meta types a validator handles itself.
pub fn is_dnssec_type(rtype: RecordType) -> bool {
    matches!(
        rtype,
        RecordType::RRSIG
            | RecordType::DNSKEY
            | RecordType::DS
            | RecordType::NSEC
            | RecordType::NSEC3
            | RecordType::NSEC3PARAM
    )
}

/// The minimum TTL across a record slice, used to decide how long a validated
/// key set or an insecure verdict may be cached.
pub fn min_ttl(records: &[Record], fallback: u32) -> u32 {
    records.iter().map(Record::ttl).min().unwrap_or(fallback)
}

/// Extracts the record data of a given type at a given owner.
pub fn records_at(records: &[Record], owner: &Name, rtype: RecordType) -> Vec<Record> {
    records
        .iter()
        .filter(|r| r.name() == owner && r.record_type() == rtype)
        .cloned()
        .collect()
}

/// The zone that signed `records`, when it lies strictly *below* `zone`.
///
/// This is how a zone cut that never produced a referral is detected. A
/// delegation is normally visible: the parent's servers answer with NS records
/// and the walk crosses the cut deliberately. But when one nameserver is
/// authoritative for a parent *and* its signed child — `cloudflare.com.` and
/// `cdnjs.cloudflare.com.`, both on the same NS set — a query for a name in the
/// child is answered from the child zone directly. No referral is ever sent, so
/// a resolver tracking only referrals still believes it is talking to the
/// parent, and validates the child's signatures against the parent's keys. That
/// mismatch is not an attack, it is the correct behaviour of both servers, and
/// rejecting it makes every such name unresolvable.
///
/// RFC 4035 §5.3.1 puts the signer name in charge: the key set to validate with
/// is the one belonging to the RRSIG's signer, not the one belonging to whatever
/// zone the resolver last descended into. This returns that signer so the caller
/// can extend the chain of trust down to it.
///
/// Three conditions, and each one is load-bearing:
///
///   - **Every** RRSIG present must name the same signer. A section mixing
///     signers cannot be validated against one key set anyway, and picking one
///     of them would decide which half goes unchecked.
///   - The signer must be a proper descendant of `zone` — never `zone` itself
///     (nothing to cross) and never outside it (a zone may not vouch for a name
///     it does not contain).
///   - The signer must contain every owner name it signed. Without this a
///     forged answer could name any signer it liked — say `nonexistent.zone.` —
///     and the caller would go off to establish trust for a name unrelated to
///     the data, which is precisely how "no DS there" becomes a downgrade of
///     data that really is signed by `zone`.
pub fn signer_below(records: &[Record], zone: &Name) -> Option<Name> {
    let mut signer: Option<Name> = None;
    for record in records {
        let Some(sig) = record.data().as_dnssec().and_then(|d| d.as_rrsig()) else {
            continue;
        };
        let candidate = sig.signer_name();
        // Equal to `zone` means the walk is already where it needs to be; outside
        // `zone` means this signature has no business here at all. Either way
        // there is no cut to cross, and a section that mixes the two is not one
        // key set's to validate.
        if candidate == zone || !zone.zone_of(candidate) {
            return None;
        }
        // The signature is over `record`'s owner; a signer that does not contain
        // that owner is not a zone cut, it is a claim.
        if !candidate.zone_of(record.name()) {
            return None;
        }
        match &signer {
            Some(seen) if seen != candidate => return None,
            Some(_) => {}
            None => signer = Some(candidate.clone()),
        }
    }
    signer
}

/// The apex of a zone *below* `zone` that an authority section's SOA names.
///
/// A server answering from a zone it holds puts that zone's SOA in the authority
/// section of a negative response. When the SOA names a zone below the one the
/// walk is at, the response came from a child served on the same nameserver —
/// the same hidden cut [`signer_below`] finds, seen from the one angle still
/// available when the child is *unsigned* and so has no signer name to report.
///
/// This is **diagnostic only**, and the distinction matters: an SOA in an
/// unsigned response is unsigned like everything else around it, so an attacker
/// can put any name there. It is fit for telling an operator which of two things
/// they are probably looking at — an unsigned zone below a signed parent, or
/// signatures stripped in flight — and it must never decide a verdict, which is
/// why nothing outside the metrics path calls it.
pub fn soa_below(records: &[Record], zone: &Name) -> Option<Name> {
    records
        .iter()
        .find(|r| r.record_type() == RecordType::SOA && zone.zone_of(r.name()) && r.name() != zone)
        .map(|r| r.name().clone())
}

/// Whether `records` contains any RRSIG at all — used only to phrase a failure,
/// never to decide security. An absent signature is not evidence of an unsigned
/// zone; see the module docs.
pub fn has_any_rrsig(records: &[Record]) -> bool {
    records
        .iter()
        .any(|r| matches!(r.data(), RData::DNSSEC(_)) && r.record_type() == RecordType::RRSIG)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("test name parses")
    }

    #[test]
    fn verdict_merge_takes_the_worst() {
        assert_eq!(Verdict::Secure.merge(Verdict::Insecure), Verdict::Insecure);
        assert_eq!(Verdict::Insecure.merge(Verdict::Secure), Verdict::Insecure);
        assert_eq!(
            Verdict::Insecure.merge(Verdict::Bogus("x".into())),
            Verdict::Bogus("x".into())
        );
        assert_eq!(
            Verdict::Bogus("first".into()).merge(Verdict::Indeterminate("second".into())),
            Verdict::Bogus("first".into())
        );
        assert_eq!(Verdict::Secure.merge(Verdict::Secure), Verdict::Secure);
    }

    #[test]
    fn bogus_and_indeterminate_withhold_the_answer() {
        assert!(Verdict::Bogus("x".into()).withholds_answer());
        assert!(Verdict::Indeterminate("x".into()).withholds_answer());
        assert!(!Verdict::Secure.withholds_answer());
        assert!(!Verdict::Insecure.withholds_answer());
    }

    /// Checked against RFC 4648 §10's base32hex test vectors. The encoder is
    /// load-bearing for every NSEC3 comparison, so it is pinned to the RFC
    /// rather than to itself.
    #[test]
    fn base32hex_matches_rfc4648_vectors() {
        assert_eq!(base32hex(b""), "");
        assert_eq!(base32hex(b"f"), "CO");
        assert_eq!(base32hex(b"fo"), "CPNG");
        assert_eq!(base32hex(b"foo"), "CPNMU");
        assert_eq!(base32hex(b"foob"), "CPNMUOG");
        assert_eq!(base32hex(b"fooba"), "CPNMUOJ1");
        assert_eq!(base32hex(b"foobar"), "CPNMUOJ1E8");
    }

    /// Order preservation is what lets the NSEC3 range checks compare encoded
    /// strings instead of raw digests. If this ever stopped holding, every
    /// "covers" test would silently start answering a different question.
    #[test]
    fn base32hex_preserves_order_for_equal_lengths() {
        let mut raw: Vec<[u8; 4]> = vec![
            [0x00, 0x00, 0x00, 0x01],
            [0xff, 0xff, 0xff, 0xff],
            [0x10, 0x20, 0x30, 0x40],
            [0x0f, 0xff, 0xff, 0xff],
            [0x80, 0x00, 0x00, 0x00],
        ];
        raw.sort();
        let encoded: Vec<String> = raw.iter().map(|b| base32hex(b)).collect();
        let mut sorted = encoded.clone();
        sorted.sort();
        assert_eq!(encoded, sorted, "base32hex must preserve byte ordering");
    }

    /// The validity window is the only thing that stops a captured signature
    /// from being replayable forever, and it is compared in a space that wraps.
    #[test]
    fn serial_comparison_wraps_per_rfc1982() {
        assert!(serial_lt(1, 2));
        assert!(!serial_lt(2, 1));
        assert!(!serial_lt(5, 5), "a serial is not less than itself");
        // Across the wrap: a signature issued just before 2^32 is still earlier
        // than one issued just after, which plain integer comparison gets
        // backwards — and getting it backwards means every live signature reads
        // as expired.
        assert!(serial_lt(u32::MAX - 10, 10));
        assert!(!serial_lt(10, u32::MAX - 10));
    }

    #[test]
    fn wildcard_of_clamps_to_the_zone_apex() {
        let zone = name("example.com.");
        assert_eq!(
            wildcard_of(&name("a.b.example.com."), &zone),
            name("*.b.example.com.")
        );
        // The parent of a name directly under the apex is the apex itself.
        assert_eq!(
            wildcard_of(&name("a.example.com."), &zone),
            name("*.example.com.")
        );
        // A name at the apex cannot borrow a wildcard from above the zone.
        assert_eq!(wildcard_of(&zone, &zone), name("*.example.com."));
    }

    #[test]
    fn next_closer_is_one_label_below_the_encloser() {
        assert_eq!(
            next_closer_name(&name("a.b.c.example.com."), &name("c.example.com.")),
            Some(name("b.c.example.com."))
        );
        assert_eq!(
            next_closer_name(&name("a.example.com."), &name("example.com.")),
            Some(name("a.example.com."))
        );
        // An "encloser" that is not shorter than the name encloses nothing.
        assert_eq!(
            next_closer_name(&name("example.com."), &name("example.com.")),
            None
        );
    }

    #[test]
    fn nsec_coverage_handles_the_wrapping_last_record() {
        // A zone whose last NSEC runs from z.example.com. back to the apex.
        let denial = Denial {
            nsec: vec![(
                name("z.example.com."),
                NSEC::new(name("example.com."), vec![RecordType::A]),
            )],
            nsec3: Vec::new(),
        };
        // Sorts after z, so it falls in the wrapped span.
        assert!(nsec_covers_name(&denial, &name("zz.example.com.")));
        // Sorts before z, so it does not.
        assert!(!nsec_covers_name(&denial, &name("a.example.com.")));
    }

    #[test]
    fn nsec_coverage_is_exclusive_at_both_ends() {
        let denial = Denial {
            nsec: vec![(
                name("a.example.com."),
                NSEC::new(name("c.example.com."), vec![RecordType::A]),
            )],
            nsec3: Vec::new(),
        };
        assert!(nsec_covers_name(&denial, &name("b.example.com.")));
        // The endpoints themselves exist; they are matched, not covered.
        assert!(!nsec_covers_name(&denial, &name("a.example.com.")));
        assert!(!nsec_covers_name(&denial, &name("c.example.com.")));
    }

    #[test]
    fn no_ds_proof_refuses_an_empty_authority_section() {
        let err = prove_no_ds(&name("child.example.com."), &Denial::default())
            .expect_err("a delegation with no DS and no denial must not be accepted");
        assert!(
            err.contains("neither a DS record nor any NSEC/NSEC3"),
            "unexpected reason: {err}"
        );
    }

    /// The downgrade attack in one test: an NSEC that says a DS *does* exist,
    /// arriving with the DS stripped out, must not be read as "no DS here".
    #[test]
    fn no_ds_proof_rejects_an_nsec_that_asserts_a_ds() {
        let child = name("child.example.com.");
        let denial = Denial {
            nsec: vec![(
                child.clone(),
                NSEC::new(name("d.example.com."), vec![RecordType::NS, RecordType::DS]),
            )],
            nsec3: Vec::new(),
        };
        let err = prove_no_ds(&child, &denial).expect_err("a DS-asserting NSEC must be refused");
        assert!(
            err.contains("asserts a DS exists"),
            "unexpected reason: {err}"
        );
    }

    #[test]
    fn no_ds_proof_rejects_the_child_apex_nsec() {
        let child = name("child.example.com.");
        let denial = Denial {
            nsec: vec![(
                child.clone(),
                NSEC::new(
                    name("a.child.example.com."),
                    vec![RecordType::NS, RecordType::SOA],
                ),
            )],
            nsec3: Vec::new(),
        };
        let err = prove_no_ds(&child, &denial)
            .expect_err("the child's own apex NSEC proves nothing about the parent");
        assert!(err.contains("child apex"), "unexpected reason: {err}");
    }

    #[test]
    fn no_ds_proof_accepts_a_delegation_nsec_without_ds() {
        let child = name("child.example.com.");
        let denial = Denial {
            nsec: vec![(
                child.clone(),
                NSEC::new(name("d.example.com."), vec![RecordType::NS]),
            )],
            nsec3: Vec::new(),
        };
        assert_eq!(prove_no_ds(&child, &denial), Ok(Denied::Proven));
    }

    #[test]
    fn nxdomain_needs_the_wildcard_denial_too() {
        // The qname is covered, but nothing rules out *.example.com.
        let denial = Denial {
            nsec: vec![(
                name("a.example.com."),
                NSEC::new(name("c.example.com."), vec![RecordType::A]),
            )],
            nsec3: Vec::new(),
        };
        let err = prove_nxdomain(&name("b.example.com."), &name("example.com."), &denial)
            .expect_err("an NXDOMAIN with no wildcard denial must not be proven");
        assert!(err.contains("wildcard"), "unexpected reason: {err}");
    }

    #[test]
    fn nxdomain_is_proven_when_both_spans_are_covered() {
        let denial = Denial {
            nsec: vec![
                (
                    name("a.example.com."),
                    NSEC::new(name("c.example.com."), vec![RecordType::A]),
                ),
                // Covers *.example.com., which sorts before "a" in canonical order.
                (
                    name("example.com."),
                    NSEC::new(name("a.example.com."), vec![RecordType::SOA]),
                ),
            ],
            nsec3: Vec::new(),
        };
        assert_eq!(
            prove_nxdomain(&name("b.example.com."), &name("example.com."), &denial),
            Ok(Denied::Proven)
        );
    }

    #[test]
    fn nodata_rejects_an_nsec_that_asserts_the_type() {
        let qname = name("a.example.com.");
        let denial = Denial {
            nsec: vec![(
                qname.clone(),
                NSEC::new(name("c.example.com."), vec![RecordType::A, RecordType::MX]),
            )],
            nsec3: Vec::new(),
        };
        let err = prove_nodata(&qname, RecordType::MX, &name("example.com."), &denial)
            .expect_err("an NSEC listing the type contradicts NODATA");
        assert!(
            err.contains("asserts MX exists"),
            "unexpected reason: {err}"
        );
    }

    #[test]
    fn nodata_rejects_an_nsec_hiding_a_cname() {
        let qname = name("a.example.com.");
        let denial = Denial {
            nsec: vec![(
                qname.clone(),
                NSEC::new(name("c.example.com."), vec![RecordType::CNAME]),
            )],
            nsec3: Vec::new(),
        };
        let err = prove_nodata(&qname, RecordType::A, &name("example.com."), &denial)
            .expect_err("a CNAME should have been followed rather than yielding NODATA");
        assert!(err.contains("CNAME"), "unexpected reason: {err}");
    }

    #[test]
    fn nodata_is_proven_by_a_matching_nsec_without_the_type() {
        let qname = name("a.example.com.");
        let denial = Denial {
            nsec: vec![(
                qname.clone(),
                NSEC::new(name("c.example.com."), vec![RecordType::A]),
            )],
            nsec3: Vec::new(),
        };
        assert_eq!(
            prove_nodata(&qname, RecordType::MX, &name("example.com."), &denial),
            Ok(Denied::Proven)
        );
    }

    #[test]
    fn wildcard_expansion_without_a_denial_is_refused() {
        let err = prove_wildcard_expansion(
            &name("a.example.com."),
            &name("example.com."),
            &Denial::default(),
        )
        .expect_err("a wildcard answer with no denial must not be accepted");
        assert!(err.contains("does not exist"), "unexpected reason: {err}");
    }

    #[test]
    fn wildcard_expansion_is_proven_when_the_qname_is_covered() {
        let denial = Denial {
            nsec: vec![(
                name("a.example.com."),
                NSEC::new(name("c.example.com."), vec![RecordType::A]),
            )],
            nsec3: Vec::new(),
        };
        assert_eq!(
            prove_wildcard_expansion(&name("b.example.com."), &name("example.com."), &denial),
            Ok(Denied::Proven)
        );
    }

    #[test]
    fn group_rrsets_separates_signatures_from_data() {
        use hickory_proto::rr::rdata;
        use std::net::Ipv4Addr;

        let a1 = Record::from_rdata(
            name("a.example.com."),
            60,
            RData::A(rdata::A(Ipv4Addr::new(192, 0, 2, 1))),
        );
        let a2 = Record::from_rdata(
            name("a.example.com."),
            60,
            RData::A(rdata::A(Ipv4Addr::new(192, 0, 2, 2))),
        );
        let b = Record::from_rdata(
            name("b.example.com."),
            60,
            RData::A(rdata::A(Ipv4Addr::new(192, 0, 2, 3))),
        );
        let (sets, sigs) = group_rrsets(&[a1, a2, b]);
        assert_eq!(sets.len(), 2, "two owners means two RRsets");
        assert_eq!(sets[0].2.len(), 2, "the two a. records are one RRset");
        assert!(sigs.is_empty());
    }

    // -----------------------------------------------------------------------
    // signer_below: finding a zone cut nobody announced
    // -----------------------------------------------------------------------

    /// An A record at `owner`, plus an RRSIG over it naming `signer`. The
    /// signature bytes are never checked here — `signer_below` reads names to
    /// decide *which keys to go and get*, and the cryptography is `verify_rrset`'s
    /// job afterwards.
    fn signed_by(owner: &str, signer: &str) -> Vec<Record> {
        use hickory_proto::dnssec::rdata::DNSSECRData;
        use hickory_proto::rr::rdata;
        use std::net::Ipv4Addr;

        let owner = name(owner);
        let data = Record::from_rdata(
            owner.clone(),
            60,
            RData::A(rdata::A(Ipv4Addr::new(192, 0, 2, 1))),
        );
        let sig = Record::from_rdata(
            owner.clone(),
            60,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::new(
                RecordType::A,
                Algorithm::ED25519,
                owner.num_labels(),
                60,
                2_000_000_000,
                1_000_000_000,
                1234,
                name(signer),
                vec![0u8; 64],
            ))),
        );
        vec![data, sig]
    }

    /// The case this exists for: `cdnjs.cloudflare.com.` is its own signed zone
    /// on `cloudflare.com.`'s nameservers, so its answers arrive signed by itself
    /// with no referral ever crossing the cut.
    #[test]
    fn signer_below_finds_a_child_zone_that_answered_for_itself() {
        let records = signed_by("cdnjs.cloudflare.com.", "cdnjs.cloudflare.com.");
        assert_eq!(
            signer_below(&records, &name("cloudflare.com.")),
            Some(name("cdnjs.cloudflare.com.")),
            "an answer signed below the zone we are talking to names the cut to cross"
        );
    }

    /// The ordinary case: the zone we are talking to signed its own data. There
    /// is no cut, and reporting one would cost a DS lookup per answer.
    #[test]
    fn signer_below_is_silent_when_the_current_zone_signed() {
        let records = signed_by("www.example.com.", "example.com.");
        assert_eq!(signer_below(&records, &name("example.com.")), None);
    }

    /// A signer outside the zone is not a delegation to descend into — it is a
    /// zone claiming a name it does not contain, and `verify_rrset` must be left
    /// to reject it.
    #[test]
    fn signer_below_ignores_a_signer_outside_the_zone() {
        let records = signed_by("www.example.com.", "attacker.test.");
        assert_eq!(signer_below(&records, &name("example.com.")), None);
    }

    /// The downgrade this guard exists for. A forged answer names a signer that
    /// does not contain the owner it signed; if that name were chased, the
    /// parent would answer "no DS there" — truthfully, since it is not a
    /// delegation at all — and a *signed* name would end up validated as
    /// insecure. The owner containment test is what keeps it Bogus.
    #[test]
    fn signer_below_rejects_a_signer_that_does_not_contain_its_owner() {
        let records = signed_by("www.example.com.", "nowhere.example.com.");
        assert_eq!(
            signer_below(&records, &name("example.com.")),
            None,
            "a signer that does not enclose the owner is a claim, not a zone cut"
        );
    }

    /// One key set cannot validate two signers, so a mixed section is left to
    /// fail rather than half-checked against whichever one was picked.
    #[test]
    fn signer_below_refuses_a_section_with_two_signers() {
        let mut records = signed_by("a.sub.example.com.", "sub.example.com.");
        records.extend(signed_by("b.example.com.", "example.com."));
        assert_eq!(signer_below(&records, &name("example.com.")), None);
    }

    /// No signatures at all is not a cut. It is an unsigned answer, and what to
    /// make of that is the caller's decision, not this function's.
    #[test]
    fn signer_below_reports_nothing_for_unsigned_records() {
        use hickory_proto::rr::rdata;
        use std::net::Ipv4Addr;

        let unsigned = vec![Record::from_rdata(
            name("www.example.com."),
            60,
            RData::A(rdata::A(Ipv4Addr::new(192, 0, 2, 1))),
        )];
        assert_eq!(signer_below(&unsigned, &name("example.com.")), None);
    }

    /// Several cuts at once, which the resolver must then descend one at a time.
    #[test]
    fn signer_below_reports_a_signer_several_labels_down() {
        let records = signed_by("host.a.b.example.com.", "a.b.example.com.");
        assert_eq!(
            signer_below(&records, &name("example.com.")),
            Some(name("a.b.example.com."))
        );
    }

    // -----------------------------------------------------------------------
    // soa_below: the unsigned twin of a hidden zone cut
    // -----------------------------------------------------------------------

    fn soa_at(owner: &str) -> Record {
        use hickory_proto::rr::rdata::SOA;
        Record::from_rdata(
            name(owner),
            60,
            RData::SOA(SOA::new(
                name("ns1.example.com."),
                name("hostmaster.example.com."),
                1,
                7200,
                3600,
                1_209_600,
                300,
            )),
        )
    }

    /// An unsigned child on its parent's nameservers: the SOA names the child's
    /// apex, which is the only hint available once there are no signatures to
    /// read a signer name from.
    #[test]
    fn soa_below_names_a_child_apex() {
        let authority = vec![soa_at("cdn.example.com.")];
        assert_eq!(
            soa_below(&authority, &name("example.com.")),
            Some(name("cdn.example.com."))
        );
    }

    /// The zone's own SOA is the ordinary case and says nothing about a cut.
    #[test]
    fn soa_below_ignores_the_zones_own_apex() {
        let authority = vec![soa_at("example.com.")];
        assert_eq!(soa_below(&authority, &name("example.com.")), None);
    }

    /// An SOA for somewhere else entirely is not evidence about this zone.
    #[test]
    fn soa_below_ignores_a_foreign_apex() {
        let authority = vec![soa_at("elsewhere.test.")];
        assert_eq!(soa_below(&authority, &name("example.com.")), None);
    }

    /// Stripped signatures leave an authority section with no SOA to read, which
    /// is the "no evidence" case the counter separates out.
    #[test]
    fn soa_below_reports_nothing_without_an_soa() {
        assert_eq!(soa_below(&[], &name("example.com.")), None);
    }

    #[test]
    fn ds_algorithm_support_gates_the_insecure_downgrade() {
        // Algorithm 8 (RSA/SHA-256) is verifiable here, so a DS naming it must
        // not be waved through as "unsupported, therefore insecure".
        let supported = DS::new(
            1234,
            Algorithm::RSASHA256,
            hickory_proto::dnssec::DigestType::SHA256,
            vec![0u8; 32],
        );
        assert!(ds_algorithms_supported(&[supported]));
        assert!(!ds_algorithms_supported(&[]));
    }
}
