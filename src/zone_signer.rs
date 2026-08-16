//! Signing a zone: DNSKEY publication, NSEC chain generation, and RRSIG
//! production over every RRset the zone holds.
//!
//! This is the whole operation, extracted from the gRPC handler that used to
//! contain it so that two callers can share it. `SignZone` is the operator-facing
//! one; [`crate::dns_server::DnsServer`]'s re-sign loop is the other, and it
//! exists because a signed zone does not stay signed on its own.
//!
//! **A mutation to a signed zone leaves it in a state that is worse than
//! unsigned, and that is why the second caller is not optional.** A record added
//! after signing has no RRSIG, which a validator reads as a stripped signature
//! rather than as an unsigned name. Worse, the NSEC chain still describes the
//! zone as it was: the new name falls inside some existing link's range, so the
//! zone is serving a *signed proof that its own record does not exist*. Nothing
//! about that is visible to the operator who added the record.
//!
//! Signatures also expire — 30 days out, per `RRSIG_VALIDITY_SECS` — so even a
//! zone nobody touches needs a periodic pass or it goes bogus on a timer.

use crate::db::{Database, DnsRecord, RecordKind, name_in_zone, normalize_name};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use tracing::info;

/// TTL for the DNSKEY records published at the zone apex.
pub const DNSKEY_TTL: u32 = 3600;

/// TTL for NSEC records when the zone apex publishes no SOA to take one from.
const NSEC_FALLBACK_TTL: u32 = 300;

/// Holds the in-progress mark for a signing pass and clears it on drop.
///
/// A plain pair of calls would leak the mark on any `?` in the middle of the
/// pass — and there are several, each after the point where the old signatures
/// have already been deleted. A leaked mark is not a small bug: the zone would
/// answer unsigned forever, silently, with no path back short of a restart.
struct ResignGuard<'a> {
    db: &'a Database,
    zone: String,
}

impl<'a> ResignGuard<'a> {
    fn new(db: &'a Database, zone: &str) -> Self {
        db.begin_zone_resign(zone);
        Self {
            db,
            zone: zone.to_string(),
        }
    }
}

impl Drop for ResignGuard<'_> {
    fn drop(&mut self) {
        self.db.end_zone_resign(&self.zone);
    }
}

/// What a signing pass did.
pub struct SignSummary {
    pub keys: usize,
    pub signed_rrsets: usize,
    pub nsec_records: usize,
    /// RRsets skipped because some member has no canonical wire form, named as
    /// `"<owner> <TYPE>"`.
    pub skipped: Vec<String>,
    /// Keys that could not be used, and why.
    pub warnings: Vec<String>,
}

/// The result of asking for a zone to be signed.
pub enum SignOutcome {
    /// The zone holds no keys, or none usable. Not an error — a zone nobody has
    /// generated keys for is simply an unsigned zone — so the caller reports it
    /// rather than failing.
    NotSigned(String),
    Signed(SignSummary),
}

/// Signs `zone` in place: republishes its DNSKEY RRset, rebuilds and publishes
/// its NSEC chain, and re-signs every RRset it holds.
///
/// The whole pass is idempotent. Running it twice over an unchanged zone
/// produces the same chain byte-for-byte (NSEC types are emitted in wire-code
/// order for exactly that reason) and replaces every signature with an
/// equivalent one over a fresh validity window.
pub fn sign_zone(db: &Database, zone: &str) -> Result<SignOutcome> {
    let zone = normalize_name(zone);
    // Bracket the whole pass. Between the deletes below and the last signature
    // written, the zone holds a partial chain and partial signatures; the
    // in-progress mark is what keeps both answer paths serving unsigned rather
    // than serving those. `end_zone_resign` runs on every exit — the guard's
    // Drop — because an early return that left the mark set would withhold this
    // zone's signatures for the life of the process.
    let _guard = ResignGuard::new(db, &zone);

    let all_keys = db
        .list_dnssec_keys(&zone)
        .context("failed to list DNSSEC keys")?;
    if all_keys.is_empty() {
        return Ok(SignOutcome::NotSigned(
            "no DNSSEC keys found for zone".to_string(),
        ));
    }

    // Load each active key's material. A key whose stored algorithm does not
    // match its bytes is dropped here with a warning rather than signed with: a
    // signature labelled with an algorithm it was not made by is worse than a
    // missing one, because it fails at the validator instead of at the operator.
    let mut warnings: Vec<String> = Vec::new();
    let mut signing_keys: Vec<crate::dnssec::SigningKey> = Vec::new();
    for key in all_keys.iter().filter(|k| k.active) {
        let Some(algo) = crate::dnssec::DnssecAlgorithm::parse(&key.algorithm) else {
            warnings.push(format!(
                "key {} has unknown algorithm {}",
                key.id, key.algorithm
            ));
            continue;
        };
        let Some(kt) = crate::dnssec::KeyType::parse(&key.key_type) else {
            warnings.push(format!(
                "key {} has unknown key type {}",
                key.id, key.key_type
            ));
            continue;
        };
        match crate::dnssec::SigningKey::from_pkcs8(algo, kt, &key.private_key) {
            Ok(loaded) => signing_keys.push(loaded),
            Err(e) => warnings.push(format!(
                "key {} ({}) unusable: {}",
                key.id, key.algorithm, e
            )),
        }
    }

    if signing_keys.is_empty() {
        return Ok(SignOutcome::NotSigned(format!(
            "no usable DNSSEC keys for zone: {}",
            warnings.join("; ")
        )));
    }

    // Republish the DNSKEY RRset from scratch so a deleted or unusable key does
    // not leave a DNSKEY behind advertising a key nothing signs with.
    db.remove_records(&zone, Some(RecordKind::DNSKEY), "")
        .context("failed to clear DNSKEY RRset")?;
    for key in &signing_keys {
        let dnskey_value = format!(
            "{} 3 {} {}",
            key.key_type.flags(),
            key.algorithm as u8,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key.public_key()),
        );
        db.add_record(&DnsRecord {
            id: None,
            name: zone.clone(),
            record_type: RecordKind::DNSKEY,
            value: dnskey_value,
            ttl: DNSKEY_TTL,
            priority: 0,
        })
        .context("failed to store DNSKEY")?;
    }

    // Drop the pending mark BEFORE reading the zone, not after writing it.
    //
    // Clearing at the end loses any mutation that lands mid-pass: the record
    // arrives too late to be in `candidates`, sets the mark, and then has it
    // wiped by a pass that never saw it — leaving the name outside the chain
    // that this very pass published, which is a signed proof that it does not
    // exist. Clearing first means such a mutation re-marks the zone and the next
    // pass picks it up. The cost is at worst one redundant pass when a mutation
    // lands between here and the read below.
    //
    // A pass that FAILS must not lose the mark either; `resign_once` re-marks on
    // error for that reason.
    db.clear_zone_resign_pending(&zone);

    // Collect the zone's records. The `*.` filter is a SQL LIKE, which also
    // matches names that merely end in the zone's text ("notexample.com." for
    // "example.com."), so the label-boundary check is redone in Rust.
    let candidates = db
        .list_records(&format!("*.{}", zone), None)
        .context("failed to list zone records")?;

    // Rebuild the NSEC chain from the zone as it stands, BEFORE the signing
    // loop, so its records are signed in this same pass. A chain written
    // afterwards would be a set of unsigned NSECs, and unsigned denial is worse
    // than none: the zone publishes DNSKEYs promising every answer is signed, so
    // a validator treats the missing signature as an attack rather than as an
    // unsigned zone.
    let chain = crate::dnssec::build_nsec_chain(&zone, &candidates);
    let nsec_ttl = apex_negative_ttl(&candidates, &zone);

    // Group into RRsets: all records sharing an owner name and type.
    let mut rrsets: HashMap<(String, RecordKind), Vec<DnsRecord>> = HashMap::new();
    // Every in-zone name that currently holds a signature. Collected from the
    // records themselves rather than from the RRsets about to be signed: a name
    // whose last record was deleted since the previous run still has an RRSIG,
    // and it is exactly the one that must not survive.
    let mut signed_names: HashSet<String> = HashSet::new();
    for record in candidates {
        if !name_in_zone(&record.name, &zone) {
            continue;
        }
        // RFC 4035 §2.2: RRSIG RRsets are not themselves signed. The old
        // signatures are cleared below.
        if record.record_type == RecordKind::RRSIG {
            signed_names.insert(record.name.clone());
            continue;
        }
        signed_names.insert(record.name.clone());
        // The stored NSECs are the previous run's chain, replaced below. Signing
        // them here would spend a signature on a record already scheduled for
        // deletion — and, worse, leave it in the zone if the rebuild produced a
        // chain that no longer names this owner.
        if record.record_type == RecordKind::NSEC {
            continue;
        }
        rrsets
            .entry((record.name.clone(), record.record_type))
            .or_default()
            .push(record);
    }

    let now = crate::dnssec::now_secs().context("cannot read the clock")?;
    let inception = now.saturating_sub(crate::dnssec::RRSIG_INCEPTION_BACKDATE_SECS as u32);
    let expiration = now.saturating_add(crate::dnssec::RRSIG_VALIDITY_SECS as u32);

    // Clear every existing RRSIG in the zone before re-signing, so a record that
    // has since been deleted does not keep its signature. The old NSEC chain
    // goes with them: it is regenerated wholesale, and a leftover NSEC at a name
    // the new chain does not cover is a signed statement that the names in its
    // range do not exist.
    for name in &signed_names {
        db.remove_records(name, Some(RecordKind::RRSIG), "")
            .context("failed to clear RRSIGs")?;
        db.remove_records(name, Some(RecordKind::NSEC), "")
            .context("failed to clear NSECs")?;
    }

    // Publish the new chain and hand it to the signing loop below.
    let mut nsec_records = 0usize;
    for (owner, nsec) in &chain {
        let record = DnsRecord {
            id: None,
            name: owner.clone(),
            record_type: RecordKind::NSEC,
            value: nsec.to_value(),
            ttl: nsec_ttl,
            priority: 0,
        };
        db.add_record(&record).context("failed to publish NSEC")?;
        rrsets.insert((owner.clone(), RecordKind::NSEC), vec![record]);
        nsec_records += 1;
    }

    let mut signed_rrsets = 0usize;
    let mut skipped: Vec<String> = Vec::new();
    // Sort for a deterministic pass, so two runs over the same zone do the same
    // work in the same order and a failure is reproducible.
    let mut ordered: Vec<((String, RecordKind), Vec<DnsRecord>)> = rrsets.into_iter().collect();
    ordered.sort_by(|a, b| (&a.0.0, a.0.1.wire_type()).cmp(&(&b.0.0, b.0.1.wire_type())));

    for ((owner, kind), records) in ordered {
        // A type with no canonical wire encoding cannot be signed; say so rather
        // than emitting a signature over an invented format.
        if records
            .iter()
            .any(|r| crate::dnssec::canonical_rdata(r).is_none())
        {
            skipped.push(format!("{} {}", owner, kind.as_str()));
            continue;
        }

        // Every RR in an RRset shares one TTL. Where the stored rows disagree the
        // smallest wins, because that is the only choice that cannot outlive what
        // an operator asked to be cached.
        let original_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(DNSKEY_TTL);

        // RFC 4035 §2.1: the DNSKEY RRset is signed by the KSK; everything else
        // by the ZSK. With only one kind of key present, it does both.
        let is_apex_dnskey = kind == RecordKind::DNSKEY && owner == zone;
        let wanted = if is_apex_dnskey {
            crate::dnssec::KeyType::KSK
        } else {
            crate::dnssec::KeyType::ZSK
        };
        let mut signers: Vec<&crate::dnssec::SigningKey> = signing_keys
            .iter()
            .filter(|k| k.key_type == wanted)
            .collect();
        if signers.is_empty() {
            signers = signing_keys.iter().collect();
        }

        for key in signers {
            let value = crate::dnssec::sign_rrset(
                key,
                &crate::dnssec::RrsetToSign {
                    signer_zone: &zone,
                    owner: &owner,
                    type_covered: kind,
                    original_ttl,
                    rrset: &records,
                    inception,
                    expiration,
                },
            )
            .with_context(|| format!("failed to sign {} {}", owner, kind.as_str()))?;

            db.add_record(&DnsRecord {
                id: None,
                name: owner.clone(),
                record_type: RecordKind::RRSIG,
                value,
                ttl: original_ttl,
                priority: 0,
            })
            .context("failed to store RRSIG")?;
        }
        signed_rrsets += 1;
    }

    info!(
        "Signed zone {} ({} keys, {} RRsets, {} NSEC, {} skipped)",
        zone,
        signing_keys.len(),
        signed_rrsets,
        nsec_records,
        skipped.len()
    );

    Ok(SignOutcome::Signed(SignSummary {
        keys: signing_keys.len(),
        signed_rrsets,
        nsec_records,
        skipped,
        warnings,
    }))
}

/// The TTL to give the zone's NSEC records: the SOA MINIMUM field, per RFC 4034
/// §4, capped by the SOA's own TTL the way RFC 2308 §3 caps a negative TTL.
///
/// An NSEC is a denial, and a denial cached for longer than the zone said its
/// absences last is a name that stays missing after it has been created. Tying
/// the two together means one knob — the SOA — governs how long this zone's
/// negatives live, whether they arrive as a bare rcode or as a signed proof.
fn apex_negative_ttl(records: &[DnsRecord], zone: &str) -> u32 {
    let apex = normalize_name(zone);
    records
        .iter()
        .find(|r| r.record_type == RecordKind::SOA && normalize_name(&r.name) == apex)
        .and_then(|soa| {
            let minimum: u32 = soa.value.split_whitespace().nth(6)?.parse().ok()?;
            Some(minimum.min(soa.ttl))
        })
        .unwrap_or(NSEC_FALLBACK_TTL)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn soa(ttl: u32, minimum: &str) -> DnsRecord {
        DnsRecord {
            id: None,
            name: "example.com.".to_string(),
            record_type: RecordKind::SOA,
            value: format!(
                "ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 {minimum}"
            ),
            ttl,
            priority: 0,
        }
    }

    /// The NSEC TTL comes from the SOA MINIMUM, so one knob governs how long
    /// this zone's absences are cached however they are expressed.
    #[test]
    fn nsec_ttl_follows_the_soa_minimum() {
        assert_eq!(apex_negative_ttl(&[soa(3600, "900")], "example.com."), 900);
    }

    /// ...but capped by the SOA's own TTL, the way RFC 2308 §3 caps a negative
    /// TTL. A MINIMUM larger than the record carrying it cannot be honoured for
    /// longer than the record itself survives in a cache.
    #[test]
    fn nsec_ttl_is_capped_by_the_soa_record_ttl() {
        assert_eq!(apex_negative_ttl(&[soa(300, "86400")], "example.com."), 300);
    }

    /// With no apex SOA there is nothing to take a TTL from, and the fallback
    /// applies rather than a zero TTL — which would make every denial
    /// uncacheable and send each repeat straight back to this server.
    #[test]
    fn nsec_ttl_falls_back_without_an_apex_soa() {
        assert_eq!(apex_negative_ttl(&[], "example.com."), NSEC_FALLBACK_TTL);

        // The control: an SOA at some OTHER name is not this zone's apex SOA.
        let mut elsewhere = soa(3600, "900");
        elsewhere.name = "sub.example.com.".to_string();
        assert_eq!(
            apex_negative_ttl(&[elsewhere], "example.com."),
            NSEC_FALLBACK_TTL
        );
    }

    /// A malformed SOA yields the fallback rather than a parse panic or a zero.
    #[test]
    fn nsec_ttl_survives_a_malformed_soa() {
        let mut broken = soa(3600, "900");
        broken.value = "not an soa".to_string();
        assert_eq!(
            apex_negative_ttl(&[broken], "example.com."),
            NSEC_FALLBACK_TTL
        );
    }
}
