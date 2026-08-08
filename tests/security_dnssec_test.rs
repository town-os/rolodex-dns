//! Security regressions for DNSSEC validation.
//!
//! Each test here is one attack, stated in observable terms: given a response
//! that an on-path adversary can construct with **no key material at all**, the
//! resolver must return a verdict that withholds the answer.
//!
//! | Test | The finding if it fails |
//! | ---- | ----------------------- |
//! | `stripping_every_signature_is_not_an_unsigned_zone` | Deleting RRSIGs in transit downgrades any signed zone to unsigned. This is the attack DNSSEC exists to stop. |
//! | `a_delegation_with_no_ds_and_no_proof_is_refused` | Deleting the DS *and* the NSEC turns a signed child into an "unsigned" one, and everything below it becomes forgeable. |
//! | `an_expired_signature_is_refused` | A captured response is replayable forever; the validity window is the only thing that bounds it. |
//! | `a_premature_signature_is_refused` | The other end of the same window, and the one a validator that only checks expiry misses. |
//! | `a_signature_from_an_unpublished_key_is_refused` | Any key verifies, so the DS and the DNSKEY RRset constrain nothing and the chain is decorative. |
//! | `a_foreign_signer_name_is_refused` | An attacker signs `www.bank.test` with a zone they own and supply the keys for, and the arithmetic checks out. |
//! | `data_mutated_after_signing_is_refused` | The signature is checked for presence rather than over the data, so records can be rewritten freely. |
//! | `an_unproven_negative_is_refused` | An NXDOMAIN needs no proof, so any name can be made to disappear — a denial-of-service that looks like the name simply not existing. |
//! | `bogus_data_is_never_returned_as_an_answer` | Bogus records reach the client (and the cache) despite the verdict. |
//! | `an_anchor_that_matches_no_root_key_fails_closed` | A resolver whose anchor matches nothing reports success while being anchored to nothing. |
//! | `malformed_trust_anchors_are_rejected` | A bad anchor is accepted or silently replaced, so the operator believes validation is on and anchored where they put it. |
//!
//! A failure in one of these is the finding, not a broken test. Never weaken an
//! assertion to make one pass: every assertion below is the difference between a
//! validating resolver and one that merely performs validation.

mod signed_hierarchy;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, RecordType};
use rolodex_dns::dnssec_validate::{Anchors, Verdict};
use rolodex_dns::resolver::IterativeResolver;
use signed_hierarchy::{NsecSpec, Tamper, Zone, ZoneKey, bind_levels, name, serve};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 51);
const TLD_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 52);
const ZONE_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 53);

const WWW_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

/// What the leaf zone (or the TLD) is made to do.
#[derive(Default, Clone)]
struct Attack {
    tld: Tamper,
    zone: Tamper,
}

struct Harness {
    resolver: IterativeResolver,
    _keep: Vec<signed_hierarchy::SignedNs>,
}

/// A three-level signed hierarchy with one zone (or delegation) under attack.
///
/// Every level is built *correctly* first and the tampering is applied when the
/// response is serialized, so each test is "a valid deployment, attacked" rather
/// than "an invalid deployment, rejected" — which would prove much less.
async fn harness(attack: Attack) -> Harness {
    let root_key = ZoneKey::generate();
    let tld_key = ZoneKey::generate();
    let zone_key = ZoneKey::generate();

    let (port, mut sockets) = bind_levels(&[ROOT_IP, TLD_IP, ZONE_IP]).await;
    let zone_sock = sockets.pop().expect("zone socket");
    let tld_sock = sockets.pop().expect("tld socket");
    let root_sock = sockets.pop().expect("root socket");

    let root_zone =
        Zone::new(".", Arc::clone(&root_key)).with_signed_child("test.", TLD_IP, &tld_key);

    let tld_zone = Zone::new("test.", Arc::clone(&tld_key))
        .with_signed_child("example.test.", ZONE_IP, &zone_key)
        .with_nsec(NsecSpec::new(
            "test.",
            "example.test.",
            &[RecordType::SOA, RecordType::NS, RecordType::RRSIG],
        ))
        .with_tamper(attack.tld);

    let leaf_zone = Zone::new("example.test.", Arc::clone(&zone_key))
        .with_a("www.example.test.", WWW_IP)
        .with_txt("txtonly.example.test.", "hello")
        .with_nsec(NsecSpec::new(
            "example.test.",
            "txtonly.example.test.",
            &[RecordType::SOA, RecordType::NS, RecordType::RRSIG],
        ))
        .with_nsec(NsecSpec::new(
            "txtonly.example.test.",
            "www.example.test.",
            &[RecordType::TXT, RecordType::RRSIG, RecordType::NSEC],
        ))
        .with_nsec(NsecSpec::new(
            "www.example.test.",
            "example.test.",
            &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
        ))
        .with_tamper(attack.zone);

    let keep = vec![
        serve(root_sock, root_zone),
        serve(tld_sock, tld_zone),
        serve(zone_sock, leaf_zone),
    ];

    let anchors = Anchors::from_dnskey_strings(&[root_key.anchor_string()]).expect("anchor parses");
    let resolver = IterativeResolver::new(vec![ROOT_IP.into()])
        .with_port(port)
        .with_timeout(Duration::from_millis(1500))
        .with_validation(anchors);

    Harness {
        resolver,
        _keep: keep,
    }
}

async fn resolve(
    harness: &Harness,
    qname: &str,
    qtype: RecordType,
) -> rolodex_dns::resolver::Resolution {
    harness
        .resolver
        .resolve(&name(qname), qtype, DNSClass::IN)
        .await
        .expect("resolution completes")
}

fn describe(verdict: &Verdict) -> String {
    match verdict.reason() {
        Some(reason) => format!("{} ({reason})", verdict.label()),
        None => verdict.label().to_string(),
    }
}

/// Asserts the answer was withheld, and says what came back if it was not.
fn assert_withheld(res: &rolodex_dns::resolver::Resolution, what: &str) {
    assert!(
        res.verdict.withholds_answer(),
        "{what}: expected the answer to be withheld, got {}",
        describe(&res.verdict)
    );
    assert!(
        res.answers.is_empty(),
        "{what}: a withheld answer must carry no records, got {} of them",
        res.answers.len()
    );
}

// ---------------------------------------------------------------------------
// CRITICAL: the downgrade attacks
// ---------------------------------------------------------------------------

/// The fundamental attack. The zone is signed and its parent published a DS, so
/// the resolver *knows* the zone claims to be signed. An adversary deletes the
/// RRSIGs from the response.
///
/// "No signature present" must never mean "insecure". If it did, DNSSEC would be
/// an opt-out an attacker chooses, and every test in the validation suite would
/// still pass.
#[tokio::test]
async fn stripping_every_signature_is_not_an_unsigned_zone() {
    let harness = harness(Attack {
        zone: Tamper::StripSignatures,
        ..Attack::default()
    })
    .await;
    let res = resolve(&harness, "www.example.test.", RecordType::A).await;
    assert_withheld(&res, "an unsigned answer from a DS-backed zone");
    assert_ne!(
        res.verdict,
        Verdict::Insecure,
        "a stripped signature is bogus, not insecure — treating it as insecure is the downgrade"
    );
}

/// The delegation-level downgrade. The TLD really does have a DS for
/// `example.test.`; the adversary deletes it and supplies no NSEC in its place.
///
/// Accepting this would mean any signed zone can be made unsigned by an attacker
/// who controls one packet, after which its records can be forged at will.
#[tokio::test]
async fn a_delegation_with_no_ds_and_no_proof_is_refused() {
    let harness = harness(Attack {
        tld: Tamper::OmitNoDsProof,
        ..Attack::default()
    })
    .await;
    let res = resolve(&harness, "www.example.test.", RecordType::A).await;
    assert_withheld(
        &res,
        "a delegation with neither a DS nor a proof of its absence",
    );
    assert_ne!(
        res.verdict,
        Verdict::Insecure,
        "an unproven missing DS must not be read as a proven insecure delegation"
    );
}

// ---------------------------------------------------------------------------
// Signature validity
// ---------------------------------------------------------------------------

/// A captured response replayed after its signatures expired. The window is the
/// only thing that makes a signature stop being usable, so a validator that
/// skips it has no replay protection whatsoever.
#[tokio::test]
async fn an_expired_signature_is_refused() {
    let harness = harness(Attack {
        zone: Tamper::ExpiredSignatures,
        ..Attack::default()
    })
    .await;
    let res = resolve(&harness, "www.example.test.", RecordType::A).await;
    assert_withheld(&res, "an expired signature");
}

/// The other end of the window. Easy to omit, because a signature that is not
/// valid *yet* still verifies cryptographically — which is exactly why the check
/// has to be explicit.
#[tokio::test]
async fn a_premature_signature_is_refused() {
    let harness = harness(Attack {
        zone: Tamper::PrematureSignatures,
        ..Attack::default()
    })
    .await;
    let res = resolve(&harness, "www.example.test.", RecordType::A).await;
    assert_withheld(&res, "a signature that is not valid yet");
}

// ---------------------------------------------------------------------------
// Key and signer binding
// ---------------------------------------------------------------------------

/// Signed with a perfectly good Ed25519 key that the zone's DNSKEY RRset does
/// not publish and the parent's DS does not cover.
///
/// If any key will do, then the DS chain is decorative and anyone can sign
/// anything.
#[tokio::test]
async fn a_signature_from_an_unpublished_key_is_refused() {
    let harness = harness(Attack {
        zone: Tamper::SignWithForeignKey,
        ..Attack::default()
    })
    .await;
    let res = resolve(&harness, "www.example.test.", RecordType::A).await;
    assert_withheld(&res, "a signature from a key outside the DNSKEY RRset");
}

/// The RRSIG names a signer in a different zone. The signature itself is
/// internally consistent; what makes it worthless is that the signer is not the
/// zone the data lives in, so no amount of key material vouches for it.
#[tokio::test]
async fn a_foreign_signer_name_is_refused() {
    let harness = harness(Attack {
        zone: Tamper::ForeignSignerName(name("attacker.test.")),
        ..Attack::default()
    })
    .await;
    let res = resolve(&harness, "www.example.test.", RecordType::A).await;
    assert_withheld(&res, "an RRSIG naming a signer outside the zone");
}

/// Every signature in the packet is genuine; the A record was rewritten after
/// they were computed. This is the case a validator that checks "is an RRSIG
/// present" rather than "does it verify over these bytes" waves through.
#[tokio::test]
async fn data_mutated_after_signing_is_refused() {
    let harness = harness(Attack {
        zone: Tamper::MutateAfterSigning,
        ..Attack::default()
    })
    .await;
    let res = resolve(&harness, "www.example.test.", RecordType::A).await;
    assert_withheld(&res, "records altered after they were signed");
    assert!(
        !res.answers
            .iter()
            .any(|r| matches!(r.data(), hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(ip)) if *ip == Ipv4Addr::new(203, 0, 113, 66))),
        "the substituted address must never reach the caller"
    );
}

// ---------------------------------------------------------------------------
// Denial of existence
// ---------------------------------------------------------------------------

/// An NXDOMAIN from a signed zone with a signed SOA but no NSEC. Without a proof
/// there is nothing to distinguish it from an attacker deleting a name: a
/// targeted, silent denial of service that looks exactly like the name not
/// existing.
#[tokio::test]
async fn an_unproven_negative_is_refused() {
    let harness = harness(Attack {
        zone: Tamper::OmitDenialProof,
        ..Attack::default()
    })
    .await;
    let res = resolve(&harness, "nothing.example.test.", RecordType::A).await;
    assert!(
        res.verdict.withholds_answer(),
        "an NXDOMAIN from a signed zone with no NSEC must not be believed, got {}",
        describe(&res.verdict)
    );
}

// ---------------------------------------------------------------------------
// Nothing bogus reaches the caller
// ---------------------------------------------------------------------------

/// The verdict and the records must agree. A `Bogus` verdict alongside a
/// populated answer section is a bug waiting to be served by the next caller who
/// forgets to check the verdict — and the response cache is one such caller.
#[tokio::test]
async fn bogus_data_is_never_returned_as_an_answer() {
    for attack in [
        Tamper::StripSignatures,
        Tamper::ExpiredSignatures,
        Tamper::SignWithForeignKey,
        Tamper::MutateAfterSigning,
    ] {
        let harness = harness(Attack {
            zone: attack.clone(),
            ..Attack::default()
        })
        .await;
        let res = resolve(&harness, "www.example.test.", RecordType::A).await;
        assert!(
            res.answers.is_empty(),
            "{attack:?}: a withheld answer must carry no records"
        );
        assert_eq!(
            res.rcode,
            ResponseCode::ServFail,
            "{attack:?}: a failed validation must surface as SERVFAIL"
        );
    }
}

// ---------------------------------------------------------------------------
// The trust anchor itself
// ---------------------------------------------------------------------------

/// Anchoring to the wrong key must fail closed. A resolver that falls back to
/// "unvalidated" when its anchor does not match the root's DNSKEY set would
/// report success while being anchored to nothing.
#[tokio::test]
async fn an_anchor_that_matches_no_root_key_fails_closed() {
    let harness = harness(Attack::default()).await;
    let wrong = ZoneKey::generate();
    let resolver = IterativeResolver::new(vec![ROOT_IP.into()])
        .with_port(harness.resolver.port())
        .with_timeout(Duration::from_millis(1500))
        .with_validation(
            Anchors::from_dnskey_strings(&[wrong.anchor_string()]).expect("anchor parses"),
        );

    let result = resolver
        .resolve(&name("www.example.test."), RecordType::A, DNSClass::IN)
        .await;

    match result {
        Err(e) => {
            let text = format!("{e:#}");
            assert!(
                text.contains("DNSSEC") || text.contains("trust anchor") || text.contains("root"),
                "the failure must name the anchor problem, got: {text}"
            );
        }
        Ok(res) => assert!(
            res.verdict.withholds_answer(),
            "an unanchorable root must not yield a usable answer, got {}",
            describe(&res.verdict)
        ),
    }
}

/// A trust anchor that cannot be parsed is a startup failure, not a silent
/// fallback to the IANA keys — an operator who configured a private root and
/// quietly got the real one would have a resolver anchored to the wrong
/// namespace while reporting that validation is on.
#[test]
fn malformed_trust_anchors_are_rejected() {
    // A real, well-formed anchor, edited per case so each rejection is caused by
    // exactly the field under test rather than by an incidentally broken string.
    let good = ZoneKey::generate().anchor_string();
    let key_b64 = good
        .split_whitespace()
        .nth(3)
        .expect("key field")
        .to_string();

    let cases: [(String, &str); 7] = [
        (String::new(), "empty"),
        ("257 3".to_string(), "too few fields"),
        (
            "257 3 15 !!!not base64!!!".to_string(),
            "undecodable key material",
        ),
        (
            format!("257 4 15 {key_b64}"),
            "protocol must be 3 (RFC 4034 §2.1.2)",
        ),
        // Flags 0 and 1 both leave the zone-key bit (0x0100) clear. RFC 4034
        // §2.1.1: such a DNSKEY MUST NOT be used to verify RRSIGs, so anchoring
        // to one is anchoring to a key that can never validate anything.
        (format!("0 3 15 {key_b64}"), "no zone-key flag"),
        (format!("1 3 15 {key_b64}"), "SEP set but no zone-key flag"),
        // Right shape, wrong size: Ed25519 keys are 32 bytes. An anchor of the
        // wrong length matches no DNSKEY, so every signed zone would fail with
        // nothing pointing at the anchor as the cause.
        ("257 3 15 SGVsbG8=".to_string(), "key too short for Ed25519"),
    ];

    for (bad, why) in cases {
        assert!(
            Anchors::from_dnskey_strings(&[&bad]).is_err(),
            "the malformed anchor {bad:?} must be rejected ({why})"
        );
    }
}

/// The rejection cases above have to be paired with acceptance, or they would
/// all pass against a parser that rejects everything.
///
/// Both flag spellings are pinned: 257 is a KSK (zone key + secure entry point)
/// and is what a published anchor normally looks like, while 256 is a ZSK —
/// zone key, SEP clear. **256 has the zone-key flag set**, so it is a legitimate
/// anchor and must not be confused with the flag-less values above. Reading 256
/// as "no zone-key flag" is the mistake this test exists to prevent.
#[test]
fn a_well_formed_trust_anchor_is_accepted() {
    let key = ZoneKey::generate();
    let ksk = key.anchor_string();
    let anchors = Anchors::from_dnskey_strings(&[&ksk]).expect("a KSK anchor parses");
    assert_eq!(anchors.len(), 1);

    let zsk = ksk.replacen("257 ", "256 ", 1);
    assert_ne!(zsk, ksk, "the KSK spelling should have started with 257");
    let anchors = Anchors::from_dnskey_strings(&[&zsk]).expect("a ZSK anchor parses");
    assert_eq!(
        anchors.len(),
        1,
        "flags 256 has the zone-key bit set and is a valid anchor"
    );
}
