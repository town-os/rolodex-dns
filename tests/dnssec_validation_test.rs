//! DNSSEC validation of upstream answers, end to end against a signed
//! hierarchy.
//!
//! This file covers the paths that must keep *working*: a signed answer that
//! validates, an unsigned zone that resolves anyway, and negative answers that
//! are proven rather than merely asserted. Its counterpart
//! `tests/security_dnssec_test.rs` covers the paths that must *fail*.
//!
//! Both matter equally and for the same reason: a validator that rejects
//! everything passes every attack test, and a validator that accepts everything
//! passes every happy-path test. Only the pair together says anything.
//!
//! The hierarchy is `.` -> `test.` -> `example.test.` / `unsigned.test.`, each
//! zone signing its own data with its own Ed25519 key, with the resolver
//! anchored to the mock root's key rather than to IANA's — see
//! [`signed_hierarchy`].

mod signed_hierarchy;

use hickory_proto::rr::{DNSClass, RecordType};
use rolodex_dns::dnssec_validate::{Anchors, Verdict};
use rolodex_dns::resolver::IterativeResolver;
use signed_hierarchy::{NsecSpec, SignedNs, Tamper, Zone, ZoneKey, bind_levels, name, serve};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 41);
const TLD_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 42);
const ZONE_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 43);
const UNSIGNED_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 44);

/// The answer address `www.example.test.` resolves to when everything is honest.
pub const WWW_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

/// A standing hierarchy, kept alive for the duration of a test.
pub struct Harness {
    pub resolver: IterativeResolver,
    pub root: SignedNs,
    pub tld: SignedNs,
    pub zone: SignedNs,
    pub unsigned: SignedNs,
}

/// Which zone a test wants to misbehave, and how.
#[derive(Default, Clone)]
pub struct Tampering {
    pub root: Tamper,
    pub tld: Tamper,
    pub zone: Tamper,
    pub unsigned: Tamper,
}

/// Stands up the signed hierarchy and a resolver anchored to the mock root.
///
/// The resolver is anchored to *this* root's key and to nothing else. Adding the
/// IANA anchors alongside would mean the real root could vouch for names in a
/// private namespace, which is why `Anchors::from_dnskey_strings` replaces
/// rather than extends.
pub async fn harness(tampering: Tampering) -> Harness {
    let root_key = ZoneKey::generate();
    let tld_key = ZoneKey::generate();
    let zone_key = ZoneKey::generate();

    let (port, mut sockets) = bind_levels(&[ROOT_IP, TLD_IP, ZONE_IP, UNSIGNED_IP]).await;
    let unsigned_sock = sockets.pop().expect("unsigned socket");
    let zone_sock = sockets.pop().expect("zone socket");
    let tld_sock = sockets.pop().expect("tld socket");
    let root_sock = sockets.pop().expect("root socket");

    // `.` delegates `test.` and publishes its DS.
    let root_zone = Zone::new(".", Arc::clone(&root_key))
        .with_signed_child("test.", TLD_IP, &tld_key)
        .with_tamper(tampering.root);

    // `test.` delegates a signed child and an unsigned one. The unsigned
    // delegation carries the NSEC that proves it has no DS — the record that
    // makes "unsigned" a fact rather than an assumption.
    let tld_zone = Zone::new("test.", Arc::clone(&tld_key))
        .with_signed_child("example.test.", ZONE_IP, &zone_key)
        .with_unsigned_child("unsigned.test.", UNSIGNED_IP, "zzz.test.")
        // Covers everything sorting between the apex and `example.test.`, which
        // is what a negative answer inside `test.` needs.
        .with_nsec(NsecSpec::new(
            "test.",
            "example.test.",
            &[RecordType::SOA, RecordType::NS, RecordType::RRSIG],
        ))
        .with_tamper(tampering.tld);

    // The signed leaf zone.
    let leaf_zone = Zone::new("example.test.", Arc::clone(&zone_key))
        .with_a("www.example.test.", WWW_IP)
        .with_txt("txtonly.example.test.", "hello")
        // Denies everything from the apex up to `www`, and the wildcard with it.
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
        .with_tamper(tampering.zone);

    // The unsigned zone signs nothing at all: `ZoneKey` exists only because the
    // struct requires one, and `StripSignatures` guarantees none reaches the
    // wire.
    let unsigned_zone = Zone::new("unsigned.test.", ZoneKey::generate())
        .with_a("host.unsigned.test.", Ipv4Addr::new(192, 0, 2, 20))
        .with_tamper(if tampering.unsigned == Tamper::None {
            Tamper::StripSignatures
        } else {
            tampering.unsigned
        });

    let root = serve(root_sock, root_zone);
    let tld = serve(tld_sock, tld_zone);
    let zone = serve(zone_sock, leaf_zone);
    let unsigned = serve(unsigned_sock, unsigned_zone);

    let anchors = Anchors::from_dnskey_strings(&[root_key.anchor_string()]).expect("anchor parses");
    let resolver = IterativeResolver::new(vec![ROOT_IP.into()])
        .with_port(port)
        .with_timeout(Duration::from_millis(1500))
        .with_validation(anchors);

    Harness {
        resolver,
        root,
        tld,
        zone,
        unsigned,
    }
}

/// Resolves a name through the harness.
pub async fn resolve(
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

/// Renders a verdict for an assertion message, reason included — a bare
/// `Bogus` in a failure line says nothing about *why*.
pub fn describe(verdict: &Verdict) -> String {
    match verdict.reason() {
        Some(reason) => format!("{} ({reason})", verdict.label()),
        None => verdict.label().to_string(),
    }
}

// ---------------------------------------------------------------------------
// The chain must work
// ---------------------------------------------------------------------------

/// The whole feature in one test: root -> TLD -> zone, every link anchored, and
/// the answer comes back Secure with the right address.
#[tokio::test]
async fn a_fully_signed_chain_validates_secure() {
    let harness = harness(Tampering::default()).await;
    let res = resolve(&harness, "www.example.test.", RecordType::A).await;

    assert_eq!(
        res.verdict,
        Verdict::Secure,
        "a fully signed chain must validate: {}",
        describe(&res.verdict)
    );
    let addrs: Vec<Ipv4Addr> = res
        .answers
        .iter()
        .filter_map(|r| match r.data() {
            hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(ip)) => Some(*ip),
            _ => None,
        })
        .collect();
    assert_eq!(
        addrs,
        vec![WWW_IP],
        "the validated answer must still be the answer"
    );
}

/// The RRSIGs must survive to the client: a validating stub downstream has to be
/// able to check for itself, and stripping them here would make that impossible
/// while looking perfectly fine to a non-validating client.
#[tokio::test]
async fn a_validated_answer_still_carries_its_signatures() {
    let harness = harness(Tampering::default()).await;
    let res = resolve(&harness, "www.example.test.", RecordType::A).await;

    assert!(
        res.answers
            .iter()
            .any(|r| r.record_type() == RecordType::RRSIG),
        "the answer section must retain the RRSIG that validated it"
    );
}

/// A delegation with no DS, proven by NSEC, is *Insecure* — not Secure and not
/// Bogus. This is most of the internet, and a validator that cannot express it
/// either lies about unsigned data or refuses to resolve it.
#[tokio::test]
async fn a_proven_unsigned_delegation_resolves_insecure() {
    let harness = harness(Tampering::default()).await;
    let res = resolve(&harness, "host.unsigned.test.", RecordType::A).await;

    assert_eq!(
        res.verdict,
        Verdict::Insecure,
        "an unsigned zone below a proven insecure delegation must resolve: {}",
        describe(&res.verdict)
    );
    assert!(
        !res.answers.is_empty(),
        "an insecure answer is still an answer and must be served"
    );
}

/// A signed NXDOMAIN is only Secure when the NSEC records actually prove it —
/// both that the name is absent and that no wildcard could have answered.
#[tokio::test]
async fn a_signed_nxdomain_is_proven() {
    let harness = harness(Tampering::default()).await;
    let res = resolve(&harness, "nothing.example.test.", RecordType::A).await;

    assert_eq!(
        res.rcode,
        hickory_proto::op::ResponseCode::NXDomain,
        "the name does not exist"
    );
    assert_eq!(
        res.verdict,
        Verdict::Secure,
        "an NSEC-proven NXDOMAIN must validate: {}",
        describe(&res.verdict)
    );
}

/// NODATA: the name exists with another type. The NSEC at the name must deny the
/// queried type without denying the name itself.
#[tokio::test]
async fn a_signed_nodata_is_proven() {
    let harness = harness(Tampering::default()).await;
    let res = resolve(&harness, "txtonly.example.test.", RecordType::A).await;

    assert_eq!(
        res.rcode,
        hickory_proto::op::ResponseCode::NoError,
        "the name exists, the type does not"
    );
    assert!(res.answers.is_empty(), "NODATA carries no answers");
    assert_eq!(
        res.verdict,
        Verdict::Secure,
        "an NSEC-proven NODATA must validate: {}",
        describe(&res.verdict)
    );
}

// ---------------------------------------------------------------------------
// The chain must not cost more than it has to
// ---------------------------------------------------------------------------

/// The validated key set is cached, so a second name in the same zone does not
/// re-walk the chain. Without this, turning validation on would multiply every
/// zone's traffic by the depth of its delegation — and put that load on the root
/// servers, which is exactly what the delegation cache exists to prevent one
/// layer down.
#[tokio::test]
async fn a_second_name_in_a_validated_zone_does_not_re_walk_the_chain() {
    let harness = harness(Tampering::default()).await;

    let first = resolve(&harness, "www.example.test.", RecordType::A).await;
    assert_eq!(
        first.verdict,
        Verdict::Secure,
        "{}",
        describe(&first.verdict)
    );
    let root_after_first = harness.root.hits();
    assert!(
        root_after_first > 0,
        "the first lookup must have started at the root"
    );

    let second = resolve(&harness, "txtonly.example.test.", RecordType::TXT).await;
    assert_eq!(
        second.verdict,
        Verdict::Secure,
        "the second lookup must validate too: {}",
        describe(&second.verdict)
    );
    assert_eq!(
        harness.root.hits(),
        root_after_first,
        "a warm zone must not send the root another query"
    );
}

// ---------------------------------------------------------------------------
// Validation switched off
// ---------------------------------------------------------------------------

/// With validation off nothing is checked and nothing is claimed: the verdict is
/// `Insecure`, which is what leaves the AD bit clear. It must specifically not
/// be `Secure` — a resolver that never verified anything must not tell its
/// clients it did.
#[tokio::test]
async fn a_non_validating_resolver_claims_nothing() {
    let harness = harness(Tampering::default()).await;
    let plain = IterativeResolver::new(vec![ROOT_IP.into()])
        .with_port(harness.resolver.port())
        .with_timeout(Duration::from_millis(1500));

    assert!(!plain.validating(), "validation must be off by default");
    let res = plain
        .resolve(&name("www.example.test."), RecordType::A, DNSClass::IN)
        .await
        .expect("resolution completes");
    assert_eq!(
        res.verdict,
        Verdict::Insecure,
        "an unvalidated answer makes no authentication claim"
    );
    assert!(!res.answers.is_empty(), "it is still resolved normally");
}
