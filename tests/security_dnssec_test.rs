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
//! | `a_rejected_roots_answer_does_not_fall_through` | A broken signature is re-asked of an upstream that does not validate, so an attacker turns validation off by breaking one signature. |
//! | `a_rejected_walk_leaves_no_delegation_behind` | The resolver keeps and reuses an NS set from a referral it just refused to verify — and persists it to disk. |
//! | `an_unvalidatable_root_zone_is_refused_not_downgraded` | Breaking root DNSKEY retrieval takes validation out of the path entirely, without ever producing a bogus verdict. |
//! | `unreachable_roots_still_fall_through` | The control for the one above: hard-failing every lookup when the network is down passes it otherwise. |
//! | `a_root_serving_invalid_dnssec_is_omitted` | A hijacked root instance keeps being asked, so an attacker who controls one of thirteen servers gets retried forever. |
//! | `the_omission_expires_and_escalates_on_relapse` | A persistent liar resets its own penalty by waiting, or a one-off outage is punished permanently. |
//! | `blame_outlives_transport_success` | A prompt reply forgives a lie, so the very server we distrust clears its own record by answering a packet. |
//! | `blaming_every_root_does_not_become_a_fallthrough` | Omission empties the candidate set, turning "invalid" into "unreachable" — the exact hole the withholding verdict closes. |
//! | `auto_mode_still_governs_when_every_root_is_blamed` | Blame invents a failure mode of its own instead of deferring to the tier machinery. |
//! | `blame_does_not_reach_other_nameservers` | A zone's own signing error gets its nameservers omitted, turning someone else's mistake into our outage. |
//!
//! A failure in one of these is the finding, not a broken test. Never weaken an
//! assertion to make one pass: every assertion below is the difference between a
//! validating resolver and one that merely performs validation.

mod signed_hierarchy;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType, rdata};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rolodex_dns::db::Database;
use rolodex_dns::dns_cache::DnsCache;
use rolodex_dns::dns_server::{DnsServer, ResolutionMode};
use rolodex_dns::dnssec_validate::{Anchors, Verdict};
use rolodex_dns::rbl::RblChecker;
use rolodex_dns::resolver::IterativeResolver;
use signed_hierarchy::{
    NsecSpec, SignedNs, Tamper, TamperSwitch, Zone, ZoneKey, bind_levels, name, serve,
    serve_switchable,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 51);
const TLD_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 52);
const ZONE_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 53);

/// The multi-root hierarchy, used by the blame tests. Separate addresses so a
/// blame test and an ordinary one can run concurrently.
const R1_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 61);
const R2_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 62);
const R3_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 63);
const MULTI_TLD_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 64);
const MULTI_ZONE_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 65);
/// Bound by nobody: a root that is unreachable rather than dishonest.
const DEAD_ROOT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 66);

const WWW_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
/// What the forwarder answers with. It has to be distinguishable from the
/// roots-tier answer, or "the client got an answer" would not say *whose*.
const FORWARDER_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

/// Auto-mode tier indices (the constants in `dns_server` are private).
const TIER_ROOTS: usize = 0;
const TIER_LOCAL: usize = 2;

/// What the leaf zone (or the TLD) is made to do.
#[derive(Default, Clone)]
struct Attack {
    tld: Tamper,
    zone: Tamper,
}

struct Harness {
    resolver: IterativeResolver,
    /// The leaf zone's server, so a test can assert on what it was asked.
    zone: SignedNs,
    _keep: Vec<SignedNs>,
}

/// The three zones every hierarchy in this file serves: `.` -> `test.` ->
/// `example.test.`, correctly signed, with the requested tampering applied at
/// serialization time.
///
/// Shared with the multi-root hierarchy below so the two cannot drift — a blame
/// test that passed because its NSEC chain was subtly different from the one the
/// rest of the file uses would be proving something other than what it claims.
fn zones(
    root_key: &Arc<ZoneKey>,
    tld_key: &Arc<ZoneKey>,
    zone_key: &Arc<ZoneKey>,
    tld_ip: Ipv4Addr,
    zone_ip: Ipv4Addr,
    attack: &Attack,
) -> (Zone, Zone, Zone) {
    let root_zone =
        Zone::new(".", Arc::clone(root_key)).with_signed_child("test.", tld_ip, tld_key);

    let tld_zone = Zone::new("test.", Arc::clone(tld_key))
        .with_signed_child("example.test.", zone_ip, zone_key)
        .with_nsec(NsecSpec::new(
            "test.",
            "example.test.",
            &[RecordType::SOA, RecordType::NS, RecordType::RRSIG],
        ))
        .with_tamper(attack.tld.clone());

    let leaf_zone = Zone::new("example.test.", Arc::clone(zone_key))
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
        .with_tamper(attack.zone.clone());

    (root_zone, tld_zone, leaf_zone)
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

    let (root_zone, tld_zone, leaf_zone) =
        zones(&root_key, &tld_key, &zone_key, TLD_IP, ZONE_IP, &attack);

    let keep = vec![serve(root_sock, root_zone), serve(tld_sock, tld_zone)];
    let zone = serve(zone_sock, leaf_zone);

    let anchors = Anchors::from_dnskey_strings(&[root_key.anchor_string()]).expect("anchor parses");
    let resolver = IterativeResolver::new(vec![ROOT_IP.into()])
        .with_port(port)
        .with_timeout(Duration::from_millis(1500))
        .with_validation(anchors);

    Harness {
        resolver,
        zone,
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

// ---------------------------------------------------------------------------
// The tier chain: a rejected answer is rejected, not re-asked elsewhere
// ---------------------------------------------------------------------------

/// A plaintext forwarder that answers everything, and counts what it was asked.
///
/// The count is the assertion in every test below. "The client got SERVFAIL" is
/// satisfied just as well by a forwarder that was consulted and happened to
/// fail, which is a completely different property from one that was never
/// consulted at all — and it is the second that the requirement is about.
struct Forwarder {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
}

impl Forwarder {
    fn hits(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

/// Spawns a forwarder that answers every query with [`FORWARDER_IP`].
///
/// It is deliberately *working*: a broken one would make "the forwarder did not
/// answer" indistinguishable from "the forwarder was never asked".
async fn spawn_forwarder() -> Forwarder {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind forwarder");
    let addr = socket.local_addr().expect("forwarder address");
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&queries);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let Ok(query) = Message::from_bytes(&buf[..len]) else {
                continue;
            };
            let mut resp = Message::new();
            resp.set_id(query.id());
            resp.set_message_type(MessageType::Response);
            resp.set_op_code(OpCode::Query);
            resp.set_recursion_desired(query.recursion_desired());
            resp.set_recursion_available(true);
            for q in query.queries() {
                resp.add_query(q.clone());
            }
            if let Some(q) = query.queries().first() {
                resp.add_answer(Record::from_rdata(
                    q.name().clone(),
                    300,
                    RData::A(rdata::A(FORWARDER_IP)),
                ));
            }
            if let Ok(bytes) = resp.to_bytes() {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    });

    Forwarder { addr, queries }
}

/// An `auto`-mode server whose roots tier is `resolver` and whose local
/// forwarder is `forwarder`. The secure and public tiers are empty, so the two
/// tiers under test are the only ones that can answer.
fn auto_server(resolver: IterativeResolver, forwarder: &Forwarder) -> Arc<DnsServer> {
    let db = Database::open_memory().expect("in-memory database");
    let cache = Arc::new(DnsCache::new(db.clone()));
    let rbl = Arc::new(RblChecker::new(false, vec![]));
    let server = Arc::new(DnsServer::new_with_options(
        db,
        rbl,
        vec![forwarder.addr],
        Some(cache),
        None,
        // No qname 0x20, so the mock forwarder can echo the question verbatim.
        false,
    ));
    server.set_resolution_mode(ResolutionMode::Auto);
    server.set_resolver(resolver);
    server.set_secure_upstreams(vec![]);
    server.set_public_fallback(vec![]);
    server
}

/// A client query with RD set, as a stub resolver sends it.
fn client_query(qname: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(0x4242);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(name(qname));
    q.set_query_type(qtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    msg.to_bytes().expect("query encodes")
}

/// Asks `server` over its real request path and parses what came back.
async fn ask(server: &DnsServer, qname: &str, qtype: RecordType) -> Message {
    let bytes = server
        .handle_query(&client_query(qname, qtype))
        .await
        .expect("the server produces a response");
    Message::from_bytes(&bytes).expect("the response parses")
}

/// The A records in a response, so a test can say *whose* answer it got.
fn a_records(msg: &Message) -> Vec<Ipv4Addr> {
    msg.answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::A(rdata::A(ip)) => Some(*ip),
            _ => None,
        })
        .collect()
}

/// A failed validation on the roots tier is a **definitive** answer. Falling
/// through to a forwarder would mean any zone whose signatures do not check out
/// is quietly re-asked of an upstream that does not validate and served anyway —
/// which turns validation into something an attacker switches off by breaking
/// one signature.
#[tokio::test]
async fn a_rejected_roots_answer_does_not_fall_through() {
    let forwarder = spawn_forwarder().await;
    let harness = harness(Attack {
        zone: Tamper::StripSignatures,
        ..Attack::default()
    })
    .await;
    let server = auto_server(harness.resolver.clone(), &forwarder);

    let response = ask(&server, "www.example.test.", RecordType::A).await;
    assert_eq!(
        response.response_code(),
        ResponseCode::ServFail,
        "a bogus roots answer must reach the client as SERVFAIL"
    );
    assert!(
        response.answers().is_empty(),
        "and it must carry no records"
    );
    assert_eq!(
        forwarder.hits(),
        0,
        "the forwarder must never be consulted for a rejected answer"
    );
}

/// The control for the test above. Without it, a tier chain that is simply
/// broken — a roots tier that answers nothing and a forwarder that is never
/// wired up — passes.
#[tokio::test]
async fn an_accepted_roots_answer_is_served_from_the_roots() {
    let forwarder = spawn_forwarder().await;
    let harness = harness(Attack::default()).await;
    let server = auto_server(harness.resolver.clone(), &forwarder);

    let response = ask(&server, "www.example.test.", RecordType::A).await;
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(
        a_records(&response),
        vec![WWW_IP],
        "the untampered name must be answered from the roots, not the forwarder"
    );
    assert_eq!(
        forwarder.hits(),
        0,
        "a working roots tier must not consult the forwarder at all"
    );
}

/// State learned during a walk that ends Bogus must not survive the rejection.
///
/// The delegation cache is written as the referral is followed, and the
/// delegation cache is persisted to disk. A referral whose DS/NSEC proof does
/// not verify must therefore leave nothing behind: no bogus data reaches a
/// client either way, but keeping an NS set we just refused to verify means
/// reusing it for every later name in that zone.
#[tokio::test]
async fn a_rejected_walk_leaves_no_delegation_behind() {
    let harness = harness(Attack {
        tld: Tamper::OmitNoDsProof,
        ..Attack::default()
    })
    .await;
    let res = resolve(&harness, "www.example.test.", RecordType::A).await;
    assert_withheld(&res, "a delegation with neither a DS nor a proof");

    // Read it back the way the resolver does: `best_match` is what decides
    // where the next lookup starts.
    let entry = harness
        .resolver
        .delegations()
        .best_match(&name("www.example.test."));
    let (zone, _) = entry.expect(
        "the delegation that *did* verify must still be cached — a resolver that \
         caches nothing at all would pass the assertion below for the wrong reason",
    );
    assert_eq!(
        zone, "test.",
        "the deepest cached delegation must be the last one that verified"
    );
}

/// And the control the assertion above leans on: when the same referral *does*
/// verify, it is cached. Otherwise "no entry for example.test." proves only that
/// the resolver never caches delegations.
#[tokio::test]
async fn an_accepted_walk_caches_its_delegation() {
    let harness = harness(Attack::default()).await;
    let res = resolve(&harness, "www.example.test.", RecordType::A).await;
    assert_eq!(res.verdict, Verdict::Secure, "{}", describe(&res.verdict));

    let (zone, servers) = harness
        .resolver
        .delegations()
        .best_match(&name("www.example.test."))
        .expect("a verified delegation is cached");
    assert_eq!(zone, "example.test.");
    assert!(
        servers.contains(&IpAddr::from(ZONE_IP)),
        "the cached delegation must name the zone's servers, got {servers:?}"
    );
}

// ---------------------------------------------------------------------------
// A root zone that does not validate is refused, not downgraded
// ---------------------------------------------------------------------------

/// The asymmetry this closes: a *domain* that fails validation SERVFAILs, but
/// the root zone's own keys failing to validate used to surface as a plain
/// error, which the tier chain reads as "the roots are unreachable" and answers
/// from the encrypted upstream instead. An on-path attacker who can reliably
/// break root DNSKEY retrieval could therefore take validation out of the path
/// without ever producing a bogus verdict.
#[tokio::test]
async fn an_unvalidatable_root_zone_is_refused_not_downgraded() {
    let forwarder = spawn_forwarder().await;
    let harness = harness(Attack::default()).await;
    let wrong = ZoneKey::generate();
    let resolver = IterativeResolver::new(vec![ROOT_IP.into()])
        .with_port(harness.resolver.port())
        .with_timeout(Duration::from_millis(1500))
        .with_validation(
            Anchors::from_dnskey_strings(&[wrong.anchor_string()]).expect("anchor parses"),
        );
    let server = auto_server(resolver, &forwarder);

    let response = ask(&server, "www.example.test.", RecordType::A).await;
    assert_eq!(
        response.response_code(),
        ResponseCode::ServFail,
        "a root zone that cannot be anchored must SERVFAIL"
    );
    assert_eq!(
        forwarder.hits(),
        0,
        "and must not be quietly re-asked of an upstream that does not validate"
    );
}

/// Unreachable is not invalid. A roots tier that cannot be *reached* must still
/// fall through, or an unplugged network hard-fails every lookup — and without
/// this control, hard-failing everything passes the test above.
#[tokio::test]
async fn unreachable_roots_still_fall_through() {
    let forwarder = spawn_forwarder().await;
    let harness = harness(Attack::default()).await;
    // Same port, an address nothing is listening on: a transport failure, with
    // the trust anchor perfectly correct.
    let resolver = harness
        .resolver
        .with_root_hints(vec![DEAD_ROOT_IP.into()])
        .with_timeout(Duration::from_millis(200));
    let server = auto_server(resolver, &forwarder);

    let response = ask(&server, "www.example.test.", RecordType::A).await;
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(
        a_records(&response),
        vec![FORWARDER_IP],
        "unreachable roots must fall through to the forwarder"
    );
    assert!(
        forwarder.hits() > 0,
        "the forwarder must actually have been consulted"
    );
}

// ---------------------------------------------------------------------------
// Blame: a single root server that serves invalid DNSSEC
// ---------------------------------------------------------------------------

/// One mock root, with the handles a blame test needs.
struct Root {
    ip: Ipv4Addr,
    /// `None` while the server is bound but not answering.
    ns: Option<SignedNs>,
    switch: Option<TamperSwitch>,
    pending: Option<(UdpSocket, Zone)>,
}

impl Root {
    /// Queries this root has actually received. Zero while it is silent — which
    /// is the honest reading: nothing is there to count them.
    fn hits(&self) -> usize {
        self.ns.as_ref().map(SignedNs::hits).unwrap_or(0)
    }

    /// Starts a root that was bound but silent, so a test can turn a timeout
    /// into a recovery without changing the server's address.
    fn start(&mut self) {
        if let Some((socket, zone)) = self.pending.take() {
            let (ns, switch) = serve_switchable(socket, zone);
            self.ns = Some(ns);
            self.switch = Some(switch);
        }
    }

    /// Changes what this root does to its responses from the next query on.
    fn behave(&self, tamper: Tamper) {
        if let Some(switch) = &self.switch {
            switch.set(tamper);
        }
    }
}

/// What a mock root does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    /// Serves the root zone correctly.
    Honest,
    /// Serves it with every signature stripped: one hijacked or broken instance
    /// among healthy peers. Its DNSKEY RRset cannot be anchored, which is the
    /// one thing a root server tells us that we can check without asking anyone
    /// else — and therefore the only claim blame may rest on.
    Liar,
    /// Bound, but not answering until the test starts it. A transport failure,
    /// which must be treated completely differently from a lie.
    Silent,
}

/// A hierarchy with several root servers, all serving the *same* root zone with
/// the same key, as the thirteen real ones do.
struct Roots {
    /// Anchored to the mock root key, pointed at every root.
    resolver: IterativeResolver,
    roots: Vec<Root>,
    /// The mock root's trust anchor, for a test that has to build its own
    /// resolver against this hierarchy.
    anchor: String,
    port: u16,
    _keep: Vec<SignedNs>,
}

impl Roots {
    fn ips(&self) -> Vec<IpAddr> {
        self.roots.iter().map(|r| IpAddr::from(r.ip)).collect()
    }

    /// A resolver pointed at exactly these roots, sharing this one's health —
    /// and therefore its blame, which is the point.
    fn pointed_at(&self, ips: Vec<IpAddr>) -> IterativeResolver {
        self.resolver.with_root_hints(ips)
    }
}

async fn root_harness(behaviours: &[Behaviour]) -> Roots {
    let root_ips = [R1_IP, R2_IP, R3_IP];
    assert!(
        behaviours.len() <= root_ips.len(),
        "the harness has {} root addresses",
        root_ips.len()
    );

    let root_key = ZoneKey::generate();
    let tld_key = ZoneKey::generate();
    let zone_key = ZoneKey::generate();

    let mut ips: Vec<Ipv4Addr> = root_ips[..behaviours.len()].to_vec();
    ips.push(MULTI_TLD_IP);
    ips.push(MULTI_ZONE_IP);
    let (port, mut sockets) = bind_levels(&ips).await;
    let zone_sock = sockets.pop().expect("zone socket");
    let tld_sock = sockets.pop().expect("tld socket");

    let (root_zone, tld_zone, leaf_zone) = zones(
        &root_key,
        &tld_key,
        &zone_key,
        MULTI_TLD_IP,
        MULTI_ZONE_IP,
        &Attack::default(),
    );

    let mut roots = Vec::new();
    for (i, behaviour) in behaviours.iter().enumerate() {
        let socket = sockets.remove(0);
        let zone = match behaviour {
            Behaviour::Liar => root_zone.clone().with_tamper(Tamper::StripSignatures),
            _ => root_zone.clone(),
        };
        let root = if *behaviour == Behaviour::Silent {
            Root {
                ip: root_ips[i],
                ns: None,
                switch: None,
                pending: Some((socket, zone)),
            }
        } else {
            let (ns, switch) = serve_switchable(socket, zone);
            Root {
                ip: root_ips[i],
                ns: Some(ns),
                switch: Some(switch),
                pending: None,
            }
        };
        roots.push(root);
    }

    let keep = vec![serve(tld_sock, tld_zone), serve(zone_sock, leaf_zone)];

    let anchor = root_key.anchor_string();
    let anchors = Anchors::from_dnskey_strings(&[&anchor]).expect("anchor parses");
    let hints: Vec<IpAddr> = roots.iter().map(|r| IpAddr::from(r.ip)).collect();
    let resolver = IterativeResolver::new(hints)
        .with_port(port)
        .with_timeout(Duration::from_millis(300))
        .with_validation(anchors);

    Roots {
        resolver,
        roots,
        anchor,
        port,
        _keep: keep,
    }
}

/// Forces the next resolution to re-establish the root's keys.
///
/// Without it the key cache answers from the last successful walk, no root is
/// queried at all, and a test asserting on which roots were contacted would be
/// asserting on nothing.
fn force_root_lookup(resolver: &IterativeResolver) {
    resolver.keys().flush();
}

/// Resolves and returns the verdict, for the blame tests where the answer itself
/// is not the point.
async fn verdict_of(resolver: &IterativeResolver, qname: &str) -> Verdict {
    resolver
        .resolve(&name(qname), RecordType::A, DNSClass::IN)
        .await
        .expect("resolution completes")
        .verdict
}

/// A root server that answers with DNSSEC that does not validate against our
/// anchor is *removed from the usable set* — not merely demoted. Nothing else
/// penalizes a server for bad cryptography, so without this an attacker who
/// controls one of thirteen root instances gets retried forever.
#[tokio::test]
async fn a_root_serving_invalid_dnssec_is_omitted() {
    let h = root_harness(&[Behaviour::Liar, Behaviour::Honest, Behaviour::Honest]).await;

    // Point the resolver at the liar alone, so the invalid answer is attributed
    // to it and to nobody else. (With one root the omission filter is inert by
    // design — see the "never omit the last root" test — but blame is still
    // recorded, which is what the rest of this test uses.)
    let solo = h.pointed_at(vec![IpAddr::from(R1_IP)]);
    let verdict = verdict_of(&solo, "www.example.test.").await;
    assert!(
        verdict.withholds_answer(),
        "an unanchorable root DNSKEY must withhold, got {}",
        describe(&verdict)
    );
    assert!(h.roots[0].hits() > 0, "the liar must have been asked");

    // The same health state, now with the honest peers in the set:
    // `with_root_hints` keeps the health map, which is where blame lives.
    let full = h.pointed_at(h.ips());
    force_root_lookup(&full);
    let before = h.roots[0].hits();
    let verdict = verdict_of(&full, "www.example.test.").await;
    assert_eq!(
        verdict,
        Verdict::Secure,
        "the honest roots must answer: {}",
        describe(&verdict)
    );
    assert_eq!(
        h.roots[0].hits(),
        before,
        "a blamed root must not be contacted at all, at any priority"
    );
    assert!(
        h.roots[1].hits() + h.roots[2].hits() > 0,
        "control: the other roots must still be queried — omitting everything \
         would satisfy the assertion above"
    );
    assert_eq!(
        full.blamed_root_count(),
        1,
        "exactly the one server that lied is omitted"
    );
}

/// The penalty expires on its own, and escalates when the same root lies again;
/// growth stops at the cap. Driven through the builder override rather than by
/// sitting out a production backoff.
#[tokio::test]
async fn the_omission_expires_and_escalates_on_relapse() {
    const BASE: Duration = Duration::from_millis(300);
    const CAP: Duration = Duration::from_millis(700);

    let h = root_harness(&[Behaviour::Liar, Behaviour::Honest]).await;
    let r = h
        .pointed_at(vec![IpAddr::from(R1_IP)])
        .with_blame_backoff(BASE, CAP);

    // First offence: the base penalty.
    assert!(verdict_of(&r, "a.example.test.").await.withholds_answer());
    assert!(r.blamed_root(R1_IP.into()), "one lie is enough to omit it");
    tokio::time::sleep(BASE + Duration::from_millis(150)).await;
    assert!(
        !r.blamed_root(R1_IP.into()),
        "the penalty must expire with no operator action and no separate probe"
    );

    // Relapse. It is consulted again on its own, lies again, and the next
    // omission is longer: time alone never forgives.
    let before = h.roots[0].hits();
    force_root_lookup(&r);
    assert!(verdict_of(&r, "b.example.test.").await.withholds_answer());
    assert!(
        h.roots[0].hits() > before,
        "a root whose penalty is up is queried again without intervention"
    );
    assert!(r.blamed_root(R1_IP.into()));
    tokio::time::sleep(BASE + Duration::from_millis(150)).await;
    assert!(
        r.blamed_root(R1_IP.into()),
        "the second penalty must be longer than the first"
    );
    tokio::time::sleep(BASE).await;
    assert!(!r.blamed_root(R1_IP.into()), "but still bounded");

    // Third offence: 4x the base is past the cap, so the cap is what it gets.
    force_root_lookup(&r);
    assert!(verdict_of(&r, "c.example.test.").await.withholds_answer());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        r.blamed_root(R1_IP.into()),
        "the third penalty is longer again"
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        !r.blamed_root(R1_IP.into()),
        "and it stops growing at the cap: 900ms is past the {CAP:?} ceiling but \
         well short of the {:?} an uncapped curve would give",
        BASE * 4
    );
}

/// The control for the escalation: the counter is cleared by an answer that
/// *validates*, and by nothing else. A root that comes back and behaves is fully
/// restored, so a single later lie costs it the base penalty rather than the
/// escalated one.
#[tokio::test]
async fn a_validating_answer_restores_a_blamed_root() {
    const BASE: Duration = Duration::from_millis(300);
    const CAP: Duration = Duration::from_millis(2_000);

    let h = root_harness(&[Behaviour::Liar]).await;
    let r = h
        .pointed_at(vec![IpAddr::from(R1_IP)])
        .with_blame_backoff(BASE, CAP);

    // Two lies: the next penalty would be 4x the base.
    assert!(verdict_of(&r, "a.example.test.").await.withholds_answer());
    force_root_lookup(&r);
    assert!(verdict_of(&r, "b.example.test.").await.withholds_answer());

    // It stops lying, and produces an answer that validates.
    h.roots[0].behave(Tamper::None);
    force_root_lookup(&r);
    let verdict = verdict_of(&r, "www.example.test.").await;
    assert_eq!(
        verdict,
        Verdict::Secure,
        "the restored root must validate: {}",
        describe(&verdict)
    );
    assert!(
        !r.blamed_root(R1_IP.into()),
        "a validating answer clears the omission"
    );

    // And it lies once more: the base penalty, not the escalated one.
    h.roots[0].behave(Tamper::StripSignatures);
    force_root_lookup(&r);
    assert!(verdict_of(&r, "c.example.test.").await.withholds_answer());
    assert!(r.blamed_root(R1_IP.into()));
    tokio::time::sleep(BASE + Duration::from_millis(200)).await;
    assert!(
        !r.blamed_root(R1_IP.into()),
        "the escalation counter was cleared by the validating answer, so this \
         costs the base penalty rather than the accumulated one"
    );
}

/// Blame must survive transport success. `note_success` clearing the whole
/// health entry would wipe blame the moment the very server we distrust answers
/// a packet promptly — which a hijacked root does by definition.
#[tokio::test]
async fn blame_outlives_transport_success() {
    let h = root_harness(&[Behaviour::Liar, Behaviour::Honest]).await;
    let solo = h.pointed_at(vec![IpAddr::from(R1_IP)]);

    assert!(
        verdict_of(&solo, "a.example.test.")
            .await
            .withholds_answer()
    );
    assert!(solo.blamed_root(R1_IP.into()));

    // It is still perfectly reachable and answers promptly. With one root the
    // filter is inert, so it *is* asked — and each of those exchanges is a
    // transport success.
    let before = h.roots[0].hits();
    force_root_lookup(&solo);
    assert!(
        verdict_of(&solo, "b.example.test.")
            .await
            .withholds_answer()
    );
    assert!(
        h.roots[0].hits() > before,
        "the blamed root answered a further exchange"
    );

    // Now that an honest peer is available, it must still be omitted.
    let full = h.pointed_at(h.ips());
    let before = h.roots[0].hits();
    for qname in ["c.example.test.", "d.example.test."] {
        force_root_lookup(&full);
        let verdict = verdict_of(&full, qname).await;
        assert_eq!(
            verdict,
            Verdict::Secure,
            "the honest root answers: {}",
            describe(&verdict)
        );
    }
    assert_eq!(
        h.roots[0].hits(),
        before,
        "blame outlives a successful exchange with the blamed server"
    );
    assert!(h.roots[1].hits() > 0, "and the honest root carried them");
}

/// The control: a root penalised only for a *timeout* is queried again after a
/// successful exchange. Blame and transport health are tracked separately, and
/// narrowing `note_success` must not have turned an ordinary backoff into a
/// permanent one.
#[tokio::test]
async fn a_timed_out_root_recovers_on_a_successful_exchange() {
    let mut h = root_harness(&[Behaviour::Silent]).await;
    let r = h
        .pointed_at(vec![IpAddr::from(R1_IP)])
        .with_timeout(Duration::from_millis(150))
        .with_failure_backoff(Duration::from_millis(50));

    // Bound but not answering: a transport failure, and not a lie.
    let result = r
        .resolve(&name("a.example.test."), RecordType::A, DNSClass::IN)
        .await;
    assert!(result.is_err(), "an unreachable root fails the lookup");
    assert!(
        !r.blamed_root(R1_IP.into()),
        "a timeout says the server was busy, not that it told us something untrue"
    );

    // It starts answering, correctly.
    h.roots[0].start();
    tokio::time::sleep(Duration::from_millis(100)).await;
    force_root_lookup(&r);
    let verdict = verdict_of(&r, "www.example.test.").await;
    assert_eq!(
        verdict,
        Verdict::Secure,
        "a recovered root is queried again and answers: {}",
        describe(&verdict)
    );
    assert!(
        h.roots[0].hits() > 0,
        "the recovered root received the queries"
    );
}

/// Omission must never empty the candidate set. Every root failing to validate
/// is not thirteen rogue servers — it is the zone or our own trust anchor — and
/// an empty set yields "no nameservers", which is *unreachable*, which falls
/// through to the forwarder. That is precisely the hole the withholding verdict
/// closes, so blame must not reopen it.
#[tokio::test]
async fn blaming_every_root_does_not_become_a_fallthrough() {
    let forwarder = spawn_forwarder().await;
    let h = root_harness(&[Behaviour::Liar, Behaviour::Liar]).await;
    let resolver = h.pointed_at(h.ips());
    let server = auto_server(resolver.clone(), &forwarder);

    // Three queries: the first two blame one root each, the third runs with
    // every root blamed — the state the guard exists for.
    for qname in ["a.example.test.", "b.example.test.", "c.example.test."] {
        force_root_lookup(&resolver);
        let response = ask(&server, qname, RecordType::A).await;
        assert_eq!(
            response.response_code(),
            ResponseCode::ServFail,
            "{qname}: a root zone that will not validate must SERVFAIL"
        );
        assert_eq!(
            forwarder.hits(),
            0,
            "{qname}: invalid must never be laundered into unreachable"
        );
    }
    assert_eq!(
        resolver.blamed_root_count(),
        2,
        "both roots are blamed, and the query still failed closed"
    );
}

/// In that state blame stops being the deciding input and the tier machinery
/// governs: tier 0 stays unreclaimable until a `Secure` root DNSKEY comes back,
/// and the committed tier does not move as a side effect of blame.
#[tokio::test]
async fn auto_mode_still_governs_when_every_root_is_blamed() {
    let forwarder = spawn_forwarder().await;
    let h = root_harness(&[Behaviour::Liar, Behaviour::Liar]).await;

    // Start with the roots unreachable so the chain degrades to the forwarder,
    // which is the state a recovery probe exists to climb out of.
    let anchors = Anchors::from_dnskey_strings(&[&h.anchor]).expect("anchor parses");
    let dead = IterativeResolver::new(vec![IpAddr::from(DEAD_ROOT_IP)])
        .with_port(h.port)
        .with_timeout(Duration::from_millis(200))
        .with_validation(anchors);
    let server = auto_server(dead, &forwarder);
    server.set_auto_params(1, 3_600);

    let response = ask(&server, "a.example.test.", RecordType::A).await;
    assert_eq!(a_records(&response), vec![FORWARDER_IP]);
    assert_eq!(
        server.active_tier(),
        TIER_LOCAL,
        "the chain must have degraded to the forwarder first"
    );

    // Now the roots are reachable again — and lying.
    let resolver = h.pointed_at(h.ips());
    server.set_resolver(resolver.clone());
    for _ in 0..3 {
        force_root_lookup(&resolver);
        server.recovery_probe_once().await;
        assert_eq!(
            server.active_tier(),
            TIER_LOCAL,
            "a root zone that does not validate must not reclaim tier {TIER_ROOTS}, \
             and must not flip the committed tier anywhere else either"
        );
    }
    assert!(
        resolver.blamed_root_count() > 0,
        "the probe did blame the lying roots — otherwise this test proves nothing"
    );
}

/// Blame is root-servers-only. Below the root a validation failure is almost
/// always the zone's own signing error: every server for that zone returns the
/// same bytes, and omitting them would turn someone else's mistake into our
/// outage. Those lookups already fail closed on the verdict, which is the whole
/// remedy they need.
#[tokio::test]
async fn blame_does_not_reach_other_nameservers() {
    // A zone whose DNSKEY RRset cannot be anchored to its parent's DS: the
    // below-the-root analogue of the root failure that *does* earn blame.
    let harness = harness(Attack {
        zone: Tamper::SignWithForeignKey,
        ..Attack::default()
    })
    .await;

    let res = resolve(&harness, "www.example.test.", RecordType::A).await;
    assert_withheld(&res, "a zone whose DNSKEY does not match its DS");

    let before = harness.zone.hits();
    let res = resolve(&harness, "txtonly.example.test.", RecordType::TXT).await;
    assert!(
        res.verdict.withholds_answer(),
        "it keeps failing closed, which is the correct remedy: {}",
        describe(&res.verdict)
    );
    assert!(
        harness.zone.hits() > before,
        "the zone's nameservers stay usable — blame must not reach them"
    );
    assert_eq!(
        harness.resolver.blamed_root_count(),
        0,
        "and nothing was blamed for someone else's signing error"
    );
}
