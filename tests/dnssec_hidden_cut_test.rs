//! A zone cut that no referral announces, because one nameserver is
//! authoritative for both sides of it.
//!
//! `cdnjs.cloudflare.com.` is its own signed zone, delegated from
//! `cloudflare.com.` and served by the same nameservers. Ask those servers for a
//! name in the child and they answer it — authoritatively, signed by the child's
//! key — instead of referring the query across the cut. A resolver that decides
//! which keys to validate with by remembering the last referral it followed is
//! therefore holding the *parent's* keys when the *child's* signatures arrive,
//! and calls a perfectly good answer bogus. That is not a rare corner: it is how
//! every hosting provider that runs a subzone on the same infrastructure looks
//! from the outside, and the names it breaks (a CDN, in the case that found this)
//! are the ones a page needs before it will render.
//!
//! RFC 4035 §5.3.1 settles it — the RRSIG's signer name says which zone's keys
//! apply — so the fix is to establish trust for that signer, by fetching the DS
//! the referral never delivered. These tests are the paths that must *work*;
//! `tests/security_dnssec_test.rs` holds the ones that must fail, and the pair is
//! the point: descending to any signer a response names would resolve everything
//! here and be a downgrade attack.
//!
//! The hierarchy is `.` -> `test.` -> `example.test.`, with `cdn.example.test.`
//! delegated from `example.test.` and served from the *same* socket, so no
//! referral to it is ever sent.

mod signed_hierarchy;

use hickory_proto::rr::{DNSClass, RData, RecordType, rdata};
use rolodex_dns::dnssec_validate::{Anchors, Verdict};
use rolodex_dns::resolver::IterativeResolver;
use signed_hierarchy::{NsecSpec, Tamper, Zone, ZoneKey, bind_levels, name, serve, serve_zones};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 51);
const TLD_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 52);
/// One address serving `example.test.` *and* `cdn.example.test.`.
const ZONE_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 53);

/// What `www.example.test.` (the parent zone) answers.
const PARENT_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
/// What `www.cdn.example.test.` (the hidden child zone) answers.
const CHILD_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);

/// How the child's delegation is set up, which is the whole variable here.
#[derive(Clone, Copy, PartialEq)]
enum Cut {
    /// The parent publishes a DS matching the key the child signs with.
    Signed,
    /// The parent publishes a DS for a key the child does not have. The names
    /// still line up; only the cryptography does not.
    MismatchedDs,
}

struct Harness {
    resolver: IterativeResolver,
    /// Kept alive for the test's duration; dropping them stops the servers.
    _servers: Vec<signed_hierarchy::SignedNs>,
}

async fn harness(cut: Cut) -> Harness {
    let root_key = ZoneKey::generate();
    let tld_key = ZoneKey::generate();
    let zone_key = ZoneKey::generate();
    let child_key = ZoneKey::generate();

    let (port, mut sockets) = bind_levels(&[ROOT_IP, TLD_IP, ZONE_IP]).await;
    let zone_sock = sockets.pop().expect("zone socket");
    let tld_sock = sockets.pop().expect("tld socket");
    let root_sock = sockets.pop().expect("root socket");

    let root_zone =
        Zone::new(".", Arc::clone(&root_key)).with_signed_child("test.", TLD_IP, &tld_key);
    let tld_zone = Zone::new("test.", Arc::clone(&tld_key)).with_signed_child(
        "example.test.",
        ZONE_IP,
        &zone_key,
    );

    // The DS the parent publishes for the child. `MismatchedDs` publishes one for
    // a key nobody holds: the delegation still exists and still validates under
    // the parent's signature, so only the DS-to-DNSKEY match can catch it.
    let ds_key = match cut {
        Cut::Signed => Arc::clone(&child_key),
        Cut::MismatchedDs => ZoneKey::generate(),
    };

    let parent_zone = Zone::new("example.test.", Arc::clone(&zone_key))
        .with_a("www.example.test.", PARENT_IP)
        // The delegation lives here and is never handed out as a referral,
        // because this server answers for the child itself.
        .with_signed_child("cdn.example.test.", ZONE_IP, &ds_key)
        .with_nsec(NsecSpec::new(
            "example.test.",
            "www.example.test.",
            &[RecordType::SOA, RecordType::NS, RecordType::RRSIG],
        ));

    let child_zone = Zone::new("cdn.example.test.", Arc::clone(&child_key))
        .with_a("www.cdn.example.test.", CHILD_IP)
        .with_txt("txt.cdn.example.test.", "hello")
        // Denies everything between the apex and `www`, wildcard included.
        .with_nsec(NsecSpec::new(
            "cdn.example.test.",
            "txt.cdn.example.test.",
            &[RecordType::SOA, RecordType::NS, RecordType::RRSIG],
        ))
        .with_nsec(NsecSpec::new(
            "txt.cdn.example.test.",
            "www.cdn.example.test.",
            &[RecordType::TXT, RecordType::RRSIG, RecordType::NSEC],
        ))
        .with_nsec(NsecSpec::new(
            "www.cdn.example.test.",
            "cdn.example.test.",
            &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
        ));

    let root = serve(root_sock, root_zone);
    let tld = serve(tld_sock, tld_zone);
    // Both zones, one socket: the configuration that hides the cut.
    let zone = serve_zones(zone_sock, vec![parent_zone, child_zone]);

    let anchors = Anchors::from_dnskey_strings(&[root_key.anchor_string()]).expect("anchor parses");
    let resolver = IterativeResolver::new(vec![ROOT_IP.into()])
        .with_port(port)
        .with_timeout(Duration::from_millis(1500))
        .with_validation(anchors);

    Harness {
        resolver,
        _servers: vec![root, tld, zone],
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

fn addresses(res: &rolodex_dns::resolver::Resolution) -> Vec<Ipv4Addr> {
    res.answers
        .iter()
        .filter_map(|r| match r.data() {
            RData::A(rdata::A(ip)) => Some(*ip),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The cut must be crossed
// ---------------------------------------------------------------------------

/// The bug, in one test. Before the fix this answer came back Bogus with
/// "RRSIG over www.cdn.example.test. A is signed by cdn.example.test., which is
/// not the zone example.test." — the resolver validating the child's signatures
/// against the parent's keys because no referral told it the cut was there.
#[tokio::test]
async fn an_answer_from_a_child_zone_on_the_parents_nameserver_validates() {
    let harness = harness(Cut::Signed).await;
    let res = resolve(&harness, "www.cdn.example.test.", RecordType::A).await;

    assert_eq!(
        res.verdict,
        Verdict::Secure,
        "a signed child zone answering for itself must validate against its own keys: {}",
        describe(&res.verdict)
    );
    assert_eq!(
        addresses(&res),
        vec![CHILD_IP],
        "the validated answer must still be the answer"
    );
}

/// Crossing the cut must not cost the parent anything: names in the parent zone
/// keep validating exactly as before, against the parent's keys.
#[tokio::test]
async fn the_parent_zone_still_validates_after_the_child_is_reached() {
    let harness = harness(Cut::Signed).await;

    let child = resolve(&harness, "www.cdn.example.test.", RecordType::A).await;
    assert_eq!(
        child.verdict,
        Verdict::Secure,
        "{}",
        describe(&child.verdict)
    );

    let parent = resolve(&harness, "www.example.test.", RecordType::A).await;
    assert_eq!(
        parent.verdict,
        Verdict::Secure,
        "the parent zone must be unaffected by the descent into its child: {}",
        describe(&parent.verdict)
    );
    assert_eq!(addresses(&parent), vec![PARENT_IP]);
}

/// A negative answer from the hidden child is proven by *its* NSEC records,
/// signed by *its* key — so the denial needs the same descent the positive
/// answer does, and gets it from the authority section instead of the answer.
#[tokio::test]
async fn a_denial_from_the_hidden_child_zone_is_proven() {
    let harness = harness(Cut::Signed).await;
    let res = resolve(&harness, "nope.cdn.example.test.", RecordType::A).await;

    assert_eq!(
        res.verdict,
        Verdict::Secure,
        "an NXDOMAIN signed by the child zone must be provable: {}",
        describe(&res.verdict)
    );
    assert_eq!(
        res.rcode,
        hickory_proto::op::ResponseCode::NXDomain,
        "the name really does not exist"
    );
}

/// NODATA from the hidden child: the name exists with another type, and the
/// proof of the missing type is again the child's to sign.
#[tokio::test]
async fn a_nodata_from_the_hidden_child_zone_is_proven() {
    let harness = harness(Cut::Signed).await;
    let res = resolve(&harness, "txt.cdn.example.test.", RecordType::A).await;

    assert_eq!(
        res.verdict,
        Verdict::Secure,
        "a NODATA signed by the child zone must be provable: {}",
        describe(&res.verdict)
    );
    assert!(res.answers.is_empty(), "NODATA carries no answer records");
}

/// The signer name says which keys to fetch; it does not say the answer is
/// trustworthy. The chain still has to reach them: a DS that names a key the
/// child does not hold breaks it, and the answer is withheld even though every
/// name in the packet lines up perfectly.
#[tokio::test]
async fn a_child_whose_ds_matches_no_key_of_its_own_is_refused() {
    let harness = harness(Cut::MismatchedDs).await;
    let res = resolve(&harness, "www.cdn.example.test.", RecordType::A).await;

    assert!(
        res.verdict.withholds_answer(),
        "a DS that matches none of the child's keys must break the chain, not extend it: {}",
        describe(&res.verdict)
    );
    assert!(
        res.answers.is_empty(),
        "a withheld answer must carry no records"
    );
}

/// The descent is a per-response detour, not a move: after validating an answer
/// from the child, the walk's own position is still the parent, so the next name
/// in the parent zone is not looked up as though it lived in the child.
#[tokio::test]
async fn descending_into_the_child_does_not_move_the_walk() {
    let harness = harness(Cut::Signed).await;

    // Child first, so the descent has happened and its keys are cached.
    let _ = resolve(&harness, "www.cdn.example.test.", RecordType::A).await;

    // A name that exists only in the parent zone, and a denial that only the
    // parent's NSEC can prove. If the walk had followed the descent, this would
    // be asked of the child and its answer would not validate.
    let res = resolve(&harness, "absent.example.test.", RecordType::A).await;
    assert_eq!(
        res.verdict,
        Verdict::Secure,
        "the parent's own denial must still validate against the parent: {}",
        describe(&res.verdict)
    );
}

// ---------------------------------------------------------------------------
// The unsigned twin, which cannot be crossed — only counted
// ---------------------------------------------------------------------------

/// Serializes the tests that measure the metrics registry.
///
/// The registry is process-wide, so two of these running concurrently read each
/// other's increments and every delta stops meaning anything — including, and
/// especially, the one asserting a counter did *not* move. Taking the lock is
/// what makes these assertions deterministic rather than dependent on the test
/// harness's scheduling.
/// Async-aware, and it has to be: the lock is held across the `.await` that
/// resolves the name, which is the whole span the counters must not move under.
/// `tokio::sync::Mutex` also does not poison, so one failing metrics test cannot
/// take the others down with it.
static METRICS_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// A hierarchy whose hidden child is *unsigned*: `example.test.` delegates
/// `unsigned.example.test.` with no DS (and proves it), and the same nameserver
/// serves both. There is no referral to announce the cut, and — with no
/// signatures — no signer name to chase either, so `descend_to` has nothing to
/// point at and the answer stays refused.
///
/// That is the honest outcome: a response with no RRSIGs inside a signed zone is
/// exactly what stripping produces, and the two are indistinguishable from here.
/// What must not happen is it being invisible, which is what the counter is for.
async fn unsigned_child_harness() -> Harness {
    let root_key = ZoneKey::generate();
    let tld_key = ZoneKey::generate();
    let zone_key = ZoneKey::generate();

    let (port, mut sockets) = bind_levels(&[ROOT_IP, TLD_IP, ZONE_IP]).await;
    let zone_sock = sockets.pop().expect("zone socket");
    let tld_sock = sockets.pop().expect("tld socket");
    let root_sock = sockets.pop().expect("root socket");

    let root_zone =
        Zone::new(".", Arc::clone(&root_key)).with_signed_child("test.", TLD_IP, &tld_key);
    let tld_zone = Zone::new("test.", Arc::clone(&tld_key)).with_signed_child(
        "example.test.",
        ZONE_IP,
        &zone_key,
    );

    let parent_zone = Zone::new("example.test.", Arc::clone(&zone_key))
        .with_a("www.example.test.", PARENT_IP)
        .with_unsigned_child("unsigned.example.test.", ZONE_IP, "zzz.example.test.");

    // Served from the same socket as its parent, and signing nothing.
    let child_zone = Zone::new("unsigned.example.test.", ZoneKey::generate())
        .with_a("host.unsigned.example.test.", CHILD_IP)
        .with_tamper(Tamper::StripSignatures);

    let root = serve(root_sock, root_zone);
    let tld = serve(tld_sock, tld_zone);
    let zone = serve_zones(zone_sock, vec![parent_zone, child_zone]);

    let anchors = Anchors::from_dnskey_strings(&[root_key.anchor_string()]).expect("anchor parses");
    let resolver = IterativeResolver::new(vec![ROOT_IP.into()])
        .with_port(port)
        .with_timeout(Duration::from_millis(1500))
        .with_validation(anchors);

    Harness {
        resolver,
        _servers: vec![root, tld, zone],
    }
}

/// A negative from the unsigned child carries that child's SOA, which is the one
/// piece of evidence left once there are no signatures: it says the response came
/// from a zone below this one rather than from an attacker stripping RRSIGs off
/// the parent's own data. Diagnostic only — the SOA is unsigned like everything
/// around it — so the answer is still refused, and only the label reflects it.
#[tokio::test]
async fn an_unsigned_child_on_the_parents_nameserver_is_counted_with_its_apex() {
    let _guard = METRICS_LOCK.lock().await;
    let m = rolodex_dns::metrics::metrics();
    let before = m
        .dnssec_unsigned_responses
        .get(rolodex_dns::metrics::UNSIGNED_EVIDENCE_CHILD_APEX_SOA);

    let harness = unsigned_child_harness().await;
    let res = resolve(&harness, "nope.unsigned.example.test.", RecordType::A).await;

    assert!(
        res.verdict.withholds_answer(),
        "an unsigned response inside a signed zone must still be refused: {}",
        describe(&res.verdict)
    );
    assert!(
        m.dnssec_unsigned_responses
            .get(rolodex_dns::metrics::UNSIGNED_EVIDENCE_CHILD_APEX_SOA)
            > before,
        "the child's apex SOA must be recorded as the evidence for the refusal"
    );
}

/// The same gap on a positive answer, where the response names no zone at all.
/// It is counted under `none`, alongside stripped signatures — because from here
/// they are the same packet, and pretending otherwise would put a guess in a
/// metric operators are meant to act on.
#[tokio::test]
async fn an_unsigned_answer_with_no_evidence_is_counted_separately() {
    let _guard = METRICS_LOCK.lock().await;
    let m = rolodex_dns::metrics::metrics();
    let before = m
        .dnssec_unsigned_responses
        .get(rolodex_dns::metrics::UNSIGNED_EVIDENCE_NONE);

    let harness = unsigned_child_harness().await;
    let res = resolve(&harness, "host.unsigned.example.test.", RecordType::A).await;

    assert!(
        res.verdict.withholds_answer(),
        "an unsigned answer inside a signed zone must still be refused: {}",
        describe(&res.verdict)
    );
    assert!(
        m.dnssec_unsigned_responses
            .get(rolodex_dns::metrics::UNSIGNED_EVIDENCE_NONE)
            > before,
        "an unsigned answer naming no zone must be counted under `none`"
    );
}

/// The counter must not fire for the case that now works. A signed hidden child
/// resolves without ever looking like an unsigned one, so a rise here is always
/// something to investigate rather than routine noise from the fix above.
#[tokio::test]
async fn a_signed_hidden_child_is_never_counted_as_unsigned() {
    let _guard = METRICS_LOCK.lock().await;
    let m = rolodex_dns::metrics::metrics();
    let before: u64 = (0..2).map(|i| m.dnssec_unsigned_responses.get(i)).sum();

    let harness = harness(Cut::Signed).await;
    let res = resolve(&harness, "www.cdn.example.test.", RecordType::A).await;
    assert_eq!(res.verdict, Verdict::Secure, "{}", describe(&res.verdict));

    let after: u64 = (0..2).map(|i| m.dnssec_unsigned_responses.get(i)).sum();
    assert_eq!(
        after, before,
        "a signed child crossing a hidden cut is not an unsigned response"
    );
}

/// Validation off means validation off: the descent is a DNSSEC mechanism and
/// must not fire (or cost a DS lookup) for a resolver that was never asked to
/// validate anything.
#[tokio::test]
async fn an_unvalidating_resolver_resolves_the_child_without_a_verdict() {
    let root_key = ZoneKey::generate();
    let tld_key = ZoneKey::generate();
    let zone_key = ZoneKey::generate();
    let child_key = ZoneKey::generate();

    let (port, mut sockets) = bind_levels(&[ROOT_IP, TLD_IP, ZONE_IP]).await;
    let zone_sock = sockets.pop().expect("zone socket");
    let tld_sock = sockets.pop().expect("tld socket");
    let root_sock = sockets.pop().expect("root socket");

    let root_zone =
        Zone::new(".", Arc::clone(&root_key)).with_signed_child("test.", TLD_IP, &tld_key);
    let tld_zone = Zone::new("test.", Arc::clone(&tld_key)).with_signed_child(
        "example.test.",
        ZONE_IP,
        &zone_key,
    );
    let parent_zone = Zone::new("example.test.", Arc::clone(&zone_key))
        .with_signed_child("cdn.example.test.", ZONE_IP, &child_key)
        .with_tamper(Tamper::None);
    let child_zone = Zone::new("cdn.example.test.", Arc::clone(&child_key))
        .with_a("www.cdn.example.test.", CHILD_IP);

    let root = serve(root_sock, root_zone);
    let tld = serve(tld_sock, tld_zone);
    let zone = serve_zones(zone_sock, vec![parent_zone, child_zone]);

    // No `with_validation`: this resolver has no anchors and no opinion.
    let resolver = IterativeResolver::new(vec![ROOT_IP.into()])
        .with_port(port)
        .with_timeout(Duration::from_millis(1500));
    let harness = Harness {
        resolver,
        _servers: vec![root, tld, zone],
    };

    let res = resolve(&harness, "www.cdn.example.test.", RecordType::A).await;
    assert_eq!(
        addresses(&res),
        vec![CHILD_IP],
        "an unvalidating resolver must still resolve the name"
    );
    assert_eq!(
        res.verdict,
        Verdict::Insecure,
        "with validation off there is nothing to say about the chain: {}",
        describe(&res.verdict)
    );
}
