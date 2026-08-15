//! `arpa.` is never resolved off this box.
//!
//! The subtree is this server's to answer from local data — a stored PTR, a
//! managed reverse zone — and nothing under it is ever sent to a root server, a
//! forwarder or an encrypted upstream. A name with no local data is REFUSED:
//! we are declining to answer for a namespace, not asserting the name does not
//! exist.
//!
//! The rule is enforced at two independent layers, and this file exercises both
//! rather than trusting either:
//!
//! - `IterativeResolver` refuses without sending a packet, so no caller can use
//!   it to reach the subtree.
//! - `DnsServer` refuses at the boundary between "data this box holds" and
//!   "data it must go and get", in every resolution mode, so no upstream is
//!   consulted whichever tier is active.
//!
//! Every assertion here has its control, because the failure modes are
//! symmetric: a resolver that refuses *everything* satisfies "arpa is refused",
//! and one that refuses nothing satisfies "ordinary names still resolve". The
//! controls are the label boundary (`notarpa.`, `arpa.example.test.` — names
//! that merely contain those four letters and must resolve and validate
//! normally) and the local-data path (a stored PTR must still be answered, or
//! the rule would have taken reverse DNS out entirely rather than moving it
//! in-house).

mod signed_hierarchy;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, RecordType, rdata};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rolodex_dns::db::{Database, DnsRecord, RecordKind};
use rolodex_dns::dns_cache::DnsCache;
use rolodex_dns::dns_server::{DnsServer, ResolutionMode};
use rolodex_dns::dnsbl::DnsblChecker;
use rolodex_dns::dnssec_validate::{Anchors, Verdict};
use rolodex_dns::resolver::IterativeResolver;
use signed_hierarchy::{NsecSpec, SignedNs, Zone, ZoneKey, bind_levels, name, serve};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 71);
const TLD_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 72);
const ZONE_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 73);
const NOTARPA_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 74);

const WWW_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
/// The answer at `arpa.example.test.` — an `arpa` label that is not the last
/// one, and therefore not in the subtree.
const ARPA_LABEL_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
/// The answer inside `notarpa.`, the label-boundary control zone.
const NOTARPA_HOST_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 60);
/// What the upstream answers with, when it is consulted at all.
const UPSTREAM_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

/// Every name in the subtree that must be refused, in the spellings that
/// actually occur: the apex, the NAT64 probe (RFC 7050) that provoked all of
/// this, both reverse trees, the RFC 8375 home namespace, and a mixed-case
/// spelling, because case is not significant in DNS and an attacker picks it.
const ARPA_NAMES: [&str; 6] = [
    "arpa.",
    "ipv4only.arpa.",
    "1.0.0.127.in-addr.arpa.",
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
    "host.home.arpa.",
    "IPV4ONLY.ARPA.",
];

/// A signed hierarchy the resolver *can* reach, so "no query was sent" is a
/// statement about policy rather than about a broken mock.
struct Harness {
    resolver: IterativeResolver,
    root: SignedNs,
    _keep: Vec<SignedNs>,
}

/// `.` -> `test.` -> `example.test.`, plus a `notarpa.` TLD. Nothing here serves
/// `arpa.` at all: the roots are reachable and would answer *something* for an
/// arpa query, which is exactly what makes the root's query count the assertion.
async fn harness() -> Harness {
    let root_key = ZoneKey::generate();
    let tld_key = ZoneKey::generate();
    let zone_key = ZoneKey::generate();
    let notarpa_key = ZoneKey::generate();

    let (port, mut sockets) = bind_levels(&[ROOT_IP, TLD_IP, ZONE_IP, NOTARPA_IP]).await;
    let notarpa_sock = sockets.pop().expect("notarpa socket");
    let zone_sock = sockets.pop().expect("zone socket");
    let tld_sock = sockets.pop().expect("tld socket");
    let root_sock = sockets.pop().expect("root socket");

    let root_zone = Zone::new(".", Arc::clone(&root_key))
        .with_signed_child("test.", TLD_IP, &tld_key)
        // A TLD whose name ends in the same four letters without ending in the
        // same *label*. A suffix test would refuse to resolve it.
        .with_signed_child("notarpa.", NOTARPA_IP, &notarpa_key);

    let tld_zone = Zone::new("test.", Arc::clone(&tld_key))
        .with_signed_child("example.test.", ZONE_IP, &zone_key)
        .with_nsec(NsecSpec::new(
            "test.",
            "example.test.",
            &[RecordType::SOA, RecordType::NS, RecordType::RRSIG],
        ));

    let leaf_zone = Zone::new("example.test.", Arc::clone(&zone_key))
        .with_a("www.example.test.", WWW_IP)
        // An `arpa` label that is not the last one: an ordinary name in an
        // ordinary zone.
        .with_a("arpa.example.test.", ARPA_LABEL_IP)
        .with_nsec(NsecSpec::new(
            "example.test.",
            "arpa.example.test.",
            &[RecordType::SOA, RecordType::NS, RecordType::RRSIG],
        ))
        .with_nsec(NsecSpec::new(
            "arpa.example.test.",
            "www.example.test.",
            &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
        ))
        .with_nsec(NsecSpec::new(
            "www.example.test.",
            "example.test.",
            &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
        ));

    let notarpa_zone =
        Zone::new("notarpa.", Arc::clone(&notarpa_key)).with_a("host.notarpa.", NOTARPA_HOST_IP);

    let root = serve(root_sock, root_zone);
    let keep = vec![
        serve(tld_sock, tld_zone),
        serve(zone_sock, leaf_zone),
        serve(notarpa_sock, notarpa_zone),
    ];

    let anchors = Anchors::from_dnskey_strings(&[root_key.anchor_string()]).expect("anchor parses");
    let resolver = IterativeResolver::new(vec![ROOT_IP.into()])
        .with_port(port)
        .with_timeout(Duration::from_millis(1500))
        .with_validation(anchors);

    Harness {
        resolver,
        root,
        _keep: keep,
    }
}

// ---------------------------------------------------------------------------
// Layer one: the iterative resolver
// ---------------------------------------------------------------------------

/// The assertion, and it is about *packets*, not about the rcode: a resolver
/// that answered REFUSED after asking a root would satisfy an rcode check while
/// having already done the thing the rule forbids.
#[tokio::test]
async fn the_resolver_refuses_arpa_without_sending_a_query() {
    let h = harness().await;

    for qname in ARPA_NAMES {
        let before = h.root.hits();
        let res = h
            .resolver
            .resolve(&name(qname), RecordType::A, DNSClass::IN)
            .await
            .expect("the resolver answers rather than erroring");

        assert_eq!(
            res.rcode,
            ResponseCode::Refused,
            "{qname} must be refused, not resolved"
        );
        assert!(
            res.answers.is_empty(),
            "{qname}: a refusal carries no records"
        );
        assert_eq!(
            h.root.hits(),
            before,
            "{qname}: no packet may be sent for a name in the arpa. subtree"
        );
    }
}

/// A refusal must not be mistaken for an authentication claim. `Insecure` is the
/// honest verdict — nothing was checked because nothing was fetched — and it
/// must specifically not be `Secure`, which is what would set AD.
#[tokio::test]
async fn a_refused_arpa_name_claims_nothing() {
    let h = harness().await;
    let res = h
        .resolver
        .resolve(&name("ipv4only.arpa."), RecordType::A, DNSClass::IN)
        .await
        .expect("the resolver answers");

    assert_ne!(
        res.verdict,
        Verdict::Secure,
        "a name we never fetched must not be reported as validated"
    );
    assert!(
        !res.verdict.withholds_answer(),
        "and it is a refusal, not a validation failure: {:?}",
        res.verdict
    );
}

/// Label-boundary control. `notarpa.` and `arpa.example.test.` merely contain
/// those four letters. They must resolve *and* validate — without this, a
/// `ends_with("arpa.")` bug passes every test above while quietly refusing to
/// resolve somebody's ordinary domain.
#[tokio::test]
async fn names_that_merely_end_in_arpa_still_resolve_and_validate() {
    let h = harness().await;

    for (qname, expected) in [
        ("host.notarpa.", NOTARPA_HOST_IP),
        ("arpa.example.test.", ARPA_LABEL_IP),
    ] {
        let res = h
            .resolver
            .resolve(&name(qname), RecordType::A, DNSClass::IN)
            .await
            .expect("resolution completes");

        assert_eq!(
            res.rcode,
            ResponseCode::NoError,
            "{qname} is not in the arpa. subtree and must resolve"
        );
        assert_eq!(
            res.verdict,
            Verdict::Secure,
            "{qname} must still be validated: {:?}",
            res.verdict
        );
        let addrs: Vec<Ipv4Addr> = res
            .answers
            .iter()
            .filter_map(|r| match r.data() {
                RData::A(rdata::A(ip)) => Some(*ip),
                _ => None,
            })
            .collect();
        assert_eq!(addrs, vec![expected], "{qname} must get its real answer");
    }
}

/// The other half of the control: the roots really are reachable through this
/// harness. Without it, "no query was sent" is indistinguishable from "no query
/// could have been sent".
#[tokio::test]
async fn the_roots_are_reachable_for_everything_else() {
    let h = harness().await;
    let res = h
        .resolver
        .resolve(&name("www.example.test."), RecordType::A, DNSClass::IN)
        .await
        .expect("resolution completes");

    assert_eq!(res.rcode, ResponseCode::NoError);
    assert!(
        h.root.hits() > 0,
        "an ordinary name must reach the root — otherwise the arpa assertions \
         prove only that this harness cannot talk to anybody"
    );
}

// ---------------------------------------------------------------------------
// Layer two: the query path
// ---------------------------------------------------------------------------

/// An upstream that answers everything, and counts what it was asked.
///
/// The count is the assertion: "the client got REFUSED" is satisfied just as
/// well by a query that went upstream, came back, and was refused afterwards.
struct Upstream {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
}

impl Upstream {
    fn hits(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

async fn spawn_upstream() -> Upstream {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind upstream");
    let addr = socket.local_addr().expect("upstream address");
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
            resp.set_recursion_available(true);
            for q in query.queries() {
                resp.add_query(q.clone());
            }
            if let Some(q) = query.queries().first() {
                resp.add_answer(hickory_proto::rr::Record::from_rdata(
                    q.name().clone(),
                    300,
                    RData::A(rdata::A(UPSTREAM_IP)),
                ));
            }
            if let Ok(bytes) = resp.to_bytes() {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    });

    Upstream { addr, queries }
}

/// A server in `mode`, with `upstream` as its forwarder and its roots pointed at
/// the same address, so *every* tier would answer if it were consulted.
fn server_with(mode: ResolutionMode, upstream: &Upstream) -> (Arc<DnsServer>, Database) {
    let db = Database::open_memory().expect("in-memory database");
    let cache = Arc::new(DnsCache::new(db.clone()));
    let rbl = Arc::new(DnsblChecker::new());
    let server = Arc::new(DnsServer::new_with_options(
        db.clone(),
        rbl,
        vec![upstream.addr],
        Some(cache),
        None,
        false,
    ));
    server.set_resolution_mode(mode);
    server.set_secure_upstreams(vec![]);
    server.set_public_fallback(vec![upstream.addr]);
    // The roots, too: if the rule leaked, the iterative path would reach this
    // same counter rather than failing for want of a reachable root.
    server.set_resolver(
        IterativeResolver::new(vec![upstream.addr.ip()])
            .with_port(upstream.addr.port())
            .with_timeout(Duration::from_millis(300)),
    );
    (server, db)
}

fn client_query(qname: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(0x5151);
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

async fn ask(server: &DnsServer, qname: &str, qtype: RecordType) -> Message {
    let bytes = server
        .handle_query(&client_query(qname, qtype))
        .await
        .expect("the server produces a response");
    Message::from_bytes(&bytes).expect("the response parses")
}

/// Every resolution mode refuses, and none of them consults an upstream. Mode is
/// tested exhaustively because each one dispatches to a different code path —
/// `forward` never touches the resolver at all, so a rule enforced only there
/// would leak in exactly the deployment shape that forwards.
#[tokio::test]
async fn every_resolution_mode_refuses_arpa_without_going_upstream() {
    for mode in [
        ResolutionMode::Recursive,
        ResolutionMode::Forward,
        ResolutionMode::Auto,
    ] {
        let upstream = spawn_upstream().await;
        let (server, _db) = server_with(mode, &upstream);

        for qname in ARPA_NAMES {
            let response = ask(&server, qname, RecordType::A).await;
            assert_eq!(
                response.response_code(),
                ResponseCode::Refused,
                "{mode:?}/{qname}: must be REFUSED"
            );
            assert!(
                response.answers().is_empty(),
                "{mode:?}/{qname}: a refusal carries no records"
            );
        }
        assert_eq!(
            upstream.hits(),
            0,
            "{mode:?}: no arpa. query may leave the box"
        );
    }
}

/// The control for the mode sweep: the same server, the same upstream, an
/// ordinary name. Without it, a server that refused *everything* — or one whose
/// upstream was never wired up — would pass the test above.
#[tokio::test]
async fn an_ordinary_name_still_goes_upstream_in_every_mode() {
    for mode in [
        ResolutionMode::Recursive,
        ResolutionMode::Forward,
        ResolutionMode::Auto,
    ] {
        let upstream = spawn_upstream().await;
        let (server, _db) = server_with(mode, &upstream);

        let response = ask(&server, "ordinary.example.", RecordType::A).await;
        assert_eq!(
            response.response_code(),
            ResponseCode::NoError,
            "{mode:?}: an ordinary name must still be resolved"
        );
        assert!(
            upstream.hits() > 0,
            "{mode:?}: and the upstream must actually have been consulted"
        );
    }
}

/// The rule moves `arpa.` in-house; it does not delete it. A PTR this server
/// holds is still answered, because the refusal sits *below* every local lookup
/// in the pipeline.
///
/// This is the assertion that keeps the policy honest: without it, "never
/// resolved externally" and "never resolved" are the same test.
#[tokio::test]
async fn a_locally_held_ptr_is_still_answered() {
    let upstream = spawn_upstream().await;
    let (server, db) = server_with(ResolutionMode::Auto, &upstream);

    db.add_record(&DnsRecord {
        id: None,
        name: "1.0.0.127.in-addr.arpa.".to_string(),
        record_type: RecordKind::PTR,
        value: "local.example.".to_string(),
        ttl: 300,
        priority: 0,
    })
    .expect("the PTR is stored");

    let response = ask(&server, "1.0.0.127.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(
        response.response_code(),
        ResponseCode::NoError,
        "a PTR this server holds must be answered, not refused"
    );
    assert!(
        response
            .answers()
            .iter()
            .any(|r| matches!(r.data(), RData::PTR(rdata::PTR(target)) if target == &name("local.example."))),
        "and it must be the stored answer, got {:?}",
        response.answers()
    );
    assert_eq!(
        upstream.hits(),
        0,
        "local data answers it without any upstream query"
    );
}

/// The DDR designation lives under `arpa.` and must be answerable, for exactly
/// the same reason a stored PTR is: the refusal sits below every local lookup.
///
/// This is what makes RFC 9462 discovery possible on a box whose policy is
/// "`arpa.` never leaves". A client asks its own resolver for
/// `_dns.resolver.arpa. SVCB` and gets that resolver's encrypted endpoints —
/// and because the refusal blocks only the upstream path, the answer can *only*
/// come from the resolver being asked, which is the property DDR needs.
#[tokio::test]
async fn the_ddr_designation_is_answered_from_local_data() {
    let upstream = spawn_upstream().await;
    let (server, db) = server_with(ResolutionMode::Auto, &upstream);

    for value in rolodex_dns::svcb::designation(
        "dns.home.",
        Some((443, "/dns-query{?dns}")),
        Some(853),
        None,
    ) {
        db.add_record(&DnsRecord {
            id: None,
            name: rolodex_dns::svcb::DDR_DESIGNATION_NAME.to_string(),
            record_type: RecordKind::SVCB,
            value,
            ttl: 7200,
            priority: 0,
        })
        .expect("the designation is stored");
    }

    let response = ask(
        &server,
        rolodex_dns::svcb::DDR_DESIGNATION_NAME,
        RecordType::SVCB,
    )
    .await;
    assert_eq!(
        response.response_code(),
        ResponseCode::NoError,
        "the resolver must answer for its own designation, got {:?}",
        response.response_code()
    );
    assert_eq!(
        response.answers().len(),
        2,
        "both designations must come back, got {:?}",
        response.answers()
    );
    // The DoH one first: :443 survives the DPI that filters DoT's :853, which is
    // the same ordering the resolver's own upstream chain prefers.
    let priorities: Vec<u16> = response
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::SVCB(svcb) => Some(svcb.svc_priority()),
            _ => None,
        })
        .collect();
    assert_eq!(priorities.len(), 2, "both answers must be SVCB rdata");
    assert!(priorities.contains(&1) && priorities.contains(&2));
    assert_eq!(
        upstream.hits(),
        0,
        "a designation is the resolver's own to answer; nothing may leave the box"
    );
}

/// ...and without one stored, the name is refused like any other `arpa.` name.
/// A box that has not published a designation must not have one invented for it
/// upstream — that would be a third party telling a client where its own
/// resolver's encrypted endpoints are.
#[tokio::test]
async fn a_missing_ddr_designation_is_refused_rather_than_fetched() {
    let upstream = spawn_upstream().await;
    let (server, _db) = server_with(ResolutionMode::Auto, &upstream);

    let response = ask(
        &server,
        rolodex_dns::svcb::DDR_DESIGNATION_NAME,
        RecordType::SVCB,
    )
    .await;
    assert_eq!(response.response_code(), ResponseCode::Refused);
    assert_eq!(upstream.hits(), 0, "and nothing left the box");
}

/// And the same name without local data is refused — the pair is what shows the
/// refusal is a fall-through rather than a blanket block.
#[tokio::test]
async fn the_same_reverse_name_without_local_data_is_refused() {
    let upstream = spawn_upstream().await;
    let (server, _db) = server_with(ResolutionMode::Auto, &upstream);

    let response = ask(&server, "1.0.0.127.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(
        response.response_code(),
        ResponseCode::Refused,
        "with nothing stored for it, the name is refused rather than resolved"
    );
    assert_eq!(upstream.hits(), 0, "and nothing left the box");
}

/// Label boundary, through the query path this time: a name that merely ends in
/// those letters is resolved normally and does reach the upstream.
#[tokio::test]
async fn the_query_path_matches_on_the_label_boundary() {
    let upstream = spawn_upstream().await;
    let (server, _db) = server_with(ResolutionMode::Forward, &upstream);

    for qname in ["host.notarpa.", "arpa.example.test.", "arpanet.example."] {
        let before = upstream.hits();
        let response = ask(&server, qname, RecordType::A).await;
        assert_eq!(
            response.response_code(),
            ResponseCode::NoError,
            "{qname} is not in the arpa. subtree"
        );
        assert!(
            upstream.hits() > before,
            "{qname} must still be resolved upstream"
        );
    }
}
