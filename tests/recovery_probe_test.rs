//! Integration tests for auto-mode tier recovery.
//!
//! Two properties, and they pull in opposite directions:
//!
//! 1. A box that degraded on a network filtering :53 must reclaim the roots
//!    tier once the network stops filtering — otherwise it is stuck on a
//!    fallback upstream forever.
//! 2. It must reclaim it *only* on a DNSSEC-validated answer. Reachability is
//!    not evidence: a captive portal or an intercepting middlebox on :53 is
//!    perfectly reachable and answers promptly, and promoting the roots on that
//!    basis lets any network that hijacks port 53 install itself as the
//!    most-trusted tier — automatically, silently, displacing the encrypted
//!    upstream the box had correctly fallen back to.
//!
//! A gate that never opens passes every test in category 2, and a gate that
//! always opens passes every test in category 1. Only the pair says anything,
//! which is why both directions are covered here.
//!
//! The hierarchy is the signed mock from [`signed_hierarchy`], anchored to its
//! own root key rather than to IANA's, so the "validated" case is a real chain
//! of trust rather than an assertion.

mod signed_hierarchy;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rolodex_dns::db::Database;
use rolodex_dns::dns_cache::DnsCache;
use rolodex_dns::dns_server::{DnsServer, ResolutionMode};
use rolodex_dns::dnsbl::DnsblChecker;
use rolodex_dns::dnssec_validate::Anchors;
use rolodex_dns::resolver::IterativeResolver;
use signed_hierarchy::{SignedNs, Tamper, Zone, ZoneKey, bind_levels, serve};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Auto-mode tier indices (mirrors the private constants in dns_server).
const TIER_ROOTS: usize = 0;
const TIER_LOCAL: usize = 2;

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 51);
const TLD_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 52);

fn build_query(name: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(0x4321);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(Name::from_ascii(name).expect("name parses"));
    q.set_query_type(qtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    msg.to_bytes().expect("query encodes")
}

fn build_mock_response(query: &Message, answer: Ipv4Addr) -> Vec<u8> {
    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_recursion_desired(query.recursion_desired());
    resp.set_recursion_available(true);
    for q in query.queries() {
        resp.add_query(q.clone());
    }
    resp.set_response_code(ResponseCode::NoError);
    if let Some(q) = query.queries().first() {
        resp.add_answer(Record::from_rdata(
            q.name().clone(),
            300,
            RData::A(rdata::A(answer)),
        ));
    }
    resp.to_bytes().expect("response encodes")
}

/// A plaintext :53 mock that answers everything, standing in for the local
/// forwarder the box degrades onto.
async fn spawn_forwarder(answer: Ipv4Addr) -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("forwarder binds");
    let addr = socket.local_addr().expect("forwarder has an address");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            if let Ok(query) = Message::from_bytes(&buf[..len]) {
                let resp = build_mock_response(&query, answer);
                let _ = socket.send_to(&resp, src).await;
            }
        }
    });
    addr
}

/// An auto-mode server already degraded to the local-forwarder tier, which is
/// the state every one of these tests starts from.
///
/// Degraded organically rather than by poking the tier: dead roots plus a live
/// forwarder, then `switch_grace_failures` queries, which is exactly the path a
/// real box on a filtering network takes to get here.
async fn degraded_server() -> (Arc<DnsServer>, SocketAddr) {
    let forwarder = spawn_forwarder(Ipv4Addr::new(10, 0, 0, 7)).await;
    let db = Database::open_memory().expect("in-memory db");
    let cache = Arc::new(DnsCache::new(db.clone()));
    let rbl = Arc::new(DnsblChecker::new());
    let server = Arc::new(DnsServer::new_with_options(
        db,
        rbl,
        vec![forwarder],
        Some(cache),
        None,
        false, // no qname 0x20, so the mock can echo the question verbatim
    ));
    server.set_resolution_mode(ResolutionMode::Auto);
    // Roots that will never answer: nothing is listening on this loopback
    // address at :53.
    server.set_root_hints(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 59))]);
    server.set_secure_upstreams(vec![]);
    server.set_public_fallback(vec![]);
    server.set_auto_params(3, 3600);

    // Distinct names so the cache cannot short-circuit the upstream path.
    for i in 0..3 {
        let query = build_query(&format!("degrade{i}.example."), RecordType::A);
        server.handle_query(&query).await.expect("query answered");
    }
    assert_eq!(
        server.active_tier(),
        TIER_LOCAL,
        "precondition: the server should have degraded off the dead roots"
    );
    (server, forwarder)
}

/// Stands up a two-level signed hierarchy (`.` delegating `test.`) and returns a
/// resolver anchored to its root, plus the live nameservers.
///
/// `root_tamper` is how the root misbehaves — the whole point of the negative
/// cases, since the probe asks the root zone for its own DNSKEY.
async fn signed_roots(root_tamper: Tamper) -> (IterativeResolver, SignedNs, SignedNs) {
    let root_key = ZoneKey::generate();
    let tld_key = ZoneKey::generate();

    let (port, mut sockets) = bind_levels(&[ROOT_IP, TLD_IP]).await;
    let tld_sock = sockets.pop().expect("tld socket");
    let root_sock = sockets.pop().expect("root socket");

    let root_zone = Zone::new(".", Arc::clone(&root_key))
        .with_signed_child("test.", TLD_IP, &tld_key)
        .with_tamper(root_tamper);
    let tld_zone = Zone::new("test.", Arc::clone(&tld_key));

    let root = serve(root_sock, root_zone);
    let tld = serve(tld_sock, tld_zone);

    let anchors = Anchors::from_dnskey_strings(&[root_key.anchor_string()]).expect("anchor parses");
    let resolver = IterativeResolver::new(vec![ROOT_IP.into()])
        .with_port(port)
        .with_timeout(Duration::from_millis(1500))
        .with_validation(anchors);

    (resolver, root, tld)
}

// The positive case: honest signed roots come back, and the box climbs back to
// its preferred tier. Without this, the gate could be "never recover" and every
// negative test below would still pass.
#[tokio::test]
async fn roots_reclaimed_when_dnssec_validates() {
    let (server, _fwd) = degraded_server().await;
    let (resolver, _root, _tld) = signed_roots(Tamper::None).await;
    server.set_resolver(resolver);

    server.recovery_probe_once().await;

    assert_eq!(
        server.active_tier(),
        TIER_ROOTS,
        "validated roots must reclaim the most-trusted tier"
    );
}

// The case the gate exists for. The roots are reachable and answering — they
// simply answer without signatures, which is what an on-path middlebox stripping
// RRSIGs looks like. Reachable is not trusted.
#[tokio::test]
async fn roots_not_reclaimed_when_answers_are_unsigned() {
    let (server, _fwd) = degraded_server().await;
    let (resolver, root, _tld) = signed_roots(Tamper::StripSignatures).await;
    server.set_resolver(resolver);

    server.recovery_probe_once().await;

    assert!(
        root.hits() > 0,
        "precondition: the probe must actually have reached the root"
    );
    assert_eq!(
        server.active_tier(),
        TIER_LOCAL,
        "unsigned roots are reachable but unvalidated and must NOT be promoted"
    );
}

// Signatures that are present and do not verify: bogus, not merely unsigned. A
// validator that folds these into "insecure" would promote an actively hostile
// root.
#[tokio::test]
async fn roots_not_reclaimed_when_signatures_are_bogus() {
    let (server, _fwd) = degraded_server().await;
    let (resolver, _root, _tld) = signed_roots(Tamper::SignWithForeignKey).await;
    server.set_resolver(resolver);

    server.recovery_probe_once().await;

    assert_eq!(
        server.active_tier(),
        TIER_LOCAL,
        "roots signed by the wrong key must NOT be promoted"
    );
}

// A replayed capture: the chain is intact, the window closed a year ago.
#[tokio::test]
async fn roots_not_reclaimed_when_signatures_expired() {
    let (server, _fwd) = degraded_server().await;
    let (resolver, _root, _tld) = signed_roots(Tamper::ExpiredSignatures).await;
    server.set_resolver(resolver);

    server.recovery_probe_once().await;

    assert_eq!(
        server.active_tier(),
        TIER_LOCAL,
        "expired root signatures must NOT be promoted"
    );
}

// Unreachable roots leave the tier alone, and — the reason any of this changed —
// the probe returns promptly instead of running the iterative resolver out to
// its 64-query budget. The bound is what keeps a dead root set from being a
// minute-long stall.
#[tokio::test]
async fn roots_not_reclaimed_when_unreachable_and_probe_is_bounded() {
    let (server, _fwd) = degraded_server().await;
    // Resolver left pointed at the dead loopback root from `degraded_server`.

    let started = std::time::Instant::now();
    server.recovery_probe_once().await;
    let elapsed = started.elapsed();

    assert_eq!(
        server.active_tier(),
        TIER_LOCAL,
        "unreachable roots must not reclaim the tier"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "probe ran {elapsed:?}; the roots tier is supposed to be wall-clock bounded"
    );
}

// The probe must not disturb a box that is already at the top: there is nothing
// above roots to reclaim, so it should not issue a query at all.
#[tokio::test]
async fn probe_is_a_noop_at_the_top_tier() {
    let (resolver, root, _tld) = signed_roots(Tamper::None).await;
    let db = Database::open_memory().expect("in-memory db");
    let rbl = Arc::new(DnsblChecker::new());
    let server = Arc::new(DnsServer::new(db, rbl, vec![]));
    server.set_resolution_mode(ResolutionMode::Auto);
    server.set_resolver(resolver);
    assert_eq!(server.active_tier(), TIER_ROOTS);

    server.recovery_probe_once().await;

    assert_eq!(server.active_tier(), TIER_ROOTS);
    assert_eq!(
        root.hits(),
        0,
        "nothing to reclaim at the top tier, so the probe must not query"
    );
}

// A client query is never spent probing. This is the regression guard for the
// reported hang: the query path used to hijack one lookup per interval and
// restart it at the roots, which on a filtered network stalled that client for
// tens of seconds. Even with the interval set to its floor, ordinary queries
// must stay fast and must never touch the roots.
#[tokio::test]
async fn client_queries_never_pay_for_a_recovery_probe() {
    let (server, _fwd) = degraded_server().await;
    let (resolver, root, _tld) = signed_roots(Tamper::None).await;
    server.set_resolver(resolver);
    // Interval floored so the *old* behavior would elect a probe immediately.
    server.set_auto_params(3, 1);
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let root_hits_before = root.hits();
    for i in 0..8 {
        let query = build_query(&format!("client{i}.example."), RecordType::A);
        let started = std::time::Instant::now();
        let resp = Message::from_bytes(&server.handle_query(&query).await.expect("answered"))
            .expect("response parses");
        let elapsed = started.elapsed();

        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(
            elapsed < Duration::from_secs(1),
            "client query {i} took {elapsed:?}; no client query may be conscripted into probing"
        );
    }

    assert_eq!(
        root.hits(),
        root_hits_before,
        "the query path must never reach the roots once degraded off them"
    );
    assert_eq!(server.active_tier(), TIER_LOCAL);
}

// The recovery loop is spawned UNCONDITIONALLY at startup, not only when the
// configured mode is auto, because the mode is no longer fixed for the life of
// the process — SetResolutionMode can switch a running server into auto, and a
// box that got there would otherwise degrade past a dead tier and never climb
// back, with no symptom beyond permanently slower and less private resolution.
//
// What makes that spawn safe is this: each pass re-reads the mode and returns
// immediately outside auto, so the loop costs one sleeping task in the modes
// that do not use it. Without this property the unconditional spawn would have
// recursive- and forward-mode boxes issuing probe queries they never asked for.
#[tokio::test]
async fn probe_does_nothing_outside_auto() {
    let (resolver, root, _tld) = signed_roots(Tamper::None).await;
    let db = Database::open_memory().expect("in-memory db");
    let dnsbl = Arc::new(DnsblChecker::new());
    let server = Arc::new(DnsServer::new(db, dnsbl, vec![]));
    server.set_resolver(resolver);

    for mode in [ResolutionMode::Recursive, ResolutionMode::Forward] {
        server.set_resolution_mode(mode);
        server.recovery_probe_once().await;
        assert_eq!(
            root.hits(),
            0,
            "the probe queried in {mode:?}, a mode that has no tier chain to reclaim"
        );
    }
}

// And the switch itself is observed: the mode an RPC sets is the mode the
// running server reports and the probe gates on. This is the half that makes
// the loop start working the moment a box is switched into auto, rather than at
// the next restart.
#[tokio::test]
async fn a_runtime_mode_switch_is_what_the_probe_reads() {
    let db = Database::open_memory().expect("in-memory db");
    let dnsbl = Arc::new(DnsblChecker::new());
    let server = Arc::new(DnsServer::new(db, dnsbl, vec![]));

    server.set_resolution_mode(ResolutionMode::Recursive);
    assert_eq!(server.get_resolution_mode(), ResolutionMode::Recursive);

    server.set_resolution_mode(ResolutionMode::Auto);
    assert_eq!(
        server.get_resolution_mode(),
        ResolutionMode::Auto,
        "a runtime switch into auto must be visible to the probe's gate"
    );
}
