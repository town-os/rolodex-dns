//! Integration tests for the `auto` resolution fallback chain
//! (roots → DoT → local forwarder → public :53).
//!
//! Root recursion is pointed at loopback so it fails fast, and the DoT (secure)
//! tier is left empty (real TLS isn't available in tests), so these exercise the
//! plaintext forwarding tiers and the definitive-answer/fallthrough logic with
//! mock UDP upstreams — mirroring a network that filters outbound :53.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rolodex_dns::db::Database;
use rolodex_dns::dns_cache::DnsCache;
use rolodex_dns::dns_server::{DnsServer, ResolutionMode};
use rolodex_dns::rbl::RblChecker;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

/// The auto-mode tier indices (mirrors the private constants in dns_server).
const TIER_ROOTS: usize = 0;
const TIER_LOCAL: usize = 2;

fn build_query(name: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(0x1234);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(Name::from_ascii(name).unwrap());
    q.set_query_type(qtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    msg.to_bytes().unwrap()
}

/// Builds a mock upstream reply: echoes the query's id/question, sets `rcode`,
/// and (optionally) adds a single A answer.
fn build_mock_response(query: &Message, rcode: ResponseCode, answer: Option<Ipv4Addr>) -> Vec<u8> {
    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_recursion_desired(query.recursion_desired());
    resp.set_recursion_available(true);
    for q in query.queries() {
        resp.add_query(q.clone());
    }
    resp.set_response_code(rcode);
    if let (Some(ip), Some(q)) = (answer, query.queries().first()) {
        resp.add_answer(Record::from_rdata(
            q.name().clone(),
            300,
            RData::A(rdata::A(ip)),
        ));
    }
    resp.to_bytes().unwrap()
}

/// Spawns a mock UDP DNS upstream that answers every query with the given rcode
/// and optional A record. Returns its address.
async fn spawn_mock_upstream(rcode: ResponseCode, answer: Option<Ipv4Addr>) -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            if let Ok(query) = Message::from_bytes(&buf[..len]) {
                let resp = build_mock_response(&query, rcode, answer);
                let _ = socket.send_to(&resp, src).await;
            }
        }
    });
    addr
}

/// An auto-mode server whose root tier is forced to fail fast (loopback hint)
/// and whose secure/DoT tier is empty, so the plaintext forward tiers decide.
fn make_auto_server(forwarders: Vec<SocketAddr>, public: Vec<SocketAddr>) -> Arc<DnsServer> {
    let db = Database::open_memory().unwrap();
    let cache = Arc::new(DnsCache::new(db.clone()));
    let rbl = Arc::new(RblChecker::new(false, vec![]));
    let server = Arc::new(DnsServer::new_with_options(
        db,
        rbl,
        forwarders,
        Some(cache),
        None,
        false, // no qname 0x20 so the mock can echo the question verbatim
    ));
    server.set_resolution_mode(ResolutionMode::Auto);
    server.set_root_hints(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    server.set_secure_upstreams(vec![]);
    server.set_public_fallback(public);
    server
}

// When roots (tier 0) fail, resolution falls through the empty secure tier to
// the local forwarder (tier 2), which answers.
#[tokio::test]
async fn auto_falls_back_to_local_forwarder() {
    let local = spawn_mock_upstream(ResponseCode::NoError, Some(Ipv4Addr::new(10, 1, 2, 3))).await;
    let server = make_auto_server(vec![local], vec![]);

    let query = build_query("fallback.example.", RecordType::A);
    let resp = Message::from_bytes(&server.handle_query(&query).await.unwrap()).unwrap();

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert_eq!(resp.answers().len(), 1);
    assert_eq!(server.active_tier(), TIER_ROOTS); // single deviation < grace: no switch yet
}

// A ServFail from the local forwarder is not definitive — resolution continues
// to the public :53 tier, whose answer is returned.
#[tokio::test]
async fn auto_skips_servfail_and_uses_public_fallback() {
    let local = spawn_mock_upstream(ResponseCode::ServFail, None).await;
    let public = spawn_mock_upstream(ResponseCode::NoError, Some(Ipv4Addr::new(9, 9, 9, 9))).await;
    let server = make_auto_server(vec![local], vec![public]);

    let query = build_query("skip-servfail.example.", RecordType::A);
    let resp = Message::from_bytes(&server.handle_query(&query).await.unwrap()).unwrap();

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert_eq!(resp.answers().len(), 1);
    // Proves the answer came from the public tier, not the ServFailing local one.
    match resp.answers()[0].data() {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(9, 9, 9, 9)),
        other => panic!("expected A record, got {:?}", other),
    }
}

// NXDOMAIN is an authoritative answer: it must be returned as-is, NOT treated as
// a failure that falls through to a lower tier.
#[tokio::test]
async fn auto_returns_nxdomain_without_falling_through() {
    let local = spawn_mock_upstream(ResponseCode::NXDomain, None).await;
    // If fallthrough (incorrectly) happened, this positive answer would appear.
    let public = spawn_mock_upstream(ResponseCode::NoError, Some(Ipv4Addr::new(9, 9, 9, 9))).await;
    let server = make_auto_server(vec![local], vec![public]);

    let query = build_query("gone.example.", RecordType::A);
    let resp = Message::from_bytes(&server.handle_query(&query).await.unwrap()).unwrap();

    assert_eq!(resp.response_code(), ResponseCode::NXDomain);
    assert!(resp.answers().is_empty());
}

// After `switch_grace_failures` (default 3) consecutive queries answered by a
// lower tier, the sticky active tier commits to it.
#[tokio::test]
async fn auto_commits_switch_after_grace() {
    let local = spawn_mock_upstream(ResponseCode::NoError, Some(Ipv4Addr::new(10, 0, 0, 7))).await;
    let server = make_auto_server(vec![local], vec![]);

    // Distinct names each iteration so the cache doesn't short-circuit the
    // upstream path — each query must actually reach a resolution tier.
    for i in 0..3 {
        let query = build_query(&format!("degrade{i}.example."), RecordType::A);
        let resp = Message::from_bytes(&server.handle_query(&query).await.unwrap()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
    }
    assert_eq!(server.active_tier(), TIER_LOCAL);
}

// Live smoke test of the encrypted (secure) client against the default public
// resolvers, in the order the secure tier prefers them: DoH (:443) first, then
// DoT (:853). Passes if ANY succeeds — mirroring `tier_secure`, so a network
// that DPI-blocks one provider/transport (observed: some filter 1.1.1.1:853 at
// the TLS layer while :443 DoH works) still validates the client via another.
// Ignored by default (needs outbound network). Run with:
//   cargo test --test auto_resolution_test -- --ignored secure_live
#[tokio::test]
#[ignore = "requires network access to a public DoH/DoT resolver"]
async fn secure_live_query_public() {
    use rolodex_dns::config::SecureUpstreamConfig;
    use rolodex_dns::secure_client::{SecureUpstream, query};

    // (transport, addr, hostname) — DoH (:443) preferred, DoT (:853) as fallback.
    let candidates = [
        ("https", "1.1.1.1:443", "cloudflare-dns.com"),
        ("https", "8.8.8.8:443", "dns.google"),
        ("tls", "8.8.8.8:853", "dns.google"),
    ];
    let dns_query = build_query("example.com.", RecordType::A);

    let mut last_err = None;
    for (transport, addr, hostname) in candidates {
        let up = SecureUpstream::from_config(&SecureUpstreamConfig {
            transport: transport.to_string(),
            addr: addr.to_string(),
            hostname: hostname.to_string(),
            path: "/dns-query".to_string(),
        })
        .unwrap();
        match query(&dns_query, &up, std::time::Duration::from_secs(8)).await {
            Ok(resp_bytes) => {
                let resp = Message::from_bytes(&resp_bytes).unwrap();
                assert_eq!(resp.response_code(), ResponseCode::NoError);
                assert!(
                    resp.answers()
                        .iter()
                        .any(|r| matches!(r.data(), RData::A(_))),
                    "expected at least one A record from {transport}://{addr}"
                );
                eprintln!("secure client validated via {transport}://{addr}");
                return;
            }
            Err(e) => {
                eprintln!("secure {transport}://{addr} failed (may be filtered): {e}");
                last_err = Some(e);
            }
        }
    }
    panic!("no secure upstream reachable; last error: {last_err:?}");
}
