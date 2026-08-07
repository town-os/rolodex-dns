//! Security regression tests for open recursion and DNS amplification.
//!
//! These assert behaviour the server *should* have and are expected to FAIL
//! against the current implementation. Do not weaken an assertion to make one
//! pass.
//!
//! `dns.bind` defaults to `0.0.0.0:53`, and source classification treats
//! everything outside `security.overlay_cidrs` as a *trusted local source* that
//! receives full upstream resolution. A host on the public internet is outside
//! the overlay range, so a default deployment on a routable interface is an open
//! recursive resolver — the classic reflection/amplification asset. Nothing in
//! `src/` rate-limits anything.
//!
//! **These tests deliberately introduce no new configuration API.** The obvious
//! way to pin this would be to invent `security.recursion_cidrs` and assert
//! against it, but a test referencing an item that does not exist fails to
//! *compile*, which breaks `cargo check` for the whole crate rather than
//! reporting one red test. So each assertion here is stated purely in terms of
//! observable behaviour, and stays true regardless of how the fix is configured:
//!
//! - a source on the public internet must not be able to make this server emit
//!   an upstream query (the open-resolver property), and
//! - whatever it does get back must not be larger than what it sent (the
//!   amplification property).
//!
//! The upstream hit counter is the load-bearing assertion. "Did the server
//! answer?" is ambiguous — a locally-served name legitimately produces an
//! answer. "Did an untrusted stranger cause an outbound query?" is not.
//!
//! Everything is loopback and in-process; the host is untouched.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rolodex_dns::db::Database;
use rolodex_dns::dns_cache::DnsCache;
use rolodex_dns::dns_server::{DnsServer, ResolutionMode};
use rolodex_dns::rbl::RblChecker;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A source on the public internet (TEST-NET-2, RFC 5737).
const PUBLIC_SOURCE: &str = "198.51.100.7";
/// An ordinary LAN client.
const LAN_SOURCE: &str = "192.168.1.10";

const UPSTREAM_ANSWER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 5);

fn build_query(name: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(0x2468);
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

/// Spawns a mock upstream that answers everything, counting the queries it is
/// asked to perform. The counter is the evidence.
async fn spawn_counting_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, src)) = socket.recv_from(&mut buf).await else {
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
            resp.set_response_code(ResponseCode::NoError);
            if let Some(q) = query.queries().first() {
                resp.add_query(q.clone());
                // Several answers, so a reflected response is meaningfully
                // larger than the query that triggered it.
                for _ in 0..8 {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        300,
                        RData::A(rdata::A(UPSTREAM_ANSWER)),
                    ));
                }
            }
            if socket
                .send_to(&resp.to_bytes().unwrap_or_default(), src)
                .await
                .is_err()
            {
                return;
            }
        }
    });

    (addr, hits)
}

/// A forwarding server pointed at a counting upstream.
async fn make_server() -> (Arc<DnsServer>, Arc<AtomicUsize>) {
    let (upstream, hits) = spawn_counting_upstream().await;
    let db = Database::open_memory().unwrap();
    let cache = Arc::new(DnsCache::new(db.clone()));
    let rbl = Arc::new(RblChecker::new(false, vec![]));
    let server = Arc::new(DnsServer::new_with_options(
        db,
        rbl,
        vec![upstream],
        Some(cache),
        None,
        false,
    ));
    server.set_resolution_mode(ResolutionMode::Forward);
    (server, hits)
}

async fn query_from(server: &DnsServer, source: &str, name: &str) -> Vec<u8> {
    let ip: IpAddr = source.parse().unwrap();
    let query = build_query(name, RecordType::A);
    server.handle_query_from(&query, ip).await.unwrap()
}

// ============================================================================
// Open recursion
// ============================================================================

/// A stranger on the internet must not be able to make this server resolve on
/// their behalf. Today every source outside `security.overlay_cidrs` is
/// classified as a trusted local source, so a public address gets the full
/// recursive service — which is what makes a default deployment an open
/// resolver.
///
/// The assertion is on the upstream hit counter rather than the response,
/// because "did an untrusted source cause an outbound query" is the open-resolver
/// property exactly, whatever rcode the client ends up seeing.
#[tokio::test]
async fn public_source_cannot_drive_upstream_resolution() {
    let (server, upstream_hits) = make_server().await;

    query_from(&server, PUBLIC_SOURCE, "not-local.example.").await;

    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        0,
        "a query from {} caused this server to resolve upstream on the stranger's \
         behalf: it is an open recursive resolver, and on a routable bind that is \
         a reflection/amplification asset",
        PUBLIC_SOURCE
    );
}

/// The response a public source does receive must not be larger than the query
/// it sent. Amplification is the reason open resolvers are abused: a small
/// spoofed query returning a large answer turns the server into a force
/// multiplier aimed at the spoofed victim. REFUSED — which is smaller than the
/// question that provoked it — is the correct shape of reply.
#[tokio::test]
async fn public_source_response_does_not_amplify() {
    let (server, _hits) = make_server().await;
    let query = build_query("not-local.example.", RecordType::A);
    let ip: IpAddr = PUBLIC_SOURCE.parse().unwrap();

    let response = server.handle_query_from(&query, ip).await.unwrap();

    assert!(
        response.len() <= query.len(),
        "a {}-byte query from {} produced a {}-byte response (amplification \
         factor {:.1}x); an untrusted source must not receive more than it sent",
        query.len(),
        PUBLIC_SOURCE,
        response.len(),
        response.len() as f64 / query.len() as f64
    );
}

/// A public source repeating the same query must not keep costing upstream
/// traffic. Even once the first query is refused, this pins the second half of
/// the problem: with no rate limiting, a flood from a spoofed source is answered
/// as fast as it arrives.
#[tokio::test]
async fn sustained_public_flood_is_not_serviced() {
    let (server, upstream_hits) = make_server().await;

    for i in 0..50 {
        let name = format!("flood{}.example.", i);
        query_from(&server, PUBLIC_SOURCE, &name).await;
    }

    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        0,
        "50 queries from {} produced {} upstream queries; an untrusted source can \
         drive unbounded outbound traffic",
        PUBLIC_SOURCE,
        upstream_hits.load(Ordering::SeqCst)
    );
}

// ============================================================================
// Controls: the LAN must keep working
// ============================================================================

/// The mirror invariant, and the reason this cannot simply be "refuse everyone":
/// a LAN client is the server's actual audience and must still resolve normally.
/// A fix that closes recursion has to keep this green.
#[tokio::test]
async fn lan_source_still_resolves_upstream() {
    let (server, upstream_hits) = make_server().await;

    let wire = query_from(&server, LAN_SOURCE, "not-local.example.").await;
    let msg = Message::from_bytes(&wire).unwrap();

    assert_eq!(
        msg.response_code(),
        ResponseCode::NoError,
        "a LAN client must still get recursive service"
    );
    assert!(
        upstream_hits.load(Ordering::SeqCst) > 0,
        "a LAN client's query should have reached the upstream"
    );
}

/// Loopback — the box's own resolver, and the path `/etc/resolv.conf` uses — must
/// likewise keep working.
#[tokio::test]
async fn loopback_source_still_resolves_upstream() {
    let (server, upstream_hits) = make_server().await;

    let wire = query_from(&server, "127.0.0.1", "not-local.example.").await;
    let msg = Message::from_bytes(&wire).unwrap();

    assert_eq!(
        msg.response_code(),
        ResponseCode::NoError,
        "the local host must still get recursive service"
    );
    assert!(upstream_hits.load(Ordering::SeqCst) > 0);
}

/// Serving *local* data to any source is a separate decision from recursing on
/// its behalf, and closing recursion must not silently turn the server into a
/// non-answering box for names it is genuinely authoritative for. This documents
/// the intended boundary: no recursion for strangers, authoritative data still
/// served.
#[tokio::test]
async fn public_source_may_still_receive_authoritative_local_data() {
    let (upstream, upstream_hits) = spawn_counting_upstream().await;
    let db = Database::open_memory().unwrap();
    db.add_record(&rolodex_dns::db::DnsRecord {
        id: None,
        name: "www.local.test.".to_string(),
        record_type: rolodex_dns::db::RecordKind::A,
        value: "10.0.0.9".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();
    let rbl = Arc::new(RblChecker::new(false, vec![]));
    let server = Arc::new(DnsServer::new_with_options(
        db,
        rbl,
        vec![upstream],
        None,
        None,
        false,
    ));
    server.set_resolution_mode(ResolutionMode::Forward);

    let wire = query_from(&server, PUBLIC_SOURCE, "www.local.test.").await;
    let msg = Message::from_bytes(&wire).unwrap();

    assert_eq!(
        msg.response_code(),
        ResponseCode::NoError,
        "locally-authoritative data may still be served to any source"
    );
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        0,
        "a locally-served name must not touch the upstream at all"
    );
}
