//! Security regression tests for the Do53 forwarding path (`forward_udp`).
//!
//! Every test here asserts behaviour the forwarder *should* have and is expected
//! to FAIL against the current implementation. Each pins one missing response
//! validation check. Do not weaken an assertion to make it pass.
//!
//! `forward_udp` sends a query and accepts whatever comes back:
//!
//! - the transaction id is never compared (`resolver.rs` does this; the
//!   forwarder does not),
//! - the pooled sockets are `bind`-ed but never `connect`-ed, so the kernel
//!   delivers datagrams from *any* source address,
//! - the response question is never matched against the query, and
//! - the 0x20 case check emits `warn!` on mismatch and then returns the response
//!   anyway, so `security.qname_case_randomization` — on by default and
//!   documented as cache-poisoning resistance — enforces nothing.
//!
//! The sockets are also bound once and reused for the process lifetime, so their
//! source ports are stable after a single observation. Together these turn
//! off-path cache poisoning from a ~32-bit guess into no guess at all.
//!
//! Each test drives a hostile mock upstream that violates exactly one of these
//! invariants and asserts the server does not serve — and does not cache — the
//! forged answer. Everything is loopback and in-process; the host is untouched.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rolodex_dns::db::Database;
use rolodex_dns::dns_cache::DnsCache;
use rolodex_dns::dns_server::{DnsServer, ResolutionMode};
use rolodex_dns::dnsbl::DnsblChecker;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

/// The address a forged answer points at. If this shows up in a response the
/// forgery was accepted.
const FORGED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 66);

fn build_query(name: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(0x4321);
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

/// How a hostile upstream should corrupt its reply.
#[derive(Clone, Copy)]
enum Forgery {
    /// Answer with a transaction id the server never used.
    WrongTransactionId,
    /// Answer a different question than the one asked.
    WrongQuestion,
    /// Echo the question with the 0x20 case bits flipped back to lowercase,
    /// as an off-path forger who could not observe the randomized query would.
    StrippedQnameCase,
    /// Reply correctly, but from a socket the server never sent to.
    UnexpectedSource,
}

/// Builds a reply echoing the query, with `FORGED` as the answer, applying the
/// requested corruption.
fn build_forged_reply(query: &Message, forgery: Forgery) -> Vec<u8> {
    let mut resp = Message::new();
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_recursion_available(true);
    resp.set_response_code(ResponseCode::NoError);

    match forgery {
        Forgery::WrongTransactionId => {
            resp.set_id(query.id().wrapping_add(1));
        }
        _ => {
            resp.set_id(query.id());
        }
    }

    let asked = query.queries().first().expect("question").clone();
    let answered_name = match forgery {
        Forgery::WrongQuestion => Name::from_ascii("unrelated.example.").unwrap(),
        Forgery::StrippedQnameCase => {
            // Undo 0x20 encoding: a forger guessing the name gets the case wrong.
            Name::from_ascii(asked.name().to_ascii().to_lowercase()).unwrap()
        }
        _ => asked.name().clone(),
    };

    let mut q = Query::new();
    q.set_name(answered_name.clone());
    q.set_query_type(asked.query_type());
    q.set_query_class(asked.query_class());
    resp.add_query(q);
    resp.add_answer(Record::from_rdata(
        answered_name,
        300,
        RData::A(rdata::A(FORGED)),
    ));
    resp.to_bytes().unwrap()
}

/// Spawns a hostile mock upstream applying `forgery` to every reply.
///
/// For `UnexpectedSource` the reply is sent from a *second*, unrelated socket,
/// so it arrives at the server's forwarding socket from an address the server
/// never queried — exactly the datagram an off-path attacker injects.
async fn spawn_hostile_upstream(forgery: Forgery) -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let spoofer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let Ok(query) = Message::from_bytes(&buf[..len]) else {
                continue;
            };
            let reply = build_forged_reply(&query, forgery);
            let sent = match forgery {
                // A different source address than the one that was queried.
                Forgery::UnexpectedSource => spoofer.send_to(&reply, src).await,
                _ => socket.send_to(&reply, src).await,
            };
            if sent.is_err() {
                break;
            }
        }
    });
    addr
}

/// A pure-forwarding server pointed at `forwarder`, with the answer cache on so
/// the tests can also assert a forgery is not persisted.
fn make_forwarding_server(forwarder: SocketAddr, qname_randomization: bool) -> Arc<DnsServer> {
    let db = Database::open_memory().unwrap();
    let cache = Arc::new(DnsCache::new(db.clone()));
    let rbl = Arc::new(DnsblChecker::new());
    let server = Arc::new(DnsServer::new_with_options(
        db,
        rbl,
        vec![forwarder],
        Some(cache),
        None,
        qname_randomization,
    ));
    server.set_resolution_mode(ResolutionMode::Forward);
    server
}

/// Whether a wire response carries the forged address.
fn contains_forged_answer(wire: &[u8]) -> bool {
    let Ok(msg) = Message::from_bytes(wire) else {
        return false;
    };
    msg.answers().iter().any(|r| match r.data() {
        RData::A(a) => a.0 == FORGED,
        _ => false,
    })
}

/// Runs one query against a hostile upstream and returns the parsed response.
async fn query_hostile(forgery: Forgery, qname_randomization: bool, name: &str) -> Vec<u8> {
    let upstream = spawn_hostile_upstream(forgery).await;
    let server = make_forwarding_server(upstream, qname_randomization);
    let query = build_query(name, RecordType::A);
    server.handle_query(&query).await.unwrap()
}

// ============================================================================
// Transaction id
// ============================================================================

/// The forwarder never compares the response's transaction id to the query's.
/// A reply carrying an id the server never issued must be discarded — it did not
/// answer any outstanding question.
#[tokio::test]
async fn forwarder_rejects_wrong_transaction_id() {
    let wire = query_hostile(Forgery::WrongTransactionId, false, "txid.example.").await;

    assert!(
        !contains_forged_answer(&wire),
        "a response whose transaction id does not match the query was accepted"
    );
    let msg = Message::from_bytes(&wire).unwrap();
    assert_eq!(
        msg.response_code(),
        ResponseCode::ServFail,
        "with no valid answer available the query should SERVFAIL"
    );
}

// ============================================================================
// Source address
// ============================================================================

/// The pooled forwarding sockets are never `connect`-ed, so `recv` accepts a
/// datagram from any source. A reply from an address the server did not query
/// must be discarded; otherwise an off-path attacker needs only the socket's
/// port, which is stable for the process lifetime across just 8 sockets.
#[tokio::test]
async fn forwarder_rejects_response_from_unexpected_source() {
    let wire = query_hostile(Forgery::UnexpectedSource, false, "source.example.").await;

    assert!(
        !contains_forged_answer(&wire),
        "a response from an address the server never queried was accepted; \
         the forwarding socket must be connected to the upstream (or the source \
         address checked) so the kernel drops off-path datagrams"
    );
}

// ============================================================================
// Question matching
// ============================================================================

/// The forwarder never compares the response's question to the query's, so a
/// reply about an entirely different name is accepted and cached under whatever
/// question it happens to carry.
#[tokio::test]
async fn forwarder_rejects_mismatched_question() {
    let wire = query_hostile(Forgery::WrongQuestion, false, "question.example.").await;

    assert!(
        !contains_forged_answer(&wire),
        "a response answering a different question than the one asked was accepted"
    );
}

// ============================================================================
// 0x20 QNAME case randomization
// ============================================================================

/// `security.qname_case_randomization` is on by default and documented as
/// cache-poisoning resistance, but the check only logs: on mismatch `forward_udp`
/// emits `warn!` and returns the response regardless. A forger who cannot observe
/// the outbound query cannot reproduce the case pattern, so enforcing the check
/// is the entire value of the feature.
#[tokio::test]
async fn forwarder_enforces_qname_case_match() {
    // A name with enough alpha characters that randomization is near-certain to
    // differ from the all-lowercase form.
    let wire = query_hostile(
        Forgery::StrippedQnameCase,
        true,
        "averylongmixedcasename.example.",
    )
    .await;

    assert!(
        !contains_forged_answer(&wire),
        "0x20 case mismatch is logged but not enforced: the response was accepted. \
         A QNAME case mismatch must cause the response to be discarded."
    );
}

/// The same check must hold on the caching side: a rejected response must not
/// reach the answer cache, or the forgery outlives the query that carried it.
#[tokio::test]
async fn rejected_forgery_is_not_cached() {
    let upstream = spawn_hostile_upstream(Forgery::WrongTransactionId).await;
    let server = make_forwarding_server(upstream, false);
    let query = build_query("nocache.example.", RecordType::A);

    // First query: the forgery should be rejected.
    let first = server.handle_query(&query).await.unwrap();
    assert!(
        !contains_forged_answer(&first),
        "forged answer served on the first query"
    );

    // Second query: if the first was cached, it is served from memory now.
    let second = server.handle_query(&query).await.unwrap();
    assert!(
        !contains_forged_answer(&second),
        "a response that failed validation was written to the answer cache"
    );
}

// ============================================================================
// Control: a well-behaved upstream must still work
// ============================================================================

/// The counterpart to the tests above: an upstream that echoes the id, the
/// question, and the 0x20 case is legitimate and must be served normally. This
/// guards against a fix that rejects everything.
#[tokio::test]
async fn honest_upstream_is_still_accepted() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let Ok(query) = Message::from_bytes(&buf[..len]) else {
                continue;
            };
            // Echo everything faithfully, including the randomized case.
            let mut resp = Message::new();
            resp.set_id(query.id());
            resp.set_message_type(MessageType::Response);
            resp.set_op_code(OpCode::Query);
            resp.set_recursion_available(true);
            resp.set_response_code(ResponseCode::NoError);
            if let Some(q) = query.queries().first() {
                resp.add_query(q.clone());
                resp.add_answer(Record::from_rdata(
                    q.name().clone(),
                    300,
                    RData::A(rdata::A(FORGED)),
                ));
            }
            if socket
                .send_to(&resp.to_bytes().unwrap(), src)
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let server = make_forwarding_server(upstream, true);
    let query = build_query("honest.example.", RecordType::A);
    let wire = server.handle_query(&query).await.unwrap();

    assert!(
        contains_forged_answer(&wire),
        "a faithful upstream response must still be accepted"
    );
}
