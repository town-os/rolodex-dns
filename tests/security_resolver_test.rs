//! Security regression tests for the iterative resolver's response validation.
//!
//! These assert behaviour the resolver *should* have and are expected to FAIL
//! against the current implementation. Do not weaken an assertion to make one
//! pass.
//!
//! `resolver.rs` is the better-defended of the two upstream paths — unlike the
//! Do53 forwarder it does check the transaction id (`query_one`, `resolver.rs:939`)
//! — but two gaps remain:
//!
//! - **The socket is never connected.** `query_one` does `UdpSocket::bind` then
//!   `send_to` then `recv`, so the kernel hands it a datagram from *any* source.
//!   The source address check that normally forces an off-path attacker to spoof
//!   the authoritative server's IP simply is not there; the only secrets left are
//!   the random transaction id and the ephemeral port. Calling `connect()` on the
//!   socket restores it for free, in the kernel, with no per-packet cost.
//!
//! - **`validate_question` compares only the name.** It checks
//!   `names_equal(q.name(), qname)` and never looks at the query type or class,
//!   so a response answering a question the resolver never asked is accepted as
//!   though it had.
//!
//! Each test drives a hostile authoritative server that violates exactly one of
//! these and asserts the forged data does not surface. The hostile servers are
//! written here rather than added to `mock_hierarchy` because that harness models
//! *honest* nameservers and is shared by the correctness suites.
//!
//! Everything is loopback and in-process; the host is untouched.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rolodex_dns::resolver::IterativeResolver;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
/// The address a forged answer points at. If it surfaces, the forgery was taken.
const FORGED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 99);

fn name(s: &str) -> Name {
    Name::from_str(s).expect("valid name")
}

/// How a hostile authoritative server corrupts its reply.
#[derive(Clone, Copy)]
enum Forgery {
    /// Correct id, correct question — but sent from a socket the resolver never
    /// queried, as an off-path injector's packet would be.
    UnexpectedSource,
    /// Correct id and question *name*, but the question's type is one the
    /// resolver never asked about.
    MismatchedQuestionType,
    /// Correct id and question name, but a different DNS class.
    MismatchedQuestionClass,
}

/// Builds a reply carrying `FORGED` as the answer, corrupted per `forgery`.
fn build_forged_reply(query: &Message, forgery: Forgery) -> Vec<u8> {
    let asked = query.queries().first().expect("question").clone();

    let mut resp = Message::new();
    resp.set_id(query.id()); // the id is checked today; get it right
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_authoritative(true);
    resp.set_response_code(ResponseCode::NoError);

    let mut q = Query::new();
    q.set_name(asked.name().clone());
    match forgery {
        Forgery::MismatchedQuestionType => {
            // Asked A, answering a question about AAAA.
            q.set_query_type(RecordType::AAAA);
            q.set_query_class(asked.query_class());
        }
        Forgery::MismatchedQuestionClass => {
            q.set_query_type(asked.query_type());
            q.set_query_class(DNSClass::CH);
        }
        Forgery::UnexpectedSource => {
            q.set_query_type(asked.query_type());
            q.set_query_class(asked.query_class());
        }
    }
    resp.add_query(q);

    resp.add_answer(Record::from_rdata(
        asked.name().clone(),
        300,
        RData::A(rdata::A(FORGED)),
    ));
    resp.to_bytes().unwrap_or_default()
}

/// A hostile authoritative server. Returns `(port, hit counter)`.
///
/// Binds `ROOT_IP` on an ephemeral port and answers every query with a forged
/// reply. For `UnexpectedSource` the reply goes out through a *second* socket, so
/// it reaches the resolver from an address it never sent to.
async fn spawn_hostile_root(forgery: Forgery) -> (u16, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind((ROOT_IP, 0))
        .await
        .expect("bind hostile root");
    let port = socket.local_addr().expect("addr").port();
    let spoofer = UdpSocket::bind((ROOT_IP, 0)).await.expect("bind spoofer");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);

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
            let reply = build_forged_reply(&query, forgery);
            let sent = match forgery {
                Forgery::UnexpectedSource => spoofer.send_to(&reply, peer).await,
                _ => socket.send_to(&reply, peer).await,
            };
            if sent.is_err() {
                return;
            }
        }
    });

    (port, hits)
}

fn resolver_for(port: u16) -> IterativeResolver {
    IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        // Short, so a rejected forgery fails the lookup quickly instead of
        // making the test wait out the default budget.
        .with_timeout(Duration::from_millis(400))
}

/// Whether a resolution surfaced the forged address.
fn contains_forged(resolution: &rolodex_dns::resolver::Resolution) -> bool {
    resolution.answers.iter().any(|r| match r.data() {
        RData::A(a) => a.0 == FORGED,
        _ => false,
    })
}

// ============================================================================
// Source address
// ============================================================================

/// `query_one` binds its UDP socket and never connects it, so `recv` accepts a
/// datagram from any peer. A reply from an address the resolver did not query
/// must be ignored — with the socket connected the kernel drops it before the
/// process ever sees it, which is both the correct behaviour and the cheap one.
#[tokio::test]
async fn resolver_ignores_response_from_unexpected_source() {
    let (port, hits) = spawn_hostile_root(Forgery::UnexpectedSource).await;
    let resolver = resolver_for(port);

    let result = resolver
        .resolve(&name("host.example.com."), RecordType::A, DNSClass::IN)
        .await;

    assert!(
        hits.load(Ordering::SeqCst) > 0,
        "the hostile root was never queried; the test proved nothing"
    );
    // An Err means the forgery was rejected and the lookup failed: correct.
    if let Ok(resolution) = result {
        assert!(
            !contains_forged(&resolution),
            "a reply from an address the resolver never queried was accepted; \
             the query socket must be connected to the nameserver"
        );
    }
}

// ============================================================================
// Question matching
// ============================================================================

/// `validate_question` compares only the name, so a response whose question is
/// about a different record type passes validation. A response must answer the
/// question that was actually asked — name, type, and class.
#[tokio::test]
async fn resolver_rejects_mismatched_question_type() {
    let (port, hits) = spawn_hostile_root(Forgery::MismatchedQuestionType).await;
    let resolver = resolver_for(port);

    let result = resolver
        .resolve(&name("host.example.com."), RecordType::A, DNSClass::IN)
        .await;

    assert!(
        hits.load(Ordering::SeqCst) > 0,
        "the hostile root was never queried; the test proved nothing"
    );
    // An Err means the forgery was rejected and the lookup failed: correct.
    if let Ok(resolution) = result {
        assert!(
            !contains_forged(&resolution),
            "a response whose question type (AAAA) differs from the query (A) was \
             accepted; validate_question must compare the type, not only the name"
        );
    }
}

/// The same omission for the query class.
#[tokio::test]
async fn resolver_rejects_mismatched_question_class() {
    let (port, hits) = spawn_hostile_root(Forgery::MismatchedQuestionClass).await;
    let resolver = resolver_for(port);

    let result = resolver
        .resolve(&name("host.example.com."), RecordType::A, DNSClass::IN)
        .await;

    assert!(
        hits.load(Ordering::SeqCst) > 0,
        "the hostile root was never queried; the test proved nothing"
    );
    // An Err means the forgery was rejected and the lookup failed: correct.
    if let Ok(resolution) = result {
        assert!(
            !contains_forged(&resolution),
            "a response whose question class (CH) differs from the query (IN) was \
             accepted; validate_question must compare the class"
        );
    }
}

// ============================================================================
// Control
// ============================================================================

/// An honest authoritative server — right id, right question, right source — must
/// still resolve. This guards against a fix that rejects everything, and against
/// one that connects the socket to the wrong address.
#[tokio::test]
async fn honest_nameserver_still_resolves() {
    let socket = UdpSocket::bind((ROOT_IP, 0))
        .await
        .expect("bind honest root");
    let port = socket.local_addr().expect("addr").port();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_bytes(&buf[..len]) else {
                continue;
            };
            let Some(asked) = query.queries().first().cloned() else {
                continue;
            };
            let mut resp = Message::new();
            resp.set_id(query.id());
            resp.set_message_type(MessageType::Response);
            resp.set_op_code(OpCode::Query);
            resp.set_authoritative(true);
            resp.set_response_code(ResponseCode::NoError);
            resp.add_query(asked.clone());
            resp.add_answer(Record::from_rdata(
                asked.name().clone(),
                300,
                RData::A(rdata::A(FORGED)),
            ));
            if socket
                .send_to(&resp.to_bytes().unwrap_or_default(), peer)
                .await
                .is_err()
            {
                return;
            }
        }
    });

    let resolution = resolver_for(port)
        .resolve(&name("host.example.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("an honest nameserver must resolve");

    assert!(
        contains_forged(&resolution),
        "a faithful response must still be accepted"
    );
}
