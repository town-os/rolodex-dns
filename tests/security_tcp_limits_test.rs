//! Security regression tests for DNS-over-TCP connection limits.
//!
//! These assert behaviour the TCP listener *should* have and are expected to
//! FAIL against the current implementation. Do not weaken an assertion to make
//! one pass.
//!
//! `serve_tcp` (`src/dns_server.rs`) spawns a task per accepted connection with
//! no cap, and `handle_tcp_connection` loops on `read_exact` with no timeout.
//! Nothing anywhere bounds either. A client that connects and sends nothing —
//! or sends one byte of the two-byte length prefix and stops — parks a task and
//! a file descriptor indefinitely. `dns.bind` defaults to `0.0.0.0:53`, so on a
//! routable interface that is a pre-auth remote resource exhaustion: hold enough
//! connections open and the process runs out of descriptors, at which point
//! `accept` fails for everyone.
//!
//! `handle_dot_connection` (`src/dot_server.rs`) has the same shape, and its TLS
//! handshake is untimed too, so a client can stall before a single byte of DNS
//! is exchanged. DoQ already sets `max_idle_timeout`; TCP and DoT are the gap.
//! The DoT half lives in `tests/security_dot_limits_test.rs` — fixing this file
//! alone leaves `:853` open, so treat the two together.
//!
//! RFC 7766 §6.2.1 is explicit that a DNS-over-TCP server should close idle
//! connections, and that the timeout is the server's to choose. These tests do
//! not pin a value — they assert only that an idle connection is *eventually*
//! closed, allowing anything up to [`IDLE_ALLOWANCE`], which is generous next to
//! the few seconds a real deployment would pick.
//!
//! Everything binds an ephemeral loopback port; the host is untouched.

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use rolodex_dns::db::Database;
use rolodex_dns::dns_server::{DnsServer, ResolutionMode};
use rolodex_dns::rbl::RblChecker;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The longest an idle connection may be left open before the server closes it.
/// Deliberately loose: this pins that a bound exists, not what it is.
const IDLE_ALLOWANCE: Duration = Duration::from_secs(30);

/// Starts a DNS TCP listener on an ephemeral loopback port and returns its
/// address.
///
/// Resolution is pinned to `forward` with no forwarders so nothing in these
/// tests can reach the network; they are about the connection lifecycle, not
/// about answers.
async fn start_tcp_server() -> String {
    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(RblChecker::new(false, vec![]));
    let server = Arc::new(DnsServer::new(db, rbl, vec![]));
    server.set_resolution_mode(ResolutionMode::Forward);

    // Bind first to learn the port, then hand the address to the server. The
    // listener is dropped before `serve_tcp` binds it again; nothing else on the
    // box is racing for an ephemeral port.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap().to_string();
    drop(probe);

    let serving = Arc::clone(&server);
    let bind = addr.clone();
    tokio::spawn(async move {
        let _unused = serving.serve_tcp(&bind).await;
    });

    // Let the listener come up before the first connect.
    tokio::time::sleep(Duration::from_millis(200)).await;
    addr
}

/// A well-formed query, length-prefixed for TCP framing.
fn framed_query(name: &str) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(0x4242);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(Name::from_str(name).unwrap());
    q.set_query_type(RecordType::A);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    let body = msg.to_bytes().unwrap();

    let mut framed = Vec::with_capacity(body.len() + 2);
    framed.extend_from_slice(&(body.len() as u16).to_be_bytes());
    framed.extend_from_slice(&body);
    framed
}

/// Waits for `stream` to reach EOF (or be reset), up to [`IDLE_ALLOWANCE`].
/// Returns whether the server closed it.
async fn closed_within_allowance(mut stream: TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match tokio::time::timeout(IDLE_ALLOWANCE, stream.read(&mut buf)).await {
        // 0 bytes is a clean EOF; an error is a reset. Either is the server
        // reclaiming the connection.
        Ok(Ok(0)) | Ok(Err(_)) => true,
        // The server sent us something unprompted, which it should not have.
        Ok(Ok(_)) => false,
        // Still open, still holding a task and a descriptor.
        Err(_) => false,
    }
}

// ============================================================================
// Idle connections
// ============================================================================

/// A client that connects and never speaks must not hold a task and a file
/// descriptor forever. This is the cheapest possible attack — a bare TCP
/// connect, no DNS knowledge required, no data sent — and repeated it exhausts
/// the process's descriptors, after which `accept` fails for every legitimate
/// client too.
#[tokio::test]
async fn an_idle_tcp_connection_is_eventually_closed() {
    let addr = start_tcp_server().await;
    let stream = TcpStream::connect(&addr).await.expect("connect");

    assert!(
        closed_within_allowance(stream).await,
        "a connection that sent nothing was still open after {}s; \
         `handle_tcp_connection` awaits `read_exact` with no timeout, so an \
         attacker holds a task and a descriptor per connect (RFC 7766 §6.2.1)",
        IDLE_ALLOWANCE.as_secs()
    );
}

/// The same attack with one byte sent, which is worse: the connection now looks
/// like a client mid-message, so any fix that only covers "sent nothing at all"
/// misses it. `read_exact` is waiting for the second half of a two-byte length
/// prefix that will never arrive.
#[tokio::test]
async fn a_half_sent_length_prefix_does_not_pin_a_connection() {
    let addr = start_tcp_server().await;
    let mut stream = TcpStream::connect(&addr).await.expect("connect");
    stream.write_all(&[0x00]).await.expect("write first byte");
    stream.flush().await.expect("flush");

    assert!(
        closed_within_allowance(stream).await,
        "a connection that sent half a length prefix was still open after {}s; \
         the read of the remaining byte is untimed",
        IDLE_ALLOWANCE.as_secs()
    );
}

/// And with a length prefix whose body never arrives — the server has already
/// allocated `msg_len` bytes for it. Announcing the 65535-byte maximum and then
/// sending nothing turns each connection into a buffer the attacker never has
/// to fill.
#[tokio::test]
async fn an_announced_body_that_never_arrives_does_not_pin_a_connection() {
    let addr = start_tcp_server().await;
    let mut stream = TcpStream::connect(&addr).await.expect("connect");
    stream
        .write_all(&u16::MAX.to_be_bytes())
        .await
        .expect("write length prefix");
    stream.flush().await.expect("flush");

    assert!(
        closed_within_allowance(stream).await,
        "a connection that announced a 65535-byte message and sent none of it \
         was still open after {}s",
        IDLE_ALLOWANCE.as_secs()
    );
}

// ============================================================================
// Controls: real clients must keep working
// ============================================================================

/// The mirror invariant: a client that asks a question gets an answer. A fix
/// that closes connections aggressively enough to break this has broken
/// DNS-over-TCP, which is not optional — it is what every truncated UDP answer
/// falls back to.
#[tokio::test]
async fn a_client_that_sends_a_query_is_answered() {
    let addr = start_tcp_server().await;
    let mut stream = TcpStream::connect(&addr).await.expect("connect");

    stream
        .write_all(&framed_query("example.com."))
        .await
        .expect("write query");
    stream.flush().await.expect("flush");

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut len_buf))
        .await
        .expect("a query must be answered within 10s")
        .expect("read length prefix");
    let len = u16::from_be_bytes(len_buf) as usize;
    assert!(len > 0, "the answer must not be empty");

    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .expect("the answer body must arrive")
        .expect("read body");
}

/// RFC 7766 connection reuse: a client is expected to hold one connection open
/// and send several queries down it. An idle timeout must be measured from the
/// last activity, not from the connection opening, or a fix turns every
/// long-lived resolver client into a reconnect loop.
#[tokio::test]
async fn a_connection_stays_usable_between_queries() {
    let addr = start_tcp_server().await;
    let mut stream = TcpStream::connect(&addr).await.expect("connect");

    for (i, name) in ["a.example.com.", "b.example.com."].iter().enumerate() {
        if i > 0 {
            // A pause a real client would take between lookups.
            tokio::time::sleep(Duration::from_millis(750)).await;
        }
        stream
            .write_all(&framed_query(name))
            .await
            .unwrap_or_else(|e| panic!("write query {}: {}", i, e));
        stream.flush().await.expect("flush");

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut len_buf))
            .await
            .unwrap_or_else(|_| panic!("query {} was not answered within 10s", i))
            .unwrap_or_else(|e| panic!("read length prefix for query {}: {}", i, e));
        let mut body = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
            .await
            .unwrap_or_else(|_| panic!("body of query {} did not arrive", i))
            .unwrap_or_else(|e| panic!("read body for query {}: {}", i, e));
    }
}
