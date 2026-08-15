//! DNS-over-QUIC (RFC 9250) transport tests.
//!
//! `src/doq_server.rs` previously carried a single `test_doq_module_exists`
//! compilation smoke test, which is the same coverage a transport gets by being
//! listed in `lib.rs`. DoQ is advertised as one of the five supported transports
//! and is the only one whose framing, ALPN token, and stream lifecycle were
//! never exercised — a regression in any of them would have surfaced at a
//! client, not here.
//!
//! These drive a real `quinn` client against a real `serve_doq` listener on an
//! ephemeral loopback port. What each test pins:
//!
//! - **ALPN** — RFC 9250 §4.1 names `doq`. A server that negotiates something
//!   else, or nothing, is not a DoQ server, and a client offering only `doq`
//!   fails the handshake outright rather than silently speaking to a listener
//!   that thinks it is doing something else.
//! - **Framing** — 2-byte length prefix, as on TCP. The length is read before
//!   the body, so a wrong prefix desynchronizes the stream permanently.
//! - **One query per bidirectional stream** — RFC 9250 §4.2. The server must
//!   `finish()` its send stream after the answer, because a client that reads to
//!   EOF (the normal shape) otherwise hangs forever holding an answer it cannot
//!   see. Reading to EOF here rather than reading exactly `len` bytes is what
//!   makes that observable.
//! - **Stream independence** — several streams on one connection, and the
//!   connection surviving between them, since `handle_doq_connection` loops on
//!   `accept_bi` and spawns per stream.
//!
//! ## Certificate handling
//!
//! As in `tests/security_dot_limits_test.rs`, the client **pins the exact
//! certificate DER** the server was built with rather than trusting it as a
//! root: a verifier that accepts precisely one known certificate cannot
//! accidentally become one that accepts anything. Signature checking is still
//! delegated to the real provider, so only the identity decision is overridden.
//!
//! Resolution is pinned to `forward` with no forwarders and the answers come
//! from local database records, so nothing here touches the network. Everything
//! binds ephemeral loopback ports; the host is untouched.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rolodex_dns::db::{Database, DnsRecord, RecordKind};
use rolodex_dns::dns_server::{DnsServer, ResolutionMode};
use rolodex_dns::dnsbl::DnsblChecker;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// RFC 9250 §4.1: the ALPN token identifying DNS-over-QUIC.
const DOQ_ALPN: &[u8] = b"doq";

/// The name served from the local database, and its address.
const LOCAL_NAME: &str = "doq.example.com.";
const LOCAL_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 77);

/// A name with no record, used for the authoritative-NXDOMAIN case.
const MISSING_NAME: &str = "absent.example.com.";

/// Nothing in this suite should take anywhere near this long; it exists so a
/// hang is reported as a failed assertion instead of a stuck test binary.
const PATIENCE: Duration = Duration::from_secs(10);

/// A certificate verifier that accepts exactly one certificate: the one the
/// test server was built with.
#[derive(Debug)]
struct PinnedCert {
    expected: CertificateDer<'static>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server presented a certificate the test did not pin".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A running DoQ listener: its address, and the certificate it serves.
struct DoqServer {
    addr: SocketAddr,
    cert: CertificateDer<'static>,
}

/// Starts a DoQ listener on an ephemeral loopback port, serving one local A
/// record.
///
/// The listener binds UDP, so unlike the TCP suites there is no bind-probe
/// dance: a `quinn::Endpoint` is created directly on port 0 and its address read
/// back. That is done here rather than inside `serve_doq` — which takes a bind
/// string — by binding a throwaway UDP socket to learn a free port, dropping it,
/// and handing the address over. The window is harmless on loopback.
async fn start_doq_server(alpn: &[u8]) -> DoqServer {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let db = Database::open_memory().expect("in-memory database");
    db.add_record(&DnsRecord {
        id: None,
        name: LOCAL_NAME.to_string(),
        record_type: RecordKind::A,
        value: LOCAL_ADDR.to_string(),
        ttl: 300,
        priority: 0,
    })
    .expect("add local record");

    let rbl = Arc::new(DnsblChecker::new());
    let server = Arc::new(DnsServer::new(db, rbl, vec![]));
    // No upstream: every answer in this suite comes from the local database, so
    // a failure is about the transport and never about resolution.
    server.set_resolution_mode(ResolutionMode::Forward);

    let (certs, key) = rolodex_dns::tls::generate_self_signed().expect("self-signed certificate");
    let cert = certs.first().expect("one certificate").clone();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config");
    server_config.alpn_protocols = vec![alpn.to_vec()];

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("probe bind");
    let addr = probe.local_addr().expect("probe addr");
    drop(probe);

    let bind = addr.to_string();
    tokio::spawn(async move {
        let _unused =
            rolodex_dns::doq_server::serve_doq(&bind, server, Arc::new(server_config)).await;
    });

    // Let the endpoint come up before the first handshake.
    tokio::time::sleep(Duration::from_millis(200)).await;
    DoqServer { addr, cert }
}

/// Builds a quinn client endpoint that pins the server's certificate and offers
/// `alpn`.
///
/// QUIC is TLS 1.3 only, so the protocol versions are restricted explicitly
/// rather than using the safe defaults (which include TLS 1.2 and would leave
/// `QuicClientConfig::try_from` to reject the config).
fn client_endpoint(server: &DoqServer, alpn: &[u8]) -> quinn::Endpoint {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCert {
            expected: server.cert.clone(),
            provider,
        }))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![alpn.to_vec()];

    let quic_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("QUIC client crypto");
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
        .expect("client endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_crypto)));
    endpoint
}

/// Completes a QUIC handshake against the DoQ listener.
async fn connect_doq(server: &DoqServer) -> quinn::Connection {
    let endpoint = client_endpoint(server, DOQ_ALPN);
    tokio::time::timeout(
        PATIENCE,
        endpoint.connect(server.addr, "localhost").expect("connect"),
    )
    .await
    .expect("QUIC handshake did not complete")
    .expect("QUIC handshake with the DoQ listener")
}

/// A well-formed query, length-prefixed for DoQ's TCP-style framing.
fn framed_query(id: u16, name: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(Name::from_ascii(name).expect("valid name"));
    q.set_query_type(qtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    let body = msg.to_bytes().expect("serialize query");

    let mut framed = Vec::with_capacity(body.len() + 2);
    framed.extend_from_slice(&(body.len() as u16).to_be_bytes());
    framed.extend_from_slice(&body);
    framed
}

/// Sends one framed query on a fresh bidirectional stream and returns the parsed
/// answer.
///
/// The response is read to **EOF** rather than to the announced length, so the
/// server finishing its send stream is part of what this asserts: RFC 9250 gives
/// one query and one answer per stream, and a server that never finishes leaves
/// an ordinary client blocked on a read.
async fn query_over(connection: &quinn::Connection, query: &[u8], label: &str) -> Message {
    let (mut send, mut recv) = tokio::time::timeout(PATIENCE, connection.open_bi())
        .await
        .unwrap_or_else(|_| panic!("{label}: opening a stream timed out"))
        .unwrap_or_else(|e| panic!("{label}: opening a stream: {e}"));

    send.write_all(query)
        .await
        .unwrap_or_else(|e| panic!("{label}: writing the query: {e}"));
    send.finish()
        .unwrap_or_else(|e| panic!("{label}: finishing the query stream: {e}"));

    let raw = tokio::time::timeout(PATIENCE, recv.read_to_end(64 * 1024))
        .await
        .unwrap_or_else(|_| panic!("{label}: no answer arrived, or the stream was never finished"))
        .unwrap_or_else(|e| panic!("{label}: reading the answer: {e}"));

    assert!(
        raw.len() >= 2,
        "{label}: the answer is too short to carry a length prefix: {} bytes",
        raw.len()
    );
    let announced = u16::from_be_bytes([raw[0], raw[1]]) as usize;
    assert_eq!(
        announced,
        raw.len() - 2,
        "{label}: the 2-byte length prefix ({announced}) disagrees with the {} bytes that \
         followed it; a client framing on the prefix would desynchronize",
        raw.len() - 2
    );

    Message::from_bytes(&raw[2..]).unwrap_or_else(|e| panic!("{label}: parsing the answer: {e}"))
}

// ============================================================================
// The handshake
// ============================================================================

/// RFC 9250 §4.1 assigns DoQ the ALPN token `doq`. A client that offers only
/// `doq` must complete the handshake, and the negotiated protocol must be that
/// token — not an empty selection the client is left to guess about.
#[tokio::test]
async fn the_listener_negotiates_the_doq_alpn_token() {
    let server = start_doq_server(DOQ_ALPN).await;
    let connection = connect_doq(&server).await;

    let negotiated = connection
        .handshake_data()
        .and_then(|d| {
            d.downcast::<quinn::crypto::rustls::HandshakeData>()
                .ok()
                .and_then(|d| d.protocol.clone())
        })
        .expect("the handshake negotiated no ALPN protocol at all");

    assert_eq!(
        negotiated,
        DOQ_ALPN.to_vec(),
        "the listener negotiated {:?} rather than RFC 9250's `doq`",
        String::from_utf8_lossy(&negotiated)
    );
}

/// The mirror: a listener that does not offer `doq` must not quietly serve a
/// client that asked for it. QUIC mandates ALPN, so a failed negotiation is a
/// failed handshake — this pins that the token is load-bearing rather than
/// decorative, which is what makes the test above meaningful.
#[tokio::test]
async fn a_client_offering_doq_cannot_connect_to_a_listener_without_it() {
    let server = start_doq_server(b"not-doq").await;
    let endpoint = client_endpoint(&server, DOQ_ALPN);

    let outcome = tokio::time::timeout(
        PATIENCE,
        endpoint.connect(server.addr, "localhost").expect("connect"),
    )
    .await
    .expect("the handshake neither succeeded nor failed within the allowance");

    assert!(
        outcome.is_err(),
        "the listener completed a handshake with a client whose only offered ALPN \
         protocol it does not support"
    );
}

// ============================================================================
// Queries
// ============================================================================

/// The base case: a query for a locally-served name comes back over QUIC with
/// the right rcode, the question echoed, and the stored address in the answer.
///
/// Asserting on the address rather than merely "an answer arrived" is what
/// separates a working transport from one that happens to return a well-formed
/// message about something else.
#[tokio::test]
async fn a_doq_query_is_answered_from_the_local_database() {
    let server = start_doq_server(DOQ_ALPN).await;
    let connection = connect_doq(&server).await;

    let response = query_over(
        &connection,
        &framed_query(0x1234, LOCAL_NAME, RecordType::A),
        "local A query",
    )
    .await;

    assert_eq!(
        response.id(),
        0x1234,
        "the answer does not carry the query's transaction ID"
    );
    assert_eq!(
        response.message_type(),
        MessageType::Response,
        "the answer is not marked as a response"
    );
    assert_eq!(
        response.response_code(),
        ResponseCode::NoError,
        "a locally-served name answered {:?}",
        response.response_code()
    );
    assert_eq!(
        response.queries().first().map(|q| q.name().to_string()),
        Some(LOCAL_NAME.to_string()),
        "the answer does not echo the question"
    );

    let addresses: Vec<Ipv4Addr> = response
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    assert_eq!(
        addresses,
        vec![LOCAL_ADDR],
        "the answer section does not carry the stored address"
    );
}

/// A name inside a zone this server holds records for, but with no record of its
/// own, is an authoritative NXDOMAIN. Running it over DoQ pins that the
/// transport carries a negative answer as faithfully as a positive one — the
/// rcode travels in the header, so a transport that only ever moved answer
/// records would pass the test above and fail this one.
#[tokio::test]
async fn a_doq_query_for_a_missing_name_returns_nxdomain() {
    let server = start_doq_server(DOQ_ALPN).await;
    let connection = connect_doq(&server).await;

    let response = query_over(
        &connection,
        &framed_query(0x5678, MISSING_NAME, RecordType::A),
        "missing name",
    )
    .await;

    assert_eq!(
        response.response_code(),
        ResponseCode::NXDomain,
        "a name with no record inside a managed zone answered {:?}",
        response.response_code()
    );
    assert!(
        response.answers().is_empty(),
        "an NXDOMAIN carried {} answer records",
        response.answers().len()
    );
}

/// RFC 9250 §4.2: one query per bidirectional stream, and streams on a
/// connection are independent. `handle_doq_connection` loops on `accept_bi` and
/// spawns a task per stream, so this pins that the loop survives a completed
/// stream — a handler that returned after the first query would answer once and
/// then hang.
///
/// Each query carries a distinct transaction ID and the answers are matched
/// against them, so a server that crossed two streams' responses fails here
/// rather than passing on "three answers arrived".
#[tokio::test]
async fn several_streams_on_one_connection_are_answered_independently() {
    let server = start_doq_server(DOQ_ALPN).await;
    let connection = connect_doq(&server).await;

    for id in [0x0001u16, 0x0002, 0x0003] {
        let response = query_over(
            &connection,
            &framed_query(id, LOCAL_NAME, RecordType::A),
            &format!("stream {id}"),
        )
        .await;
        assert_eq!(
            response.id(),
            id,
            "the answer on stream {id} carries another stream's transaction ID"
        );
        assert_eq!(
            response.response_code(),
            ResponseCode::NoError,
            "stream {id} was not answered successfully"
        );
    }
}

/// Concurrent streams, opened before any answer is read. The sequential test
/// above would pass against a handler that serialized every stream behind the
/// previous one; this one would not, because all three queries are in flight at
/// once.
#[tokio::test]
async fn concurrent_streams_are_all_answered() {
    let server = start_doq_server(DOQ_ALPN).await;
    let connection = Arc::new(connect_doq(&server).await);

    let mut tasks = Vec::new();
    for id in [0x0011u16, 0x0012, 0x0013, 0x0014] {
        let conn = Arc::clone(&connection);
        tasks.push(tokio::spawn(async move {
            let response = query_over(
                &conn,
                &framed_query(id, LOCAL_NAME, RecordType::A),
                &format!("concurrent stream {id}"),
            )
            .await;
            (id, response.id(), response.response_code())
        }));
    }

    for task in tasks {
        let (sent, echoed, rcode) = task.await.expect("stream task panicked");
        assert_eq!(echoed, sent, "concurrent streams crossed their answers");
        assert_eq!(
            rcode,
            ResponseCode::NoError,
            "concurrent stream {sent} was not answered successfully"
        );
    }
}

// ============================================================================
// Framing
// ============================================================================

/// The length prefix is what the stream is framed on, so an announced length
/// that never arrives must not be answered as if it had. `handle_doq_stream`
/// reads exactly `msg_len` bytes; a client that announces more than it sends and
/// then finishes the stream must get no answer, not a truncated one parsed from
/// whatever did arrive.
///
/// The stream is finished (rather than left open) so that the failure mode being
/// pinned is "the server answered something it should not have", not "the server
/// is still waiting" — waiting is correct.
#[tokio::test]
async fn a_truncated_body_is_not_answered() {
    let server = start_doq_server(DOQ_ALPN).await;
    let connection = connect_doq(&server).await;

    let query = framed_query(0x4321, LOCAL_NAME, RecordType::A);
    let (mut send, mut recv) = connection.open_bi().await.expect("open stream");

    // Announce the real length, then send only half the body.
    let half = 2 + (query.len() - 2) / 2;
    send.write_all(&query[..half]).await.expect("partial write");
    send.finish().expect("finish");

    match tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024)).await {
        // Still waiting for the rest of the body, or the stream was reset:
        // either is the server declining to answer, which is correct.
        Err(_) | Ok(Err(_)) => {}
        Ok(Ok(body)) => assert!(
            body.is_empty(),
            "the server answered a query whose announced length never arrived: \
             {} bytes came back",
            body.len()
        ),
    }
}

/// A zero-length message is rejected outright by `handle_doq_stream` rather than
/// handed to the parser. Pinning it here keeps the guard from being dropped as
/// redundant: `Message::from_bytes(&[])` fails, but it fails *after* a buffer of
/// the announced size has been allocated on the say-so of an unauthenticated
/// peer, and the same check is what bounds that allocation.
#[tokio::test]
async fn a_zero_length_message_is_rejected() {
    let server = start_doq_server(DOQ_ALPN).await;
    let connection = connect_doq(&server).await;

    let (mut send, mut recv) = connection.open_bi().await.expect("open stream");
    send.write_all(&0u16.to_be_bytes())
        .await
        .expect("write zero length");
    send.finish().expect("finish");

    let body = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024))
        .await
        .unwrap_or(Ok(Vec::new()))
        .unwrap_or_default();

    assert!(
        body.is_empty(),
        "the server replied to a zero-length message with {} bytes",
        body.len()
    );

    // The connection itself must survive one bad stream; a listener that tore
    // down the whole connection would let a single malformed stream deny service
    // to every other query multiplexed on it.
    let response = query_over(
        &connection,
        &framed_query(0x9999, LOCAL_NAME, RecordType::A),
        "after a rejected stream",
    )
    .await;
    assert_eq!(
        response.response_code(),
        ResponseCode::NoError,
        "a malformed stream took the whole connection down with it"
    );
}

/// A malformed DNS message (correctly framed, but not parseable) must produce a
/// FORMERR rather than silence or a panic — the framing layer did its job, so
/// the error belongs to the DNS layer and travels back as an rcode.
#[tokio::test]
async fn a_malformed_message_is_answered_with_formerr() {
    let server = start_doq_server(DOQ_ALPN).await;
    let connection = connect_doq(&server).await;

    // A two-byte truncated header: correctly framed, but not a DNS message.
    // Those two bytes are still the transaction ID, which the error response
    // must echo — that is how a client matches the failure to its query.
    let garbage: [u8; 2] = [0xAB, 0xCD];
    let mut framed = Vec::with_capacity(garbage.len() + 2);
    framed.extend_from_slice(&(garbage.len() as u16).to_be_bytes());
    framed.extend_from_slice(&garbage);

    let response = query_over(&connection, &framed, "malformed message").await;
    assert_eq!(
        response.response_code(),
        ResponseCode::FormErr,
        "a malformed query answered {:?} rather than FORMERR",
        response.response_code()
    );
    assert_eq!(
        response.id(),
        0xABCD,
        "the FORMERR does not echo the transaction ID, so a client cannot match \
         it to the query that failed"
    );
}
