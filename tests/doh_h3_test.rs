//! DNS-over-HTTPS over HTTP/3 (RFC 9114 + RFC 8484) transport tests.
//!
//! `doh.enable_h3` was accepted and ignored for as long as it existed: the
//! config key parsed, the RPC returned success, and the box served h2 over TCP
//! and nothing else. These drive a real `h3` client against a real HTTP/3
//! listener on an ephemeral loopback port, which is the only way to tell an
//! implemented flag from an accepted one.
//!
//! What each group pins:
//!
//! - **ALPN** — RFC 9114 §3.1 names `h3`, and the listener must negotiate it
//!   even though the certificate it borrows from the TCP listener was built
//!   advertising `h2`/`http/1.1`. The ALPN replacement in `h3_config` is the
//!   whole reason that works, and the control is a client offering `h2` over
//!   QUIC, which must fail the handshake rather than be quietly served.
//! - **Both request forms** — RFC 8484 gives GET with a base64url `dns`
//!   parameter and POST with an `application/dns-message` body. A listener that
//!   implements one is not a DoH server; each is tested against the same stored
//!   record so a failure is about the form and not about resolution.
//! - **The response head** — `content-type: application/dns-message` and a
//!   `Cache-Control` whose max-age is the answer's minimum TTL (RFC 8484 §5.1).
//!   A cache that outlived the record it holds keeps answering with data the
//!   zone has replaced, and nothing at the client would report that.
//! - **Refusals** — a wrong path is a 404, a wrong method a 405, a missing or
//!   undecodable parameter a 400. Each is answered and the stream FINISHED: a
//!   refusal that sends headers and never closes leaves the client waiting out
//!   its own timeout, which reads as a hung resolver rather than a rejected
//!   request.
//! - **Stream independence** — several requests in flight on one connection.
//!   Serving them in sequence inside the server would rebuild exactly the
//!   head-of-line blocking HTTP/3 exists to remove, and a sequential test cannot
//!   see the difference.
//!
//! ## Certificate handling
//!
//! As in `tests/doq_test.rs`, the client **pins the exact certificate DER** the
//! server was built with rather than trusting it as a root: a verifier that
//! accepts precisely one known certificate cannot accidentally become one that
//! accepts anything. Signature checking is still delegated to the real provider.
//!
//! Resolution is pinned to `forward` with no forwarders and every answer comes
//! from local database records, so nothing here touches the network. Everything
//! binds ephemeral loopback ports; the host is untouched.

use base64::Engine;
use bytes::{Buf, Bytes};
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

/// RFC 9114 §3.1: the ALPN token identifying HTTP/3.
const H3_ALPN: &[u8] = b"h3";

/// The name served from the local database, its address, and its TTL. The TTL is
/// checked against the `Cache-Control` the listener sends, so it is deliberately
/// not a round number that a hardcoded default could coincide with.
const LOCAL_NAME: &str = "h3.example.com.";
const LOCAL_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 91);
const LOCAL_TTL: u32 = 317;

/// A name with no record, used for the authoritative-NXDOMAIN case.
const MISSING_NAME: &str = "absent.example.com.";

/// Nothing here should take anywhere near this long; it exists so a hang is
/// reported as a failed assertion instead of a stuck test binary.
const PATIENCE: Duration = Duration::from_secs(10);

/// A certificate verifier that accepts exactly one certificate: the one the test
/// server was built with.
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

/// A running HTTP/3 DoH listener: its address, and the certificate it serves.
struct H3Server {
    addr: SocketAddr,
    cert: CertificateDer<'static>,
    /// The certificate channel's sender, held so the listener's receiver stays
    /// open for the life of the test. The listener follows a channel rather than
    /// holding a snapshot so a renewal reaches the endpoint without a restart;
    /// nothing here renews one, but the sender still has to outlive the listener.
    _tls: tokio::sync::watch::Sender<Arc<rustls::ServerConfig>>,
}

/// A resolver holding exactly one record and reaching nowhere.
///
/// Resolution is pinned to `forward` with no forwarders, so every answer comes
/// from the local database: a failure in this suite is about the transport, and
/// can never be about the network.
fn local_dns_server() -> Arc<DnsServer> {
    let db = Database::open_memory().expect("in-memory database");
    db.add_record(&DnsRecord {
        id: None,
        name: LOCAL_NAME.to_string(),
        record_type: RecordKind::A,
        value: LOCAL_ADDR.to_string(),
        ttl: LOCAL_TTL,
        priority: 0,
    })
    .expect("add local record");

    let rbl = Arc::new(DnsblChecker::new());
    let server = Arc::new(DnsServer::new(db, rbl, vec![]));
    server.set_resolution_mode(ResolutionMode::Forward);
    server
}

/// Starts an HTTP/3 DoH listener on an ephemeral loopback port, serving one
/// local A record.
///
/// The server config is built advertising `h2`/`http/1.1` — exactly what the DoH
/// listener's TLS manager produces — precisely so that the h3 negotiation test
/// is checking `h3_config`'s ALPN replacement rather than a token the test
/// helpfully supplied.
async fn start_h3_server() -> H3Server {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let server = local_dns_server();

    let (certs, key) = rolodex_dns::tls::generate_self_signed().expect("self-signed certificate");
    let cert = certs.first().expect("one certificate").clone();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config");
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let server_config = Arc::new(server_config);

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("probe bind");
    let addr = probe.local_addr().expect("probe addr");
    drop(probe);

    let endpoint =
        rolodex_dns::doh_h3_server::bind_doh_h3(&addr.to_string(), server_config.clone())
            .expect("bind the HTTP/3 endpoint");
    let addr = endpoint.local_addr().expect("endpoint address");

    let (tls_tx, tls_rx) = tokio::sync::watch::channel(server_config);
    tokio::spawn(async move {
        let _unused = rolodex_dns::doh_h3_server::serve_doh_h3_on(endpoint, server, tls_rx).await;
    });

    H3Server {
        addr,
        cert,
        _tls: tls_tx,
    }
}

/// Builds a quinn client endpoint that pins the server's certificate and offers
/// `alpn`.
///
/// QUIC is TLS 1.3 only, so the protocol versions are restricted explicitly
/// rather than using the safe defaults (which include TLS 1.2 and would leave
/// `QuicClientConfig::try_from` to reject the config).
fn client_endpoint(server: &H3Server, alpn: &[u8]) -> quinn::Endpoint {
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

/// Completes a QUIC handshake against the HTTP/3 listener.
async fn connect_quic(server: &H3Server) -> quinn::Connection {
    let endpoint = client_endpoint(server, H3_ALPN);
    tokio::time::timeout(
        PATIENCE,
        endpoint.connect(server.addr, "localhost").expect("connect"),
    )
    .await
    .expect("QUIC handshake did not complete")
    .expect("QUIC handshake with the HTTP/3 listener")
}

/// An HTTP/3 client connection, with its driver running.
struct H3Client {
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    /// The connection driver. HTTP/3 needs it polled for the whole life of the
    /// connection — control streams, QPACK, settings — so it is spawned and its
    /// handle kept only to abort at the end of the test.
    driver: tokio::task::JoinHandle<()>,
}

impl Drop for H3Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// Establishes HTTP/3 over a fresh QUIC connection.
async fn connect_h3(server: &H3Server) -> H3Client {
    let connection = connect_quic(server).await;
    let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .expect("HTTP/3 client setup");
    let driver = tokio::spawn(async move {
        let _closed = driver.wait_idle().await;
    });
    H3Client {
        send_request,
        driver,
    }
}

/// One HTTP/3 response: the head, and the body it carried.
struct H3Response {
    status: http::StatusCode,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

impl H3Response {
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }
}

/// Sends one request and reads the whole response.
///
/// The body is read to the end of the stream rather than to a content length, so
/// a handler that answers and never finishes fails here — as a timeout naming
/// the request — rather than at some client months later.
async fn request(client: &mut H3Client, req: http::Request<Bytes>, label: &str) -> H3Response {
    let (parts, body) = req.into_parts();
    let head = http::Request::from_parts(parts, ());

    let mut stream = tokio::time::timeout(PATIENCE, client.send_request.send_request(head))
        .await
        .unwrap_or_else(|_| panic!("{label}: sending the request head timed out"))
        .unwrap_or_else(|e| panic!("{label}: sending the request head: {e}"));

    if !body.is_empty() {
        stream
            .send_data(body)
            .await
            .unwrap_or_else(|e| panic!("{label}: sending the request body: {e}"));
    }
    stream
        .finish()
        .await
        .unwrap_or_else(|e| panic!("{label}: finishing the request: {e}"));

    let response = tokio::time::timeout(PATIENCE, stream.recv_response())
        .await
        .unwrap_or_else(|_| panic!("{label}: no response head arrived"))
        .unwrap_or_else(|e| panic!("{label}: reading the response head: {e}"));

    let mut collected = Vec::new();
    loop {
        let chunk = tokio::time::timeout(PATIENCE, stream.recv_data())
            .await
            .unwrap_or_else(|_| {
                panic!("{label}: the response body never ended; the handler did not finish")
            })
            .unwrap_or_else(|e| panic!("{label}: reading the response body: {e}"));
        let Some(mut chunk) = chunk else { break };
        while chunk.has_remaining() {
            let advanced = {
                let segment = chunk.chunk();
                collected.extend_from_slice(segment);
                segment.len()
            };
            chunk.advance(advanced);
        }
    }

    H3Response {
        status: response.status(),
        headers: response.headers().clone(),
        body: collected,
    }
}

/// A well-formed query, wire-encoded.
fn wire_query(id: u16, name: &str, qtype: RecordType) -> Vec<u8> {
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
    msg.to_bytes().expect("serialize query")
}

/// The GET form's URI: base64url with the padding stripped, as RFC 8484 §4.1
/// requires.
fn get_uri(query: &[u8]) -> String {
    format!(
        "https://localhost/dns-query?dns={}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(query)
    )
}

/// The addresses an answer carries, for asserting on what was resolved rather
/// than on a well-formed message about something else.
fn addresses(message: &Message) -> Vec<Ipv4Addr> {
    message
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect()
}

// ============================================================================
// The handshake
// ============================================================================

/// RFC 9114 §3.1 assigns HTTP/3 the ALPN token `h3`. The listener must negotiate
/// it from a TLS config built advertising `h2` and `http/1.1` — that replacement
/// is what lets one certificate serve both transports, and getting it wrong
/// would let a client negotiate a protocol this endpoint cannot speak.
#[tokio::test]
async fn the_listener_negotiates_the_h3_alpn_token() {
    let server = start_h3_server().await;
    let connection = connect_quic(&server).await;

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
        H3_ALPN.to_vec(),
        "the listener negotiated {:?} rather than RFC 9114's `h3`",
        String::from_utf8_lossy(&negotiated)
    );
}

/// The control for the test above: the TCP listener's tokens must NOT be offered
/// over QUIC. A client that offers only `h2` has to fail the handshake — QUIC
/// mandates ALPN, so a listener that accepted it would have negotiated a protocol
/// it cannot speak and the failure would land after the handshake, where a client
/// reads it as a broken resolver.
#[tokio::test]
async fn a_client_offering_h2_over_quic_cannot_connect() {
    let server = start_h3_server().await;
    let endpoint = client_endpoint(&server, b"h2");

    let outcome = tokio::time::timeout(
        PATIENCE,
        endpoint.connect(server.addr, "localhost").expect("connect"),
    )
    .await
    .expect("the handshake neither succeeded nor failed within the allowance");

    assert!(
        outcome.is_err(),
        "the HTTP/3 listener completed a handshake with a client offering only `h2`"
    );
}

// ============================================================================
// Queries
// ============================================================================

/// The GET form (RFC 8484 §4.1): the query travels as base64url in the `dns`
/// parameter. Asserting on the resolved address, the echoed question and the
/// transaction ID is what separates a working transport from one that returns a
/// well-formed message about something else.
#[tokio::test]
async fn a_get_query_is_answered_from_the_local_database() {
    let server = start_h3_server().await;
    let mut client = connect_h3(&server).await;

    let response = request(
        &mut client,
        http::Request::get(get_uri(&wire_query(0x1234, LOCAL_NAME, RecordType::A)))
            .body(Bytes::new())
            .expect("build GET"),
        "GET local A",
    )
    .await;

    assert_eq!(
        response.status,
        http::StatusCode::OK,
        "GET was not answered"
    );
    assert_eq!(
        response.header("content-type").as_deref(),
        Some("application/dns-message"),
        "the answer is not labelled as a DNS message, so a strict client discards it"
    );

    let message = Message::from_bytes(&response.body).expect("parse the answer");
    assert_eq!(message.id(), 0x1234, "the answer lost the transaction ID");
    assert_eq!(
        message.response_code(),
        ResponseCode::NoError,
        "a locally-served name answered {:?}",
        message.response_code()
    );
    assert_eq!(
        message.queries().first().map(|q| q.name().to_string()),
        Some(LOCAL_NAME.to_string()),
        "the answer does not echo the question"
    );
    assert_eq!(
        addresses(&message),
        vec![LOCAL_ADDR],
        "the answer section does not carry the stored address"
    );
}

/// The POST form (RFC 8484 §4.1): the same query as a request body. A listener
/// that implements one form and not the other is not a DoH server, and the two
/// take entirely separate paths through the handler.
#[tokio::test]
async fn a_post_query_is_answered_from_the_local_database() {
    let server = start_h3_server().await;
    let mut client = connect_h3(&server).await;

    let response = request(
        &mut client,
        http::Request::post("https://localhost/dns-query")
            .header("content-type", "application/dns-message")
            .body(Bytes::from(wire_query(0x4321, LOCAL_NAME, RecordType::A)))
            .expect("build POST"),
        "POST local A",
    )
    .await;

    assert_eq!(
        response.status,
        http::StatusCode::OK,
        "POST was not answered"
    );
    let message = Message::from_bytes(&response.body).expect("parse the answer");
    assert_eq!(message.id(), 0x4321, "the answer lost the transaction ID");
    assert_eq!(
        addresses(&message),
        vec![LOCAL_ADDR],
        "the answer section does not carry the stored address"
    );
}

/// RFC 8484 §5.1: the response's freshness must not outlive the shortest TTL it
/// carries. A cache holding an answer past its TTL goes on serving data the zone
/// has replaced, and nothing at the client reports that — which is why the TTL
/// here is an unusual number rather than one a hardcoded default could match.
#[tokio::test]
async fn the_cache_control_carries_the_answers_minimum_ttl() {
    let server = start_h3_server().await;
    let mut client = connect_h3(&server).await;

    let response = request(
        &mut client,
        http::Request::get(get_uri(&wire_query(0x0f0f, LOCAL_NAME, RecordType::A)))
            .body(Bytes::new())
            .expect("build GET"),
        "GET for cache-control",
    )
    .await;

    assert_eq!(
        response.header("cache-control").as_deref(),
        Some(format!("max-age={}", LOCAL_TTL).as_str()),
        "the response's max-age is not the answer's TTL"
    );
}

/// A name inside a zone this server holds records for, but with no record of its
/// own, is an authoritative NXDOMAIN. The rcode travels in the DNS header, so a
/// transport that only ever moved answer records would pass the tests above and
/// fail this one — and the HTTP status must still be 200, because the DNS layer
/// answered.
#[tokio::test]
async fn an_nxdomain_travels_as_a_dns_answer_not_an_http_error() {
    let server = start_h3_server().await;
    let mut client = connect_h3(&server).await;

    let response = request(
        &mut client,
        http::Request::get(get_uri(&wire_query(0x5678, MISSING_NAME, RecordType::A)))
            .body(Bytes::new())
            .expect("build GET"),
        "GET missing name",
    )
    .await;

    assert_eq!(
        response.status,
        http::StatusCode::OK,
        "a DNS-level NXDOMAIN was reported as an HTTP error, which a DoH client \
         cannot tell from an unreachable resolver"
    );
    let message = Message::from_bytes(&response.body).expect("parse the answer");
    assert_eq!(
        message.response_code(),
        ResponseCode::NXDomain,
        "a name with no record inside a managed zone answered {:?}",
        message.response_code()
    );
    assert!(
        message.answers().is_empty(),
        "an NXDOMAIN carried {} answer records",
        message.answers().len()
    );
}

// ============================================================================
// Refusals
// ============================================================================

/// A request that will not be resolved still gets a complete response: status,
/// and a finished stream. Each of these would otherwise hang the client — the
/// body read in `request` only returns when the handler finishes — so this pins
/// the refusal path as much as the status codes.
#[tokio::test]
async fn malformed_requests_are_refused_with_a_finished_response() {
    let server = start_h3_server().await;
    let mut client = connect_h3(&server).await;

    let wrong_path = request(
        &mut client,
        http::Request::get("https://localhost/not-dns-query")
            .body(Bytes::new())
            .expect("build GET"),
        "wrong path",
    )
    .await;
    assert_eq!(
        wrong_path.status,
        http::StatusCode::NOT_FOUND,
        "a path this listener does not serve answered {}",
        wrong_path.status
    );

    let wrong_method = request(
        &mut client,
        http::Request::put("https://localhost/dns-query")
            .body(Bytes::new())
            .expect("build PUT"),
        "wrong method",
    )
    .await;
    assert_eq!(
        wrong_method.status,
        http::StatusCode::METHOD_NOT_ALLOWED,
        "a method RFC 8484 does not define answered {}",
        wrong_method.status
    );

    let no_param = request(
        &mut client,
        http::Request::get("https://localhost/dns-query")
            .body(Bytes::new())
            .expect("build GET"),
        "no dns parameter",
    )
    .await;
    assert_eq!(
        no_param.status,
        http::StatusCode::BAD_REQUEST,
        "a GET with no `dns` parameter answered {}",
        no_param.status
    );

    let undecodable = request(
        &mut client,
        http::Request::get("https://localhost/dns-query?dns=!!!not-base64!!!")
            .body(Bytes::new())
            .expect("build GET"),
        "undecodable parameter",
    )
    .await;
    assert_eq!(
        undecodable.status,
        http::StatusCode::BAD_REQUEST,
        "a `dns` parameter that is not base64url answered {}",
        undecodable.status
    );

    // The connection must survive every one of them: a listener that tore down
    // the connection on a bad request would let one malformed query deny service
    // to everything else multiplexed on it.
    let good = request(
        &mut client,
        http::Request::get(get_uri(&wire_query(0x9999, LOCAL_NAME, RecordType::A)))
            .body(Bytes::new())
            .expect("build GET"),
        "after the refusals",
    )
    .await;
    assert_eq!(
        good.status,
        http::StatusCode::OK,
        "a refused request took the whole connection down with it"
    );
}

// ============================================================================
// Stream independence
// ============================================================================

/// Requests in flight together on one connection, all answered, none crossed.
/// A handler that served requests in sequence would rebuild — inside the server —
/// exactly the head-of-line blocking HTTP/3 exists to remove, and a sequential
/// test cannot tell the two apart.
#[tokio::test]
async fn concurrent_requests_on_one_connection_are_all_answered() {
    let server = start_h3_server().await;
    let client = connect_h3(&server).await;

    let mut tasks = Vec::new();
    for id in [0x0011u16, 0x0012, 0x0013, 0x0014] {
        // Each task needs its own handle to the request sender; that is what
        // `SendRequest` clones for.
        let mut sender = client.send_request.clone();
        tasks.push(tokio::spawn(async move {
            let mut stream = sender
                .send_request(
                    http::Request::get(get_uri(&wire_query(id, LOCAL_NAME, RecordType::A)))
                        .body(())
                        .expect("build GET"),
                )
                .await
                .expect("send request");
            stream.finish().await.expect("finish request");
            let response = stream.recv_response().await.expect("response head");
            let mut body = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.expect("response body") {
                while chunk.has_remaining() {
                    let advanced = {
                        let segment = chunk.chunk();
                        body.extend_from_slice(segment);
                        segment.len()
                    };
                    chunk.advance(advanced);
                }
            }
            let message = Message::from_bytes(&body).expect("parse the answer");
            (id, response.status(), message.id(), message.response_code())
        }));
    }

    for task in tasks {
        let (sent, status, echoed, rcode) = tokio::time::timeout(PATIENCE, task)
            .await
            .expect("a concurrent request never completed")
            .expect("request task panicked");
        assert_eq!(status, http::StatusCode::OK, "request {sent} was refused");
        assert_eq!(echoed, sent, "concurrent requests crossed their answers");
        assert_eq!(
            rcode,
            ResponseCode::NoError,
            "concurrent request {sent} was not resolved"
        );
    }
}

// ============================================================================
// Advertisement
// ============================================================================

/// A client that reached the TCP listener has no other way to learn this box
/// speaks HTTP/3. RFC 7838's `Alt-Svc` is the in-band announcement, and without
/// it the QUIC endpoint is reachable only by a client that was told about it out
/// of band — through the DDR designation, or by hand.
///
/// The port is asserted rather than the header's mere presence: an advertisement
/// naming the wrong port sends the client to something that does not answer, and
/// it waits out its own timeout before falling back.
#[tokio::test]
async fn the_tcp_listener_advertises_http3_when_it_is_running() {
    use axum::body::Body;
    use tower::ServiceExt;

    let app = rolodex_dns::doh_server::build_router(local_dns_server(), Some(8443));
    let request = http::Request::builder()
        .method("POST")
        .uri("/dns-query")
        .header("content-type", "application/dns-message")
        .body(Body::from(wire_query(0x2222, LOCAL_NAME, RecordType::A)))
        .expect("build POST");

    let response = app.oneshot(request).await.expect("router response");
    assert_eq!(response.status(), 200, "the query itself was not answered");

    let alt_svc = response
        .headers()
        .get("alt-svc")
        .and_then(|v| v.to_str().ok())
        .expect("no Alt-Svc header, so an h2 client never discovers HTTP/3");
    assert!(
        alt_svc.contains("h3=\":8443\""),
        "Alt-Svc is {alt_svc:?}, which does not advertise h3 on the listener's port"
    );
}

/// The control, and the more important half: with HTTP/3 off there must be no
/// advertisement at all. An `Alt-Svc` for a port nothing answers on is worse than
/// silence — every client that believes it spends a timeout on a dead endpoint
/// before falling back to the connection it already had.
#[tokio::test]
async fn the_tcp_listener_advertises_nothing_when_http3_is_off() {
    use axum::body::Body;
    use tower::ServiceExt;

    let app = rolodex_dns::doh_server::build_router(local_dns_server(), None);
    let request = http::Request::builder()
        .method("POST")
        .uri("/dns-query")
        .header("content-type", "application/dns-message")
        .body(Body::from(wire_query(0x3333, LOCAL_NAME, RecordType::A)))
        .expect("build POST");

    let response = app.oneshot(request).await.expect("router response");
    assert_eq!(response.status(), 200, "the query itself was not answered");
    assert!(
        response.headers().get("alt-svc").is_none(),
        "an Alt-Svc header was sent with no HTTP/3 listener behind it: {:?}",
        response.headers().get("alt-svc")
    );
}
