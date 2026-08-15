//! DNS-over-TLS (RFC 7858) transport tests.
//!
//! `src/dot_server.rs` carried a single `test_dot_module_exists` compilation
//! smoke test, and `tests/security_dot_limits_test.rs` covers what the listener
//! must *refuse* — an untimed handshake, an unbounded connection count, a
//! half-delivered message. Nothing covered what it must *do*: negotiate the
//! transport, frame a message, answer, and keep the session open for the next
//! query. DoT is one of the five advertised transports and the one a LAN client
//! is most likely to be pointed at, so a regression in any of that would have
//! surfaced at a stub resolver rather than here.
//!
//! The file has two halves, and they are answering different questions.
//!
//! ## In-process: does the listener behave?
//!
//! A real `tokio-rustls` client against a real `serve_dot` on an ephemeral
//! loopback port. What each case pins:
//!
//! - **ALPN** — the IANA registry assigns DoT the token `dot` (RFC 7858). Three
//!   cases, because one alone proves nothing: a client offering `dot` must get
//!   `dot` back; a client offering *nothing* must still be served, since the
//!   stub resolvers that never send the extension (Android Private DNS,
//!   systemd-resolved in opportunistic mode) are most of the real installed
//!   base; and a client offering only a *different* protocol must be rejected,
//!   which is what distinguishes a listener that negotiates from one that
//!   ignores the extension and would "succeed" at all three.
//! - **Framing** — the 2-byte length prefix DoT shares with plain TCP. The
//!   prefix is asserted against the body that followed it, because a client
//!   frames on the prefix and a wrong one desynchronizes the session for good.
//! - **Answers** — a programmed name comes back with its address and a queried
//!   name that does not exist comes back NXDOMAIN. The pair matters: a listener
//!   that answered everything and one that answered nothing each satisfy one
//!   half.
//! - **Session reuse** — RFC 7766 connection reuse, which DoT depends on more
//!   than plain TCP does because reconnecting costs a fresh handshake. Several
//!   queries down one connection, each with its own ID, each matched back.
//!
//! ## Out-of-process: is it wired up?
//!
//! The in-process half builds its own `rustls::ServerConfig`, so it cannot
//! notice a `main.rs` that forgets to advertise ALPN or to name the bind address
//! in the certificate — exactly the two defects this suite was written for.
//! Those cases spawn the real `rolodex-dns` binary against a real config file
//! with a `dot:` section, the way a deployment runs it, and:
//!
//! - query a name programmed over the management socket, so the assertion runs
//!   the whole path a LAN client does — config parse, TLS construction,
//!   listener, DNS pipeline — and not a re-implementation of it;
//! - decode the subject alternative names out of the certificate the server
//!   actually presented, and check that the address it was bound to is among
//!   them. `127.0.0.2` is used rather than `127.0.0.1` precisely because the
//!   loopback set is baked in unconditionally: an address that is *not* in that
//!   set is the only one whose presence proves it was derived from the bind.
//!
//! ## Certificate handling
//!
//! In-process, as in `tests/security_dot_limits_test.rs` and `tests/doq_test.rs`,
//! the client **pins the exact certificate DER** the server was built with: a
//! verifier that accepts precisely one known certificate cannot accidentally
//! become one that accepts anything. Out-of-process the server generates its own
//! certificate, which the test cannot know in advance, so the verifier there
//! accepts what it is shown and *records* it — the assertion is about the
//! certificate's contents, so rejecting it before the test can look would defeat
//! the purpose. Both delegate signature checking to the real provider, so a
//! server that could not prove possession of its key still fails the handshake.
//!
//! Resolution is pinned to `forward` with no forwarders in both halves, and
//! every answer comes from local database records, so nothing here touches the
//! network. Everything binds loopback on ephemeral ports and writes only into a
//! temporary directory; the host is untouched.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rolodex_dns::db::{Database, DnsRecord, RecordKind};
use rolodex_dns::dns_server::{DnsServer, ResolutionMode};
use rolodex_dns::dnsbl::DnsblChecker;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The ALPN token IANA assigns to DNS-over-TLS (RFC 7858).
///
/// Written out here rather than imported from the crate so the two can disagree:
/// this is the value on the wire, and a test that reads the same constant the
/// server does would follow it wherever it went.
const DOT_ALPN: &[u8] = b"dot";

/// The name served from the local database, and its address.
const LOCAL_NAME: &str = "dot.example.com.";
const LOCAL_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

/// A name with no record, used for the authoritative-NXDOMAIN case.
const MISSING_NAME: &str = "absent.example.com.";

/// Nothing in this suite should take anywhere near this long; it exists so a
/// hang is reported as a failed assertion instead of a stuck test binary.
const PATIENCE: Duration = Duration::from_secs(10);

// ============================================================================
// Certificate verifiers
// ============================================================================

/// A verifier that accepts exactly one certificate: the one the test server was
/// built with.
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

/// A verifier that accepts any certificate and records the one it was shown.
///
/// Used only against the spawned binary, which generates its own certificate:
/// the assertion is about what is *inside* that certificate, so a verifier that
/// rejected it would leave nothing to assert on. Signature verification is still
/// delegated to the real provider.
#[derive(Debug)]
struct RecordingVerifier {
    seen: Arc<Mutex<Option<CertificateDer<'static>>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut slot) = self.seen.lock() {
            *slot = Some(end_entity.clone().into_owned());
        }
        Ok(ServerCertVerified::assertion())
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

// ============================================================================
// Shared helpers
// ============================================================================

/// Reserves an ephemeral port on `host` by binding and immediately dropping it.
///
/// Good enough for a test: nothing else on the box is racing for it, and the
/// window between the probe closing and the server binding is microseconds on
/// loopback.
fn free_port(host: &str) -> u16 {
    let listener = std::net::TcpListener::bind((host, 0)).expect("probe bind");
    listener.local_addr().expect("probe addr").port()
}

/// A well-formed query, length-prefixed for DoT's TCP-style framing.
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

/// Writes one framed query and reads back exactly one framed answer.
///
/// The length prefix is read first and the body read to that length, which is
/// what a client does — and is why the prefix is checked against the parse
/// below: a server whose prefix disagreed with its body would leave the session
/// permanently misaligned rather than merely returning one bad answer.
async fn query_over<S>(stream: &mut S, query: &[u8], label: &str) -> Message
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(PATIENCE, stream.write_all(query))
        .await
        .unwrap_or_else(|_| panic!("{label}: writing the query timed out"))
        .unwrap_or_else(|e| panic!("{label}: writing the query: {e}"));
    tokio::time::timeout(PATIENCE, stream.flush())
        .await
        .unwrap_or_else(|_| panic!("{label}: flushing the query timed out"))
        .unwrap_or_else(|e| panic!("{label}: flushing the query: {e}"));

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(PATIENCE, stream.read_exact(&mut len_buf))
        .await
        .unwrap_or_else(|_| panic!("{label}: no answer arrived"))
        .unwrap_or_else(|e| panic!("{label}: reading the length prefix: {e}"));
    let announced = u16::from_be_bytes(len_buf) as usize;
    // 12 octets is the DNS header (RFC 1035 §4.1.1) and the floor for any
    // message at all. A prefix shorter than that is not a short answer, it is a
    // desynchronized stream — the two bytes just read were message body.
    assert!(
        announced >= 12,
        "{label}: the server announced a {announced}-byte answer, which cannot even carry a \
         DNS header"
    );

    let mut body = vec![0u8; announced];
    tokio::time::timeout(PATIENCE, stream.read_exact(&mut body))
        .await
        .unwrap_or_else(|_| {
            panic!("{label}: the server announced {announced} bytes and did not send them")
        })
        .unwrap_or_else(|e| panic!("{label}: reading the answer body: {e}"));

    // Parsing exactly the announced bytes is the framing assertion: a prefix
    // that overstated the body would have timed out above, and one that
    // understated it leaves a message truncated mid-record, which fails here.
    Message::from_bytes(&body)
        .unwrap_or_else(|e| panic!("{label}: parsing the answer ({announced} bytes): {e}"))
}

/// Extracts the A record addresses from an answer section.
fn a_records(msg: &Message) -> Vec<Ipv4Addr> {
    msg.answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect()
}

// ============================================================================
// In-process listener
// ============================================================================

/// A running in-process DoT listener: its address, and the certificate it
/// serves.
struct DotServer {
    addr: String,
    cert: CertificateDer<'static>,
    /// The channel the listener reads its certificate from.
    ///
    /// `serve_dot` follows this rather than holding an acceptor, which is what
    /// lets a renewed certificate reach it without a restart. Held here for two
    /// reasons: the receiver inside the listener must not see every sender drop,
    /// and `the_listener_serves_a_renewed_certificate_without_a_restart` sends
    /// on it.
    tls: tokio::sync::watch::Sender<Arc<rustls::ServerConfig>>,
}

/// Starts a DoT listener on an ephemeral loopback port, serving one local A
/// record and advertising `alpn`.
///
/// Resolution is pinned to `forward` with no forwarders, so every answer comes
/// from the local database and a failure is about the transport rather than
/// about upstream resolution.
async fn start_dot_server(alpn: Vec<Vec<u8>>) -> DotServer {
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
    server.set_resolution_mode(ResolutionMode::Forward);

    let (certs, key) = rolodex_dns::tls::generate_self_signed().expect("self-signed certificate");
    let cert = certs.first().expect("one certificate").clone();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config");
    server_config.alpn_protocols = alpn;

    // Bind first to learn the port, then hand the address to the server. The
    // probe is dropped before `serve_dot` binds it again.
    let addr = format!("127.0.0.1:{}", free_port("127.0.0.1"));

    let bind = addr.clone();
    let (tls_tx, tls_rx) = tokio::sync::watch::channel(Arc::new(server_config));
    tokio::spawn(async move {
        let _unused = rolodex_dns::dot_server::serve_dot(&bind, server, tls_rx).await;
    });

    wait_for_tcp(&addr).await;
    DotServer {
        addr,
        cert,
        tls: tls_tx,
    }
}

/// Waits for something to accept TCP connections at `addr`.
///
/// Polling beats a fixed sleep: it is faster when the listener is up
/// immediately, and it does not turn a slow machine into a flake.
async fn wait_for_tcp(addr: &str) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("nothing is listening on {addr} after {PATIENCE:?}");
}

/// Builds a client config pinning the in-process server's certificate and
/// offering `alpn` (empty for a client that sends no ALPN extension at all).
fn client_config(server: &DotServer, alpn: Vec<Vec<u8>>) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCert {
            expected: server.cert.clone(),
            provider,
        }))
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    config
}

/// Attempts a handshake against the in-process listener, returning the result so
/// the negative ALPN case can assert on the failure.
async fn try_connect(
    server: &DotServer,
    alpn: Vec<Vec<u8>>,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let connector = TlsConnector::from(Arc::new(client_config(server, alpn)));
    let tcp = TcpStream::connect(&server.addr).await.expect("tcp connect");
    let name = ServerName::try_from("localhost").expect("server name");
    tokio::time::timeout(PATIENCE, connector.connect(name, tcp))
        .await
        .expect("the TLS handshake never completed or failed")
}

/// Completes a handshake offering `dot`, which is what an ordinary DoT client
/// does.
async fn connect_dot(server: &DotServer) -> tokio_rustls::client::TlsStream<TcpStream> {
    try_connect(server, vec![DOT_ALPN.to_vec()])
        .await
        .expect("TLS handshake with the DoT listener")
}

// ============================================================================
// The handshake
// ============================================================================

/// The IANA ALPN registry assigns DoT the token `dot` (RFC 7858). A client that
/// offers only `dot` must complete the handshake, and the negotiated protocol
/// must be that token — not an empty selection the client is left to guess
/// about, which is what a listener that never configured ALPN produces.
#[tokio::test]
async fn the_listener_negotiates_the_dot_alpn_token() {
    let server = start_dot_server(rolodex_dns::dot_server::alpn_protocols()).await;
    let stream = connect_dot(&server).await;

    let negotiated = stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|p| p.to_vec())
        .expect("the handshake negotiated no ALPN protocol at all");

    assert_eq!(
        negotiated,
        DOT_ALPN.to_vec(),
        "the listener negotiated {:?} rather than RFC 7858's `dot`",
        String::from_utf8_lossy(&negotiated)
    );
}

/// The compatibility control. Advertising `dot` must not shut out the clients
/// that send no ALPN extension at all — Android's Private DNS and
/// systemd-resolved in opportunistic mode among them, which is most of the
/// installed base a LAN resolver actually serves. TLS leaves ALPN unnegotiated
/// in that case rather than failing, and the session must work anyway.
#[tokio::test]
async fn a_client_that_offers_no_alpn_is_still_served() {
    let server = start_dot_server(rolodex_dns::dot_server::alpn_protocols()).await;
    let mut stream = try_connect(&server, Vec::new())
        .await
        .expect("a client offering no ALPN was refused by the DoT listener");

    assert!(
        stream.get_ref().1.alpn_protocol().is_none(),
        "a client that offered no protocols was told one was negotiated"
    );

    let answer = query_over(
        &mut stream,
        &framed_query(0x1001, LOCAL_NAME, RecordType::A),
        "no-alpn client",
    )
    .await;
    assert_eq!(
        a_records(&answer),
        vec![LOCAL_ADDR],
        "a client that offered no ALPN completed the handshake but was not answered"
    );
}

/// The negotiation control. A listener that advertises `dot` must *refuse* a
/// client offering only something else, because that is what makes the previous
/// two assertions mean anything: a listener that ignored the extension
/// altogether would pass both, and would leave a client silently talking the
/// wrong protocol to the port.
#[tokio::test]
async fn a_client_offering_only_another_protocol_is_refused() {
    let server = start_dot_server(rolodex_dns::dot_server::alpn_protocols()).await;
    let outcome = try_connect(&server, vec![b"h2".to_vec()]).await;

    assert!(
        outcome.is_err(),
        "a client offering only `h2` completed a handshake with the DoT listener"
    );
}

// ============================================================================
// Framing and answers
// ============================================================================

/// A name programmed into the database is answered over DoT with its address,
/// NOERROR, and the question echoed back.
#[tokio::test]
async fn a_programmed_name_is_answered_over_dot() {
    let server = start_dot_server(rolodex_dns::dot_server::alpn_protocols()).await;
    let mut stream = connect_dot(&server).await;

    let answer = query_over(
        &mut stream,
        &framed_query(0x2002, LOCAL_NAME, RecordType::A),
        "programmed name",
    )
    .await;

    assert_eq!(
        answer.id(),
        0x2002,
        "the answer carries a different ID than the query; a client with more than one query \
         in flight would mismatch them"
    );
    assert_eq!(answer.response_code(), ResponseCode::NoError);
    assert_eq!(
        answer.queries().first().map(|q| q.name().to_ascii()),
        Some(LOCAL_NAME.to_string()),
        "the answer does not echo the question"
    );
    assert_eq!(a_records(&answer), vec![LOCAL_ADDR]);
}

/// The control for the case above: a name with no record must come back
/// NXDOMAIN with an empty answer section. A listener that returned the
/// programmed record for everything would pass the previous test on its own.
#[tokio::test]
async fn an_unprogrammed_name_is_nxdomain_over_dot() {
    let server = start_dot_server(rolodex_dns::dot_server::alpn_protocols()).await;
    let mut stream = connect_dot(&server).await;

    let answer = query_over(
        &mut stream,
        &framed_query(0x3003, MISSING_NAME, RecordType::A),
        "unprogrammed name",
    )
    .await;

    assert_eq!(
        answer.response_code(),
        ResponseCode::NXDomain,
        "a name with no record was not refused: {:?}",
        answer.response_code()
    );
    assert!(
        a_records(&answer).is_empty(),
        "an NXDOMAIN answer carried address records: {:?}",
        a_records(&answer)
    );
}

/// RFC 7766 connection reuse. A client may hold one connection open and send
/// many queries down it, which matters more on DoT than on plain TCP because
/// reconnecting costs a fresh handshake.
///
/// The IDs are distinct and checked back individually, and the queries alternate
/// between a name that exists and one that does not: a server that answered from
/// a stale buffer, or that framed the second answer against the first query,
/// fails here and would not fail a single-query test.
#[tokio::test]
async fn one_connection_carries_many_queries() {
    let server = start_dot_server(rolodex_dns::dot_server::alpn_protocols()).await;
    let mut stream = connect_dot(&server).await;

    for (i, (id, name, expect_records)) in [
        (0x4001u16, LOCAL_NAME, true),
        (0x4002, MISSING_NAME, false),
        (0x4003, LOCAL_NAME, true),
        (0x4004, LOCAL_NAME, true),
    ]
    .into_iter()
    .enumerate()
    {
        let label = format!("query {i} on the reused connection");
        let answer = query_over(&mut stream, &framed_query(id, name, RecordType::A), &label).await;

        assert_eq!(answer.id(), id, "{label}: answered with the wrong ID");
        assert_eq!(
            answer.queries().first().map(|q| q.name().to_ascii()),
            Some(name.to_string()),
            "{label}: answered a different question"
        );
        if expect_records {
            assert_eq!(a_records(&answer), vec![LOCAL_ADDR], "{label}");
        } else {
            assert!(a_records(&answer).is_empty(), "{label}");
        }
    }
}

// ============================================================================
// Certificate rotation
// ============================================================================

/// A renewed certificate is served without restarting the listener.
///
/// `serve_dot` builds its acceptor per connection from a watch channel rather
/// than holding one, so pushing a new config onto the channel is the whole of a
/// renewal: no rebind, no dropped connections, no window where the port is
/// closed. The same listener, on the same address, that was serving the first
/// certificate a moment earlier serves the second one here — which is the
/// property, and is why the test never touches the listener between the two
/// handshakes.
///
/// Three things are pinned, and the middle one is the reason the first is not
/// enough on its own:
///
/// 1. a connection made **before** the rotation is unaffected — it finishes the
///    session it handshook, which is all TLS permits and all an in-flight query
///    needs;
/// 2. a connection made **after** it is served the new certificate, and the new
///    certificate is genuinely different from the old;
/// 3. the listener still *answers* under the new certificate. A swap that
///    replaced the acceptor and broke the DNS path would satisfy (2) alone.
#[tokio::test]
async fn the_listener_serves_a_renewed_certificate_without_a_restart() {
    let server = start_dot_server(rolodex_dns::dot_server::alpn_protocols()).await;

    // Before: a session on the original certificate, held open across the
    // rotation below.
    let (mut before, first) = connect_recording(&server.addr).await;
    assert_eq!(
        first.as_ref(),
        server.cert.as_ref(),
        "the listener did not start on the certificate it was built with"
    );

    // Renew. A fresh self-signed pair stands in for what an ACME client writes;
    // what reaches the listener is the same `rustls::ServerConfig` either way.
    let (renewed_certs, renewed_key) =
        rolodex_dns::tls::generate_self_signed().expect("renewed certificate");
    let renewed = renewed_certs.first().expect("one certificate").clone();
    assert_ne!(
        renewed.as_ref(),
        server.cert.as_ref(),
        "the renewal generated the same certificate; the test cannot tell the two apart"
    );
    let mut renewed_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(renewed_certs, renewed_key)
        .expect("renewed server config");
    renewed_config.alpn_protocols = rolodex_dns::dot_server::alpn_protocols();
    server
        .tls
        .send(Arc::new(renewed_config))
        .expect("the listener dropped its certificate receiver");

    // (1) The session opened before the rotation is untouched.
    let answer = query_over(
        &mut before,
        &framed_query(0x6001, LOCAL_NAME, RecordType::A),
        "session opened before the renewal",
    )
    .await;
    assert_eq!(
        a_records(&answer),
        vec![LOCAL_ADDR],
        "renewing the certificate broke a connection that was already open"
    );

    // (2) A new connection gets the new certificate.
    let (mut after, presented) = connect_recording(&server.addr).await;
    assert_eq!(
        presented.as_ref(),
        renewed.as_ref(),
        "a connection made after the renewal was served the old certificate; the listener is \
         holding a snapshot and would need a restart"
    );

    // (3) And is still a working DoT listener.
    let answer = query_over(
        &mut after,
        &framed_query(0x6002, LOCAL_NAME, RecordType::A),
        "session opened after the renewal",
    )
    .await;
    assert_eq!(
        a_records(&answer),
        vec![LOCAL_ADDR],
        "the listener served the renewed certificate but stopped answering"
    );
    assert_eq!(
        after
            .get_ref()
            .1
            .alpn_protocol()
            .map(|p| p.to_vec())
            .as_deref(),
        Some(DOT_ALPN),
        "the renewal lost the ALPN token"
    );
}

// ============================================================================
// The real binary: is the `dot:` config section wired up?
// ============================================================================

/// The loopback address the spawned server's DoT listener binds.
///
/// Deliberately not `127.0.0.1`: the generated certificate carries the loopback
/// identities unconditionally, so only an address *outside* that set can show
/// that the bind address was folded into the SAN list. All of `127.0.0.0/8` is
/// routed to `lo` on Linux, so binding this configures nothing on the host.
const SPAWNED_DOT_HOST: &str = "127.0.0.2";

/// A name configured as an extra SAN, and one that is not, so the SAN assertion
/// has a control.
const CONFIGURED_SAN: &str = "dot.test.invalid";
const UNCONFIGURED_SAN: &str = "not-configured.test.invalid";

/// A spawned server that is killed and reaped on drop, whatever the test does.
struct SpawnedServer {
    child: Child,
    dot_addr: String,
    socket_path: PathBuf,
    /// Where the process's stderr was sent.
    ///
    /// A listener that never comes up otherwise fails as a bare timeout with
    /// nothing to read, and the reason — a config field it rejected, a bind that
    /// failed — is exactly what the process said on the way past.
    log_path: PathBuf,
    /// Held so the temporary directory outlives the process using it.
    _dir: tempfile::TempDir,
}

impl SpawnedServer {
    /// Waits for both the management socket and the DoT listener, reporting what
    /// the process logged if either never appears.
    async fn wait_ready(&self) {
        let deadline = Instant::now() + PATIENCE;
        while Instant::now() < deadline {
            if self.socket_path.exists() && TcpStream::connect(&self.dot_addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!(
            "the spawned server did not come up: management socket {} {}, DoT listener {} not \
             accepting connections.\n--- server stderr ---\n{}",
            self.socket_path.display(),
            if self.socket_path.exists() {
                "present"
            } else {
                "absent"
            },
            self.dot_addr,
            std::fs::read_to_string(&self.log_path)
                .unwrap_or_else(|e| format!("(unreadable: {e})")),
        );
    }
}

impl Drop for SpawnedServer {
    fn drop(&mut self) {
        let _unused = self.child.kill();
        let _unused = self.child.wait();
    }
}

/// Path to the compiled server binary.
fn server_binary() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("rolodex-dns").to_path_buf()
}

/// Spawns the real `rolodex-dns` against a config file carrying a `dot:`
/// section, and waits for both the management socket and the DoT listener.
///
/// Everything is loopback and inside a temporary directory. `forwarders` is
/// empty and `resolution.mode` is `forward`, so the process cannot reach
/// upstream even if it wanted to; the answers come from records programmed over
/// the management socket below.
fn spawn_server_with_dot() -> SpawnedServer {
    let dir = tempfile::tempdir().expect("temp dir");
    let db_path = dir.path().join("rolodex-dns.db");
    let socket_path = dir.path().join("rolodex-dns.sock");
    let config_path = dir.path().join("rolodex-dns.yml");

    let dns_port = free_port("127.0.0.1");
    let dot_port = free_port(SPAWNED_DOT_HOST);
    let dot_addr = format!("{SPAWNED_DOT_HOST}:{dot_port}");

    let config = format!(
        "database_path: {db}\n\
         forwarders: []\n\
         dns:\n\
         \x20 bind:\n\
         \x20   - udp: \"127.0.0.1:{dns_port}\"\n\
         \x20   - tcp: \"127.0.0.1:{dns_port}\"\n\
         resolution:\n\
         \x20 mode: forward\n\
         grpc:\n\
         \x20 tcp_bind: \"\"\n\
         \x20 unix_socket: {sock}\n\
         \x20 shared_secret: \"\"\n\
         dot:\n\
         \x20 bind: \"{dot_addr}\"\n\
         \x20 tls:\n\
         \x20   auto_self_signed: true\n\
         \x20   self_signed_sans:\n\
         \x20     - \"{san}\"\n\
         dnsbl:\n\
         \x20 enabled: false\n\
         \x20 providers: []\n\
         address_family:\n\
         \x20 mode: off\n",
        db = db_path.display(),
        sock = socket_path.display(),
        dns_port = dns_port,
        dot_addr = dot_addr,
        san = CONFIGURED_SAN,
    );
    let mut f = std::fs::File::create(&config_path).expect("create config");
    f.write_all(config.as_bytes()).expect("write config");

    let log_path = dir.path().join("rolodex-dns.log");
    let log = std::fs::File::create(&log_path).expect("create log file");

    let child = Command::new(server_binary())
        .arg("-c")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .expect("failed to spawn rolodex-dns");

    SpawnedServer {
        child,
        dot_addr,
        socket_path,
        log_path,
        _dir: dir,
    }
}

/// Programs an A record into the spawned server over its management socket.
///
/// Driven through the real CLI against the real gRPC socket rather than by
/// writing the database file: the point of this half is that the deployed
/// pipeline is wired up end to end, and a record inserted behind the server's
/// back would prove nothing about it.
fn program_record(server: &SpawnedServer, name: &str, addr: Ipv4Addr) {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("rolodex-dns-cli"))
        .args([
            "-u",
            &server.socket_path.to_string_lossy(),
            "add-record",
            "-n",
            name,
            "-r",
            "a",
            "-v",
            &addr.to_string(),
            "--ttl",
            "300",
        ])
        .output()
        .expect("run rolodex-dns-cli");
    assert!(
        output.status.success(),
        "programming {name} failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Connects to the spawned server's DoT listener offering `dot`, returning the
/// session and the certificate it presented.
async fn connect_spawned(
    server: &SpawnedServer,
) -> (
    tokio_rustls::client::TlsStream<TcpStream>,
    CertificateDer<'static>,
) {
    connect_recording(&server.dot_addr).await
}

/// Completes a handshake against a DoT listener whose certificate the test
/// cannot know in advance, returning the session and the certificate presented.
///
/// Used wherever the certificate is the thing under test — the spawned binary
/// generates its own, and the rotation case is asking which of two the listener
/// is currently serving.
async fn connect_recording(
    addr: &str,
) -> (
    tokio_rustls::client::TlsStream<TcpStream>,
    CertificateDer<'static>,
) {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let seen = Arc::new(Mutex::new(None));
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RecordingVerifier {
            seen: Arc::clone(&seen),
            provider,
        }))
        .with_no_client_auth();
    config.alpn_protocols = vec![DOT_ALPN.to_vec()];

    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("tcp connect to the DoT listener at {addr}: {e}"));
    let name = ServerName::try_from("localhost").expect("server name");
    let stream = tokio::time::timeout(PATIENCE, connector.connect(name, tcp))
        .await
        .expect("the TLS handshake never completed or failed")
        .expect("TLS handshake with the DoT listener");

    let cert = seen
        .lock()
        .expect("seen")
        .clone()
        .expect("the handshake completed without presenting a certificate");
    (stream, cert)
}

/// Returns the dNSName and iPAddress subject alternative names in a certificate,
/// as the strings a client compares against.
///
/// Decoded from the certificate the server actually presented, rather than
/// re-derived from the list that produced it: a check written the other way
/// round would pass against an encoder that dropped every SAN on the floor.
fn subject_alt_names(cert: &CertificateDer<'_>) -> Vec<String> {
    use x509_parser::prelude::*;

    let (_rest, parsed) =
        X509Certificate::from_der(cert.as_ref()).expect("parse the presented certificate");
    let extension = parsed
        .subject_alternative_name()
        .expect("read the SAN extension")
        .expect("the certificate carries no subject alternative name extension");

    extension
        .value
        .general_names
        .iter()
        .filter_map(|gn| match gn {
            GeneralName::DNSName(name) => Some(name.to_string()),
            GeneralName::IPAddress(bytes) => match bytes.len() {
                4 => {
                    let octets: [u8; 4] = (*bytes).try_into().ok()?;
                    Some(IpAddr::from(octets).to_string())
                }
                16 => {
                    let octets: [u8; 16] = (*bytes).try_into().ok()?;
                    Some(IpAddr::from(octets).to_string())
                }
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// The wiring assertion. A `dot:` section in a config file must produce a
/// listener that a DoT client can reach, that negotiates `dot`, and that answers
/// a name programmed over the management API.
///
/// The in-process half above builds its own `rustls::ServerConfig`, so it cannot
/// see a `main.rs` that never asks for the ALPN token. This can.
#[tokio::test]
async fn the_configured_dot_listener_negotiates_alpn_and_answers() {
    let server = spawn_server_with_dot();
    server.wait_ready().await;

    program_record(&server, LOCAL_NAME, LOCAL_ADDR);

    let (mut stream, _cert) = connect_spawned(&server).await;

    let negotiated = stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|p| p.to_vec())
        .expect("the deployed DoT listener negotiated no ALPN protocol at all");
    assert_eq!(
        negotiated,
        DOT_ALPN.to_vec(),
        "the deployed DoT listener negotiated {:?} rather than RFC 7858's `dot`",
        String::from_utf8_lossy(&negotiated)
    );

    let answer = query_over(
        &mut stream,
        &framed_query(0x5005, LOCAL_NAME, RecordType::A),
        "deployed listener",
    )
    .await;
    assert_eq!(answer.response_code(), ResponseCode::NoError);
    assert_eq!(
        a_records(&answer),
        vec![LOCAL_ADDR],
        "the deployed DoT listener did not serve the programmed record"
    );

    // The control, on the same connection: the listener is answering from the
    // database rather than echoing something back for every name.
    let missing = query_over(
        &mut stream,
        &framed_query(0x5006, MISSING_NAME, RecordType::A),
        "deployed listener, unprogrammed name",
    )
    .await;
    assert_eq!(missing.response_code(), ResponseCode::NXDomain);
}

/// A generated DoT certificate must name the address the listener is bound to
/// and any `self_signed_sans` the operator configured.
///
/// This is what a LAN client needs: a stub resolver configured with an
/// authentication name checks the identity it dialled, and a certificate
/// covering only `localhost` fails that check on every address the box is
/// actually reachable at. `127.0.0.2` stands in for the LAN address here because
/// it is loopback (so the test configures nothing on the host) but is *not* one
/// of the identities baked into every generated certificate — which is what
/// makes its presence evidence of derivation rather than of the default.
#[tokio::test]
async fn the_generated_certificate_names_the_bind_address() {
    let server = spawn_server_with_dot();
    server.wait_ready().await;

    let (_stream, cert) = connect_spawned(&server).await;
    let sans = subject_alt_names(&cert);

    assert!(
        sans.iter().any(|s| s == SPAWNED_DOT_HOST),
        "the certificate does not name the address the listener is bound to \
         ({SPAWNED_DOT_HOST}); a name-checking client cannot use it. SANs: {sans:?}"
    );
    assert!(
        sans.iter().any(|s| s == CONFIGURED_SAN),
        "the certificate does not carry the configured `self_signed_sans` entry \
         ({CONFIGURED_SAN}). SANs: {sans:?}"
    );
    assert!(
        sans.iter().any(|s| s == "localhost"),
        "adding the bind address dropped the built-in loopback identities, which the box's \
         own resolver path dials. SANs: {sans:?}"
    );

    // The control. Without it, a certificate carrying a wildcard of names — or
    // one this test simply failed to look at properly — would pass everything
    // above.
    assert!(
        !sans.iter().any(|s| s == UNCONFIGURED_SAN),
        "the certificate names {UNCONFIGURED_SAN}, which was never configured. SANs: {sans:?}"
    );
}
