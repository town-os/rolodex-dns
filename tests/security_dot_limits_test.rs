//! Security regression tests for DNS-over-TLS connection limits.
//!
//! These assert behaviour the DoT listener *should* have and are expected to
//! FAIL against the current implementation. Do not weaken an assertion to make
//! one pass.
//!
//! The companion to `tests/security_tcp_limits_test.rs`: `handle_dot_connection`
//! (`src/dot_server.rs`) has the same untimed `read_exact` loop as the plain-TCP
//! handler, and `serve_dot` spawns a task per connection with no cap. Fixing
//! `:53` and leaving `:853` alone closes nothing — an attacker picks whichever
//! port is still free.
//!
//! DoT is also *worse* than plain TCP in one respect, which is why it gets its
//! own file rather than another case in that one: the **TLS handshake itself is
//! untimed**. `serve_dot` awaits `acceptor.accept(stream)` inside the spawned
//! task, so a client that opens a TCP connection and never sends a ClientHello
//! parks a task before a single byte of DNS has been exchanged. That attack
//! needs no TLS implementation at all — a bare `connect()` is the whole exploit —
//! and no fix aimed at the DNS read loop touches it, because the connection
//! never reaches the DNS read loop.
//!
//! ## Certificate handling
//!
//! The server is built from `rolodex_dns::tls::generate_self_signed`, the same
//! certificate a default deployment serves, and the client **pins that exact
//! certificate DER**. Pinning rather than trusting it as a root: this is a test
//! verifier, and one that accepts precisely one known certificate cannot
//! accidentally become one that accepts anything. It also sidesteps the question
//! of whether a self-signed leaf is usable as a webpki trust anchor, which is
//! not what these tests are about.
//!
//! As in the TCP suite, [`IDLE_ALLOWANCE`] is deliberately loose — it pins that
//! a bound exists, not what it is.
//!
//! Everything binds an ephemeral loopback port; the host is untouched.

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use rolodex_dns::db::Database;
use rolodex_dns::dns_server::{DnsServer, ResolutionMode};
use rolodex_dns::dnsbl::DnsblChecker;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The longest an idle connection may be left open before the server closes it.
const IDLE_ALLOWANCE: Duration = Duration::from_secs(30);

/// RFC 7858's ALPN token, which production DoT listeners advertise.
const DOT_ALPN: &[u8] = b"dot";

/// A certificate verifier that accepts exactly one certificate: the one the test
/// server was built with.
///
/// Signature checking is delegated to the real provider, so only the identity
/// decision is overridden — a verifier that skipped signature verification too
/// would accept a handshake the server never actually completed.
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

/// A running DoT listener: its address, and the certificate it serves.
struct DotServer {
    addr: String,
    cert: CertificateDer<'static>,
    /// The certificate channel's sender, held so the listener's receiver stays
    /// open for the life of the test. `serve_dot` follows a channel rather than
    /// holding an acceptor, so that a renewed certificate reaches it without a
    /// restart; nothing here renews one, but the sender still has to outlive the
    /// listener.
    _tls: tokio::sync::watch::Sender<Arc<rustls::ServerConfig>>,
}

/// Starts a DoT listener on an ephemeral loopback port.
///
/// Resolution is pinned to `forward` with no forwarders so nothing here can
/// reach the network; these tests are about the connection lifecycle, not about
/// answers.
async fn start_dot_server() -> DotServer {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(DnsblChecker::new());
    let server = Arc::new(DnsServer::new(db, rbl, vec![]));
    server.set_resolution_mode(ResolutionMode::Forward);

    let (certs, key) = rolodex_dns::tls::generate_self_signed().expect("self-signed certificate");
    let cert = certs.first().expect("one certificate").clone();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config");
    server_config.alpn_protocols = vec![DOT_ALPN.to_vec()];

    // Bind first to learn the port, then hand the address to the server. The
    // probe is dropped before `serve_dot` binds it again; nothing else on the
    // box is racing for an ephemeral port.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap().to_string();
    drop(probe);

    let bind = addr.clone();
    let (tls_tx, tls_rx) = tokio::sync::watch::channel(Arc::new(server_config));
    tokio::spawn(async move {
        let _unused = rolodex_dns::dot_server::serve_dot(&bind, server, tls_rx).await;
    });

    // Let the listener come up before the first connect.
    tokio::time::sleep(Duration::from_millis(200)).await;
    DotServer {
        addr,
        cert,
        _tls: tls_tx,
    }
}

/// Completes a TLS handshake against the DoT listener.
async fn connect_dot(server: &DotServer) -> tokio_rustls::client::TlsStream<TcpStream> {
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
    config.alpn_protocols = vec![DOT_ALPN.to_vec()];

    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(&server.addr).await.expect("tcp connect");
    let name = ServerName::try_from("localhost").expect("server name");
    connector
        .connect(name, tcp)
        .await
        .expect("TLS handshake with the DoT listener")
}

/// A well-formed query, length-prefixed for DoT's TCP-style framing.
fn framed_query(name: &str) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(0x5151);
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
async fn closed_within_allowance<S>(mut stream: S) -> bool
where
    S: AsyncRead + Unpin,
{
    let mut buf = [0u8; 1];
    match tokio::time::timeout(IDLE_ALLOWANCE, stream.read(&mut buf)).await {
        // 0 bytes is a clean EOF (or a TLS close_notify); an error is a reset.
        // Either is the server reclaiming the connection.
        Ok(Ok(0)) | Ok(Err(_)) => true,
        // The server sent us something unprompted, which it should not have.
        Ok(Ok(_)) => false,
        // Still open, still holding a task and a descriptor.
        Err(_) => false,
    }
}

/// Reads one length-prefixed DNS message, failing the test if it does not
/// arrive.
async fn read_framed_response<S>(stream: &mut S, label: &str)
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut len_buf))
        .await
        .unwrap_or_else(|_| panic!("{}: no answer within 10s", label))
        .unwrap_or_else(|e| panic!("{}: reading length prefix: {}", label, e));
    let len = u16::from_be_bytes(len_buf) as usize;
    assert!(len > 0, "{}: the answer must not be empty", label);

    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .unwrap_or_else(|_| panic!("{}: answer body did not arrive", label))
        .unwrap_or_else(|e| panic!("{}: reading answer body: {}", label, e));
}

// ============================================================================
// Before the handshake
// ============================================================================

/// The cheapest attack on this listener, and the one unique to it: open a TCP
/// connection and never start TLS. `serve_dot` is inside `acceptor.accept()`,
/// which has no timeout, so the task waits for a ClientHello that never comes.
///
/// No TLS implementation is required to mount this — `connect()` is the entire
/// exploit — and a timeout added to the DNS read loop does not help, because the
/// connection never gets that far.
#[tokio::test]
async fn a_connection_that_never_starts_tls_is_eventually_closed() {
    let server = start_dot_server().await;
    let stream = TcpStream::connect(&server.addr).await.expect("connect");

    assert!(
        closed_within_allowance(stream).await,
        "a TCP connection to the DoT port that sent no ClientHello was still \
         open after {}s; `serve_dot` awaits `acceptor.accept()` with no timeout",
        IDLE_ALLOWANCE.as_secs()
    );
}

/// The same attack from inside a started handshake: send a TLS record header
/// announcing a ClientHello and then stop. rustls is now mid-message rather than
/// waiting for a first byte, so a fix that only covers "sent nothing at all"
/// misses it.
#[tokio::test]
async fn a_stalled_client_hello_does_not_pin_a_connection() {
    let server = start_dot_server().await;
    let mut stream = TcpStream::connect(&server.addr).await.expect("connect");
    // TLS record: handshake (0x16), version 3.3, length 0x0200 — of which
    // nothing follows.
    stream
        .write_all(&[0x16, 0x03, 0x03, 0x02, 0x00])
        .await
        .expect("write record header");
    stream.flush().await.expect("flush");

    assert!(
        closed_within_allowance(stream).await,
        "a connection that announced a ClientHello and sent none of it was still \
         open after {}s",
        IDLE_ALLOWANCE.as_secs()
    );
}

// ============================================================================
// After the handshake
// ============================================================================

/// A completed TLS session that never carries a query must not be held forever
/// either. This one costs the attacker a handshake, but it also costs the server
/// the session state, so it is the more expensive connection of the two to keep.
#[tokio::test]
async fn an_idle_dot_session_is_eventually_closed() {
    let server = start_dot_server().await;
    let stream = connect_dot(&server).await;

    assert!(
        closed_within_allowance(stream).await,
        "a DoT session that sent no query was still open after {}s; \
         `handle_dot_connection` awaits `read_exact` with no timeout",
        IDLE_ALLOWANCE.as_secs()
    );
}

/// And with half a length prefix delivered inside the TLS session — the DoT
/// mirror of the plain-TCP case.
#[tokio::test]
async fn a_half_sent_length_prefix_does_not_pin_a_dot_session() {
    let server = start_dot_server().await;
    let mut stream = connect_dot(&server).await;
    stream.write_all(&[0x00]).await.expect("write first byte");
    stream.flush().await.expect("flush");

    assert!(
        closed_within_allowance(stream).await,
        "a DoT session that sent half a length prefix was still open after {}s",
        IDLE_ALLOWANCE.as_secs()
    );
}

// ============================================================================
// Controls: real DoT clients must keep working
// ============================================================================

/// The mirror invariant: a client that completes the handshake and asks a
/// question gets an answer. A fix that closes DoT connections aggressively
/// enough to break this has broken the transport.
#[tokio::test]
async fn a_dot_client_that_sends_a_query_is_answered() {
    let server = start_dot_server().await;
    let mut stream = connect_dot(&server).await;

    stream
        .write_all(&framed_query("example.com."))
        .await
        .expect("write query");
    stream.flush().await.expect("flush");

    read_framed_response(&mut stream, "single query").await;
}

/// DoT exists partly to amortize the handshake across many queries, so an idle
/// timeout has to be measured from the last activity rather than from the
/// session opening. Otherwise a fix turns every stub resolver into a
/// re-handshake loop — which is far more expensive here than on plain TCP.
#[tokio::test]
async fn a_dot_session_stays_usable_between_queries() {
    let server = start_dot_server().await;
    let mut stream = connect_dot(&server).await;

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
        read_framed_response(&mut stream, &format!("query {}", i)).await;
    }
}
