//! Discovery Designation (RFC 9462) followed end to end.
//!
//! Both halves of DDR were already covered, and separately: `svcb.rs` proves a
//! designation is *built* correctly, `arpa_refusal_test.rs` proves one is
//! *answered* from local data, and the orchestrator's own tests prove one is
//! *published*. What none of them did was act on the answer — nothing resolved
//! `_dns.resolver.arpa. SVCB` and then went and used what came back. Every part
//! could be individually right and the chain still broken: a `dohpath` template
//! nothing serves, a port naming a listener that is not there, an `alpn` token
//! the endpoint will not negotiate. Each of those is invisible to a test that
//! stops at the record.
//!
//! So this one is a client. It asks a running resolver over a real UDP socket
//! where its encrypted endpoints are, parses the SVCB answer, and builds a DoH
//! request from **nothing but what the record said** — the target, the port, the
//! ALPN token, the URI template. Then it resolves a name over that connection
//! and checks the address. A break anywhere in the chain fails here.
//!
//! The transport followed is HTTP/3, because the designation advertises it
//! (`alpn=h2,h3`) and it is the DoH transport this suite can drive natively; the
//! h2 half of the same endpoint is covered by `new_features_test.rs`, and the
//! record shape by `svcb.rs`'s own tests.
//!
//! ## What is deliberately NOT faked
//!
//! The port in the record is the port the listener actually took, read back from
//! the endpoint rather than assumed, and the request URL is assembled from the
//! parsed record rather than from the constants that seeded it. A test that
//! rebuilt the URL from its own inputs would pass against a resolver that
//! answered the designation with anything at all.
//!
//! ## Certificate handling
//!
//! As in `tests/doq_test.rs` and `tests/doh_h3_test.rs`, the client pins the
//! exact certificate DER the server was built with rather than trusting it as a
//! root. Everything binds ephemeral loopback ports; nothing reaches the network.

use base64::Engine;
use bytes::Buf;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
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

/// The name the encrypted endpoints are reached and authenticated as. It is
/// `localhost` because the test dials a loopback listener and the TLS handshake
/// has to carry a name the client can spell; on a real box it is `dns.<tld>`.
const ENDPOINT_NAME: &str = "localhost.";

/// The URI template the designation carries and the listener serves (RFC 9461
/// §5). Written once: the test follows the one it PARSES, and this is only what
/// seeds it.
const DOH_PATH_TEMPLATE: &str = "/dns-query{?dns}";

/// The name resolved over the discovered endpoint, and its address.
const LOCAL_NAME: &str = "ddr.example.com.";
const LOCAL_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 44);

/// Long enough that a hang is reported as a failed assertion rather than as a
/// stuck test binary.
const PATIENCE: Duration = Duration::from_secs(10);

/// A certificate verifier that accepts exactly one certificate: the one the test
/// server was built with. A verifier that accepts precisely one known
/// certificate cannot accidentally become one that accepts anything.
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

/// A resolver with a designation to hand out and one name to resolve, reachable
/// two ways: plain DNS over UDP (where discovery starts) and DoH over HTTP/3
/// (where it ends).
struct Box_ {
    /// The unencrypted resolver a client already has configured. This is the
    /// bootstrap DDR is defined around: a client asks the resolver it is using
    /// where that resolver's encrypted endpoints are.
    plain_dns: SocketAddr,
    cert: CertificateDer<'static>,
    _tls: tokio::sync::watch::Sender<Arc<rustls::ServerConfig>>,
}

/// Grabs a free loopback UDP port by binding one and letting it go.
///
/// The window between the drop and the real bind is harmless on loopback and is
/// the same approach `doq_test.rs` takes: the alternative is a listener API that
/// hands back its address, which `serve_udp` does not have.
async fn free_udp_port() -> SocketAddr {
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("probe bind");
    let addr = probe.local_addr().expect("probe addr");
    drop(probe);
    addr
}

/// Starts the box: the HTTP/3 endpoint first, so the designation can name the
/// port it actually took, then the plain-DNS listener that hands that
/// designation out.
async fn start_box() -> Box_ {
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
    .expect("add the resolvable record");

    let (certs, key) = rolodex_dns::tls::generate_self_signed().expect("self-signed certificate");
    let cert = certs.first().expect("one certificate").clone();
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config");
    // What the DoH listener's TLS manager produces. The HTTP/3 listener replaces
    // it with `h3`; seeding it this way keeps the test honest about where the
    // token comes from.
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let server_config = Arc::new(server_config);

    let doh_addr = free_udp_port().await;
    let endpoint =
        rolodex_dns::doh_h3_server::bind_doh_h3(&doh_addr.to_string(), server_config.clone())
            .expect("bind the HTTP/3 endpoint");
    let doh_port = endpoint
        .local_addr()
        .expect("HTTP/3 endpoint address")
        .port();

    // The designation names the port the listener actually took. Advertising an
    // endpoint nothing is listening on is the failure this whole test is for.
    for value in rolodex_dns::svcb::designation(
        ENDPOINT_NAME,
        Some((doh_port, DOH_PATH_TEMPLATE, true)),
        None,
        None,
    ) {
        db.add_record(&DnsRecord {
            id: None,
            name: rolodex_dns::svcb::DDR_DESIGNATION_NAME.to_string(),
            record_type: RecordKind::SVCB,
            value,
            ttl: 7200,
            priority: 0,
        })
        .expect("store the designation");
    }

    let rbl = Arc::new(DnsblChecker::new());
    let server = Arc::new(DnsServer::new(db, rbl, vec![]));
    // No upstream: every answer comes from local data, so a failure here is
    // about discovery and never about the network.
    server.set_resolution_mode(ResolutionMode::Forward);

    let (tls_tx, tls_rx) = tokio::sync::watch::channel(server_config);
    let h3_server = Arc::clone(&server);
    tokio::spawn(async move {
        let _unused =
            rolodex_dns::doh_h3_server::serve_doh_h3_on(endpoint, h3_server, tls_rx).await;
    });

    let plain_dns = free_udp_port().await;
    let udp_server = Arc::clone(&server);
    let bind = plain_dns.to_string();
    tokio::spawn(async move {
        let _unused = udp_server.serve_udp(&bind).await;
    });
    // Let the UDP socket come up before the first query; the HTTP/3 endpoint is
    // already bound above.
    tokio::time::sleep(Duration::from_millis(200)).await;

    Box_ {
        plain_dns,
        cert,
        _tls: tls_tx,
    }
}

/// A wire-format query.
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

/// Asks the plain resolver one question over a real UDP socket.
async fn ask_over_udp(server: &Box_, name: &str, qtype: RecordType) -> Message {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client socket");
    socket
        .send_to(&wire_query(0x0dd7, name, qtype), server.plain_dns)
        .await
        .expect("send the query");

    let mut buf = vec![0u8; 4096];
    let (n, _from) = tokio::time::timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("the resolver did not answer over UDP")
        .expect("receive the answer");
    Message::from_bytes(&buf[..n]).expect("parse the answer")
}

/// Everything a client needs to reach an endpoint, taken from one SVCB record
/// and nothing else.
#[derive(Debug)]
struct Designation {
    priority: u16,
    target: String,
    alpn: Vec<String>,
    port: Option<u16>,
    dohpath: Option<String>,
}

/// The `dohpath` SvcParamKey (RFC 9461 §5), carried as an unknown key because
/// hickory models no variant for it.
const SVC_PARAM_KEY_DOHPATH: u16 = 7;

/// Reads a designation out of an answer exactly as a client would: from the
/// rdata, not from the presentation string the test happened to store.
fn designations(message: &Message) -> Vec<Designation> {
    message
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::SVCB(svcb) => Some(svcb),
            _ => None,
        })
        .map(|svcb| {
            let mut alpn = Vec::new();
            let mut port = None;
            let mut dohpath = None;
            for (key, value) in svcb.svc_params() {
                match (key, value) {
                    (SvcParamKey::Alpn, SvcParamValue::Alpn(list)) => {
                        alpn = list.0.clone();
                    }
                    (SvcParamKey::Port, SvcParamValue::Port(p)) => port = Some(*p),
                    (SvcParamKey::Unknown(k), SvcParamValue::Unknown(bytes))
                        if *k == SVC_PARAM_KEY_DOHPATH =>
                    {
                        dohpath = String::from_utf8(bytes.0.clone()).ok();
                    }
                    _ => {}
                }
            }
            Designation {
                priority: svcb.svc_priority(),
                target: svcb.target_name().to_utf8(),
                alpn,
                port,
                dohpath,
            }
        })
        .collect()
}

/// Builds the request URI from a designation's template, the way RFC 9461 says
/// a client does: the `{?dns}` expansion is the base64url query, and everything
/// before it is the path the record named.
fn expand(template: &str, query: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(query);
    template.replace("{?dns}", &format!("?dns={}", encoded))
}

/// Follows a designation: connects over HTTP/3 to the address it names and
/// resolves one question there.
///
/// Everything used to reach the endpoint comes from `designation` — the ALPN
/// token offered, the port dialled, the path requested. Only the IP is supplied
/// separately, because the target name is `localhost` and resolving it is not
/// what this test is about.
async fn follow(
    server: &Box_,
    designation: &Designation,
    query: &[u8],
) -> (http::StatusCode, Vec<u8>) {
    let alpn = designation
        .alpn
        .iter()
        .find(|a| a.as_str() == "h3")
        .expect("the designation does not offer h3, so there is nothing to follow here");
    let port = designation.port.expect("the designation names no port");
    let template = designation
        .dohpath
        .as_deref()
        .expect("the designation carries no dohpath, so a client cannot build a URL");

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
    crypto.alpn_protocols = vec![alpn.as_bytes().to_vec()];

    let quic_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("QUIC client crypto");
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
        .expect("client endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_crypto)));

    let authority = designation.target.trim_end_matches('.').to_string();
    let addr: SocketAddr = format!("127.0.0.1:{}", port)
        .parse()
        .expect("endpoint address");
    let connection = tokio::time::timeout(
        PATIENCE,
        endpoint
            .connect(addr, &authority)
            .expect("connect to the designated endpoint"),
    )
    .await
    .expect("the designated endpoint did not complete a handshake")
    .expect("handshake with the designated endpoint");

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .expect("HTTP/3 client setup");
    let driving = tokio::spawn(async move {
        let _closed = driver.wait_idle().await;
    });

    let uri = format!("https://{}:{}{}", authority, port, expand(template, query));
    let mut stream = send_request
        .send_request(
            http::Request::get(&uri)
                .body(())
                .expect("build the request"),
        )
        .await
        .expect("send the request");
    stream.finish().await.expect("finish the request");

    let response = tokio::time::timeout(PATIENCE, stream.recv_response())
        .await
        .expect("no response from the designated endpoint")
        .expect("read the response head");

    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.expect("read the response body") {
        while chunk.has_remaining() {
            let advanced = {
                let segment = chunk.chunk();
                body.extend_from_slice(segment);
                segment.len()
            };
            chunk.advance(advanced);
        }
    }

    driving.abort();
    (response.status(), body)
}

/// The whole chain: ask the resolver you already have where its encrypted
/// endpoints are, then go and resolve a name at one of them.
///
/// This is the test the DDR work was missing. Everything it needs to reach the
/// endpoint is read out of the answer, so a designation that names the wrong
/// port, a template nothing serves, or an ALPN token the listener will not
/// negotiate fails here rather than at somebody's phone.
#[tokio::test]
async fn a_designation_is_discovered_and_followed_to_a_working_doh_endpoint() {
    let server = start_box().await;

    let answer = ask_over_udp(
        &server,
        rolodex_dns::svcb::DDR_DESIGNATION_NAME,
        RecordType::SVCB,
    )
    .await;
    assert_eq!(
        answer.response_code(),
        ResponseCode::NoError,
        "the resolver refused its own designation: {:?}",
        answer.response_code()
    );

    let found = designations(&answer);
    let designation = found
        .iter()
        .find(|d| d.dohpath.is_some())
        .expect("no DoH designation came back, so there is nothing for a client to follow");
    assert_eq!(
        designation.priority, 1,
        "the DoH endpoint is not the first choice; :443 is what survives the DPI \
         that filters :853"
    );
    assert_eq!(
        designation.target, ENDPOINT_NAME,
        "the designation names an endpoint other than the one it was published for"
    );
    assert!(
        designation.alpn.contains(&"h3".to_string()),
        "the designation does not advertise h3: {:?}",
        designation.alpn
    );

    let (status, body) = follow(
        &server,
        designation,
        &wire_query(0x2b2b, LOCAL_NAME, RecordType::A),
    )
    .await;

    assert_eq!(
        status,
        http::StatusCode::OK,
        "the designated endpoint refused a query built from its own record"
    );
    let resolved = Message::from_bytes(&body).expect("parse the answer from the endpoint");
    assert_eq!(
        resolved.response_code(),
        ResponseCode::NoError,
        "the discovered endpoint answered {:?}",
        resolved.response_code()
    );
    let addresses: Vec<Ipv4Addr> = resolved
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
        "the name resolved over the discovered endpoint came back with the wrong address"
    );
}

/// The control for the `dohpath` half. The template is what turns a designation
/// into a URL, and a client that ignored it and guessed `/dns-query` would pass
/// the test above on this server by luck. Asking at a path the record did not
/// name must be refused — which is what makes following the template meaningful
/// rather than decorative.
#[tokio::test]
async fn a_path_the_designation_did_not_name_is_not_served() {
    let server = start_box().await;

    let answer = ask_over_udp(
        &server,
        rolodex_dns::svcb::DDR_DESIGNATION_NAME,
        RecordType::SVCB,
    )
    .await;
    let found = designations(&answer);
    let designation = found
        .iter()
        .find(|d| d.dohpath.is_some())
        .expect("no DoH designation came back");

    let wrong = Designation {
        priority: designation.priority,
        target: designation.target.clone(),
        alpn: designation.alpn.clone(),
        port: designation.port,
        dohpath: Some("/not-the-designated-path{?dns}".to_string()),
    };

    let (status, _body) = follow(
        &server,
        &wrong,
        &wire_query(0x2c2c, LOCAL_NAME, RecordType::A),
    )
    .await;
    assert_eq!(
        status,
        http::StatusCode::NOT_FOUND,
        "the endpoint served a path its designation never named, so following \
         the template proves nothing"
    );
}
