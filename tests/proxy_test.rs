//! Upstream forwarding through a proxy: HTTP CONNECT, SOCKS5, and DoH.
//!
//! `src/doh_proxy.rs` had unit tests for URL parsing, mode parsing, and the DoH
//! connection pool — everything *except* whether a DNS query actually reaches an
//! upstream through a proxy. The three protocol implementations (a CONNECT
//! tunnel, RFC 1928's SOCKS5 handshake, and a DoH POST in absolute-URI form)
//! were byte-assembled by hand and never spoken to anything.
//!
//! Each test here stands up a mock proxy that **parses what the server sends**
//! rather than echoing a canned reply, so a malformed greeting, a wrong address
//! type, or a missing header fails at the proxy rather than being absorbed. The
//! mocks record what they saw, and the recording is the assertion: "the client
//! got an answer" would pass just as happily against a proxy that ignored the
//! protocol entirely, so every test also pins *what was asked of the proxy* —
//! the tunnel target, the credentials, the request line.
//!
//! Two properties are checked per mode:
//!
//! - the query reaches the upstream and its answer reaches the client, and
//! - a proxy that refuses is not mistaken for one that succeeded (the failure
//!   must surface as SERVFAIL, never as a fabricated or empty answer).
//!
//! The server is built with **no response cache**, so a second query in a test
//! is genuinely a second trip through the proxy rather than a cache hit.
//!
//! Everything binds ephemeral loopback ports; the host is untouched.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rolodex_dns::db::Database;
use rolodex_dns::dns_server::{DnsServer, ResolutionMode};
use rolodex_dns::dnsbl::DnsblChecker;
use rolodex_dns::doh_proxy::{ProxyConfig, ProxyMode};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The name every test resolves, and the address the mock upstream answers with.
const UPSTREAM_NAME: &str = "proxied.example.com.";
const UPSTREAM_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 42);

/// An ordinary LAN client, inside the default `security.recursion_cidrs` so
/// upstream resolution is permitted; these tests are about the proxy, not about
/// recursion access control.
const CLIENT: &str = "192.168.1.20";

/// A proxy that answers promptly should answer well inside this.
const PATIENCE: Duration = Duration::from_secs(10);

/// What a mock proxy observed, so a test can assert on the protocol exchange
/// rather than only on the answer that came back.
#[derive(Default)]
struct ProxyLog {
    /// The tunnel target as the proxy understood it (`host:port`).
    target: Option<String>,
    /// Credentials the server presented, decoded to `user:pass`.
    credentials: Option<String>,
    /// The first line of an HTTP request, for the DoH mode.
    request_line: Option<String>,
    /// Header lines of an HTTP request, lowercased.
    headers: Vec<String>,
    /// The request body, for the DoH mode.
    body: Vec<u8>,
    /// How many TCP connections the proxy accepted.
    connections: usize,
}

type SharedLog = Arc<Mutex<ProxyLog>>;

fn new_log() -> SharedLog {
    Arc::new(Mutex::new(ProxyLog::default()))
}

/// Builds the answer the upstream (or the DoH proxy) returns for `query`.
fn answer_for(query: &Message) -> Vec<u8> {
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
            RData::A(rdata::A(UPSTREAM_ADDR)),
        ));
    }
    resp.to_bytes().unwrap_or_default()
}

/// A DNS-over-TCP upstream: 2-byte length prefix, one answer per message, and
/// it stays open for the life of the tunnel.
///
/// This is what the CONNECT and SOCKS5 tunnels must actually deliver bytes to.
/// A proxy mock that replied "200 OK" and then dropped the connection would let
/// the client fail; making the far end a real DNS server is what proves the
/// tunnel carries traffic in both directions.
async fn spawn_tcp_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                loop {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut body = vec![0u8; len];
                    if stream.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    let Ok(query) = Message::from_bytes(&body) else {
                        return;
                    };
                    let response = answer_for(&query);
                    if stream
                        .write_all(&(response.len() as u16).to_be_bytes())
                        .await
                        .is_err()
                        || stream.write_all(&response).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });

    addr
}

/// Reads an HTTP request head (up to and including the blank line) one byte at a
/// time, so nothing of the body is consumed.
async fn read_http_head(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if stream.read_exact(&mut byte).await.is_err() {
            return None;
        }
        head.push(byte[0]);
        if head.len() >= 4 && &head[head.len() - 4..] == b"\r\n\r\n" {
            return Some(String::from_utf8_lossy(&head).to_string());
        }
        if head.len() > 8192 {
            return None;
        }
    }
}

fn decode_basic(value: &str) -> Option<String> {
    let encoded = value.trim().strip_prefix("Basic ")?;
    let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    String::from_utf8(raw).ok()
}

/// An HTTP CONNECT proxy.
///
/// `status` is the response line it returns; when it is a 2xx the proxy dials
/// the requested target and splices the two sockets, so the tunnel is real.
async fn spawn_connect_proxy(status: &'static str, log: SharedLog) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let addr = listener.local_addr().expect("proxy addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let Some(head) = read_http_head(&mut client).await else {
                    return;
                };

                let mut lines = head.lines();
                let request_line = lines.next().unwrap_or_default().to_string();
                let target = request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let credentials = head
                    .lines()
                    .find(|l| l.to_lowercase().starts_with("proxy-authorization:"))
                    .and_then(|l| l.split_once(':').map(|(_, v)| v))
                    .and_then(decode_basic);

                {
                    let mut guard = log.lock().expect("log");
                    guard.connections += 1;
                    guard.request_line = Some(request_line.clone());
                    guard.target = Some(target.clone());
                    guard.credentials = credentials;
                    guard.headers = head.lines().skip(1).map(|l| l.to_lowercase()).collect();
                }

                if !status.contains("200") {
                    let _unused = client
                        .write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes())
                        .await;
                    return;
                }

                let Ok(mut upstream) = TcpStream::connect(&target).await else {
                    let _unused = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return;
                };
                if client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let _unused = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });

    addr
}

/// A SOCKS5 proxy (RFC 1928).
///
/// `require_auth` makes it select username/password (RFC 1929) instead of
/// no-auth, and `expected_credentials` is what it will accept. `failure_code`,
/// when set, is returned as the CONNECT reply instead of success.
async fn spawn_socks5_proxy(
    require_auth: bool,
    expected_credentials: Option<&'static str>,
    failure_code: Option<u8>,
    log: SharedLog,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks5");
    let addr = listener.local_addr().expect("socks5 addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                log.lock().expect("log").connections += 1;

                // Greeting: version, method count, methods.
                let mut header = [0u8; 2];
                if client.read_exact(&mut header).await.is_err() {
                    return;
                }
                assert_eq!(
                    header[0], 0x05,
                    "SOCKS5 greeting used version {}",
                    header[0]
                );
                let mut methods = vec![0u8; header[1] as usize];
                if client.read_exact(&mut methods).await.is_err() {
                    return;
                }

                if require_auth {
                    assert!(
                        methods.contains(&0x02),
                        "the server did not offer username/password authentication"
                    );
                    if client.write_all(&[0x05, 0x02]).await.is_err() {
                        return;
                    }

                    // RFC 1929: version, ulen, user, plen, pass.
                    let mut version = [0u8; 2];
                    if client.read_exact(&mut version).await.is_err() {
                        return;
                    }
                    let mut user = vec![0u8; version[1] as usize];
                    if client.read_exact(&mut user).await.is_err() {
                        return;
                    }
                    let mut plen = [0u8; 1];
                    if client.read_exact(&mut plen).await.is_err() {
                        return;
                    }
                    let mut pass = vec![0u8; plen[0] as usize];
                    if client.read_exact(&mut pass).await.is_err() {
                        return;
                    }
                    let presented = format!(
                        "{}:{}",
                        String::from_utf8_lossy(&user),
                        String::from_utf8_lossy(&pass)
                    );
                    log.lock().expect("log").credentials = Some(presented.clone());

                    let ok = expected_credentials.map(|e| e == presented).unwrap_or(true);
                    if client
                        .write_all(&[0x01, if ok { 0x00 } else { 0x01 }])
                        .await
                        .is_err()
                        || !ok
                    {
                        return;
                    }
                } else {
                    assert!(
                        methods.contains(&0x00),
                        "the server did not offer the no-auth method"
                    );
                    if client.write_all(&[0x05, 0x00]).await.is_err() {
                        return;
                    }
                }

                // CONNECT request: version, command, reserved, address type.
                let mut request = [0u8; 4];
                if client.read_exact(&mut request).await.is_err() {
                    return;
                }
                assert_eq!(request[0], 0x05, "SOCKS5 request used a bad version");
                assert_eq!(request[1], 0x01, "SOCKS5 command was not CONNECT");

                let host = match request[3] {
                    0x01 => {
                        let mut octets = [0u8; 4];
                        if client.read_exact(&mut octets).await.is_err() {
                            return;
                        }
                        IpAddr::from(octets).to_string()
                    }
                    0x04 => {
                        let mut octets = [0u8; 16];
                        if client.read_exact(&mut octets).await.is_err() {
                            return;
                        }
                        IpAddr::from(octets).to_string()
                    }
                    other => panic!("SOCKS5 request used address type {other}"),
                };
                let mut port = [0u8; 2];
                if client.read_exact(&mut port).await.is_err() {
                    return;
                }
                let target = format!("{host}:{}", u16::from_be_bytes(port));
                log.lock().expect("log").target = Some(target.clone());

                if let Some(code) = failure_code {
                    let _unused = client
                        .write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return;
                }

                let Ok(mut upstream) = TcpStream::connect(&target).await else {
                    let _unused = client
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return;
                };
                // Success, with a bound address of 0.0.0.0:0.
                if client
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .is_err()
                {
                    return;
                }
                let _unused = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });

    addr
}

/// An HTTP proxy that answers DoH POSTs itself, with HTTP/1.1 keep-alive so the
/// connection pool has something to reuse.
///
/// `status` is the response status line; a non-200 exercises the failure path.
async fn spawn_doh_proxy(status: &'static str, log: SharedLog) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind doh proxy");
    let addr = listener.local_addr().expect("doh proxy addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                log.lock().expect("log").connections += 1;
                loop {
                    let Some(head) = read_http_head(&mut client).await else {
                        return;
                    };
                    let request_line = head.lines().next().unwrap_or_default().to_string();
                    let headers: Vec<String> =
                        head.lines().skip(1).map(|l| l.to_lowercase()).collect();
                    let length: usize = headers
                        .iter()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);

                    let mut body = vec![0u8; length];
                    if length > 0 && client.read_exact(&mut body).await.is_err() {
                        return;
                    }

                    let credentials = head
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("proxy-authorization:"))
                        .and_then(|l| l.split_once(':').map(|(_, v)| v))
                        .and_then(decode_basic);

                    {
                        let mut guard = log.lock().expect("log");
                        guard.request_line = Some(request_line);
                        guard.headers = headers;
                        guard.body = body.clone();
                        if credentials.is_some() {
                            guard.credentials = credentials;
                        }
                    }

                    let payload = match Message::from_bytes(&body) {
                        Ok(query) => answer_for(&query),
                        Err(_) => Vec::new(),
                    };

                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/dns-message\r\n\
                         Content-Length: {}\r\n\r\n",
                        payload.len()
                    );
                    if client.write_all(response.as_bytes()).await.is_err()
                        || client.write_all(&payload).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });

    addr
}

/// A forwarding server pointed at `upstream`, tunnelling through `proxy`.
///
/// No response cache: every query in a test must make a real trip through the
/// proxy, which is what the connection-reuse and per-query assertions depend on.
fn make_server(upstream: SocketAddr, proxy: Option<ProxyConfig>) -> Arc<DnsServer> {
    let db = Database::open_memory().expect("in-memory database");
    let rbl = Arc::new(DnsblChecker::new());
    let server = Arc::new(DnsServer::new(db, rbl, vec![upstream]));
    server.set_resolution_mode(ResolutionMode::Forward);
    server.set_proxy_config(proxy);
    server
}

fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(Name::from_ascii(name).expect("valid name"));
    q.set_query_type(RecordType::A);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    msg.to_bytes().expect("serialize query")
}

/// Resolves `UPSTREAM_NAME` through the server and returns the parsed response.
async fn resolve(server: &DnsServer, id: u16) -> Message {
    let query = build_query(id, UPSTREAM_NAME);
    let client: IpAddr = CLIENT.parse().expect("client address");
    let raw = tokio::time::timeout(PATIENCE, server.handle_query_from(&query, client))
        .await
        .expect("the query never came back")
        .expect("handling the query");
    Message::from_bytes(&raw).expect("parse response")
}

/// The addresses in a response's answer section.
fn addresses(response: &Message) -> Vec<Ipv4Addr> {
    response
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect()
}

// ============================================================================
// HTTP CONNECT
// ============================================================================

/// The base case for `ProxyMode::Connect`: the server opens a tunnel to the
/// forwarder through the proxy and the upstream's answer comes back.
///
/// The proxy's recorded target is asserted against the forwarder address,
/// because a tunnel opened to the *wrong* place would still produce a working
/// query in a test where only one upstream exists.
#[tokio::test]
async fn a_query_is_tunnelled_through_an_http_connect_proxy() {
    let upstream = spawn_tcp_upstream().await;
    let log = new_log();
    let proxy = spawn_connect_proxy("200 Connection Established", Arc::clone(&log)).await;

    let server = make_server(
        upstream,
        Some(ProxyConfig {
            url: format!("http://{proxy}"),
            auth: None,
            mode: ProxyMode::Connect,
        }),
    );

    let response = resolve(&server, 0x0101).await;
    assert_eq!(
        response.response_code(),
        ResponseCode::NoError,
        "the tunnelled query answered {:?}",
        response.response_code()
    );
    assert_eq!(
        addresses(&response),
        vec![UPSTREAM_ADDR],
        "the answer did not come from the upstream behind the tunnel"
    );

    let guard = log.lock().expect("log");
    assert_eq!(
        guard.target.as_deref(),
        Some(upstream.to_string().as_str()),
        "the proxy was asked to tunnel to the wrong target"
    );
    let request_line = guard.request_line.clone().unwrap_or_default();
    assert!(
        request_line.starts_with("CONNECT "),
        "the proxy received {request_line:?} rather than a CONNECT request"
    );
    assert!(
        guard.headers.iter().any(|h| h.starts_with("host:")),
        "the CONNECT request carried no Host header"
    );
}

/// Configured credentials must reach the proxy as an RFC 7617 Basic
/// `Proxy-Authorization` header. Decoding it at the proxy — rather than
/// asserting the header merely exists — is what catches the credentials being
/// sent unencoded, double-encoded, or as the wrong pair.
#[tokio::test]
async fn connect_proxy_credentials_are_sent_as_basic_authorization() {
    let upstream = spawn_tcp_upstream().await;
    let log = new_log();
    let proxy = spawn_connect_proxy("200 Connection Established", Arc::clone(&log)).await;

    let server = make_server(
        upstream,
        Some(ProxyConfig {
            url: format!("http://{proxy}"),
            auth: Some("alice:s3cret".to_string()),
            mode: ProxyMode::Connect,
        }),
    );

    let response = resolve(&server, 0x0102).await;
    assert_eq!(addresses(&response), vec![UPSTREAM_ADDR]);

    assert_eq!(
        log.lock().expect("log").credentials.as_deref(),
        Some("alice:s3cret"),
        "the proxy did not receive the configured credentials as Basic authorization"
    );
}

/// A proxy that refuses the tunnel must not be mistaken for one that opened it.
/// The forwarder list has a single entry, so there is nothing to fall back to
/// and the correct outcome is SERVFAIL with no answer — never a fabricated one.
#[tokio::test]
async fn a_refused_connect_tunnel_is_servfail() {
    let upstream = spawn_tcp_upstream().await;
    let log = new_log();
    let proxy = spawn_connect_proxy("403 Forbidden", Arc::clone(&log)).await;

    let server = make_server(
        upstream,
        Some(ProxyConfig {
            url: format!("http://{proxy}"),
            auth: None,
            mode: ProxyMode::Connect,
        }),
    );

    let response = resolve(&server, 0x0103).await;
    assert_eq!(
        response.response_code(),
        ResponseCode::ServFail,
        "a proxy that refused the tunnel produced {:?}",
        response.response_code()
    );
    assert!(
        response.answers().is_empty(),
        "a refused tunnel still produced {} answer records",
        response.answers().len()
    );
    assert_eq!(
        log.lock().expect("log").connections,
        1,
        "the proxy was not contacted exactly once"
    );
}

// ============================================================================
// SOCKS5
// ============================================================================

/// The base case for `ProxyMode::Socks5`. The mock performs the real RFC 1928
/// exchange and asserts on the greeting, the command, and the address type as it
/// reads them, so a malformed handshake fails inside the proxy rather than
/// silently working against a permissive echo.
#[tokio::test]
async fn a_query_is_tunnelled_through_a_socks5_proxy() {
    let upstream = spawn_tcp_upstream().await;
    let log = new_log();
    let proxy = spawn_socks5_proxy(false, None, None, Arc::clone(&log)).await;

    let server = make_server(
        upstream,
        Some(ProxyConfig {
            url: format!("socks5://{proxy}"),
            auth: None,
            mode: ProxyMode::Socks5,
        }),
    );

    let response = resolve(&server, 0x0201).await;
    assert_eq!(
        response.response_code(),
        ResponseCode::NoError,
        "the SOCKS5-tunnelled query answered {:?}",
        response.response_code()
    );
    assert_eq!(
        addresses(&response),
        vec![UPSTREAM_ADDR],
        "the answer did not come from the upstream behind the SOCKS5 tunnel"
    );
    assert_eq!(
        log.lock().expect("log").target.as_deref(),
        Some(upstream.to_string().as_str()),
        "SOCKS5 CONNECT named the wrong target address or port"
    );
}

/// When the proxy selects username/password, the server must complete RFC 1929
/// rather than proceeding as if no-auth had been negotiated. The proxy verifies
/// the pair it receives, so wrong or absent credentials end the exchange there.
#[tokio::test]
async fn socks5_username_password_authentication_is_performed() {
    let upstream = spawn_tcp_upstream().await;
    let log = new_log();
    let proxy = spawn_socks5_proxy(true, Some("bob:hunter2"), None, Arc::clone(&log)).await;

    let server = make_server(
        upstream,
        Some(ProxyConfig {
            url: format!("socks5://{proxy}"),
            auth: Some("bob:hunter2".to_string()),
            mode: ProxyMode::Socks5,
        }),
    );

    let response = resolve(&server, 0x0202).await;
    assert_eq!(
        addresses(&response),
        vec![UPSTREAM_ADDR],
        "authenticated SOCKS5 did not deliver the upstream answer"
    );
    assert_eq!(
        log.lock().expect("log").credentials.as_deref(),
        Some("bob:hunter2"),
        "the proxy did not receive the configured credentials"
    );
}

/// A SOCKS5 server that rejects the CONNECT (here: 0x05, connection refused)
/// must surface as SERVFAIL. The reply is well-formed SOCKS5 — only the status
/// byte says no — so this pins that the status byte is actually read rather than
/// the reply being skipped past on its way to the tunnel.
#[tokio::test]
async fn a_refused_socks5_connect_is_servfail() {
    let upstream = spawn_tcp_upstream().await;
    let log = new_log();
    let proxy = spawn_socks5_proxy(false, None, Some(0x05), Arc::clone(&log)).await;

    let server = make_server(
        upstream,
        Some(ProxyConfig {
            url: format!("socks5://{proxy}"),
            auth: None,
            mode: ProxyMode::Socks5,
        }),
    );

    let response = resolve(&server, 0x0203).await;
    assert_eq!(
        response.response_code(),
        ResponseCode::ServFail,
        "a refused SOCKS5 CONNECT produced {:?}",
        response.response_code()
    );
    assert!(
        response.answers().is_empty(),
        "a refused SOCKS5 CONNECT still produced answer records"
    );
    assert_eq!(
        log.lock().expect("log").target.as_deref(),
        Some(upstream.to_string().as_str()),
        "the proxy never saw the CONNECT it was supposed to refuse"
    );
}

// ============================================================================
// DoH through an HTTP proxy
// ============================================================================

/// `ProxyMode::Doh` sends the query as an RFC 8484 POST in absolute-URI form,
/// which is what an HTTP proxy needs to route it. Three things are pinned: the
/// request line names the upstream's `/dns-query`, the content type is
/// `application/dns-message`, and the body is the query bytes **unmodified** —
/// no length prefix, no re-encoding.
#[tokio::test]
async fn a_query_is_sent_as_doh_through_an_http_proxy() {
    let log = new_log();
    let proxy = spawn_doh_proxy("200 OK", Arc::clone(&log)).await;
    // In DoH mode the forwarder address is not dialled; it names the DoH
    // endpoint the proxy is asked to fetch.
    let upstream: SocketAddr = "192.0.2.53:443".parse().expect("upstream address");

    let server = make_server(
        upstream,
        Some(ProxyConfig {
            url: format!("http://{proxy}"),
            auth: None,
            mode: ProxyMode::Doh,
        }),
    );

    let query = build_query(0x0301, UPSTREAM_NAME);
    let client: IpAddr = CLIENT.parse().expect("client address");
    let raw = tokio::time::timeout(PATIENCE, server.handle_query_from(&query, client))
        .await
        .expect("the query never came back")
        .expect("handling the query");
    let response = Message::from_bytes(&raw).expect("parse response");

    assert_eq!(
        addresses(&response),
        vec![UPSTREAM_ADDR],
        "the DoH proxy's answer did not reach the client"
    );

    let guard = log.lock().expect("log");
    let request_line = guard.request_line.clone().unwrap_or_default();
    assert_eq!(
        request_line,
        format!("POST https://{upstream}/dns-query HTTP/1.1"),
        "the proxy received an unexpected request line"
    );
    assert!(
        guard
            .headers
            .iter()
            .any(|h| h.starts_with("content-type:") && h.contains("application/dns-message")),
        "the DoH request did not declare the application/dns-message content type"
    );
    assert_eq!(
        guard.body, query,
        "the proxied DoH body is not the query bytes as sent"
    );
}

/// The pool in `src/doh_proxy.rs` exists so a busy resolver does not open a TCP
/// connection per query. Two queries against the same proxy address must ride
/// one connection.
///
/// The server has no response cache, so the second query is genuinely a second
/// request — the proxy's recorded body proves it saw two — and the connection
/// count is what distinguishes a reused socket from a fresh one.
#[tokio::test]
async fn the_doh_proxy_connection_is_reused_across_queries() {
    let log = new_log();
    let proxy = spawn_doh_proxy("200 OK", Arc::clone(&log)).await;
    let upstream: SocketAddr = "192.0.2.54:443".parse().expect("upstream address");

    let server = make_server(
        upstream,
        Some(ProxyConfig {
            url: format!("http://{proxy}"),
            auth: None,
            mode: ProxyMode::Doh,
        }),
    );

    let first = resolve(&server, 0x0311).await;
    assert_eq!(addresses(&first), vec![UPSTREAM_ADDR]);
    let second = resolve(&server, 0x0312).await;
    assert_eq!(addresses(&second), vec![UPSTREAM_ADDR]);

    let guard = log.lock().expect("log");
    assert_eq!(
        guard.connections, 1,
        "two queries to the same proxy opened {} connections; the pool is not \
         being reused",
        guard.connections
    );
    let second_id = Message::from_bytes(&guard.body)
        .expect("the proxy recorded a parseable body")
        .id();
    assert_eq!(
        second_id, 0x0312,
        "the proxy's last request was not the second query, so the two queries \
         did not both reach it"
    );
}

/// A DoH proxy returning a non-200 must surface as SERVFAIL rather than the
/// status being ignored and an empty body parsed as an answer.
#[tokio::test]
async fn a_failing_doh_proxy_is_servfail() {
    let log = new_log();
    let proxy = spawn_doh_proxy("502 Bad Gateway", Arc::clone(&log)).await;
    let upstream: SocketAddr = "192.0.2.55:443".parse().expect("upstream address");

    let server = make_server(
        upstream,
        Some(ProxyConfig {
            url: format!("http://{proxy}"),
            auth: None,
            mode: ProxyMode::Doh,
        }),
    );

    let response = resolve(&server, 0x0321).await;
    assert_eq!(
        response.response_code(),
        ResponseCode::ServFail,
        "a 502 from the DoH proxy produced {:?}",
        response.response_code()
    );
    assert!(
        response.answers().is_empty(),
        "a failed DoH request still produced answer records"
    );
}

// ============================================================================
// Controls
// ============================================================================

/// The control for every test above: with no proxy configured the server takes
/// the plain Do53 path. Without this, a proxy implementation that quietly fell
/// back to direct UDP would pass the success cases — the answers would arrive,
/// just not through the proxy.
#[tokio::test]
async fn no_proxy_configured_forwards_over_plain_udp() {
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp upstream");
    let upstream = udp.local_addr().expect("udp upstream addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, src)) = udp.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_bytes(&buf[..len]) else {
                continue;
            };
            if udp.send_to(&answer_for(&query), src).await.is_err() {
                return;
            }
        }
    });

    let server = make_server(upstream, None);

    let response = resolve(&server, 0x0401).await;
    assert_eq!(
        addresses(&response),
        vec![UPSTREAM_ADDR],
        "the unproxied UDP forwarding path did not deliver the upstream answer"
    );
}

/// A proxy that is configured but not listening must fail the query rather than
/// falling back to a direct connection. Falling back would defeat the point of
/// configuring a proxy at all — on a network where the proxy is the only allowed
/// egress it would leak the query, and where it is a privacy boundary it would
/// silently cross it.
#[tokio::test]
async fn an_unreachable_proxy_does_not_fall_back_to_a_direct_connection() {
    let upstream = spawn_tcp_upstream().await;

    // Bind and immediately drop, so the address is almost certainly unused.
    let dead = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let dead_addr = dead.local_addr().expect("addr");
    drop(dead);

    let server = make_server(
        upstream,
        Some(ProxyConfig {
            url: format!("http://{dead_addr}"),
            auth: None,
            mode: ProxyMode::Connect,
        }),
    );

    let response = resolve(&server, 0x0402).await;
    assert_eq!(
        response.response_code(),
        ResponseCode::ServFail,
        "an unreachable proxy produced {:?}; the query must not have been sent \
         directly instead",
        response.response_code()
    );
    assert!(
        response.answers().is_empty(),
        "an unreachable proxy still produced an answer, which means the query \
         bypassed it"
    );
}
