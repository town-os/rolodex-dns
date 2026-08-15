//! DNS-over-HTTPS carried over HTTP/3 (RFC 9114), the QUIC half of the DoH
//! listener.
//!
//! # Why this is its own listener rather than a flag on the other one
//!
//! HTTP/3 is HTTP over QUIC, and QUIC is UDP. The DoH listener is a TCP socket
//! with axum on top of it; there is no configuration of that socket which also
//! answers on UDP. So `doh.enable_h3` opens a SECOND listener — same address,
//! same port, same certificate, different transport — and the two run side by
//! side for the life of the transport. This is the same shape the DoQ listener
//! already has, and most of the machinery here is deliberately its twin.
//!
//! # Why a client would want it
//!
//! The one that matters for a resolver is head-of-line blocking. Over TCP a lost
//! segment stalls every DNS query multiplexed onto that connection, including
//! the ones whose packets already arrived; QUIC delivers each stream
//! independently, so one lost packet delays one query. On the networks where a
//! home resolver is reached over the internet — mobile, congested wifi — that is
//! the difference between one slow lookup and a stalled browser tab. The second
//! is connection setup: a client that has spoken to this box before resumes in
//! zero round trips rather than the TCP handshake plus TLS handshake h2 pays.
//!
//! # How a client finds it
//!
//! Two ways, and both are needed because they reach different clients. A client
//! that already has an h2 connection learns from the `Alt-Svc` header the DoH
//! router sends (see `doh_server::build_router`). A client that has not
//! connected at all learns from the DDR designation, whose `alpn=h3` value is
//! published by whatever manages this box's zone. Neither is a fallback for the
//! other: the header cannot reach a client that never speaks h2, and the
//! designation cannot reach a client that was configured with a URL by hand.

use crate::dns_server::DnsServer;
use anyhow::{Context, Result};
use base64::Engine;
use bytes::{Buf, Bytes};
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// The ALPN token RFC 9114 assigns to HTTP/3.
///
/// Exactly one, and deliberately: this endpoint speaks HTTP/3 and nothing else,
/// so a client offering `h2` over QUIC — which no client does, but a proxy
/// might — is refused at the handshake rather than served something it did not
/// ask for. The h2/http1.1 tokens belong to the TCP listener next door.
pub fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"h3".to_vec()]
}

/// The one path RFC 8484 servers publish, and the one this listener answers.
const DNS_QUERY_PATH: &str = "/dns-query";

/// Largest request body accepted, in bytes.
///
/// A DNS message cannot exceed 65535 bytes because its length is carried in a
/// 16-bit field on every other transport, so anything larger is not a query that
/// got big — it is a body that is never going to parse, sent by something that
/// found an unauthenticated endpoint. The cap is on the accumulated body rather
/// than on a single frame: HTTP/3 lets a sender split a body across as many
/// DATA frames as it likes, and a per-frame check bounds nothing at all.
const MAX_REQUEST_BODY: usize = 65535;

/// How long a QUIC connection may sit idle before it is closed.
///
/// The same 30 seconds the DoQ listener uses. A resolver's connections are
/// bursty — a page load, then nothing — and holding state for an absent client
/// is what an idle timeout exists to stop.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Builds the QUIC server config this listener runs with, from the certificate
/// the DoH listener next door is serving.
///
/// The ALPN list is REPLACED rather than extended. The manager built that config
/// for the TCP listener, where the tokens are `h2` and `http/1.1`; offering
/// those over QUIC would let a client negotiate a protocol this endpoint cannot
/// speak, and the failure would land after the handshake, where a client reads
/// it as "the resolver is broken" rather than as "no shared protocol".
///
/// Everything else — the certificate, the key, the chain — is shared with the
/// TCP listener by construction, which is the point of deriving the config from
/// its watch rather than loading the material a second time. Two managers over
/// one pair of files would drift for as long as it took one poll to notice a
/// renewal, and with GENERATED material they would never agree at all: each
/// would mint its own self-signed certificate, so the same name would be served
/// by two different keys depending on which transport a client chose.
fn h3_config(server_config: Arc<rustls::ServerConfig>) -> Result<quinn::ServerConfig> {
    let mut crypto = (*server_config).clone();
    crypto.alpn_protocols = alpn_protocols();

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(crypto))
        .context("failed to create HTTP/3 QUIC crypto config")?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let idle_timeout =
        quinn::IdleTimeout::try_from(IDLE_TIMEOUT).context("HTTP/3 idle timeout out of range")?;
    config.transport_config(Arc::new({
        let mut tc = quinn::TransportConfig::default();
        tc.max_idle_timeout(Some(idle_timeout));
        tc
    }));
    Ok(config)
}

/// Binds an HTTP/3 endpoint without starting its accept loop.
///
/// Split from the serve loop for the reason every other transport's bind is: the
/// supervisor has to be able to report a bind failure to whoever asked for the
/// listener, and an error discovered inside a spawned task has nowhere to go but
/// the log.
///
/// `bind` is a UDP address even though it is spelled the same as the DoH
/// listener's TCP one. That is not a collision — the two protocols have separate
/// port spaces — and it is required rather than merely allowed: `Alt-Svc` and
/// the DDR designation both advertise HTTP/3 at the DoH endpoint's port, so an
/// h3 listener anywhere else is advertised at an address nothing answers on.
pub fn bind_doh_h3(
    bind: &str,
    server_config: Arc<rustls::ServerConfig>,
) -> Result<quinn::Endpoint> {
    let initial = h3_config(server_config)?;
    let addr: std::net::SocketAddr = bind
        .parse()
        .context(format!("invalid DoH HTTP/3 bind address: {}", bind))?;
    quinn::Endpoint::server(initial, addr).context("failed to create the HTTP/3 QUIC endpoint")
}

/// Serves DoH over HTTP/3 on an already-bound endpoint.
///
/// `tls` is a live view of the DoH listener's certificate rather than a
/// snapshot. QUIC keeps its crypto config on the endpoint rather than reading it
/// per connection, so a renewal is applied with `set_server_config`: connections
/// already established keep the certificate they handshook with, the next one to
/// arrive gets the new one, and there is no window where the listener is not
/// accepting.
pub async fn serve_doh_h3_on(
    endpoint: quinn::Endpoint,
    dns_server: Arc<DnsServer>,
    mut tls: watch::Receiver<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let addr = endpoint
        .local_addr()
        .context("HTTP/3 endpoint has no local address")?;

    info!("DoH HTTP/3 server listening on {} (UDP)", addr);

    // Once every sender is gone the certificate can never change again, and
    // `changed()` returns immediately and forever. The branch is disabled rather
    // than looped on — the difference between a listener that stops watching and
    // one that spins a core.
    let mut renewals_possible = true;

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let dns = Arc::clone(&dns_server);
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(connection) => {
                            debug!("DoH HTTP/3 connection from {}", connection.remote_address());
                            handle_h3_connection(connection, dns).await;
                        }
                        Err(e) => debug!("DoH HTTP/3 connection failed: {}", e),
                    }
                });
            }
            // A renewal. A rebuild that fails leaves the endpoint on the
            // certificate it already has rather than tearing the listener down —
            // the same bargain every other listener here makes.
            changed = tls.changed(), if renewals_possible => {
                if changed.is_err() {
                    renewals_possible = false;
                    continue;
                }
                match h3_config(tls.borrow_and_update().clone()) {
                    Ok(updated) => {
                        endpoint.set_server_config(Some(updated));
                        info!("DoH HTTP/3 listener on {} picked up a renewed certificate", addr);
                    }
                    Err(e) => warn!(
                        "DoH HTTP/3 certificate renewal on {} not applied: {:#}", addr, e
                    ),
                }
            }
        }
    }

    Ok(())
}

/// Drives one QUIC connection's HTTP/3 requests.
///
/// Each request gets its own task. That is what the transport is for: streams on
/// one QUIC connection are independent, so a query waiting on a slow upstream
/// must not hold up the one behind it — serving them in sequence here would
/// rebuild, inside the server, exactly the head-of-line blocking HTTP/3 exists
/// to remove.
async fn handle_h3_connection(connection: quinn::Connection, dns_server: Arc<DnsServer>) {
    let peer = connection.remote_address();
    let mut conn: h3::server::Connection<h3_quinn::Connection, Bytes> = match h3::server::builder()
        .build(h3_quinn::Connection::new(connection))
        .await
    {
        Ok(conn) => conn,
        Err(e) => {
            debug!("DoH HTTP/3 connection setup from {} failed: {}", peer, e);
            return;
        }
    };

    loop {
        match conn.accept().await {
            Ok(Some(resolver)) => {
                let dns = Arc::clone(&dns_server);
                tokio::spawn(async move {
                    if let Err(e) = handle_h3_request(resolver, dns, peer).await {
                        debug!("DoH HTTP/3 request error: {:#}", e);
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                debug!("DoH HTTP/3 accept error from {}: {}", peer, e);
                break;
            }
        }
    }
}

/// The status and body of a request that will not be resolved.
///
/// Returned rather than sent from the point of failure so that every refusal
/// leaves by the same door: an HTTP/3 request that is answered with headers and
/// never finished holds a stream open on both ends until the idle timeout.
struct Refused(http::StatusCode);

/// Answers one HTTP/3 request.
async fn handle_h3_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    dns_server: Arc<DnsServer>,
    peer: std::net::SocketAddr,
) -> Result<()> {
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .context("reading the HTTP/3 request head")?;

    let query = match read_query(&request, &mut stream).await {
        Ok(query) => query,
        Err(Refused(status)) => return respond(&mut stream, status, Bytes::new(), None).await,
    };

    let response = match dns_server
        .handle_query_proto(&query, Some(peer.ip()), None, crate::metrics::Proto::Doh)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            warn!("DoH HTTP/3 query failed: {:#}", e);
            return respond(
                &mut stream,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                Bytes::new(),
                None,
            )
            .await;
        }
    };

    let min_ttl = crate::doh_server::extract_min_ttl(&response);
    respond(
        &mut stream,
        http::StatusCode::OK,
        Bytes::from(response),
        Some(min_ttl),
    )
    .await
}

/// Extracts the DNS query from a request, whichever of RFC 8484's two forms it
/// took.
///
/// The path is checked before the method so that a wrong path is a 404 rather
/// than a 405, which is what a client probing for the endpoint expects to see.
async fn read_query(
    request: &http::Request<()>,
    stream: &mut h3::server::RequestStream<
        <h3_quinn::Connection as h3::quic::OpenStreams<Bytes>>::BidiStream,
        Bytes,
    >,
) -> std::result::Result<Vec<u8>, Refused> {
    if request.uri().path() != DNS_QUERY_PATH {
        return Err(Refused(http::StatusCode::NOT_FOUND));
    }

    match *request.method() {
        http::Method::GET => {
            let param =
                dns_param(request.uri().query()).ok_or(Refused(http::StatusCode::BAD_REQUEST))?;
            decode_dns_param(&param).ok_or(Refused(http::StatusCode::BAD_REQUEST))
        }
        http::Method::POST => read_body(stream).await,
        _ => Err(Refused(http::StatusCode::METHOD_NOT_ALLOWED)),
    }
}

/// Reads the request body, refusing one that grows past a DNS message's
/// maximum. See [`MAX_REQUEST_BODY`].
async fn read_body(
    stream: &mut h3::server::RequestStream<
        <h3_quinn::Connection as h3::quic::OpenStreams<Bytes>>::BidiStream,
        Bytes,
    >,
) -> std::result::Result<Vec<u8>, Refused> {
    let mut body: Vec<u8> = Vec::new();
    loop {
        let chunk = stream.recv_data().await;
        let Ok(chunk) = chunk else {
            return Err(Refused(http::StatusCode::BAD_REQUEST));
        };
        let Some(mut chunk) = chunk else { break };
        if body.len().saturating_add(chunk.remaining()) > MAX_REQUEST_BODY {
            return Err(Refused(http::StatusCode::PAYLOAD_TOO_LARGE));
        }
        while chunk.has_remaining() {
            // The borrow of the segment has to end before the cursor moves, so
            // the copy and the length are taken in one expression.
            let advanced = {
                let segment = chunk.chunk();
                body.extend_from_slice(segment);
                segment.len()
            };
            chunk.advance(advanced);
        }
    }
    if body.is_empty() {
        return Err(Refused(http::StatusCode::BAD_REQUEST));
    }
    Ok(body)
}

/// Finds the `dns` parameter in a query string.
///
/// Hand-parsed rather than deserialized because there is exactly one parameter
/// and its value needs no unescaping: RFC 8484 sends base64url with the padding
/// removed, whose alphabet (`A-Z a-z 0-9 - _`) is entirely unreserved in a URI.
/// A value that arrived percent-encoded anyway fails the decode below and is
/// answered with a 400, which is the same answer any other malformed query gets.
pub fn dns_param(query: Option<&str>) -> Option<String> {
    for pair in query?.split('&') {
        if let Some(("dns", value)) = pair.split_once('=') {
            return Some(value.to_string());
        }
    }
    None
}

/// Decodes the `dns` parameter's base64url.
///
/// Padding is accepted on the way in although RFC 8484 §4.1 says it must not be
/// sent: a client that pads is asking the same question as one that does not,
/// and refusing it would be strictness with nothing on the other side of it.
pub fn decode_dns_param(param: &str) -> Option<Vec<u8>> {
    let trimmed = param.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .ok()
        .filter(|decoded| !decoded.is_empty() && decoded.len() <= MAX_REQUEST_BODY)
}

/// Sends a complete response and closes the stream.
///
/// `max_age` is the DNS answer's minimum TTL, which is what a DoH response's
/// `Cache-Control` must carry (RFC 8484 §5.1): a cache that outlived the record
/// it holds would go on answering with data the zone has replaced. Absent on
/// every error response, because there is nothing there to cache.
async fn respond(
    stream: &mut h3::server::RequestStream<
        <h3_quinn::Connection as h3::quic::OpenStreams<Bytes>>::BidiStream,
        Bytes,
    >,
    status: http::StatusCode,
    body: Bytes,
    max_age: Option<u32>,
) -> Result<()> {
    let mut builder = http::Response::builder().status(status);
    if let Some(max_age) = max_age {
        builder = builder
            .header(http::header::CONTENT_TYPE, "application/dns-message")
            .header(http::header::CACHE_CONTROL, format!("max-age={}", max_age));
    }
    let response = builder
        .body(())
        .context("building the HTTP/3 response head")?;

    stream
        .send_response(response)
        .await
        .context("sending the HTTP/3 response head")?;
    if !body.is_empty() {
        stream
            .send_data(body)
            .await
            .context("sending the HTTP/3 response body")?;
    }
    stream
        .finish()
        .await
        .context("finishing the HTTP/3 response")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The listener speaks HTTP/3 and only HTTP/3. The control is that the TCP
    /// listener's tokens are absent: offering `h2` here would let a client
    /// negotiate a protocol this endpoint cannot speak.
    #[test]
    fn alpn_advertises_exactly_h3() {
        assert_eq!(alpn_protocols(), vec![b"h3".to_vec()]);
    }

    #[test]
    fn the_dns_parameter_is_found_among_others() {
        assert_eq!(dns_param(Some("dns=AAAB")).as_deref(), Some("AAAB"));
        assert_eq!(
            dns_param(Some("ct=application/dns-message&dns=AAAB")).as_deref(),
            Some("AAAB")
        );
        // The controls: a query string with no `dns`, a parameter whose name
        // merely ends in it, and no query string at all. Each would be a query
        // resolved from whatever happened to follow the first `=`.
        assert_eq!(dns_param(Some("ct=application/dns-message")), None);
        assert_eq!(dns_param(Some("notdns=AAAB")), None);
        assert_eq!(dns_param(None), None);
    }

    #[test]
    fn base64url_is_decoded_padded_or_not() {
        // "\0\x01" — two bytes, so the unpadded form is three characters.
        let unpadded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8, 1]);
        assert_eq!(decode_dns_param(&unpadded), Some(vec![0u8, 1]));
        assert_eq!(
            decode_dns_param(&format!("{}=", unpadded)),
            Some(vec![0u8, 1])
        );
    }

    #[test]
    fn an_undecodable_or_empty_parameter_is_refused() {
        // Standard base64's `+` and `/` are not in the URL-safe alphabet, and a
        // query that decodes to nothing is not a query.
        assert_eq!(decode_dns_param("++//"), None);
        assert_eq!(decode_dns_param(""), None);
        assert_eq!(decode_dns_param("!!!!"), None);
    }
}
