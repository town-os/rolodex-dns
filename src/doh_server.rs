/// DNS-over-HTTPS (DoH) server (RFC 8484).
///
/// Serves DNS queries over HTTPS at `/dns-query`.
/// Supports both POST (application/dns-message) and GET (?dns= base64url).
/// Uses axum with axum-server for TLS support.
use crate::dns_server::DnsServer;
use anyhow::{Context, Result};
use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, Query, State},
    http::{Extensions, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use base64::Engine;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{error, info};

/// Shared state for the DoH server.
#[derive(Clone)]
struct DohState {
    dns_server: Arc<DnsServer>,
}

/// Query parameters for GET requests.
#[derive(serde::Deserialize)]
struct DnsQueryParams {
    dns: Option<String>,
}

/// Builds the DoH axum Router (for testing without TLS).
///
/// `h3_port` is the UDP port the HTTP/3 listener took, when one is running. It
/// is not decoration: a client that reached this listener over TCP has no other
/// way to learn the box speaks HTTP/3. RFC 7838's `Alt-Svc` header is the
/// in-band announcement, and without it the QUIC endpoint is reachable only by a
/// client that was told about it out of band — through the DDR designation, or
/// by hand. `None` when HTTP/3 is off, which must advertise nothing at all: an
/// `Alt-Svc` for a port nothing answers on sends a client to a dead endpoint and
/// makes it wait out its own timeout before falling back.
pub fn build_router(dns_server: Arc<DnsServer>, h3_port: Option<u16>) -> Router {
    let state = DohState { dns_server };
    let router = Router::new()
        .route("/dns-query", get(handle_doh_get).post(handle_doh_post))
        .with_state(state);
    match h3_port {
        Some(port) => router.layer(axum::middleware::from_fn(move |req, next| {
            add_alt_svc(port, req, next)
        })),
        None => router,
    }
}

/// How long a client may remember the `Alt-Svc` advertisement, in seconds.
///
/// A day. The alternative endpoint is the same box on the same port, so it
/// stops being true only when HTTP/3 is turned off — and a client holding a
/// stale advertisement falls back to TCP on the first failed attempt rather
/// than losing resolution. A short lifetime would buy nothing and re-advertise
/// on every query.
const ALT_SVC_MAX_AGE: u32 = 86400;

/// Adds the `Alt-Svc` header advertising this box's HTTP/3 endpoint.
///
/// The value names the port only (`h3=":443"`), which RFC 7838 §3 reads as "the
/// same host". That is what makes the advertisement correct on a box whose name
/// this listener does not know: it is reached as whatever the client dialled.
async fn add_alt_svc(
    port: u16,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    match http::HeaderValue::from_str(&format!("h3=\":{}\"; ma={}", port, ALT_SVC_MAX_AGE)) {
        Ok(value) => {
            response.headers_mut().insert("alt-svc", value);
        }
        // A port always formats into a valid header value, so this cannot
        // happen — and if it somehow did, the response is still a correct DNS
        // answer and is worth more than the advertisement.
        Err(e) => error!("DoH Alt-Svc header not added: {}", e),
    }
    response
}

/// Serves DNS-over-HTTPS on the specified bind address.
///
/// `tls` is a live view of the certificate rather than a snapshot: a renewal is
/// stored into the listener's `RustlsConfig` by the task below and picked up by
/// the next connection, with no restart.
///
/// This serves TCP alone and advertises no HTTP/3: pairing the two listeners is
/// the supervisor's job, because only it knows which port the QUIC endpoint
/// actually took (see `transports::TransportSupervisor::start`).
pub async fn serve_doh(
    bind: &str,
    dns_server: Arc<DnsServer>,
    tls: watch::Receiver<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let listener = bind_doh(bind)?;
    serve_doh_on(listener, build_router(dns_server, None), tls).await
}

/// Binds a DoH listener without starting it.
///
/// Split from [`serve_doh`] so a caller that must report a bind failure to
/// somebody — the transport supervisor, answering a `SetDohConfig` RPC — can
/// take the error synchronously instead of discovering it inside a spawned task,
/// where the only place it could go is the log.
///
/// A std listener rather than a tokio one because that is what
/// `axum_server::from_tcp_rustls` takes; it is set non-blocking there.
pub fn bind_doh(bind: &str) -> Result<std::net::TcpListener> {
    let addr: std::net::SocketAddr = bind
        .parse()
        .context(format!("invalid DoH bind address: {}", bind))?;
    std::net::TcpListener::bind(addr).context(format!("failed to bind DoH listener on {}", addr))
}

/// Serves DNS-over-HTTPS on an already-bound listener. See [`serve_doh`].
pub async fn serve_doh_on(
    listener: std::net::TcpListener,
    app: Router,
    tls: watch::Receiver<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(tls.borrow().clone());

    let addr = listener
        .local_addr()
        .context("DoH listener has no local address")?;
    info!("DoH server listening on {}", addr);

    let renewals = tokio::spawn(crate::tls::drive_axum_tls(tls_config.clone(), tls));

    // With connect info, so the peer address reaches source classification: DoH
    // is a full resolution path, and without the peer every query would look
    // like a local one — reopening the recursion the `:53` listener closes.
    let outcome = axum_server::from_tcp_rustls(listener, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await;

    // The listener is finished, so nothing is left to hand a certificate to.
    renewals.abort();
    outcome.context("DoH server error")?;

    Ok(())
}

/// Resolves a query on behalf of the connecting peer.
///
/// The peer is read out of the request extensions rather than extracted, so a
/// router built without connect info still works: that is `build_router`, used
/// by in-process tests. A real listener always supplies it (see `serve_doh`).
async fn resolve(
    state: &DohState,
    extensions: &Extensions,
    query: &[u8],
) -> anyhow::Result<Vec<u8>> {
    // Absent ConnectInfo the peer is unknown, which is the same unscoped case
    // `handle_query` represents — pass None rather than inventing an address.
    let source_ip = extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    state
        .dns_server
        .handle_query_proto(query, source_ip, None, crate::metrics::Proto::Doh)
        .await
}

/// Handles POST /dns-query with application/dns-message body.
async fn handle_doh_post(
    State(state): State<DohState>,
    extensions: Extensions,
    body: Bytes,
) -> impl IntoResponse {
    let response = match resolve(&state, &extensions, &body).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("DoH POST error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "DNS query failed").into_response();
        }
    };

    let min_ttl = extract_min_ttl(&response);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/dns-message"),
            (
                header::CACHE_CONTROL,
                Box::leak(format!("max-age={}", min_ttl).into_boxed_str()),
            ),
        ],
        response,
    )
        .into_response()
}

/// Handles GET /dns-query?dns=<base64url-encoded query>.
async fn handle_doh_get(
    State(state): State<DohState>,
    extensions: Extensions,
    Query(params): Query<DnsQueryParams>,
) -> impl IntoResponse {
    let dns_param = match params.dns {
        Some(d) => d,
        None => return (StatusCode::BAD_REQUEST, "missing 'dns' query parameter").into_response(),
    };

    let query_data = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&dns_param) {
        Ok(d) => d,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid base64url encoding").into_response(),
    };

    let response = match resolve(&state, &extensions, &query_data).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("DoH GET error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "DNS query failed").into_response();
        }
    };

    let min_ttl = extract_min_ttl(&response);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/dns-message"),
            (
                header::CACHE_CONTROL,
                Box::leak(format!("max-age={}", min_ttl).into_boxed_str()),
            ),
        ],
        response,
    )
        .into_response()
}

/// Extracts the minimum TTL from a DNS response for Cache-Control header.
///
/// Visible to the crate because the HTTP/3 listener answers the same requests
/// with the same caching rule, and a second implementation of it is a second
/// place for the two to disagree about how long an answer may be held.
pub(crate) fn extract_min_ttl(response_bytes: &[u8]) -> u32 {
    use hickory_proto::op::Message;
    use hickory_proto::serialize::binary::BinDecodable;

    if let Ok(msg) = Message::from_bytes(response_bytes) {
        msg.answers().iter().map(|r| r.ttl()).min().unwrap_or(0)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_min_ttl_empty() {
        assert_eq!(extract_min_ttl(&[]), 0);
    }

    #[test]
    fn test_extract_min_ttl_invalid() {
        assert_eq!(extract_min_ttl(&[0, 1, 2]), 0);
    }
}
