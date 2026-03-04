/// DNS-over-HTTPS (DoH) server (RFC 8484).
///
/// Serves DNS queries over HTTPS at `/dns-query`.
/// Supports both POST (application/dns-message) and GET (?dns= base64url).
/// Uses axum with axum-server for TLS support.
use crate::dns_server::DnsServer;
use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use base64::Engine;
use std::sync::Arc;
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
pub fn build_router(dns_server: Arc<DnsServer>) -> Router {
    let state = DohState { dns_server };
    Router::new()
        .route("/dns-query", get(handle_doh_get).post(handle_doh_post))
        .with_state(state)
}

/// Serves DNS-over-HTTPS on the specified bind address.
pub async fn serve_doh(
    bind: &str,
    dns_server: Arc<DnsServer>,
    server_config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    let state = DohState { dns_server };

    let app = Router::new()
        .route("/dns-query", get(handle_doh_get).post(handle_doh_post))
        .with_state(state);

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(server_config);

    let addr: std::net::SocketAddr = bind
        .parse()
        .context(format!("invalid DoH bind address: {}", bind))?;

    info!("DoH server listening on {}", addr);

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .context("DoH server error")?;

    Ok(())
}

/// Handles POST /dns-query with application/dns-message body.
async fn handle_doh_post(
    State(state): State<DohState>,
    body: Bytes,
) -> impl IntoResponse {
    let response = match state.dns_server.handle_query(&body).await {
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
    Query(params): Query<DnsQueryParams>,
) -> impl IntoResponse {
    let dns_param = match params.dns {
        Some(d) => d,
        None => {
            return (StatusCode::BAD_REQUEST, "missing 'dns' query parameter").into_response()
        }
    };

    let query_data = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&dns_param) {
        Ok(d) => d,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid base64url encoding").into_response()
        }
    };

    let response = match state.dns_server.handle_query(&query_data).await {
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
fn extract_min_ttl(response_bytes: &[u8]) -> u32 {
    use hickory_proto::op::Message;
    use hickory_proto::serialize::binary::BinDecodable;

    if let Ok(msg) = Message::from_bytes(response_bytes) {
        msg.answers()
            .iter()
            .map(|r| r.ttl())
            .min()
            .unwrap_or(0)
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
