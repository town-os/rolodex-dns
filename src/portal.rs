//! Trusted-network enrollment portal for the ACME issuer.
//!
//! End users are not expected to be PKI- or CLI-literate, so the portal is the
//! friendly self-service path: a small web page (served at `/`) plus a JSON API
//! (`/api/*`) that the page — and the companion browser extension — call to
//!
//! - mint an ACME account credential (External Account Binding) scoped to a zone,
//!   returning copy-paste client config,
//! - download the Rolodex root CA to trust,
//! - list issued certificates and the zones that can be enrolled.
//!
//! **Access control is trusted-network only**: the portal is intended to be bound
//! to an internal address (see `acme.portal_bind`), and anyone who can reach it
//! may enroll — mirroring the Unix-socket gRPC auth-bypass philosophy. Do not
//! expose `portal_bind` to untrusted networks.

use crate::acme_server::AcmeState;
use crate::ca;
use crate::db::Database;
use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::rand::SecureRandom;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::info;

/// Shared state for the enrollment portal.
#[derive(Clone)]
pub struct PortalState {
    pub db: Database,
    pub acme: AcmeState,
}

const PORTAL_HTML: &str = include_str!("portal.html");

/// Builds the portal axum router.
pub fn build_router(state: PortalState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/ca", get(get_ca))
        .route("/api/zones", get(list_zones))
        .route("/api/certs", get(list_certs))
        .route("/api/account", post(create_account))
        .with_state(state)
}

/// Serves the enrollment portal over HTTPS on `bind`.
pub async fn serve_portal(
    bind: &str,
    state: PortalState,
    server_config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    let app = build_router(state);
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(server_config);
    let addr: std::net::SocketAddr = bind
        .parse()
        .context(format!("invalid ACME portal bind address: {}", bind))?;
    info!("ACME enrollment portal listening on {}", addr);
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .context("ACME portal error")?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(PORTAL_HTML)
}

async fn get_ca(State(state): State<PortalState>) -> Response {
    match ca::root_ca_pem(&state.db) {
        Ok(pem) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/x-pem-file"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"rolodex-root-ca.pem\"",
                ),
            ],
            pem,
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn list_zones(State(state): State<PortalState>) -> Response {
    match state.db.list_zone_cas() {
        Ok(zones) => {
            let trimmed: Vec<String> = zones
                .iter()
                .map(|z| z.trim_end_matches('.').to_string())
                .collect();
            (StatusCode::OK, axum::Json(json!({ "zones": trimmed }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct CertsQuery {
    zone: Option<String>,
}

async fn list_certs(State(state): State<PortalState>, Query(q): Query<CertsQuery>) -> Response {
    match state.db.list_acme_certificates(q.zone.as_deref()) {
        Ok(certs) => {
            let items: Vec<_> = certs
                .iter()
                .map(|c| json!({"domain": c.domain, "issued_at": c.issued_at, "expires_at": c.expires_at}))
                .collect();
            (StatusCode::OK, axum::Json(json!({ "certificates": items }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct AccountRequest {
    zone: String,
}

async fn create_account(State(state): State<PortalState>, body: axum::body::Bytes) -> Response {
    match create_account_inner(&state, &body) {
        Ok(resp) => resp,
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

fn create_account_inner(state: &PortalState, body: &[u8]) -> Result<Response> {
    let req: AccountRequest = serde_json::from_slice(body).context("invalid request body")?;
    let zone = req.zone.trim();
    if zone.is_empty() {
        return Err(anyhow!("zone is required"));
    }

    // Ensure the per-zone intermediate CA exists so issuance can succeed.
    // This also publishes the CA chain into DNS (CERT + TXT records).
    ca::ensure_zone_intermediate(&state.db, zone)?;
    if let Some(dns) = &state.acme.dns_server {
        dns.flush_cache();
    }

    // Mint an EAB credential scoped to this zone.
    let kid = random_b64(16)?;
    let secret = random_bytes(32)?;
    state
        .db
        .create_eab(&kid, &secret, Some(zone))
        .context("failed to store EAB credential")?;
    let hmac_b64 = B64.encode(&secret);

    info!("Portal minted EAB {} for zone {}", kid, zone);

    let dir = &state.acme.directory_url;
    let example = format!("host.{}", zone.trim_end_matches('.'));
    let snippets = vec![
        format!(
            "# lego\nlego --server {dir} --email you@{zone} \\\n  --eab --kid {kid} --hmac {hmac} \\\n  --dns rolodex -d {example} run",
            dir = dir,
            zone = zone.trim_end_matches('.'),
            kid = kid,
            hmac = hmac_b64,
            example = example
        ),
        format!(
            "# certbot\ncertbot certonly --server {dir} \\\n  --eab-kid {kid} --eab-hmac-key {hmac} \\\n  --preferred-challenges dns -d {example}",
            dir = dir,
            kid = kid,
            hmac = hmac_b64,
            example = example
        ),
        format!(
            "# Caddy (Caddyfile)\n{{\n  acme_ca {dir}\n  acme_eab {{\n    key_id {kid}\n    mac_key {hmac}\n  }}\n}}",
            dir = dir,
            kid = kid,
            hmac = hmac_b64
        ),
    ];

    let body = json!({
        "directory_url": dir,
        "zone": zone,
        "eab_kid": kid,
        "eab_hmac_key": hmac_b64,
        "snippets": snippets,
    });
    Ok((StatusCode::OK, axum::Json(body)).into_response())
}

/// Returns `n` random bytes from the system CSPRNG.
fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| anyhow!("secure RNG failure"))?;
    Ok(buf)
}

/// Returns a base64url token with `n` bytes of entropy.
fn random_b64(n: usize) -> Result<String> {
    Ok(B64.encode(random_bytes(n)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme_server::AcmeState;

    fn state() -> PortalState {
        let db = Database::open_memory().unwrap();
        ca::ensure_root_ca(&db, "Portal Test Root").unwrap();
        let acme = AcmeState {
            db: db.clone(),
            dns_server: None,
            directory_url: "https://localhost:8555/acme".to_string(),
            require_eab: true,
            issuance_any: false,
            leaf_validity_days: 90,
            tlsa_port: 443,
            tlsa_proto: "tcp".to_string(),
        };
        PortalState { db, acme }
    }

    #[test]
    fn account_mints_eab_and_creates_intermediate() {
        let st = state();
        let body = serde_json::to_vec(&json!({"zone": "example.com"})).unwrap();
        let resp = create_account_inner(&st, &body).expect("account");
        assert_eq!(resp.status(), StatusCode::OK);
        // The intermediate CA must now exist.
        assert!(st.db.get_zone_ca("example.com.").unwrap().is_some());
        // And an EAB credential must have been stored.
        let zones = st.db.list_zone_cas().unwrap();
        assert!(zones.iter().any(|z| z == "example.com."));
    }

    #[test]
    fn empty_zone_is_rejected() {
        let st = state();
        let body = serde_json::to_vec(&json!({"zone": ""})).unwrap();
        assert!(create_account_inner(&st, &body).is_err());
    }
}
