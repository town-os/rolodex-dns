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
//!
//! Two things that decision does *not* cover, and which are enforced here:
//!
//! - **Enrollment is confined to zones this server manages** (see
//!   [`zone_is_managed`]). "Anyone who can reach it may enroll" was never meant
//!   to mean "may become a CA for the entire namespace": without the check, a
//!   reachable client could mint an intermediate for `windowsupdate.com`, have
//!   it published as DANE-TA records in the local DNS, and issue against a name
//!   the operator has no relationship with — under a root every enrolled client
//!   trusts.
//! - **Cross-site requests are rejected** (see [`reject_cross_site`]). Reaching
//!   the portal must mean *the user* reached it, not a page in their browser.

use crate::acme_server::AcmeState;
use crate::ca;
use crate::db::Database;
use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, Uri, header},
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
///
/// `tls` is a live view of the certificate rather than a snapshot, so a renewal
/// is served by the next connection without a restart.
pub async fn serve_portal(
    bind: &str,
    state: PortalState,
    tls: tokio::sync::watch::Receiver<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let app = build_router(state);
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(tls.borrow().clone());
    let addr: std::net::SocketAddr = bind
        .parse()
        .context(format!("invalid ACME portal bind address: {}", bind))?;
    info!("ACME enrollment portal listening on {}", addr);
    let renewals = tokio::spawn(crate::tls::drive_axum_tls(tls_config.clone(), tls));
    let outcome = axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await;
    renewals.abort();
    outcome.context("ACME portal error")?;
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

async fn create_account(
    State(state): State<PortalState>,
    headers: HeaderMap,
    uri: Uri,
    body: axum::body::Bytes,
) -> Response {
    if let Some(rejection) = reject_cross_site(&headers, &uri) {
        return rejection;
    }
    match create_account_inner(&state, &body) {
        Ok(resp) => resp,
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// Rejects a request that a browser could have made on some other site's behalf.
///
/// The portal is unauthenticated by design, so a request that *arrives* is
/// authorized — which makes "who actually initiated it" the only remaining
/// question, and CSRF exactly the attack that lies about it. Two checks, both
/// cheap and both needed:
///
/// - **A JSON content-type is mandatory.** `text/plain`, `application/x-www-form-urlencoded`,
///   and `multipart/form-data` are the three types a cross-origin form POST can
///   send without a CORS preflight. Requiring `application/json` forces the
///   browser to preflight, and the portal answers no preflight — so the request
///   never leaves the browser. Without this, a form on any page a LAN user
///   visits reshapes the local PKI, blind but effective: the attacker cannot
///   read the EAB back, yet the CA creation and the DNS publication still happen.
/// - **A foreign `Origin` is refused.** Whatever the content-type, an `Origin`
///   that is not this server is a cross-site request by definition. Browser
///   extensions are exempt: their origin is only attached once the user has
///   granted host permission for this portal, which is a deliberate act, and the
///   bundled extension (`extension/`) is a first-class client of this API.
fn reject_cross_site(headers: &HeaderMap, uri: &Uri) -> Option<Response> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !is_json_content_type(content_type) {
        return Some(
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "content-type must be application/json",
            )
                .into_response(),
        );
    }

    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if let Some(origin) = origin
        && !origin_is_self(origin, headers, uri)
    {
        info!("Portal rejected cross-origin enrollment from {}", origin);
        return Some((StatusCode::FORBIDDEN, "cross-origin request refused").into_response());
    }
    None
}

/// Whether `value` is `application/json` (parameters such as `; charset=utf-8`
/// are allowed, everything else is not).
fn is_json_content_type(value: &str) -> bool {
    let essence = value.split(';').next().unwrap_or("").trim();
    essence.eq_ignore_ascii_case("application/json")
}

/// Whether an `Origin` header names this server.
///
/// Compared on authority (`host[:port]`) rather than the full origin: the portal
/// serves the page over HTTPS on the same listener the API is on, so the scheme
/// is never the discriminator, and a reverse proxy in front may terminate TLS.
/// An origin of `null` (a sandboxed iframe, a `file://` page, some redirects) is
/// never self.
fn origin_is_self(origin: &str, headers: &HeaderMap, uri: &Uri) -> bool {
    if origin.eq_ignore_ascii_case("null") {
        return false;
    }
    if is_browser_extension_origin(origin) {
        return true;
    }
    let Some(origin_authority) = origin.split_once("://").map(|(_, rest)| rest) else {
        return false;
    };
    // HTTP/1.1 carries the authority in `Host`; HTTP/2 puts it in `:authority`,
    // which hyper surfaces on the request URI.
    let self_authority = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.authority().map(|a| a.as_str()));
    match self_authority {
        Some(host) => host.eq_ignore_ascii_case(origin_authority),
        // No authority to compare against: cannot establish same-origin, so don't.
        None => false,
    }
}

/// Whether `origin` belongs to a browser extension.
fn is_browser_extension_origin(origin: &str) -> bool {
    let lower = origin.to_ascii_lowercase();
    lower.starts_with("chrome-extension://")
        || lower.starts_with("moz-extension://")
        || lower.starts_with("safari-web-extension://")
}

/// Whether this server has a relationship with `zone` that justifies becoming a
/// CA for it.
///
/// Any of: a scope owns it as a TLD (which covers a scope's implicit `.home`
/// domain), it has records in the local database, it is a declared
/// authoritative zone, or it already has an intermediate CA — the last because
/// an operator who ran `EnsureZoneCa` over the control plane has already made
/// the decision explicitly. Each check is suffix-matched, so a subzone of a
/// managed zone enrolls too.
///
/// `acme.issuance_scope: any` disables the check, matching what that setting
/// already means for the ACME issuer itself.
fn zone_is_managed(state: &PortalState, zone: &str) -> bool {
    if state.acme.issuance_any {
        return true;
    }
    state.db.find_tld_owner(zone).is_some()
        || state.db.find_managed_zone(zone).is_some()
        || state.db.find_authoritative_zone(zone).is_some()
        || matches!(state.db.get_zone_ca(zone), Ok(Some(_)))
}

fn create_account_inner(state: &PortalState, body: &[u8]) -> Result<Response> {
    let req: AccountRequest = serde_json::from_slice(body).context("invalid request body")?;
    let zone = req.zone.trim();
    if zone.is_empty() {
        return Err(anyhow!("zone is required"));
    }
    if !zone_is_managed(state, zone) {
        return Err(anyhow!(
            "zone '{}' is not managed by this server; add records for it, \
             declare it authoritative, or give a network scope ownership of it \
             before enrolling",
            zone
        ));
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
            tlsa_endpoints: vec![(443, "tcp".to_string())],
        };
        PortalState { db, acme }
    }

    /// Makes `zone` managed the same way ordinary operation does: by giving it a
    /// record.
    fn manage(st: &PortalState, zone: &str) {
        st.db
            .add_record(&crate::db::DnsRecord {
                id: None,
                name: format!("host.{}.", zone.trim_end_matches('.')),
                record_type: crate::db::RecordKind::A,
                value: "10.0.0.5".to_string(),
                ttl: 300,
                priority: 0,
            })
            .unwrap();
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn account_mints_eab_and_creates_intermediate() {
        let st = state();
        manage(&st, "example.com");
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

    #[test]
    fn unmanaged_zone_is_rejected() {
        let st = state();
        let body = serde_json::to_vec(&json!({"zone": "windowsupdate.com"})).unwrap();
        assert!(create_account_inner(&st, &body).is_err());
        assert!(st.db.get_zone_ca("windowsupdate.com.").unwrap().is_none());
    }

    #[test]
    fn a_subzone_of_a_managed_zone_is_managed() {
        let st = state();
        manage(&st, "lab.internal");
        assert!(zone_is_managed(&st, "team.lab.internal"));
        assert!(!zone_is_managed(&st, "internal"));
    }

    #[test]
    fn a_scopes_owned_tld_is_managed() {
        let st = state();
        st.db
            .create_network_scope(&crate::db::NetworkScope {
                name: "office".to_string(),
                home_domain: "office.home.".to_string(),
            })
            .unwrap();
        assert!(zone_is_managed(&st, "office.home"));
    }

    #[test]
    fn issuance_scope_any_enrolls_anything() {
        let mut st = state();
        st.acme.issuance_any = true;
        assert!(zone_is_managed(&st, "windowsupdate.com"));
    }

    #[test]
    fn only_a_json_content_type_is_accepted() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("Application/JSON; charset=utf-8"));
        // The three types a cross-origin form POST can send without a preflight.
        assert!(!is_json_content_type("text/plain;charset=UTF-8"));
        assert!(!is_json_content_type("application/x-www-form-urlencoded"));
        assert!(!is_json_content_type("multipart/form-data; boundary=x"));
        assert!(!is_json_content_type(""));
    }

    #[test]
    fn a_missing_or_foreign_content_type_is_refused() {
        let uri: Uri = "/api/account".parse().unwrap();
        let rejected = reject_cross_site(&headers(&[("content-type", "text/plain")]), &uri)
            .expect("text/plain must be refused");
        assert_eq!(rejected.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            reject_cross_site(&HeaderMap::new(), &uri)
                .expect("a missing content-type must be refused")
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn a_foreign_origin_is_refused_and_a_matching_one_is_not() {
        let uri: Uri = "/api/account".parse().unwrap();
        let foreign = reject_cross_site(
            &headers(&[
                ("content-type", "application/json"),
                ("origin", "https://attacker.example"),
                ("host", "portal.internal:8500"),
            ]),
            &uri,
        )
        .expect("a foreign origin must be refused");
        assert_eq!(foreign.status(), StatusCode::FORBIDDEN);

        assert!(
            reject_cross_site(
                &headers(&[
                    ("content-type", "application/json"),
                    ("origin", "https://portal.internal:8500"),
                    ("host", "portal.internal:8500"),
                ]),
                &uri,
            )
            .is_none(),
            "the portal's own page must still enroll"
        );
        assert!(
            reject_cross_site(&headers(&[("content-type", "application/json")]), &uri).is_none(),
            "a non-browser client sends no Origin and must still enroll"
        );
    }

    #[test]
    fn origin_self_comparison() {
        let uri: Uri = "/api/account".parse().unwrap();
        let host = headers(&[("host", "portal.internal:8500")]);
        // Scheme is not the discriminator: a proxy may terminate TLS.
        assert!(origin_is_self("http://portal.internal:8500", &host, &uri));
        // A different port is a different origin.
        assert!(!origin_is_self("https://portal.internal:9000", &host, &uri));
        // `null` (sandboxed iframe, file:// page) is never self.
        assert!(!origin_is_self("null", &host, &uri));
        // Nothing to compare against: refuse rather than assume.
        assert!(!origin_is_self(
            "https://portal.internal:8500",
            &HeaderMap::new(),
            &uri
        ));
        // Extensions are exempt; the user granted host permission deliberately.
        assert!(origin_is_self("chrome-extension://abcdef", &host, &uri));
        assert!(origin_is_self("moz-extension://abcdef", &host, &uri));
    }
}
