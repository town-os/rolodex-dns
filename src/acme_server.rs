//! ACME server / certificate authority (RFC 8555, server side).
//!
//! Rolodex acts as an ACME CA that off-the-shelf clients (certbot, lego, acme.sh,
//! Caddy) can point at. It implements the directory, nonce, account (with
//! External Account Binding), order, authorization, dns-01 challenge, finalize,
//! and certificate-download flows.
//!
//! - **Validation** is **dns-01 only**, checked against Rolodex's own DNS
//!   database — the client provisions the `_acme-challenge` TXT through the
//!   Rolodex control plane (e.g. a `rolodex-dns-cli` dns-01 hook).
//! - **Issuance** signs the client CSR with the per-zone intermediate CA (see
//!   [`crate::ca`]) and returns the `leaf + intermediate` chain.
//! - On issuance the matching **DANE-TA** TLSA record (`2 1 1` of the
//!   intermediate) is published so the cert validates via DANE.
//!
//! Every response carries a fresh `Replay-Nonce` (RFC 8555 §6.5) via the
//! [`attach_nonce`] middleware.

use crate::ca;
use crate::dane;
use crate::db::{
    AcmeAccount, AcmeAuthorization, AcmeChallenge, AcmeOrder, Database, DnsRecord, RecordKind,
};
use crate::dns_server::DnsServer;
use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    body::Bytes,
    extract::{Path, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::rand::SecureRandom;
use serde_json::{Value, json};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{error, info};

/// How long orders and authorizations remain valid before expiry.
const ORDER_TTL_SECS: i64 = 7 * 24 * 3600;

/// Shared state for the ACME server.
#[derive(Clone)]
pub struct AcmeState {
    pub db: Database,
    /// Optional handle to the running DNS server, so caches can be flushed when
    /// DANE records are published. `None` in tests.
    pub dns_server: Option<Arc<DnsServer>>,
    /// External base URL of the ACME endpoint, e.g. `https://host:8555/acme`
    /// (no trailing slash). Advertised in the directory and signed by clients.
    pub directory_url: String,
    /// Whether External Account Binding is required for newAccount.
    pub require_eab: bool,
    /// If true, issue for any name; if false, only names under an intermediate-backed zone.
    pub issuance_any: bool,
    /// Validity of issued leaf certificates, in days.
    pub leaf_validity_days: i64,
    /// Default port/protocol used to place the DANE-TA TLSA record.
    pub tlsa_port: u16,
    pub tlsa_proto: String,
}

impl AcmeState {
    fn url(&self, suffix: &str) -> String {
        format!("{}/{}", self.directory_url.trim_end_matches('/'), suffix)
    }

    /// Generates, stores, and returns a fresh anti-replay nonce.
    fn new_nonce(&self) -> Result<String> {
        let nonce = random_token(16)?;
        self.db.store_nonce(&nonce)?;
        Ok(nonce)
    }
}

/// Generates a random URL-safe token of `n` bytes of entropy.
fn random_token(n: usize) -> Result<String> {
    let mut buf = vec![0u8; n];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| anyhow!("secure RNG failure"))?;
    Ok(B64.encode(&buf))
}

/// Builds the ACME axum router. Routes are mounted under `/acme`.
pub fn build_router(state: AcmeState) -> Router {
    Router::new()
        .route("/acme/directory", get(directory))
        .route("/acme/new-nonce", get(new_nonce).head(new_nonce))
        .route("/acme/new-account", post(new_account))
        .route("/acme/new-order", post(new_order))
        .route("/acme/order/{id}", post(get_order))
        .route("/acme/authz/{id}", post(get_authz))
        .route("/acme/challenge/{id}", post(respond_challenge))
        .route("/acme/finalize/{id}", post(finalize))
        .route("/acme/cert/{id}", post(get_cert))
        .route("/acme/revoke-cert", post(revoke_cert))
        .layer(middleware::from_fn_with_state(state.clone(), attach_nonce))
        .with_state(state)
}

/// Serves the ACME endpoint over HTTPS on `bind`.
pub async fn serve_acme(
    bind: &str,
    state: AcmeState,
    server_config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    let app = build_router(state);
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(server_config);
    let addr: std::net::SocketAddr = bind
        .parse()
        .context(format!("invalid ACME bind address: {}", bind))?;
    info!("ACME server listening on {}", addr);
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .context("ACME server error")?;
    Ok(())
}

/// Middleware: attach a fresh `Replay-Nonce` header to every response.
async fn attach_nonce(State(state): State<AcmeState>, req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    match state.new_nonce() {
        Ok(nonce) => {
            if let Ok(val) = HeaderValue::from_str(&nonce) {
                resp.headers_mut().insert("replay-nonce", val);
            }
        }
        Err(e) => error!("failed to mint replay nonce: {}", e),
    }
    resp
}

// ============================================================================
// Errors
// ============================================================================

/// An ACME problem document (RFC 8555 §6.7 / RFC 7807).
struct AcmeError {
    status: StatusCode,
    typ: &'static str,
    detail: String,
}

impl AcmeError {
    fn new(status: StatusCode, typ: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            typ,
            detail: detail.into(),
        }
    }
    fn malformed(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:malformed",
            detail,
        )
    }
    fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "urn:ietf:params:acme:error:unauthorized",
            detail,
        )
    }
    fn bad_nonce(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:badNonce",
            detail,
        )
    }
    fn server_internal(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "urn:ietf:params:acme:error:serverInternal",
            detail,
        )
    }
}

impl IntoResponse for AcmeError {
    fn into_response(self) -> Response {
        let body = json!({"type": self.typ, "detail": self.detail});
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            serde_json::to_vec(&body).unwrap_or_default(),
        )
            .into_response()
    }
}

/// Convenience: convert an `anyhow::Error` from internal calls into a 500.
fn internal<E: std::fmt::Display>(e: E) -> AcmeError {
    AcmeError::server_internal(e.to_string())
}

// ============================================================================
// JWS request verification
// ============================================================================

/// A verified ACME request.
struct Verified {
    payload: Value,
    /// The account, if the request used a `kid` (existing account).
    account: Option<AcmeAccount>,
    /// The verified account public key JWK.
    jwk: Value,
    /// The account public key thumbprint.
    thumbprint: String,
}

/// Parses and verifies the JWS in `body`, enforcing nonce and URL binding.
fn verify_request(
    state: &AcmeState,
    body: &[u8],
    expected_url: &str,
) -> Result<Verified, AcmeError> {
    let jws =
        crate::acme_jose::FlatJws::parse(body).map_err(|e| AcmeError::malformed(e.to_string()))?;
    let header = jws
        .protected_header()
        .map_err(|e| AcmeError::malformed(e.to_string()))?;

    // URL binding (RFC 8555 §6.4).
    if let Some(url) = &header.url
        && url != expected_url
    {
        return Err(AcmeError::malformed(format!(
            "JWS url {} does not match request {}",
            url, expected_url
        )));
    }

    // Anti-replay nonce (RFC 8555 §6.5).
    let nonce = header
        .nonce
        .as_ref()
        .ok_or_else(|| AcmeError::bad_nonce("missing nonce"))?;
    match state.db.consume_nonce(nonce) {
        Ok(true) => {}
        Ok(false) => return Err(AcmeError::bad_nonce("unrecognized or reused nonce")),
        Err(e) => return Err(internal(e)),
    }

    // Resolve the verification key: embedded jwk (newAccount) or kid (account url).
    let (jwk, account) = match (&header.jwk, &header.kid) {
        (Some(jwk), None) => (jwk.clone(), None),
        (None, Some(kid)) => {
            let account_id = kid.rsplit('/').next().unwrap_or_default().to_string();
            let account = state
                .db
                .get_acme_account(&account_id)
                .map_err(internal)?
                .ok_or_else(|| {
                    AcmeError::new(
                        StatusCode::BAD_REQUEST,
                        "urn:ietf:params:acme:error:accountDoesNotExist",
                        "unknown account",
                    )
                })?;
            let jwk: Value = serde_json::from_str(&account.jwk)
                .map_err(|e| AcmeError::server_internal(e.to_string()))?;
            (jwk, Some(account))
        }
        _ => {
            return Err(AcmeError::malformed(
                "JWS must contain exactly one of jwk or kid",
            ));
        }
    };

    jws.verify(&header.alg, &jwk)
        .map_err(|e| AcmeError::unauthorized(e.to_string()))?;

    let payload = jws
        .payload_json()
        .map_err(|e| AcmeError::malformed(e.to_string()))?;
    let thumbprint =
        crate::acme_jose::jwk_thumbprint(&jwk).map_err(|e| AcmeError::malformed(e.to_string()))?;

    Ok(Verified {
        payload,
        account,
        jwk,
        thumbprint,
    })
}

/// JSON response helper.
fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&body).unwrap_or_default(),
    )
        .into_response()
}

/// JSON response with a `Location` header.
fn json_located(status: StatusCode, location: &str, body: Value) -> Response {
    let mut resp = json_response(status, body);
    if let Ok(val) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, val);
    }
    resp
}

fn rfc3339(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_default()
}

// ============================================================================
// Handlers
// ============================================================================

async fn directory(State(state): State<AcmeState>) -> Response {
    let body = json!({
        "newNonce": state.url("new-nonce"),
        "newAccount": state.url("new-account"),
        "newOrder": state.url("new-order"),
        "revokeCert": state.url("revoke-cert"),
        "meta": { "externalAccountRequired": state.require_eab },
    });
    json_response(StatusCode::OK, body)
}

async fn new_nonce() -> Response {
    // The Replay-Nonce header is attached by the middleware.
    StatusCode::NO_CONTENT.into_response()
}

async fn new_account(State(state): State<AcmeState>, body: Bytes) -> Response {
    match new_account_inner(&state, &body).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

async fn new_account_inner(state: &AcmeState, body: &[u8]) -> Result<Response, AcmeError> {
    let expected = state.url("new-account");
    let verified = verify_request(state, body, &expected)?;

    // Account-key reuse: return the existing account if this key already has one.
    if let Some(existing) = state
        .db
        .get_acme_account_by_thumbprint(&verified.thumbprint)
        .map_err(internal)?
    {
        let loc = state.url(&format!("account/{}", existing.account_id));
        return Ok(json_located(StatusCode::OK, &loc, account_json(&existing)));
    }

    if verified
        .payload
        .get("onlyReturnExisting")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Err(AcmeError::new(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:accountDoesNotExist",
            "no account exists for this key",
        ));
    }

    // External Account Binding.
    let mut zone: Option<String> = None;
    let mut eab_kid: Option<String> = None;
    if let Some(eab) = verified.payload.get("externalAccountBinding") {
        let kid =
            crate::acme_jose::eab_kid(eab).map_err(|e| AcmeError::malformed(e.to_string()))?;
        let cred = state
            .db
            .get_eab(&kid)
            .map_err(internal)?
            .ok_or_else(|| AcmeError::unauthorized("unknown External Account Binding key"))?;
        crate::acme_jose::verify_eab(eab, &verified.jwk, &cred.hmac_key)
            .map_err(|e| AcmeError::unauthorized(e.to_string()))?;
        state.db.mark_eab_used(&kid).map_err(internal)?;
        zone = cred.zone.clone();
        eab_kid = Some(kid);
        // Make sure the per-zone intermediate exists for this account's zone.
        if let Some(z) = &zone {
            ca::ensure_zone_intermediate(&state.db, z).map_err(internal)?;
            // ensure_zone_intermediate publishes CA records into DNS.
            if let Some(dns) = &state.dns_server {
                dns.flush_cache();
            }
        }
    } else if state.require_eab {
        return Err(AcmeError::new(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:externalAccountRequired",
            "this ACME server requires External Account Binding",
        ));
    }

    let account_id = random_token(16).map_err(internal)?;
    let contacts = verified.payload.get("contact").map(|c| c.to_string());
    let account = AcmeAccount {
        account_id: account_id.clone(),
        jwk: serde_json::to_string(&verified.jwk)
            .map_err(|e| AcmeError::server_internal(e.to_string()))?,
        thumbprint: verified.thumbprint.clone(),
        contacts,
        status: "valid".to_string(),
        eab_kid,
        zone,
    };
    state.db.create_acme_account(&account).map_err(internal)?;
    info!("ACME account created: {}", account_id);

    let loc = state.url(&format!("account/{}", account_id));
    Ok(json_located(
        StatusCode::CREATED,
        &loc,
        account_json(&account),
    ))
}

fn account_json(account: &AcmeAccount) -> Value {
    json!({
        "status": account.status,
        "orders": "",
    })
}

async fn new_order(State(state): State<AcmeState>, body: Bytes) -> Response {
    match new_order_inner(&state, &body).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

async fn new_order_inner(state: &AcmeState, body: &[u8]) -> Result<Response, AcmeError> {
    let expected = state.url("new-order");
    let verified = verify_request(state, body, &expected)?;
    let account = verified
        .account
        .ok_or_else(|| AcmeError::malformed("newOrder requires an account (kid)"))?;

    let identifiers = verified
        .payload
        .get("identifiers")
        .and_then(Value::as_array)
        .ok_or_else(|| AcmeError::malformed("missing identifiers"))?;
    if identifiers.is_empty() {
        return Err(AcmeError::malformed("no identifiers"));
    }

    let mut names = Vec::new();
    for id in identifiers {
        let typ = id.get("type").and_then(Value::as_str).unwrap_or_default();
        if typ != "dns" {
            return Err(AcmeError::malformed("only dns identifiers are supported"));
        }
        let value = id
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| AcmeError::malformed("identifier missing value"))?;
        // Scope check: the name must be issuable.
        check_issuable(state, &account, value)?;
        names.push(value.to_string());
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let expires = now + ORDER_TTL_SECS;
    let order_id = random_token(16).map_err(internal)?;

    // Create one authorization (+ dns-01 challenge) per identifier.
    let mut authz_ids = Vec::new();
    for name in &names {
        let authz_id = random_token(16).map_err(internal)?;
        let authz = AcmeAuthorization {
            id: authz_id.clone(),
            order_id: order_id.clone(),
            account_id: account.account_id.clone(),
            identifier: name.clone(),
            status: "pending".to_string(),
            expires_at: expires,
        };
        state.db.create_authorization(&authz).map_err(internal)?;

        let challenge = AcmeChallenge {
            id: random_token(16).map_err(internal)?,
            authz_id: authz_id.clone(),
            challenge_type: "dns-01".to_string(),
            token: random_token(32).map_err(internal)?,
            status: "pending".to_string(),
            validated_at: None,
        };
        state.db.create_challenge(&challenge).map_err(internal)?;
        authz_ids.push(authz_id);
    }

    let identifiers_json = serde_json::to_string(&names).map_err(internal)?;
    let authz_json = serde_json::to_string(&authz_ids).map_err(internal)?;
    let order = AcmeOrder {
        id: order_id.clone(),
        account_id: account.account_id.clone(),
        status: "pending".to_string(),
        identifiers: identifiers_json,
        authorizations: authz_json,
        cert_id: None,
        expires_at: expires,
    };
    state.db.create_order(&order).map_err(internal)?;

    let loc = state.url(&format!("order/{}", order_id));
    Ok(json_located(
        StatusCode::CREATED,
        &loc,
        order_json(state, &order).map_err(internal)?,
    ))
}

/// Determines whether `name` may be issued for `account`, returning the zone.
fn check_issuable(
    state: &AcmeState,
    account: &AcmeAccount,
    name: &str,
) -> Result<String, AcmeError> {
    let normalized = crate::db::normalize_name(name);
    // EAB-scoped accounts may only get names under their zone.
    if let Some(zone) = &account.zone {
        let z = crate::db::normalize_name(zone);
        if normalized != z && !normalized.ends_with(&format!(".{}", z)) {
            return Err(AcmeError::new(
                StatusCode::FORBIDDEN,
                "urn:ietf:params:acme:error:rejectedIdentifier",
                format!("{} is not within the account's zone {}", name, zone),
            ));
        }
        return Ok(z);
    }
    // Otherwise resolve to an intermediate-backed zone.
    match ca::responsible_zone(&state.db, name).map_err(internal)? {
        Some(z) => Ok(z),
        None if state.issuance_any => {
            // Derive a zone from the last two labels and create an intermediate.
            let zone = derive_zone(&normalized);
            ca::ensure_zone_intermediate(&state.db, &zone).map_err(internal)?;
            // ensure_zone_intermediate publishes CA records into DNS.
            if let Some(dns) = &state.dns_server {
                dns.flush_cache();
            }
            Ok(zone)
        }
        None => Err(AcmeError::new(
            StatusCode::FORBIDDEN,
            "urn:ietf:params:acme:error:rejectedIdentifier",
            format!("no CA configured for {}", name),
        )),
    }
}

/// Derives a registrable zone (last two labels) from a normalized name.
fn derive_zone(normalized: &str) -> String {
    let labels: Vec<&str> = normalized.trim_end_matches('.').split('.').collect();
    let n = labels.len();
    if n >= 2 {
        format!("{}.{}.", labels[n - 2], labels[n - 1])
    } else {
        normalized.to_string()
    }
}

async fn get_order(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    match get_order_inner(&state, &id, &body).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

async fn get_order_inner(state: &AcmeState, id: &str, body: &[u8]) -> Result<Response, AcmeError> {
    let expected = state.url(&format!("order/{}", id));
    verify_request(state, body, &expected)?;
    let order = state
        .db
        .get_order(id)
        .map_err(internal)?
        .ok_or_else(|| AcmeError::malformed("unknown order"))?;
    Ok(json_response(
        StatusCode::OK,
        order_json(state, &order).map_err(internal)?,
    ))
}

fn order_json(state: &AcmeState, order: &AcmeOrder) -> Result<Value> {
    let names: Vec<String> = serde_json::from_str(&order.identifiers)?;
    let authz_ids: Vec<String> = serde_json::from_str(&order.authorizations)?;
    let identifiers: Vec<Value> = names
        .iter()
        .map(|n| json!({"type":"dns","value": n}))
        .collect();
    let authorizations: Vec<String> = authz_ids
        .iter()
        .map(|a| state.url(&format!("authz/{}", a)))
        .collect();
    let mut obj = json!({
        "status": order.status,
        "expires": rfc3339(order.expires_at),
        "identifiers": identifiers,
        "authorizations": authorizations,
        "finalize": state.url(&format!("finalize/{}", order.id)),
    });
    if let Some(cert_id) = order.cert_id {
        obj["certificate"] = json!(state.url(&format!("cert/{}", cert_id)));
    }
    Ok(obj)
}

async fn get_authz(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    match get_authz_inner(&state, &id, &body).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

async fn get_authz_inner(state: &AcmeState, id: &str, body: &[u8]) -> Result<Response, AcmeError> {
    let expected = state.url(&format!("authz/{}", id));
    verify_request(state, body, &expected)?;
    let authz = state
        .db
        .get_authorization(id)
        .map_err(internal)?
        .ok_or_else(|| AcmeError::malformed("unknown authorization"))?;
    Ok(json_response(
        StatusCode::OK,
        authz_json(state, &authz).map_err(internal)?,
    ))
}

fn authz_json(state: &AcmeState, authz: &AcmeAuthorization) -> Result<Value> {
    let challenges = state.db.list_challenges_for_authz(&authz.id)?;
    let challenges_json: Vec<Value> = challenges
        .iter()
        .map(|c| {
            json!({
                "type": c.challenge_type,
                "url": state.url(&format!("challenge/{}", c.id)),
                "token": c.token,
                "status": c.status,
            })
        })
        .collect();
    Ok(json!({
        "status": authz.status,
        "expires": rfc3339(authz.expires_at),
        "identifier": {"type":"dns","value": authz.identifier},
        "challenges": challenges_json,
    }))
}

async fn respond_challenge(
    State(state): State<AcmeState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    match respond_challenge_inner(&state, &id, &body).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

async fn respond_challenge_inner(
    state: &AcmeState,
    id: &str,
    body: &[u8],
) -> Result<Response, AcmeError> {
    let expected = state.url(&format!("challenge/{}", id));
    let verified = verify_request(state, body, &expected)?;
    let account = verified
        .account
        .ok_or_else(|| AcmeError::malformed("challenge requires an account (kid)"))?;

    let challenge = state
        .db
        .get_challenge(id)
        .map_err(internal)?
        .ok_or_else(|| AcmeError::malformed("unknown challenge"))?;
    let authz = state
        .db
        .get_authorization(&challenge.authz_id)
        .map_err(internal)?
        .ok_or_else(|| AcmeError::malformed("orphan challenge"))?;

    // Perform dns-01 validation against our own DNS data.
    let key_auth = crate::acme_jose::key_authorization(&challenge.token, &account.thumbprint);
    let expected_txt = crate::acme_jose::dns01_txt_value(&key_auth);
    let record_name = format!(
        "_acme-challenge.{}.",
        authz.identifier.trim_end_matches('.')
    );
    let txt_records = state
        .db
        .lookup(&record_name, Some(RecordKind::TXT))
        .map_err(internal)?;
    let matched = txt_records
        .iter()
        .any(|r| r.value.trim_matches('"') == expected_txt);

    let now = OffsetDateTime::now_utc().unix_timestamp();
    if matched {
        state
            .db
            .update_challenge_status(&challenge.id, "valid", Some(now))
            .map_err(internal)?;
        state
            .db
            .update_authorization_status(&authz.id, "valid")
            .map_err(internal)?;
        maybe_advance_order(state, &authz.order_id)?;
    } else {
        state
            .db
            .update_challenge_status(&challenge.id, "invalid", None)
            .map_err(internal)?;
        state
            .db
            .update_authorization_status(&authz.id, "invalid")
            .map_err(internal)?;
    }

    // Re-read the challenge for its updated status.
    let updated = state
        .db
        .get_challenge(id)
        .map_err(internal)?
        .ok_or_else(|| internal(anyhow!("challenge vanished")))?;
    Ok(json_response(
        StatusCode::OK,
        json!({
            "type": updated.challenge_type,
            "url": expected,
            "token": updated.token,
            "status": updated.status,
        }),
    ))
}

/// If all of an order's authorizations are valid, move it to `ready`.
fn maybe_advance_order(state: &AcmeState, order_id: &str) -> Result<(), AcmeError> {
    let order = match state.db.get_order(order_id).map_err(internal)? {
        Some(o) => o,
        None => return Ok(()),
    };
    let authz_ids: Vec<String> = serde_json::from_str(&order.authorizations).map_err(internal)?;
    let mut all_valid = true;
    for aid in &authz_ids {
        let authz = state.db.get_authorization(aid).map_err(internal)?;
        if authz.map(|a| a.status != "valid").unwrap_or(true) {
            all_valid = false;
            break;
        }
    }
    if all_valid && order.status == "pending" {
        state
            .db
            .update_order(order_id, "ready", None)
            .map_err(internal)?;
    }
    Ok(())
}

async fn finalize(State(state): State<AcmeState>, Path(id): Path<String>, body: Bytes) -> Response {
    match finalize_inner(&state, &id, &body).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

async fn finalize_inner(state: &AcmeState, id: &str, body: &[u8]) -> Result<Response, AcmeError> {
    let expected = state.url(&format!("finalize/{}", id));
    let verified = verify_request(state, body, &expected)?;
    let account = verified
        .account
        .ok_or_else(|| AcmeError::malformed("finalize requires an account (kid)"))?;

    let order = state
        .db
        .get_order(id)
        .map_err(internal)?
        .ok_or_else(|| AcmeError::malformed("unknown order"))?;
    if order.status != "ready" {
        return Err(AcmeError::new(
            StatusCode::FORBIDDEN,
            "urn:ietf:params:acme:error:orderNotReady",
            format!("order is {}, not ready", order.status),
        ));
    }

    let csr_b64 = verified
        .payload
        .get("csr")
        .and_then(Value::as_str)
        .ok_or_else(|| AcmeError::malformed("missing csr"))?;
    let csr_der = B64
        .decode(csr_b64.as_bytes())
        .map_err(|e| AcmeError::malformed(format!("csr is not base64url: {}", e)))?;
    let csr_pem = der_to_pem("CERTIFICATE REQUEST", &csr_der);

    let names: Vec<String> = serde_json::from_str(&order.identifiers).map_err(internal)?;
    let primary = names.first().cloned().unwrap_or_default();
    let zone = check_issuable(state, &account, &primary)?;

    let issued = ca::issue_leaf(&state.db, &zone, &csr_pem, state.leaf_validity_days)
        .map_err(|e| AcmeError::malformed(format!("CSR signing failed: {}", e)))?;

    let cert_id = state
        .db
        .store_acme_certificate(
            &primary,
            &issued.leaf_pem,
            "",
            &issued.chain_pem,
            issued.expires_at,
        )
        .map_err(internal)?;

    // Publish the DANE-TA TLSA record for each identifier so the cert validates.
    publish_dane(state, &zone, &names).map_err(internal)?;

    state
        .db
        .update_order(&order.id, "valid", Some(cert_id))
        .map_err(internal)?;
    info!("ACME issued certificate {} for {}", cert_id, primary);

    let order = state
        .db
        .get_order(id)
        .map_err(internal)?
        .ok_or_else(|| internal(anyhow!("order vanished")))?;
    let loc = state.url(&format!("order/{}", order.id));
    Ok(json_located(
        StatusCode::OK,
        &loc,
        order_json(state, &order).map_err(internal)?,
    ))
}

/// Publishes the per-zone intermediate as a DANE-TA TLSA record for each name.
fn publish_dane(state: &AcmeState, zone: &str, names: &[String]) -> Result<()> {
    let tlsa = ca::intermediate_tlsa(&state.db, zone)?;
    for name in names {
        let record_name = dane::tlsa_dns_name(name, state.tlsa_port, &state.tlsa_proto);
        state.db.add_record(&DnsRecord {
            id: None,
            name: record_name,
            record_type: RecordKind::TLSA,
            value: tlsa.clone(),
            ttl: 3600,
            priority: 0,
        })?;
    }
    if let Some(dns) = &state.dns_server {
        dns.flush_cache();
    }
    Ok(())
}

async fn get_cert(State(state): State<AcmeState>, Path(id): Path<String>, body: Bytes) -> Response {
    match get_cert_inner(&state, &id, &body).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

async fn get_cert_inner(state: &AcmeState, id: &str, body: &[u8]) -> Result<Response, AcmeError> {
    let expected = state.url(&format!("cert/{}", id));
    verify_request(state, body, &expected)?;
    let cert_id: i64 = id
        .parse()
        .map_err(|_| AcmeError::malformed("invalid certificate id"))?;
    let cert = state
        .db
        .get_acme_certificate_by_id(cert_id)
        .map_err(internal)?
        .ok_or_else(|| AcmeError::malformed("unknown certificate"))?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pem-certificate-chain")],
        cert.chain_pem,
    )
        .into_response())
}

async fn revoke_cert(State(state): State<AcmeState>, body: Bytes) -> Response {
    let expected = state.url("revoke-cert");
    // Authenticate the request; revocation tracking is not yet implemented.
    match verify_request(&state, &body, &expected) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => e.into_response(),
    }
}

/// Wraps DER bytes in a PEM block with the given label.
fn der_to_pem(label: &str, der: &[u8]) -> String {
    let b64 = B64_STD.encode(der);
    let mut out = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {}-----\n", label));
    out
}
