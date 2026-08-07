//! Security regression tests for the ACME issuer (RFC 8555 server side).
//!
//! Every test in this file asserts the behaviour the issuer *should* have. They
//! are expected to FAIL against the current implementation — each one pins an
//! open security issue, and turns green when that issue is fixed. Do not weaken
//! an assertion to make it pass; fix the issuer.
//!
//! The issues pinned here:
//!
//! | Test | Issue |
//! | ---- | ----- |
//! | `csr_sans_must_be_confined_to_the_order` | `ca::issue_leaf` signs the CSR's SANs verbatim, so any account can obtain a trusted certificate for a name it never validated. |
//! | `csr_subject_cn_must_be_confined_to_the_order` | Same defect via the CSR subject DN rather than the SAN extension. |
//! | `finalize_requires_order_ownership` | `finalize` looks the order up by id and never checks it belongs to the requesting account (RFC 8555 §7.4). |
//! | `order_read_requires_ownership` / `authz_read_requires_ownership` / `challenge_response_requires_ownership` | Same missing check on the read/validate paths. |
//! | `certificate_download_requires_ownership` | Certificates are addressed by a sequential rowid and any account may download any of them. |
//! | `nonces_are_not_retained_unboundedly` | A nonce is minted and stored on every response and never expired, so an unauthenticated client can grow the table without limit. |
//! | `jws_without_url_is_rejected` | URL binding is skipped entirely when the protected header omits `url`, permitting cross-endpoint replay. |
//! | `eab_credential_is_single_use` | An EAB credential is accepted forever; `mark_eab_used` records the use but nothing enforces it. |
//! | `revoke_cert_does_not_claim_false_success` | `revoke-cert` returns 200 OK without revoking anything. |
//! | `expired_order_cannot_be_finalized` | `expires_at` is stored on orders and authorizations but never enforced. |
//!
//! Everything runs in-process against the axum router via `tower::oneshot`, with
//! real JWS bodies signed by test keys. The host is never touched.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::hmac;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rolodex_dns::acme_server::{AcmeState, build_router};
use rolodex_dns::db::Database;
use serde_json::{Value, json};
use tower::ServiceExt;

const ORIGIN: &str = "https://acme.test";

fn base() -> String {
    format!("{}/acme", ORIGIN)
}

fn path_of(url: &str) -> String {
    url.strip_prefix(ORIGIN).unwrap_or(url).to_string()
}

// ============================================================================
// Test client
// ============================================================================

/// A test ACME client holding an Ed25519 account key and the current nonce.
struct Client {
    router: Router,
    kp: Ed25519KeyPair,
    jwk: Value,
    nonce: String,
    kid: Option<String>,
}

impl Client {
    fn new(router: Router, nonce: String) -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let x = B64.encode(kp.public_key().as_ref());
        let jwk = json!({"kty":"OKP","crv":"Ed25519","x":x});
        Self {
            router,
            kp,
            jwk,
            nonce,
            kid: None,
        }
    }

    /// Signs and sends a JWS POST, returning `(status, Location, body)`.
    async fn post(
        &mut self,
        url: &str,
        payload: Option<Value>,
    ) -> (StatusCode, Option<String>, Value) {
        let mut protected = json!({"alg":"EdDSA","nonce": self.nonce,"url": url});
        match &self.kid {
            Some(kid) => protected["kid"] = json!(kid),
            None => protected["jwk"] = self.jwk.clone(),
        }
        self.send(url, &protected, payload).await
    }

    /// Signs and sends a JWS POST with a caller-built protected header, so a
    /// test can omit or corrupt header fields the normal client always sets.
    async fn post_with_header(
        &mut self,
        url: &str,
        protected: Value,
        payload: Option<Value>,
    ) -> (StatusCode, Option<String>, Value) {
        self.send(url, &protected, payload).await
    }

    async fn send(
        &mut self,
        url: &str,
        protected: &Value,
        payload: Option<Value>,
    ) -> (StatusCode, Option<String>, Value) {
        let protected_b64 = B64.encode(serde_json::to_vec(protected).unwrap());
        let payload_b64 = match &payload {
            Some(p) => B64.encode(serde_json::to_vec(p).unwrap()),
            None => String::new(),
        };
        let signing_input = format!("{}.{}", protected_b64, payload_b64);
        let sig = self.kp.sign(signing_input.as_bytes());
        let jws = json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": B64.encode(sig.as_ref()),
        });

        let req = Request::builder()
            .method("POST")
            .uri(path_of(url))
            .header("content-type", "application/jose+json")
            .body(Body::from(serde_json::to_vec(&jws).unwrap()))
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        if let Some(n) = resp.headers().get("replay-nonce") {
            self.nonce = n.to_str().unwrap().to_string();
        }
        let location = resp
            .headers()
            .get("location")
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, location, body)
    }

    /// POST-as-GET, returning the raw (non-JSON) body — used for cert download.
    async fn post_raw(&mut self, url: &str) -> (StatusCode, String) {
        let protected = json!({
            "alg":"EdDSA","nonce": self.nonce,"url": url,
            "kid": self.kid.clone().expect("kid"),
        });
        let protected_b64 = B64.encode(serde_json::to_vec(&protected).unwrap());
        let signing_input = format!("{}.", protected_b64);
        let sig = self.kp.sign(signing_input.as_bytes());
        let jws = json!({
            "protected": protected_b64,
            "payload": "",
            "signature": B64.encode(sig.as_ref()),
        });
        let req = Request::builder()
            .method("POST")
            .uri(path_of(url))
            .header("content-type", "application/jose+json")
            .body(Body::from(serde_json::to_vec(&jws).unwrap()))
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        if let Some(n) = resp.headers().get("replay-nonce") {
            self.nonce = n.to_str().unwrap().to_string();
        }
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }
}

// ============================================================================
// Harness helpers
// ============================================================================

fn state_for(db: &Database, require_eab: bool, issuance_any: bool) -> AcmeState {
    AcmeState {
        db: db.clone(),
        dns_server: None,
        directory_url: base(),
        require_eab,
        issuance_any,
        leaf_validity_days: 90,
        tlsa_port: 443,
        tlsa_proto: "tcp".to_string(),
    }
}

async fn initial_nonce(router: &Router) -> String {
    let req = Request::builder()
        .method("GET")
        .uri("/acme/new-nonce")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    resp.headers()
        .get("replay-nonce")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

/// Builds an EAB inner JWS binding `account_jwk` under `kid`, signed with `secret`.
fn make_eab(kid: &str, secret: &[u8], account_jwk: &Value, url: &str) -> Value {
    let protected = json!({"alg":"HS256","kid":kid,"url":url});
    let protected_b64 = B64.encode(serde_json::to_vec(&protected).unwrap());
    let payload_b64 = B64.encode(serde_json::to_vec(account_jwk).unwrap());
    let signing_input = format!("{}.{}", protected_b64, payload_b64);
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, signing_input.as_bytes());
    json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": B64.encode(tag.as_ref()),
    })
}

/// Builds a DER PKCS#10 CSR whose SAN list is exactly `names`.
fn make_csr_der(names: &[&str]) -> Vec<u8> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params =
        rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
            .unwrap();
    let csr = params.serialize_request(&key).unwrap();
    csr.der().to_vec()
}

/// Builds a DER PKCS#10 CSR with no SANs and `cn` as the subject common name.
fn make_csr_der_with_cn(cn: &str) -> Vec<u8> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let csr = params.serialize_request(&key).unwrap();
    csr.der().to_vec()
}

/// Registers an EAB-bound account scoped to `zone` and returns the client.
async fn account_for_zone(router: &Router, db: &Database, kid: &str, zone: &str) -> Client {
    let secret = b"0123456789abcdef0123456789abcdef";
    db.create_eab(kid, secret, Some(zone)).unwrap();
    let nonce = initial_nonce(router).await;
    let mut client = Client::new(router.clone(), nonce);
    let eab = make_eab(kid, secret, &client.jwk, &format!("{}/new-account", base()));
    let (status, location, _) = client
        .post(
            &format!("{}/new-account", base()),
            Some(json!({"externalAccountBinding": eab})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "account setup should succeed");
    client.kid = Some(location.expect("account Location"));
    client
}

/// Drives an order for `name` all the way to `ready` (order_url, finalize_url).
async fn ready_order(client: &mut Client, db: &Database, name: &str) -> (String, String) {
    let (status, order_loc, order) = client
        .post(
            &format!("{}/new-order", base()),
            Some(json!({"identifiers":[{"type":"dns","value": name}]})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "order setup should succeed");
    let order_url = order_loc.expect("order Location");
    let finalize_url = order["finalize"].as_str().unwrap().to_string();
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();

    let (_, _, authz) = client.post(&authz_url, None).await;
    let challenge = authz["challenges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["type"] == json!("dns-01"))
        .expect("dns-01 challenge");
    let challenge_url = challenge["url"].as_str().unwrap().to_string();
    let token = challenge["token"].as_str().unwrap().to_string();

    let thumbprint = rolodex_dns::acme_jose::jwk_thumbprint(&client.jwk).unwrap();
    let key_auth = rolodex_dns::acme_jose::key_authorization(&token, &thumbprint);
    let txt = rolodex_dns::acme_jose::dns01_txt_value(&key_auth);
    rolodex_dns::acme::set_acme_challenge(db, name, &txt).unwrap();

    let (status, _, chal) = client.post(&challenge_url, Some(json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(chal["status"], json!("valid"), "dns-01 should validate");

    (order_url, finalize_url)
}

/// Every DNS name asserted by an issued certificate: SAN entries plus the
/// subject CN. Parsed from the leaf DER with x509-parser.
fn cert_names(leaf_pem: &str) -> Vec<String> {
    use x509_parser::prelude::*;
    let der = rustls_pemfile::certs(&mut leaf_pem.as_bytes())
        .next()
        .expect("a leaf certificate")
        .expect("valid PEM");
    let (_, cert) = X509Certificate::from_der(&der).expect("parse leaf");
    let mut names: Vec<String> = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let GeneralName::DNSName(d) = gn {
                names.push(d.to_string());
            }
        }
    }
    for cn in cert.subject().iter_common_name() {
        if let Ok(s) = cn.as_str() {
            names.push(s.to_string());
        }
    }
    names
}

// ============================================================================
// CRITICAL: the CSR must not widen what was validated
// ============================================================================

/// An account validated `host.example.com` and may only receive a certificate
/// for that name. Submitting a CSR that additionally requests
/// `victim.example.com` must be rejected outright — the issuer must not sign a
/// name the order never validated.
///
/// Today `ca::issue_leaf` hands the CSR's `subject_alt_names` straight through
/// to rcgen's `signed_by`, so the extra name is signed by the zone intermediate
/// and chains to the Rolodex root that every enrolled client trusts.
#[tokio::test]
async fn csr_sans_must_be_confined_to_the_order() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "example.com").unwrap();
    let router = build_router(state_for(&db, true, false));

    let mut client = account_for_zone(&router, &db, "eab-san", "example.com").await;
    let (_, finalize_url) = ready_order(&mut client, &db, "host.example.com").await;

    // The order validated exactly one name; the CSR asks for two.
    let csr = make_csr_der(&["host.example.com", "victim.example.com"]);
    let (status, _, body) = client
        .post(&finalize_url, Some(json!({"csr": B64.encode(&csr)})))
        .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a CSR naming an unvalidated identifier must be rejected, got {}: {}",
        status,
        body
    );
    assert_eq!(
        body["type"],
        json!("urn:ietf:params:acme:error:badCSR"),
        "rejection should be reported as badCSR"
    );
}

/// The same widening via the subject DN rather than the SAN extension: a CSR
/// with no SANs and a common name the order never validated must not be signed.
#[tokio::test]
async fn csr_subject_cn_must_be_confined_to_the_order() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "example.com").unwrap();
    let router = build_router(state_for(&db, true, false));

    let mut client = account_for_zone(&router, &db, "eab-cn", "example.com").await;
    let (_, finalize_url) = ready_order(&mut client, &db, "host.example.com").await;

    let csr = make_csr_der_with_cn("victim.example.com");
    let (status, _, body) = client
        .post(&finalize_url, Some(json!({"csr": B64.encode(&csr)})))
        .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a CSR whose CN was never validated must be rejected, got {}: {}",
        status,
        body
    );
}

/// The end-to-end statement of the same defect, asserted on the artifact rather
/// than the status code: whatever the issuer chooses to sign, the certificate it
/// hands back must not assert a name outside the order. This is the invariant
/// that actually matters, and it holds regardless of how the fix is shaped
/// (reject the CSR, or ignore its extra names).
#[tokio::test]
async fn issued_certificate_asserts_only_validated_names() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "example.com").unwrap();
    let router = build_router(state_for(&db, true, false));

    let mut client = account_for_zone(&router, &db, "eab-artifact", "example.com").await;
    let (_, finalize_url) = ready_order(&mut client, &db, "host.example.com").await;

    let csr = make_csr_der(&["host.example.com", "victim.example.com"]);
    let (status, _, order) = client
        .post(&finalize_url, Some(json!({"csr": B64.encode(&csr)})))
        .await;

    // Either finalize refuses (the preferred fix) ...
    if status != StatusCode::OK {
        return;
    }
    // ... or, if it issues, the certificate must carry only the validated name.
    let cert_url = order["certificate"].as_str().expect("certificate url");
    let (status, chain) = client.post_raw(cert_url).await;
    assert_eq!(status, StatusCode::OK);

    let names = cert_names(&chain);
    assert!(
        !names.iter().any(|n| n == "victim.example.com"),
        "issued certificate asserts an identifier the order never validated: {:?}",
        names
    );
}

/// The scope check in `check_issuable` covers the order's identifiers, but the
/// CSR is unconstrained — so an account scoped to one zone can reach clean out
/// of it. This is the cross-tenant form of the same bug and the most damaging:
/// the certificate is for a zone the account has no relationship with.
#[tokio::test]
async fn csr_cannot_escape_the_accounts_zone() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "tenant-a.test").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "tenant-b.test").unwrap();
    let router = build_router(state_for(&db, true, false));

    // The account is scoped to tenant-a and validates a name there.
    let mut client = account_for_zone(&router, &db, "eab-tenant-a", "tenant-a.test").await;
    let (_, finalize_url) = ready_order(&mut client, &db, "host.tenant-a.test").await;

    // The CSR reaches into tenant-b, which new-order would have refused.
    let csr = make_csr_der(&["host.tenant-a.test", "admin.tenant-b.test"]);
    let (status, _, order) = client
        .post(&finalize_url, Some(json!({"csr": B64.encode(&csr)})))
        .await;

    if status != StatusCode::OK {
        return; // finalize refused: correct.
    }
    let cert_url = order["certificate"].as_str().expect("certificate url");
    let (_, chain) = client.post_raw(cert_url).await;
    let names = cert_names(&chain);
    assert!(
        !names.iter().any(|n| n.ends_with("tenant-b.test")),
        "an account scoped to tenant-a.test obtained a certificate for tenant-b.test: {:?}",
        names
    );
}

// ============================================================================
// Missing per-account authorization (IDOR)
// ============================================================================

/// RFC 8555 §7.4: an order may only be finalized by the account that created it.
/// `finalize_inner` looks the order up by id and never compares `account_id`, so
/// a second account can finalize the first account's ready order with its own
/// CSR — and thereby take delivery of a certificate for the victim's name under
/// a key the attacker controls.
#[tokio::test]
async fn finalize_requires_order_ownership() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "example.com").unwrap();
    let router = build_router(state_for(&db, true, false));

    // Victim drives an order to ready but does not finalize it.
    let mut victim = account_for_zone(&router, &db, "eab-victim", "example.com").await;
    let (_, finalize_url) = ready_order(&mut victim, &db, "host.example.com").await;

    // A second, unrelated account in the same zone finalizes it.
    let mut attacker = account_for_zone(&router, &db, "eab-attacker", "example.com").await;
    let csr = make_csr_der(&["host.example.com"]);
    let (status, _, body) = attacker
        .post(&finalize_url, Some(json!({"csr": B64.encode(&csr)})))
        .await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "finalizing another account's order must be rejected, got {}: {}",
        status,
        body
    );
}

/// An order may only be read by the account that created it.
#[tokio::test]
async fn order_read_requires_ownership() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "example.com").unwrap();
    let router = build_router(state_for(&db, true, false));

    let mut victim = account_for_zone(&router, &db, "eab-v-order", "example.com").await;
    let (order_url, _) = ready_order(&mut victim, &db, "host.example.com").await;

    let mut attacker = account_for_zone(&router, &db, "eab-a-order", "example.com").await;
    let (status, _, body) = attacker.post(&order_url, None).await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "reading another account's order must be rejected, got {}: {}",
        status,
        body
    );
}

/// An authorization may only be read by the account that owns it. Leaking it
/// discloses the challenge token, which is one half of the key authorization.
#[tokio::test]
async fn authz_read_requires_ownership() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "example.com").unwrap();
    let router = build_router(state_for(&db, true, false));

    let mut victim = account_for_zone(&router, &db, "eab-v-authz", "example.com").await;
    let (_, _, order) = victim
        .post(
            &format!("{}/new-order", base()),
            Some(json!({"identifiers":[{"type":"dns","value":"host.example.com"}]})),
        )
        .await;
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();

    let mut attacker = account_for_zone(&router, &db, "eab-a-authz", "example.com").await;
    let (status, _, body) = attacker.post(&authz_url, None).await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "reading another account's authorization must be rejected, got {}: {}",
        status,
        body
    );
}

/// A challenge may only be responded to by the account that owns its
/// authorization. `respond_challenge_inner` computes the expected TXT from the
/// *requesting* account's thumbprint while updating the *victim's* authorization
/// — the two are never required to be the same account.
#[tokio::test]
async fn challenge_response_requires_ownership() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "example.com").unwrap();
    let router = build_router(state_for(&db, true, false));

    let mut victim = account_for_zone(&router, &db, "eab-v-chal", "example.com").await;
    let (_, _, order) = victim
        .post(
            &format!("{}/new-order", base()),
            Some(json!({"identifiers":[{"type":"dns","value":"host.example.com"}]})),
        )
        .await;
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    let (_, _, authz) = victim.post(&authz_url, None).await;
    let challenge_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();

    let mut attacker = account_for_zone(&router, &db, "eab-a-chal", "example.com").await;
    let (status, _, body) = attacker.post(&challenge_url, Some(json!({}))).await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "responding to another account's challenge must be rejected, got {}: {}",
        status,
        body
    );
}

/// Certificates are addressed by a sequential rowid and `get_cert_inner` never
/// checks ownership, so any account can walk the id space and download every
/// certificate the CA has ever issued.
#[tokio::test]
async fn certificate_download_requires_ownership() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "example.com").unwrap();
    let router = build_router(state_for(&db, true, false));

    // Victim issues a certificate.
    let mut victim = account_for_zone(&router, &db, "eab-v-cert", "example.com").await;
    let (_, finalize_url) = ready_order(&mut victim, &db, "host.example.com").await;
    let csr = make_csr_der(&["host.example.com"]);
    let (status, _, order) = victim
        .post(&finalize_url, Some(json!({"csr": B64.encode(&csr)})))
        .await;
    assert_eq!(status, StatusCode::OK, "victim issuance should succeed");
    let cert_url = order["certificate"].as_str().expect("certificate url");

    // An unrelated account downloads it.
    let mut attacker = account_for_zone(&router, &db, "eab-a-cert", "example.com").await;
    let (status, _body) = attacker.post_raw(cert_url).await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "downloading another account's certificate must be rejected, got {}",
        status
    );
}

// ============================================================================
// Anti-replay nonces
// ============================================================================

/// A nonce is minted and persisted on *every* response, including unauthenticated
/// `GET /acme/directory`. Unconsumed nonces are never expired — `created_at` is
/// written and never read — so an unauthenticated client grows `acme_nonces` by
/// one row per request until the disk fills, contending all the while on the
/// same database mutex the DNS hot path uses.
///
/// The table must stay bounded no matter how many requests arrive.
///
/// A TTL alone does not achieve that — a flood arriving inside one second is
/// entirely within the window — so the invariant is stated against the hard cap:
/// issue comfortably more requests than `MAX_OUTSTANDING_NONCES` and require the
/// table to have stopped growing.
#[tokio::test]
async fn nonces_are_not_retained_unboundedly() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    let router = build_router(state_for(&db, false, true));

    let cap = Database::MAX_OUTSTANDING_NONCES;
    let requests = cap + 200;
    for _ in 0..requests {
        let req = Request::builder()
            .method("GET")
            .uri("/acme/directory")
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let outstanding = db.count_nonces().unwrap();
    assert!(
        outstanding <= cap,
        "{} unauthenticated requests left {} nonce rows outstanding against a cap \
         of {}: an unauthenticated client can grow the table without limit",
        requests,
        outstanding,
        cap
    );
}

/// The cap must not break the thing nonces are for: a freshly minted nonce, used
/// straight away as a real client would, has to still work.
#[tokio::test]
async fn a_fresh_nonce_is_still_usable() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    let router = build_router(state_for(&db, false, true));

    let nonce = initial_nonce(&router).await;
    let mut client = Client::new(router.clone(), nonce);
    let (status, _, _) = client
        .post(&format!("{}/new-account", base()), Some(json!({})))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a nonce minted and used immediately must be accepted"
    );
}

// ============================================================================
// JWS / EAB binding
// ============================================================================

/// RFC 8555 §6.4 makes the `url` field of the protected header mandatory.
/// `verify_request` checks it only `if let Some(url)`, so a JWS that omits it is
/// bound to no endpoint at all and can be replayed against a different one.
#[tokio::test]
async fn jws_without_url_is_rejected() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    let router = build_router(state_for(&db, false, true));
    let nonce = initial_nonce(&router).await;
    let mut client = Client::new(router.clone(), nonce);

    // A protected header with alg/nonce/jwk but deliberately no `url`.
    let protected = json!({"alg":"EdDSA","nonce": client.nonce, "jwk": client.jwk});
    let (status, _, body) = client
        .post_with_header(
            &format!("{}/new-account", base()),
            protected,
            Some(json!({})),
        )
        .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a JWS with no url binding must be rejected, got {}: {}",
        status,
        body
    );
}

/// An EAB credential is a one-time enrollment token: the portal mints one per
/// enrollment and hands it to a single user. `new_account_inner` calls
/// `mark_eab_used` but nothing ever consults it, so a leaked or shared credential
/// registers unlimited accounts against the zone forever.
#[tokio::test]
async fn eab_credential_is_single_use() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "example.com").unwrap();
    let router = build_router(state_for(&db, true, false));

    let kid = "eab-reuse";
    let secret = b"0123456789abcdef0123456789abcdef";
    db.create_eab(kid, secret, Some("example.com")).unwrap();

    // First enrollment consumes the credential.
    let nonce = initial_nonce(&router).await;
    let mut first = Client::new(router.clone(), nonce);
    let eab = make_eab(kid, secret, &first.jwk, &format!("{}/new-account", base()));
    let (status, _, _) = first
        .post(
            &format!("{}/new-account", base()),
            Some(json!({"externalAccountBinding": eab})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "first enrollment should work");

    // A second, different account key presents the same credential.
    let nonce = initial_nonce(&router).await;
    let mut second = Client::new(router.clone(), nonce);
    let eab = make_eab(kid, secret, &second.jwk, &format!("{}/new-account", base()));
    let (status, _, body) = second
        .post(
            &format!("{}/new-account", base()),
            Some(json!({"externalAccountBinding": eab})),
        )
        .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an already-used EAB credential must not enroll a second account, got {}: {}",
        status,
        body
    );
}

// ============================================================================
// Revocation and expiry
// ============================================================================

/// `revoke_cert` verifies the JWS and returns 200 OK without revoking anything.
/// Telling a client its certificate was revoked when it was not is worse than
/// refusing: the operator believes a compromised key is dead. Until revocation
/// exists the endpoint must report that it is unimplemented.
#[tokio::test]
async fn revoke_cert_does_not_claim_false_success() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "example.com").unwrap();
    let router = build_router(state_for(&db, true, false));

    let mut client = account_for_zone(&router, &db, "eab-revoke", "example.com").await;
    let (_, finalize_url) = ready_order(&mut client, &db, "host.example.com").await;
    let csr = make_csr_der(&["host.example.com"]);
    let (status, _, order) = client
        .post(&finalize_url, Some(json!({"csr": B64.encode(&csr)})))
        .await;
    assert_eq!(status, StatusCode::OK);
    let cert_url = order["certificate"].as_str().unwrap().to_string();
    let (_, chain) = client.post_raw(&cert_url).await;
    let leaf_der = rustls_pemfile::certs(&mut chain.as_bytes())
        .next()
        .unwrap()
        .unwrap();

    let (status, _, _) = client
        .post(
            &format!("{}/revoke-cert", base()),
            Some(json!({"certificate": B64.encode(leaf_der.as_ref())})),
        )
        .await;

    assert_ne!(
        status,
        StatusCode::OK,
        "revoke-cert reports success without revoking; it must return an error \
         (501 NOT_IMPLEMENTED) until revocation is actually implemented"
    );
}

/// Orders and authorizations carry `expires_at`, but no code path reads it. An
/// order whose validation window has closed must not be finalizable — otherwise
/// a validation performed once is good forever, long after the operator has
/// removed the challenge record or lost control of the name.
#[tokio::test]
async fn expired_order_cannot_be_finalized() {
    // File-backed so the test can age the rows through a second connection
    // rather than reaching into the Database's internals.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("expiry.db");
    let db = Database::open(&db_path).unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "example.com").unwrap();
    let router = build_router(state_for(&db, true, false));

    let mut client = account_for_zone(&router, &db, "eab-expiry", "example.com").await;
    let (order_url, finalize_url) = ready_order(&mut client, &db, "host.example.com").await;

    // Age the order and its authorizations past their expiry, as the clock
    // would after the 7-day ORDER_TTL_SECS window.
    let order_id = order_url.rsplit('/').next().unwrap();
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let past = 1_000_000i64; // long before now
        conn.execute(
            "UPDATE acme_orders SET expires_at = ?1 WHERE id = ?2",
            rusqlite::params![past, order_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE acme_authorizations SET expires_at = ?1 WHERE order_id = ?2",
            rusqlite::params![past, order_id],
        )
        .unwrap();
    }

    let csr = make_csr_der(&["host.example.com"]);
    let (status, _, body) = client
        .post(&finalize_url, Some(json!({"csr": B64.encode(&csr)})))
        .await;

    assert_ne!(
        status,
        StatusCode::OK,
        "an expired order must not be finalizable, got {}: {}",
        status,
        body
    );
}
