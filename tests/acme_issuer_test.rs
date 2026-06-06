//! End-to-end ACME issuance test.
//!
//! Drives the ACME router in-process via `tower::oneshot` with real JWS bodies
//! signed by a test Ed25519 account key, exercising the full RFC 8555 flow:
//! directory → new-nonce → new-account (with EAB) → new-order → dns-01 challenge
//! (TXT pre-seeded into the DB, as the client's dns-01 hook would) → finalize
//! (CSR) → certificate download.
//!
//! Asserts the issued chain validates to the Rolodex root and that the DANE-TA
//! TLSA record was auto-published. Everything is simulated; the host is never
//! touched.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::hmac;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rolodex_dns::acme_server::{AcmeState, build_router};
use rolodex_dns::db::{Database, RecordKind};
use serde_json::{Value, json};
use tower::ServiceExt;

const ORIGIN: &str = "https://acme.test";

fn base() -> String {
    format!("{}/acme", ORIGIN)
}

fn path_of(url: &str) -> String {
    url.strip_prefix(ORIGIN).unwrap_or(url).to_string()
}

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

    /// Signs and sends a JWS POST to `url`, returning (status, headers-as-needed, body).
    async fn post(
        &mut self,
        url: &str,
        payload: Option<Value>,
    ) -> (StatusCode, Option<String>, Value) {
        let mut protected = json!({
            "alg": "EdDSA",
            "nonce": self.nonce,
            "url": url,
        });
        match &self.kid {
            Some(kid) => protected["kid"] = json!(kid),
            None => protected["jwk"] = self.jwk.clone(),
        }
        let protected_b64 = B64.encode(serde_json::to_vec(&protected).unwrap());
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
        // Refresh nonce for the next request.
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
}

/// Fetches the directory and returns the initial Replay-Nonce.
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

#[tokio::test]
async fn full_acme_issuance_flow() {
    // --- Server setup ------------------------------------------------------
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "example.com").unwrap();

    // Provision an EAB credential scoped to example.com (as the portal would).
    let eab_kid = "eab-test-kid";
    let eab_secret = b"0123456789abcdef0123456789abcdef";
    db.create_eab(eab_kid, eab_secret, Some("example.com"))
        .unwrap();

    let state = AcmeState {
        db: db.clone(),
        dns_server: None,
        directory_url: base(),
        require_eab: true,
        issuance_any: false,
        leaf_validity_days: 90,
        tlsa_port: 443,
        tlsa_proto: "tcp".to_string(),
    };
    let router = build_router(state);

    // --- Directory ---------------------------------------------------------
    let dir_req = Request::builder()
        .method("GET")
        .uri("/acme/directory")
        .body(Body::empty())
        .unwrap();
    let dir_resp = router.clone().oneshot(dir_req).await.unwrap();
    assert_eq!(dir_resp.status(), StatusCode::OK);
    let dir_bytes = axum::body::to_bytes(dir_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let dir: Value = serde_json::from_slice(&dir_bytes).unwrap();
    assert_eq!(dir["newOrder"], json!(format!("{}/new-order", base())));
    assert_eq!(dir["meta"]["externalAccountRequired"], json!(true));

    let nonce = initial_nonce(&router).await;
    let mut client = Client::new(router.clone(), nonce);

    // --- new-account (with EAB) -------------------------------------------
    let eab = make_eab(
        eab_kid,
        eab_secret,
        &client.jwk,
        &format!("{}/new-account", base()),
    );
    let (status, location, _body) = client
        .post(
            &format!("{}/new-account", base()),
            Some(json!({"externalAccountBinding": eab, "termsOfServiceAgreed": true})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "account should be created");
    client.kid = Some(location.expect("account Location header"));

    // --- new-order ---------------------------------------------------------
    let (status, order_loc, order) = client
        .post(
            &format!("{}/new-order", base()),
            Some(json!({"identifiers":[{"type":"dns","value":"host.example.com"}]})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(order["status"], json!("pending"));
    let order_url = order_loc.expect("order Location");
    let authz_url = order["authorizations"][0].as_str().unwrap().to_string();
    let finalize_url = order["finalize"].as_str().unwrap().to_string();

    // --- authz (POST-as-GET) ----------------------------------------------
    let (status, _, authz) = client.post(&authz_url, None).await;
    assert_eq!(status, StatusCode::OK);
    let challenge = authz["challenges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["type"] == json!("dns-01"))
        .expect("dns-01 challenge");
    let challenge_url = challenge["url"].as_str().unwrap().to_string();
    let token = challenge["token"].as_str().unwrap().to_string();

    // --- Provision the dns-01 TXT (what the client's dns-01 hook would do) --
    let thumbprint = rolodex_dns::acme_jose::jwk_thumbprint(&client.jwk).unwrap();
    let key_auth = rolodex_dns::acme_jose::key_authorization(&token, &thumbprint);
    let txt = rolodex_dns::acme_jose::dns01_txt_value(&key_auth);
    rolodex_dns::acme::set_acme_challenge(&db, "host.example.com", &txt).unwrap();

    // --- respond to challenge ---------------------------------------------
    let (status, _, chal) = client.post(&challenge_url, Some(json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(chal["status"], json!("valid"), "dns-01 should validate");

    // --- poll order: should be ready --------------------------------------
    let (status, _, order) = client.post(&order_url, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(order["status"], json!("ready"));

    // --- finalize with a CSR ----------------------------------------------
    let csr_der = make_csr_der("host.example.com");
    let (status, _, order) = client
        .post(&finalize_url, Some(json!({"csr": B64.encode(&csr_der)})))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(order["status"], json!("valid"));
    let cert_url = order["certificate"]
        .as_str()
        .expect("certificate url")
        .to_string();

    // --- download the certificate chain -----------------------------------
    let chain = download_chain(&router, &mut client, &cert_url).await;
    let chain_certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut chain.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    assert_eq!(chain_certs.len(), 2, "chain is leaf + intermediate");

    // The leaf must chain to the Rolodex root.
    let root_pem = rolodex_dns::ca::root_ca_pem(&db).unwrap();
    let root_der: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut root_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let anchors: Vec<_> = root_der
        .iter()
        .map(|d| webpki::anchor_from_trusted_cert(d).unwrap())
        .collect();
    let ee = webpki::EndEntityCert::try_from(&chain_certs[0]).unwrap();
    let now = rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        time::OffsetDateTime::now_utc().unix_timestamp() as u64,
    ));
    ee.verify_for_usage(
        &[webpki::ring::ED25519],
        &anchors,
        &chain_certs[1..],
        now,
        webpki::KeyUsage::server_auth(),
        None,
        None,
    )
    .expect("issued leaf must chain to the Rolodex root");

    // --- DANE-TA record was auto-published --------------------------------
    let tlsa = db
        .lookup("_443._tcp.host.example.com.", Some(RecordKind::TLSA))
        .unwrap();
    assert_eq!(tlsa.len(), 1, "DANE-TA TLSA record should be published");
    assert!(tlsa[0].value.starts_with("2 1 1 "));
    let expected_tlsa = rolodex_dns::ca::intermediate_tlsa(&db, "example.com").unwrap();
    assert_eq!(tlsa[0].value, expected_tlsa);
}

#[tokio::test]
async fn issuance_rejected_outside_account_zone() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    rolodex_dns::ca::ensure_zone_intermediate(&db, "example.com").unwrap();
    let eab_kid = "eab-kid-2";
    let eab_secret = b"abcdef0123456789abcdef0123456789";
    db.create_eab(eab_kid, eab_secret, Some("example.com"))
        .unwrap();

    let state = AcmeState {
        db: db.clone(),
        dns_server: None,
        directory_url: base(),
        require_eab: true,
        issuance_any: false,
        leaf_validity_days: 90,
        tlsa_port: 443,
        tlsa_proto: "tcp".to_string(),
    };
    let router = build_router(state);
    let nonce = initial_nonce(&router).await;
    let mut client = Client::new(router.clone(), nonce);

    let eab = make_eab(
        eab_kid,
        eab_secret,
        &client.jwk,
        &format!("{}/new-account", base()),
    );
    let (status, location, _) = client
        .post(
            &format!("{}/new-account", base()),
            Some(json!({"externalAccountBinding": eab})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    client.kid = Some(location.unwrap());

    // A name outside the account's zone must be rejected.
    let (status, _, body) = client
        .post(
            &format!("{}/new-order", base()),
            Some(json!({"identifiers":[{"type":"dns","value":"host.evil.org"}]})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body["type"],
        json!("urn:ietf:params:acme:error:rejectedIdentifier")
    );
}

#[tokio::test]
async fn reused_nonce_is_rejected() {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    let state = AcmeState {
        db,
        dns_server: None,
        directory_url: base(),
        require_eab: false,
        issuance_any: true,
        leaf_validity_days: 90,
        tlsa_port: 443,
        tlsa_proto: "tcp".to_string(),
    };
    let router = build_router(state);
    let nonce = initial_nonce(&router).await;
    let mut client = Client::new(router.clone(), nonce.clone());

    // First account creation consumes the nonce.
    let (status, _, _) = client
        .post(&format!("{}/new-account", base()), Some(json!({})))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Replay the original (now-consumed) nonce → badNonce.
    client.nonce = nonce;
    let (status, _, body) = client
        .post(&format!("{}/new-account", base()), Some(json!({})))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["type"], json!("urn:ietf:params:acme:error:badNonce"));
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

/// Builds a DER-encoded PKCS#10 CSR for `name` with a fresh Ed25519 key.
fn make_csr_der(name: &str) -> Vec<u8> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
    let csr = params.serialize_request(&key).unwrap();
    csr.der().to_vec()
}

/// POST-as-GET the certificate URL and return the PEM chain.
async fn download_chain(_router: &Router, client: &mut Client, cert_url: &str) -> String {
    let protected = json!({
        "alg": "EdDSA",
        "nonce": client.nonce,
        "url": cert_url,
        "kid": client.kid.clone().unwrap(),
    });
    let protected_b64 = B64.encode(serde_json::to_vec(&protected).unwrap());
    let payload_b64 = String::new();
    let signing_input = format!("{}.{}", protected_b64, payload_b64);
    let sig = client.kp.sign(signing_input.as_bytes());
    let jws = json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": B64.encode(sig.as_ref()),
    });
    let req = Request::builder()
        .method("POST")
        .uri(path_of(cert_url))
        .header("content-type", "application/jose+json")
        .body(Body::from(serde_json::to_vec(&jws).unwrap()))
        .unwrap();
    let resp = client.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    if let Some(n) = resp.headers().get("replay-nonce") {
        client.nonce = n.to_str().unwrap().to_string();
    }
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}
