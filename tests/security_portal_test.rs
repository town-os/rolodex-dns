//! Security regression tests for the trusted-network enrollment portal.
//!
//! These assert behaviour the portal *should* have and are expected to FAIL
//! against the current implementation. Do not weaken an assertion to make one
//! pass.
//!
//! The portal is deliberately unauthenticated — "anyone who can reach it may
//! enroll" is a stated design decision and these tests do not challenge it. What
//! they pin is narrower and not covered by that decision:
//!
//! - **Any zone at all.** `create_account_inner` takes the `zone` string
//!   verbatim, calls `ensure_zone_intermediate` on it, and mints an EAB scoped
//!   to it. Nothing ties the zone to anything the server actually manages, so a
//!   reachable client can create a CA for `windowsupdate.com` — a name the
//!   operator has no relationship with — and have it published as DANE-TA
//!   records in the local DNS. "May enroll" was never meant to mean "may become
//!   a CA for the entire namespace".
//!
//! - **Drive-by CSRF.** The handler reads `axum::body::Bytes` and parses JSON
//!   without requiring a JSON content-type or checking `Origin`. A cross-origin
//!   form POST with `Content-Type: text/plain` is a CORS *simple request*: no
//!   preflight, so the browser sends it and the side effect lands. The attacker
//!   cannot read the EAB back, but the CA creation and the DNS publication
//!   happen — a page in any LAN user's browser can reshape the local PKI.
//!
//! Both run in-process against the portal router via `tower::oneshot`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rolodex_dns::acme_server::AcmeState;
use rolodex_dns::db::Database;
use rolodex_dns::portal::{PortalState, build_router};
use serde_json::json;
use tower::ServiceExt;

fn portal_state(db: &Database) -> PortalState {
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
    PortalState {
        db: db.clone(),
        acme,
    }
}

fn test_db() -> Database {
    let db = Database::open_memory().unwrap();
    rolodex_dns::ca::ensure_root_ca(&db, "Rolodex Test Root").unwrap();
    db
}

/// POSTs `body` to `/api/account` with the given content type and optional
/// `Origin`, returning the status.
async fn post_account(
    db: &Database,
    body: &str,
    content_type: &str,
    origin: Option<&str>,
) -> StatusCode {
    let router = build_router(portal_state(db));
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/account")
        .header("content-type", content_type);
    if let Some(o) = origin {
        req = req.header("origin", o);
    }
    let resp = router
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    resp.status()
}

// ============================================================================
// Zone scoping
// ============================================================================

/// Enrolling a zone the server has no relationship with must be refused. The
/// portal should only issue credentials for zones the operator actually manages
/// — an owned TLD, a scope's home domain, a zone with existing records, or an
/// explicit allowlist. Anything else means a reachable client can mint a CA for
/// any name on the internet.
#[tokio::test]
async fn portal_refuses_to_enroll_an_unmanaged_zone() {
    let db = test_db();

    let status = post_account(
        &db,
        &json!({"zone": "windowsupdate.com"}).to_string(),
        "application/json",
        None,
    )
    .await;

    assert_ne!(
        status,
        StatusCode::OK,
        "the portal minted a CA and an EAB credential for windowsupdate.com, \
         a zone this server does not manage"
    );
    assert!(
        db.get_zone_ca("windowsupdate.com.").unwrap().is_none(),
        "no intermediate CA should have been created for an unmanaged zone"
    );
}

/// The counterpart: a zone the operator does manage must still enroll, so the
/// fix is a scope check rather than a blanket refusal. Here the zone is made
/// managed by giving it a record in the local database.
#[tokio::test]
async fn portal_still_enrolls_a_managed_zone() {
    let db = test_db();
    db.add_record(&rolodex_dns::db::DnsRecord {
        id: None,
        name: "host.lab.internal.".to_string(),
        record_type: rolodex_dns::db::RecordKind::A,
        value: "10.0.0.5".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();

    let status = post_account(
        &db,
        &json!({"zone": "lab.internal"}).to_string(),
        "application/json",
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a zone the server manages must still be enrollable"
    );
    assert!(
        db.get_zone_ca("lab.internal.").unwrap().is_some(),
        "enrolling a managed zone should create its intermediate CA"
    );
}

// ============================================================================
// Cross-site request forgery
// ============================================================================

/// `text/plain` is the CSRF vector: it makes the request a CORS simple request,
/// so a form on any page a LAN user visits reaches the portal with no preflight.
/// The handler must require a real JSON content-type so the browser is forced to
/// preflight — which the portal will not answer.
#[tokio::test]
async fn portal_rejects_non_json_content_type() {
    let db = test_db();
    db.add_record(&rolodex_dns::db::DnsRecord {
        id: None,
        name: "host.lab.internal.".to_string(),
        record_type: rolodex_dns::db::RecordKind::A,
        value: "10.0.0.5".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();

    let status = post_account(
        &db,
        &json!({"zone": "lab.internal"}).to_string(),
        "text/plain;charset=UTF-8",
        None,
    )
    .await;

    assert!(
        status == StatusCode::UNSUPPORTED_MEDIA_TYPE || status == StatusCode::BAD_REQUEST,
        "a text/plain body was accepted, so a cross-origin form POST reaches this \
         endpoint without a preflight; got {}",
        status
    );
    assert!(
        db.get_zone_ca("lab.internal.").unwrap().is_none(),
        "a simple-request CSRF POST created an intermediate CA"
    );
}

/// A request carrying an `Origin` from somewhere other than the portal is a
/// cross-site request by definition and must be refused, whatever its
/// content-type.
#[tokio::test]
async fn portal_rejects_foreign_origin() {
    let db = test_db();
    db.add_record(&rolodex_dns::db::DnsRecord {
        id: None,
        name: "host.lab.internal.".to_string(),
        record_type: rolodex_dns::db::RecordKind::A,
        value: "10.0.0.5".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();

    let status = post_account(
        &db,
        &json!({"zone": "lab.internal"}).to_string(),
        "application/json",
        Some("https://attacker.example"),
    )
    .await;

    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::BAD_REQUEST,
        "a request with a foreign Origin was accepted; got {}",
        status
    );
    assert!(
        db.get_zone_ca("lab.internal.").unwrap().is_none(),
        "a cross-origin POST created an intermediate CA"
    );
}
