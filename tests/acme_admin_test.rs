//! The ACME issuer's administrative gRPC surface.
//!
//! `EnsureZoneCa`, `CreateEabCredential`, `RemoveEabCredential`,
//! `ListAcmeAccounts` and `ListAcmeCertificates` were the five RPCs in
//! `proto/rolodex_dns.proto` that no test referenced. `EnsureZoneCa` was reached
//! indirectly through the CLI in the JavaScript integration suite and EAB
//! minting through the portal, but the handlers themselves — the auth check, the
//! CA materialization, what comes back in each field — were unexercised.
//!
//! These are the operator's controls for a certificate authority, so the
//! assertions are about the properties an operator depends on rather than about
//! the calls returning `success: true`:
//!
//! - `EnsureZoneCa` is **idempotent**. It is called on every portal enrollment
//!   and every EAB mint; if it re-minted the intermediate each time, every
//!   certificate issued under the previous one would stop chaining, and the
//!   published DANE-TA TLSA record would stop matching.
//! - A minted EAB is **usable and zone-scoped**. A `kid` and a base64url string
//!   that do not correspond to a stored credential would fail only later, inside
//!   a client's ACME registration.
//! - Removal is **honest about whether it removed anything**, because "removed"
//!   for a credential that is still live is how a revoked enrollment stays
//!   valid.
//! - The listings are filtered as documented, and `ListAcmeCertificates`
//!   suffix-matches on the zone.
//!
//! Everything is in-memory; no network, no host state.

use rolodex_dns::db::{AcmeAccount, Database};
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::dnsbl::{DnsblChecker, DnsblResolver};
use rolodex_dns::grpc_service::proto;
use rolodex_dns::grpc_service::proto::rolodex_dns_service_server::RolodexDnsService;
use std::sync::Arc;

const ZONE: &str = "example.com.";
const OTHER_ZONE: &str = "other.test.";
const DIRECTORY_URL: &str = "https://acme.example.com/acme";

struct NeverListedResolver;

#[async_trait::async_trait]
impl DnsblResolver for NeverListedResolver {
    async fn lookup(
        &self,
        _query: &str,
    ) -> Result<Option<rolodex_dns::dnsbl::DnsblAnswer>, anyhow::Error> {
        Ok(None)
    }
}

/// A service with the ACME issuer parameters set, and its database.
///
/// The shared secret is empty, which is the documented "no authentication"
/// configuration; the dedicated auth tests live in
/// `tests/security_auth_hardening_test.rs`.
fn make_service() -> (rolodex_dns::grpc_service::RolodexDnsGrpcService, Database) {
    let db = Database::open_memory().expect("open memory db");
    let dnsbl = Arc::new(DnsblChecker::with_resolver(Arc::new(NeverListedResolver)));
    let dns_server = Arc::new(DnsServer::new(db.clone(), dnsbl.clone(), vec![]));
    let service = rolodex_dns::grpc_service::RolodexDnsGrpcService::new(
        db.clone(),
        dns_server,
        dnsbl,
        String::new(),
        true,
    )
    .with_acme(DIRECTORY_URL.to_string(), "Rolodex Test Root".to_string());
    (service, db)
}

async fn ensure_zone_ca(
    service: &rolodex_dns::grpc_service::RolodexDnsGrpcService,
    zone: &str,
) -> proto::EnsureZoneCaResponse {
    service
        .ensure_zone_ca(tonic::Request::new(proto::EnsureZoneCaRequest {
            zone: zone.to_string(),
            auth_token: String::new(),
        }))
        .await
        .expect("ensure_zone_ca transport")
        .into_inner()
}

async fn create_eab(
    service: &rolodex_dns::grpc_service::RolodexDnsGrpcService,
    zone: &str,
) -> proto::CreateEabCredentialResponse {
    service
        .create_eab_credential(tonic::Request::new(proto::CreateEabCredentialRequest {
            zone: zone.to_string(),
            auth_token: String::new(),
        }))
        .await
        .expect("create_eab_credential transport")
        .into_inner()
}

async fn remove_eab(
    service: &rolodex_dns::grpc_service::RolodexDnsGrpcService,
    kid: &str,
) -> proto::RemoveEabCredentialResponse {
    service
        .remove_eab_credential(tonic::Request::new(proto::RemoveEabCredentialRequest {
            kid: kid.to_string(),
            auth_token: String::new(),
        }))
        .await
        .expect("remove_eab_credential transport")
        .into_inner()
}

async fn list_accounts(
    service: &rolodex_dns::grpc_service::RolodexDnsGrpcService,
) -> Vec<proto::AcmeAccountInfo> {
    service
        .list_acme_accounts(tonic::Request::new(proto::ListAcmeAccountsRequest {
            auth_token: String::new(),
        }))
        .await
        .expect("list_acme_accounts transport")
        .into_inner()
        .accounts
}

async fn list_certificates(
    service: &rolodex_dns::grpc_service::RolodexDnsGrpcService,
    zone: &str,
) -> Vec<proto::AcmeCertificateInfo> {
    service
        .list_acme_certificates(tonic::Request::new(proto::ListAcmeCertificatesRequest {
            zone: zone.to_string(),
            auth_token: String::new(),
        }))
        .await
        .expect("list_acme_certificates transport")
        .into_inner()
        .certificates
}

fn account(id: &str, zone: Option<&str>, eab_kid: Option<&str>, status: &str) -> AcmeAccount {
    AcmeAccount {
        account_id: id.to_string(),
        jwk: format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{id}"}}"#),
        thumbprint: format!("thumb-{id}"),
        contacts: None,
        status: status.to_string(),
        eab_kid: eab_kid.map(|s| s.to_string()),
        zone: zone.map(|s| s.to_string()),
    }
}

// ============================================================================
// EnsureZoneCa
// ============================================================================

/// The base case: the call materializes a root CA and a per-zone intermediate
/// and hands both back as PEM.
///
/// Both PEMs are checked to be *distinct* certificates rather than merely
/// non-empty. Returning the root twice would produce a response that passes any
/// "is it a certificate" check and a chain that no client can build.
#[tokio::test]
async fn ensure_zone_ca_returns_a_root_and_a_distinct_intermediate() {
    let (service, db) = make_service();

    let response = ensure_zone_ca(&service, ZONE).await;
    assert!(
        response.success,
        "ensure_zone_ca failed: {}",
        response.message
    );
    assert!(
        response.root_ca_pem.contains("BEGIN CERTIFICATE"),
        "the root CA is not PEM: {:?}",
        response.root_ca_pem
    );
    assert!(
        response.intermediate_ca_pem.contains("BEGIN CERTIFICATE"),
        "the intermediate CA is not PEM: {:?}",
        response.intermediate_ca_pem
    );
    assert_ne!(
        response.root_ca_pem, response.intermediate_ca_pem,
        "the intermediate returned is the root certificate; there is no chain"
    );

    // And it is the intermediate that was actually stored for the zone, not a
    // freshly generated one that exists only in the response.
    let stored = db
        .get_zone_ca(ZONE)
        .expect("read zone CA")
        .expect("a zone CA was stored");
    assert_eq!(
        stored.0, response.intermediate_ca_pem,
        "the returned intermediate is not the one persisted for the zone"
    );
}

/// Idempotence is the property the whole enrollment flow rests on:
/// `ensure_zone_intermediate` runs on portal account creation, on every
/// `CreateEabCredential`, and on ACME account and finalize paths. A second call
/// must return the *same* intermediate.
///
/// If it re-minted, every certificate already issued under the old intermediate
/// would stop chaining to what the server now presents, and the published
/// DANE-TA TLSA record — a hash of the intermediate's SPKI — would stop
/// matching. Both failures appear at a client, days later.
#[tokio::test]
async fn ensure_zone_ca_is_idempotent() {
    let (service, _db) = make_service();

    let first = ensure_zone_ca(&service, ZONE).await;
    let second = ensure_zone_ca(&service, ZONE).await;

    assert!(second.success, "the second call failed: {}", second.message);
    assert_eq!(
        first.root_ca_pem, second.root_ca_pem,
        "the root CA was regenerated on a second call"
    );
    assert_eq!(
        first.intermediate_ca_pem, second.intermediate_ca_pem,
        "the zone intermediate was regenerated on a second call; every \
         certificate issued under the previous one has stopped chaining"
    );
}

/// Two zones get two different intermediates under one shared root. That is the
/// hierarchy the design describes, and it is what confines a compromised zone
/// key to its own zone.
#[tokio::test]
async fn each_zone_gets_its_own_intermediate_under_one_root() {
    let (service, _db) = make_service();

    let first = ensure_zone_ca(&service, ZONE).await;
    let second = ensure_zone_ca(&service, OTHER_ZONE).await;

    assert_eq!(
        first.root_ca_pem, second.root_ca_pem,
        "the two zones were issued under different roots"
    );
    assert_ne!(
        first.intermediate_ca_pem, second.intermediate_ca_pem,
        "two zones share one intermediate CA"
    );
}

/// The CA chain is published into DNS as part of ensuring the intermediate (see
/// `publish_ca_dns_records`), which is what makes the chain retrievable by any
/// client that can resolve the zone. Pinning it here keeps the publication tied
/// to the RPC rather than to whichever caller happened to do it.
#[tokio::test]
async fn ensure_zone_ca_publishes_the_chain_into_dns() {
    let (service, db) = make_service();
    ensure_zone_ca(&service, ZONE).await;

    let cert_records = db
        .lookup(
            &format!("_ca.{ZONE}"),
            Some(rolodex_dns::db::RecordKind::CERT),
        )
        .expect("lookup CERT records");
    assert!(
        cert_records.len() >= 2,
        "expected CERT records for both the root and the intermediate at _ca.{ZONE}, found {}",
        cert_records.len()
    );

    let txt_records = db
        .lookup(
            &format!("_rolodex-ca.{ZONE}"),
            Some(rolodex_dns::db::RecordKind::TXT),
        )
        .expect("lookup TXT fallback");
    assert!(
        !txt_records.is_empty(),
        "the chunked TXT fallback was not published at _rolodex-ca.{ZONE}"
    );
    assert!(
        txt_records
            .iter()
            .all(|r| r.value.starts_with("rolodex-ca:v1:")),
        "the TXT fallback chunks are not framed with the rolodex-ca prefix"
    );
}

// ============================================================================
// CreateEabCredential
// ============================================================================

/// A minted credential must actually exist, be scoped to the requested zone, and
/// carry a key that matches the base64url string handed to the operator.
///
/// Decoding the returned key and comparing it to the stored secret is the point:
/// a response that returned a *different* random string would look correct in
/// every way until a client's registration failed its EAB signature check.
#[tokio::test]
async fn a_minted_eab_credential_is_stored_and_scoped_to_its_zone() {
    let (service, db) = make_service();

    let response = create_eab(&service, ZONE).await;
    assert!(response.success, "create_eab failed: {}", response.message);
    assert!(!response.kid.is_empty(), "no kid was returned");
    assert_eq!(
        response.directory_url, DIRECTORY_URL,
        "the response did not carry the configured directory URL, so the \
         operator cannot hand a client a working configuration"
    );

    let stored = db
        .get_eab(&response.kid)
        .expect("read EAB")
        .expect("the minted credential was not stored");
    assert_eq!(
        stored.zone.as_deref(),
        Some(rolodex_dns::db::normalize_name(ZONE).as_str()),
        "the credential is not scoped to the zone it was minted for"
    );
    assert!(!stored.used, "a freshly minted credential is already used");

    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &response.hmac_key,
    )
    .expect("the returned HMAC key is not base64url");
    assert_eq!(
        decoded, stored.hmac_key,
        "the HMAC key handed to the operator is not the one stored"
    );
    assert_eq!(
        decoded.len(),
        32,
        "the EAB secret is {} bytes; HS256 wants a 256-bit key",
        decoded.len()
    );
}

/// Minting is what an operator does per enrollment, so two mints must produce
/// two distinct credentials. A reused kid or a reused secret would let one
/// enrollee's credential authorize another's.
#[tokio::test]
async fn each_minted_credential_is_distinct() {
    let (service, _db) = make_service();

    let first = create_eab(&service, ZONE).await;
    let second = create_eab(&service, ZONE).await;

    assert_ne!(first.kid, second.kid, "two mints produced the same kid");
    assert_ne!(
        first.hmac_key, second.hmac_key,
        "two mints produced the same HMAC secret"
    );
}

/// Minting also ensures the zone's CA, because a credential that authorizes
/// issuance for a zone with no intermediate is an enrollment that fails at
/// finalize — after the client has already been configured.
#[tokio::test]
async fn minting_a_credential_ensures_the_zone_ca() {
    let (service, db) = make_service();
    assert!(
        db.get_zone_ca(ZONE).expect("read zone CA").is_none(),
        "the zone CA exists before anything created it"
    );

    let response = create_eab(&service, ZONE).await;
    assert!(response.success);

    assert!(
        db.get_zone_ca(ZONE).expect("read zone CA").is_some(),
        "minting an EAB for a zone left it without an intermediate CA"
    );
}

// ============================================================================
// RemoveEabCredential
// ============================================================================

/// Removal must both remove the credential and say that it did.
#[tokio::test]
async fn removing_a_credential_deletes_it() {
    let (service, db) = make_service();
    let minted = create_eab(&service, ZONE).await;

    let removed = remove_eab(&service, &minted.kid).await;
    assert!(
        removed.success,
        "removing an existing credential reported failure: {}",
        removed.message
    );
    assert!(
        db.get_eab(&minted.kid).expect("read EAB").is_none(),
        "the credential is still in the database after removal"
    );
}

/// Removing something that is not there must report failure. Reporting success
/// is how a revoked enrollment stays live: the operator sees the removal
/// succeed — because they mistyped the kid — and the real credential keeps
/// authorizing issuance.
#[tokio::test]
async fn removing_an_unknown_credential_reports_failure() {
    let (service, _db) = make_service();

    let removed = remove_eab(&service, "no-such-kid").await;
    assert!(
        !removed.success,
        "removing a credential that does not exist reported success"
    );
    assert!(
        !removed.message.is_empty(),
        "the failed removal carried no explanation"
    );
}

/// Removing one credential must not disturb the others.
#[tokio::test]
async fn removal_is_confined_to_the_named_credential() {
    let (service, db) = make_service();
    let keep = create_eab(&service, ZONE).await;
    let drop = create_eab(&service, ZONE).await;

    assert!(remove_eab(&service, &drop.kid).await.success);

    assert!(
        db.get_eab(&keep.kid).expect("read EAB").is_some(),
        "removing one credential removed another"
    );
}

// ============================================================================
// ListAcmeAccounts
// ============================================================================

/// An empty issuer lists nothing rather than erroring — an operator's first
/// `list-acme-accounts` runs against exactly this state.
#[tokio::test]
async fn listing_accounts_on_a_fresh_issuer_is_empty() {
    let (service, _db) = make_service();
    assert!(
        list_accounts(&service).await.is_empty(),
        "a fresh issuer reported registered accounts"
    );
}

/// Registered accounts come back with the fields the CLI prints. The zone and
/// EAB kid are what tie an account to what it may issue for, so an account
/// listed without them is one an operator cannot audit.
#[tokio::test]
async fn registered_accounts_are_listed_with_their_zone_and_eab() {
    let (service, db) = make_service();
    db.create_acme_account(&account("acct-1", Some(ZONE), Some("kid-1"), "valid"))
        .expect("create account");
    db.create_acme_account(&account("acct-2", Some(OTHER_ZONE), Some("kid-2"), "valid"))
        .expect("create account");

    let accounts = list_accounts(&service).await;
    assert_eq!(accounts.len(), 2, "both accounts must be listed");

    let first = accounts
        .iter()
        .find(|a| a.account_id == "acct-1")
        .expect("acct-1 is missing from the listing");
    assert_eq!(first.status, "valid");
    assert_eq!(
        first.zone,
        rolodex_dns::db::normalize_name(ZONE),
        "the account's zone scope was not reported"
    );
    assert_eq!(
        first.eab_kid, "kid-1",
        "the account's EAB kid was not reported"
    );
}

/// An account with no zone and no EAB — which is what registration without EAB
/// produces when `require_eab` is off — must list as empty strings rather than
/// being dropped from the listing. An account that cannot be seen cannot be
/// audited.
#[tokio::test]
async fn an_account_without_a_zone_or_eab_still_lists() {
    let (service, db) = make_service();
    db.create_acme_account(&account("acct-bare", None, None, "valid"))
        .expect("create account");

    let accounts = list_accounts(&service).await;
    assert_eq!(accounts.len(), 1, "the unscoped account was not listed");
    assert_eq!(accounts[0].account_id, "acct-bare");
    assert!(
        accounts[0].zone.is_empty() && accounts[0].eab_kid.is_empty(),
        "an account with no zone or EAB reported {:?}/{:?}",
        accounts[0].zone,
        accounts[0].eab_kid
    );
}

// ============================================================================
// ListAcmeCertificates
// ============================================================================

/// With no zone filter, every issued certificate is listed.
#[tokio::test]
async fn certificates_are_listed_unfiltered_when_no_zone_is_given() {
    let (service, db) = make_service();
    db.store_acme_certificate("www.example.com.", "cert-a", "key-a", "chain-a", 4_000_000)
        .expect("store certificate");
    db.store_acme_certificate("api.other.test.", "cert-b", "key-b", "chain-b", 5_000_000)
        .expect("store certificate");

    let certificates = list_certificates(&service, "").await;
    assert_eq!(
        certificates.len(),
        2,
        "an unfiltered listing must return every certificate"
    );
    assert!(
        certificates.iter().all(|c| c.id != 0),
        "certificates were listed without their database ids"
    );
    assert!(
        certificates.iter().all(|c| c.issued_at > 0),
        "certificates were listed without an issuance time"
    );
}

/// The zone filter is a **suffix** match, so a name under the zone is included
/// and a name merely ending in similar text is not.
///
/// `notexample.com.` is the case that matters: a naive `ends_with` on the
/// undotted zone would match it, and an operator auditing `example.com` would be
/// shown a certificate belonging to somebody else's name.
#[tokio::test]
async fn the_zone_filter_matches_on_suffix() {
    let (service, db) = make_service();
    for domain in [
        "www.example.com.",
        "deep.sub.example.com.",
        "example.com.",
        "api.other.test.",
        "notexample.com.",
    ] {
        db.store_acme_certificate(domain, "cert", "key", "chain", 4_000_000)
            .expect("store certificate");
    }

    let listed: Vec<String> = list_certificates(&service, ZONE)
        .await
        .into_iter()
        .map(|c| c.domain)
        .collect();

    for expected in ["www.example.com.", "deep.sub.example.com.", "example.com."] {
        assert!(
            listed.iter().any(|d| d == expected),
            "{expected} is under {ZONE} but was filtered out: {listed:?}"
        );
    }
    assert!(
        !listed.iter().any(|d| d == "api.other.test."),
        "a certificate from another zone was listed: {listed:?}"
    );
    assert!(
        !listed.iter().any(|d| d == "notexample.com."),
        "notexample.com. was matched as part of {ZONE}; the zone filter is not \
         matching on a label boundary: {listed:?}"
    );
}

/// A zone with no certificates lists nothing rather than falling back to
/// everything — an empty filter and a filter that matches nothing are different
/// questions with different answers.
#[tokio::test]
async fn a_zone_with_no_certificates_lists_nothing() {
    let (service, db) = make_service();
    db.store_acme_certificate("www.example.com.", "cert", "key", "chain", 4_000_000)
        .expect("store certificate");

    assert!(
        list_certificates(&service, "unrelated.test.")
            .await
            .is_empty(),
        "a zone with no certificates returned some"
    );
}
