//! Security regression tests for gRPC shared-secret authentication.
//!
//! These assert behaviour `check_auth` *should* have and are expected to FAIL
//! against the current implementation. Do not weaken an assertion to make one
//! pass.
//!
//! `check_auth` (`src/grpc_service.rs:124`) compares the presented token with
//! `token == self.shared_secret`. Rust's `String: PartialEq` compares lengths and
//! then defers to `memcmp`, which short-circuits at the first differing byte, so
//! the comparison is not constant-time. There is also no throttling: a client may
//! present wrong tokens as fast as the transport allows.
//!
//! ## Why there is no timing test here
//!
//! The obvious test — measure the wrong-at-byte-0 case against the
//! wrong-at-last-byte case and assert they take the same time — would be
//! worthless, and writing it would be worse than writing nothing.
//!
//! The signal is a `memcmp` over a few dozen bytes: single-digit nanoseconds.
//! Through tonic it sits underneath HTTP/2 framing, a tokio task wake, and an
//! allocator, each of which contributes microseconds of variance — three orders
//! of magnitude more noise than signal. Such a test passes on a quiet laptop and
//! fails on a loaded CI runner for reasons having nothing to do with the code,
//! and a green result would be evidence of nothing. Statistical approaches
//! (many samples, robust estimators) can recover the signal in a tuned
//! microbenchmark, but not through a network service, and not reliably enough to
//! gate a build.
//!
//! So the timing property is pinned as a **fitness test** over the source
//! instead: assert that the secret comparison uses a constant-time primitive and
//! not `==`. That is deterministic, fast, and it fails for exactly the right
//! reason. It is a weaker guarantee than a measurement — it checks the shape of
//! the code rather than its behaviour — and is labelled as such.
//!
//! The genuinely behavioural half of the finding, and the one that carries the
//! real risk, is the missing brute-force throttle. That is tested for real,
//! over a socket.

use rolodex_dns::db::Database;
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::dnsbl::DnsblChecker;
use rolodex_dns::grpc_service::RolodexDnsGrpcService;
use rolodex_dns::grpc_service::proto::rolodex_dns_service_client::RolodexDnsServiceClient;
use rolodex_dns::grpc_service::proto::rolodex_dns_service_server::RolodexDnsServiceServer;
use rolodex_dns::grpc_service::proto::{ListRecordsRequest, ListRecordsResponse};
use std::sync::Arc;
use tokio::net::TcpListener;
use tonic::transport::Server;
use tonic::{Code, Request, Response, Status};

const SECRET: &str = "correct-horse-battery-staple";

/// Starts a gRPC TCP server requiring `SECRET` and returns its `host:port`.
async fn start_server() -> String {
    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(DnsblChecker::new());
    let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
    let service = RolodexDnsGrpcService::new(
        db,
        dns_server,
        rbl,
        SECRET.to_string(),
        false, // TCP: authentication applies
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    tokio::spawn(async move {
        let _unused = Server::builder()
            .add_service(RolodexDnsServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await;
    });

    // Let the listener come up before the first connect.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    addr
}

/// Issues one `ListRecords` with `token`, returning the resulting status.
async fn attempt(addr: &str, token: &str) -> Result<Response<ListRecordsResponse>, Status> {
    let mut client = RolodexDnsServiceClient::connect(format!("http://{}", addr))
        .await
        .expect("connect");
    client
        .list_records(Request::new(ListRecordsRequest {
            name_filter: String::new(),
            record_type_filter: 0,
            filter_by_type: false,
            auth_token: token.to_string(),
        }))
        .await
}

// ============================================================================
// Brute-force throttling
// ============================================================================

/// There is no limit on failed authentication attempts, so a client that can
/// reach the gRPC port may guess tokens as fast as it can open connections. A
/// shared secret is a password; an online guessing oracle with no backoff is the
/// thing that makes a weak one fatal.
///
/// After a run of failures the server must stop treating the source as a fresh
/// caller — by rejecting it outright, by backing off, or by dropping it. The
/// assertion is deliberately loose about *how*: anything other than an
/// indefinite stream of instant `Unauthenticated` replies satisfies it.
#[tokio::test]
async fn repeated_auth_failures_are_throttled() {
    let addr = start_server().await;

    const ATTEMPTS: usize = 40;
    let mut unauthenticated = 0usize;
    let mut throttled = 0usize;

    for i in 0..ATTEMPTS {
        match attempt(&addr, &format!("wrong-guess-{}", i)).await {
            Ok(_) => panic!("a wrong token was accepted"),
            Err(status) => match status.code() {
                Code::Unauthenticated => unauthenticated += 1,
                // Any of these mean the server pushed back rather than serving
                // another free guess.
                Code::ResourceExhausted | Code::Unavailable | Code::PermissionDenied => {
                    throttled += 1
                }
                other => panic!("unexpected status {:?}: {}", other, status.message()),
            },
        }
    }

    assert!(
        throttled > 0,
        "all {} wrong-token attempts were answered with an immediate \
         Unauthenticated ({} of them): the management plane is an unthrottled \
         online password-guessing oracle",
        ATTEMPTS,
        unauthenticated
    );
}

/// The counterpart: throttling must not lock out a caller presenting the correct
/// secret. A fix that trips on total request volume rather than on *failed*
/// attempts would break every legitimate automation on the box.
#[tokio::test]
async fn correct_token_is_not_throttled() {
    let addr = start_server().await;

    for i in 0..40 {
        let result = attempt(&addr, SECRET).await;
        assert!(
            result.is_ok(),
            "a correct token was rejected on attempt {}: {:?}",
            i,
            result.err().map(|s| s.code())
        );
    }
}

/// A wrong token must still be rejected, whatever else changes. This is the
/// invariant the throttling work must not regress.
#[tokio::test]
async fn wrong_token_is_still_rejected() {
    let addr = start_server().await;
    let err = attempt(&addr, "definitely-not-the-secret")
        .await
        .expect_err("a wrong token must be rejected");
    assert_ne!(err.code(), Code::Ok);
}

// ============================================================================
// Constant-time comparison (fitness test)
// ============================================================================

/// A **fitness test**, not a measurement: it inspects the shape of the source
/// rather than the behaviour of the binary. See the module docs for why a real
/// timing test is not written here.
///
/// The token comparison must use a constant-time primitive —
/// `ring::constant_time::verify_slices_are_equal` is already available, since
/// `ring` is a direct dependency — rather than `==`, whose `memcmp` returns as
/// soon as two bytes differ.
///
/// This test reads `src/grpc_service.rs` from `CARGO_MANIFEST_DIR`, isolates the
/// body of `check_auth`, and checks it. It is intentionally scoped to that one
/// function so unrelated `==` elsewhere in the file cannot trip it.
#[test]
fn secret_comparison_is_constant_time() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/grpc_service.rs");
    let source = std::fs::read_to_string(&path).expect("read grpc_service.rs");

    let start = source
        .find("fn check_auth")
        .expect("check_auth should exist in src/grpc_service.rs");
    // The function body runs to the first line that closes it at method indent.
    let rest = &source[start..];
    let end = rest
        .find("\n    }")
        .map(|i| i + start)
        .unwrap_or(source.len());
    let body = &source[start..end];

    assert!(
        !body.contains("token == self.shared_secret")
            && !body.contains("self.shared_secret == token"),
        "check_auth compares the shared secret with `==`, which short-circuits at \
         the first differing byte. Use a constant-time comparison, e.g.\n\
         \x20   ring::constant_time::verify_slices_are_equal(\n\
         \x20       token.as_bytes(), self.shared_secret.as_bytes()\n\
         \x20   ).is_ok()\n\
         Body inspected:\n{}",
        body
    );

    assert!(
        body.contains("constant_time") || body.contains("ct_eq") || body.contains("subtle::"),
        "check_auth does not appear to use a constant-time comparison primitive. \
         Body inspected:\n{}",
        body
    );
}

/// The empty-secret early return is a separate fail-open path and must survive
/// the constant-time rewrite: an empty secret means "authentication disabled",
/// which is checked in `tests/security_local_access_test.rs`. This pins that the
/// rewrite does not accidentally make an empty configured secret match every
/// presented token via a zero-length constant-time comparison.
#[tokio::test]
async fn empty_presented_token_does_not_match_a_configured_secret() {
    let addr = start_server().await;
    let err = attempt(&addr, "")
        .await
        .expect_err("an empty token must not satisfy a configured secret");
    assert_ne!(err.code(), Code::Ok);
}
