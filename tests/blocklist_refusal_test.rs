//! Integration tests for blocklist **refusal codes** and provider rotation.
//!
//! A DNSxL answers a listing and a complaint about the querier with the same
//! record type in the same address block. `zen.spamhaus.org` says "listed" with
//! `127.0.0.2` and "you are querying via a public resolver" with
//! `127.255.255.254`; only the address distinguishes them. A resolver that
//! reads any `A` record as a listing therefore returns NXDOMAIN for **every**
//! name it checks the moment a blocklist decides to stop answering us — and it
//! starts doing that hours or weeks after deployment, when query volume crosses
//! the provider's threshold, so nothing about the configuration looks wrong.
//! Spamhaus documents this failure explicitly: the error codes "should NOT be
//! interpreted as any sort of reputation".
//!
//! These tests drive the whole path over real UDP DNS — a mock blocklist zone
//! answering with real `A` records, through `RecursiveDnsblResolver`'s forwarder
//! fallback, through classification, into `DnsServer`'s query handler — because
//! every layer in between is somewhere the distinction could be lost. Asserting
//! on `classify` alone would pass just as happily with a query path that never
//! calls it.
//!
//! Each test pairs the refusal with a **control** returning a genuine listing
//! down the identical path. Without the control, a checker that had simply
//! stopped blocking anything would pass every test here.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rolodex_dns::db::Database;
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::dnsbl::{DnsblChecker, DnsblProvider, RecursiveDnsblResolver};
use rolodex_dns::grpc_service::proto::rolodex_dns_service_server::RolodexDnsService;
use rolodex_dns::grpc_service::{RolodexDnsGrpcService, proto};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tonic::Request;

/// A mock blocklist zone on loopback UDP, answering every `A` query with a
/// fixed code and counting the queries it received.
///
/// The count is the load-bearing assertion for rotation: "the provider was
/// taken out of rotation" is only observable as "we stopped asking it".
struct MockBlocklist {
    addr: SocketAddr,
    queries: Arc<AtomicU32>,
}

impl MockBlocklist {
    /// Starts a zone answering with `code`, or NXDOMAIN when `code` is `None`.
    async fn start(code: Option<Ipv4Addr>) -> Self {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let queries = Arc::new(AtomicU32::new(0));
        let counter = queries.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let Ok(req) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let mut resp = Message::new();
                resp.set_id(req.id());
                resp.set_message_type(MessageType::Response);
                resp.set_op_code(OpCode::Query);
                resp.set_recursion_available(true);
                let question = req.queries().first().cloned();
                for q in req.queries() {
                    resp.add_query(q.clone());
                }
                match (code, question) {
                    (Some(code), Some(q)) => {
                        resp.set_response_code(ResponseCode::NoError);
                        resp.add_answer(Record::from_rdata(
                            q.name().clone(),
                            300,
                            RData::A(rdata::A(code)),
                        ));
                    }
                    _ => {
                        resp.set_response_code(ResponseCode::NXDomain);
                    }
                }
                let Ok(bytes) = resp.to_bytes() else { continue };
                let _ = sock.send_to(&bytes, src).await;
            }
        });
        Self { addr, queries }
    }

    fn queries(&self) -> u32 {
        self.queries.load(Ordering::SeqCst)
    }
}

/// A resolver that reaches the mock zone over real UDP.
///
/// Root recursion is pointed at a loopback address with nothing listening, so
/// the roots tier fails immediately (ICMP port unreachable) and the forwarder
/// fallback — the mock — answers. This is the same shape `auto_resolution_test`
/// uses to keep the real internet out of the test.
fn mock_resolver(mock: &MockBlocklist) -> Arc<RecursiveDnsblResolver> {
    Arc::new(RecursiveDnsblResolver::new(
        vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
        vec![mock.addr],
    ))
}

/// A DNSBL-enabled server whose single provider queries `mock`.
async fn dnsbl_server(
    mock: &MockBlocklist,
    refusal_codes: Vec<String>,
    cooldown: Option<Duration>,
) -> (Arc<DnsServer>, Arc<DnsblChecker>) {
    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(DnsblChecker::with_resolver(mock_resolver(mock)));
    rbl.set_config(
        true,
        vec![DnsblProvider {
            zone: "dbl.test".to_string(),
            enabled: true,
            refusal_codes: rolodex_dns::dnsbl::resolve_refusal_codes(&refusal_codes)
                .unwrap()
                .into(),
            cooldown,
        }],
    )
    .await;
    let server = Arc::new(DnsServer::new(db, rbl.clone(), vec![]));
    (server, rbl)
}

fn build_query(name: &str) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(rand::random::<u16>());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(Name::from_ascii(name).unwrap());
    q.set_query_type(RecordType::A);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    msg.to_bytes().unwrap()
}

async fn rcode(server: &Arc<DnsServer>, name: &str) -> ResponseCode {
    let bytes = server.handle_query(&build_query(name)).await.unwrap();
    Message::from_bytes(&bytes).unwrap().response_code()
}

/// Blocklist fills are fire-and-forget, so the first query for a name primes
/// the cache and is answered before the verdict lands. Polls until the block
/// takes effect, returning the final rcode.
async fn poll_for_nxdomain(server: &Arc<DnsServer>, name: &str) -> ResponseCode {
    for _ in 0..250 {
        let rc = rcode(server, name).await;
        if rc == ResponseCode::NXDomain {
            return rc;
        }
        tokio::time::sleep(Duration::from_millis(4)).await;
    }
    rcode(server, name).await
}

/// Waits until the mock has been asked at least `n` times.
async fn wait_for_queries(mock: &MockBlocklist, n: u32) {
    for _ in 0..250 {
        if mock.queries() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(4)).await;
    }
    panic!("expected >= {n} blocklist queries, saw {}", mock.queries());
}

/// The control. A genuine listing (`127.0.0.2`, RFC 5782 §2.1) travelling the
/// identical path must still produce NXDOMAIN — otherwise every assertion below
/// would be satisfied by a blocklist that had simply stopped working.
#[tokio::test]
async fn genuine_listing_over_the_wire_still_blocks() {
    let mock = MockBlocklist::start(Some(Ipv4Addr::new(127, 0, 0, 2))).await;
    let (server, _) = dnsbl_server(&mock, vec![], None).await;

    assert_eq!(
        poll_for_nxdomain(&server, "ads.example.com.").await,
        ResponseCode::NXDomain,
        "127.0.0.2 is a listing and must block"
    );
}

/// Each documented refusal code, over the wire, must not block. These are the
/// exact codes the providers publish, and each one of them read as a listing is
/// a total outage for every name checked against that provider.
#[tokio::test]
async fn documented_refusal_codes_do_not_block() {
    for (code, meaning) in [
        ([127, 255, 255, 252], "Spamhaus: typo in the DNSBL name"),
        (
            [127, 255, 255, 254],
            "Spamhaus: query via a public resolver",
        ),
        ([127, 255, 255, 255], "Spamhaus: excessive queries"),
        ([127, 0, 1, 255], "Spamhaus DBL: IP queries not supported"),
        ([127, 0, 2, 255], "Spamhaus ZRD: IP queries not supported"),
        ([127, 0, 0, 1], "URIBL/SURBL: query blocked"),
        ([127, 0, 0, 255], "URIBL: query blocked"),
    ] {
        let ip = Ipv4Addr::from(code);
        let mock = MockBlocklist::start(Some(ip)).await;
        let (server, checker) = dnsbl_server(&mock, vec![], None).await;

        // Prime, let the fill land, then ask again — the verdict is served from
        // cache on the second query, which is where a wrong reading shows up.
        assert_eq!(
            rcode(&server, "ads.example.com.").await,
            ResponseCode::ServFail
        );
        wait_for_queries(&mock, 1).await;
        assert_eq!(
            rcode(&server, "ads.example.com.").await,
            ResponseCode::ServFail,
            "{ip} means '{meaning}' — it must not be read as a listing"
        );
        assert_eq!(
            checker.rotated_out().len(),
            1,
            "{ip} must also take the provider out of rotation"
        );
    }
}

/// Refusal rotates the provider out: we stop asking a blocklist that has just
/// told us to stop. Every subsequent name is a distinct cache key, so a
/// suppressed lookup can only be the rotation.
#[tokio::test]
async fn refusal_stops_further_queries_to_the_provider() {
    let mock = MockBlocklist::start(Some(Ipv4Addr::new(127, 255, 255, 255))).await;
    let (server, checker) = dnsbl_server(&mock, vec![], Some(Duration::from_secs(3600))).await;

    assert_eq!(
        rcode(&server, "first.example.com.").await,
        ResponseCode::ServFail
    );
    wait_for_queries(&mock, 1).await;

    let rotated = checker.rotated_out();
    assert_eq!(rotated.len(), 1);
    assert_eq!(rotated[0].zone, "dbl.test");
    assert_eq!(rotated[0].code, "127.255.255.255");
    assert!(rotated[0].seconds_remaining > 3500);

    for i in 0..10 {
        assert_eq!(
            rcode(&server, &format!("n{i}.example.com.")).await,
            ResponseCode::ServFail
        );
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        mock.queries(),
        1,
        "a rotated-out provider must not be queried again"
    );
}

/// The rotation is for a configurable duration, not permanent: a provider that
/// refused because we were briefly over quota comes back on its own.
#[tokio::test]
async fn rotation_lapses_and_the_provider_is_queried_again() {
    let mock = MockBlocklist::start(Some(Ipv4Addr::new(127, 255, 255, 254))).await;
    let (server, checker) = dnsbl_server(&mock, vec![], Some(Duration::from_millis(60))).await;

    assert_eq!(
        rcode(&server, "a.example.com.").await,
        ResponseCode::ServFail
    );
    wait_for_queries(&mock, 1).await;
    assert_eq!(checker.rotated_out().len(), 1);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        checker.rotated_out().is_empty(),
        "the cooldown must lapse without an operator doing anything"
    );

    assert_eq!(
        rcode(&server, "b.example.com.").await,
        ResponseCode::ServFail
    );
    wait_for_queries(&mock, 2).await;
}

/// `none` restores the pre-refusal-codes reading, for a private blocklist whose
/// real listings collide with a default code. Pinned because it is the escape
/// hatch an operator reaches for, and because it demonstrates precisely what
/// the defaults prevent: the same `127.0.0.1` now NXDOMAINs the name.
#[tokio::test]
async fn refusal_detection_disabled_reads_the_code_as_a_listing() {
    let mock = MockBlocklist::start(Some(Ipv4Addr::new(127, 0, 0, 1))).await;
    let (server, checker) = dnsbl_server(&mock, vec!["none".to_string()], None).await;

    assert_eq!(
        poll_for_nxdomain(&server, "internal.example.com.").await,
        ResponseCode::NXDomain
    );
    assert!(checker.rotated_out().is_empty());
}

/// A narrowed list is the list: a code outside it is a listing again. This is
/// what lets an operator take responsibility for a provider whose codes differ
/// from the built-in set.
#[tokio::test]
async fn explicit_refusal_codes_replace_the_defaults() {
    // Only 127.9.9.9 is a refusal here, so 127.255.255.254 — a default — is a
    // listing.
    let mock = MockBlocklist::start(Some(Ipv4Addr::new(127, 255, 255, 254))).await;
    let (server, _) = dnsbl_server(&mock, vec!["127.9.9.9".to_string()], None).await;

    assert_eq!(
        poll_for_nxdomain(&server, "ads.example.com.").await,
        ResponseCode::NXDomain
    );
}

/// Builds a service and server sharing one checker, as the daemon does.
fn grpc_service(
    mock: &MockBlocklist,
) -> (RolodexDnsGrpcService, Arc<DnsServer>, Arc<DnsblChecker>) {
    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(DnsblChecker::with_resolver(mock_resolver(mock)));
    let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
    let service =
        RolodexDnsGrpcService::new(db, dns_server.clone(), rbl.clone(), String::new(), true);
    (service, dns_server, rbl)
}

/// Refusal codes and cooldowns are programmable over gRPC, per provider and
/// list-wide.
#[tokio::test]
async fn refusal_codes_are_programmable_over_grpc() {
    let mock = MockBlocklist::start(None).await;
    let (service, _, _) = grpc_service(&mock);

    service
        .set_dnsbl_config(Request::new(proto::SetDnsblConfigRequest {
            enabled: true,
            providers: vec![proto::DnsblConfig {
                zone: "dbl.spamhaus.org".to_string(),
                enabled: true,
                refusal_codes: vec!["127.0.1.255".to_string(), "127.255.255.0/24".to_string()],
                refusal_cooldown_secs: 120,
            }],
            auth_token: String::new(),
            refusal_cooldown_secs: 600,
        }))
        .await
        .unwrap();

    let cfg = service
        .get_dnsbl_config(Request::new(proto::GetDnsblConfigRequest {
            auth_token: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(cfg.refusal_cooldown_secs, 600);
    assert_eq!(cfg.providers[0].refusal_codes.len(), 2);
    assert_eq!(cfg.providers[0].refusal_cooldown_secs, 120);
}

/// A code that does not parse is rejected, not dropped. A silently-ignored code
/// is a refusal that reads as a listing, with the RPC having reported success —
/// the operator would have no way to tell.
#[tokio::test]
async fn malformed_refusal_code_is_rejected() {
    let mock = MockBlocklist::start(None).await;
    let (service, _, _) = grpc_service(&mock);

    let status = service
        .set_dnsbl_config(Request::new(proto::SetDnsblConfigRequest {
            enabled: true,
            providers: vec![proto::DnsblConfig {
                zone: "bad.example".to_string(),
                enabled: true,
                refusal_codes: vec!["not-an-ip".to_string()],
                refusal_cooldown_secs: 0,
            }],
            auth_token: String::new(),
            refusal_cooldown_secs: 0,
        }))
        .await
        .expect_err("a malformed refusal code must not be accepted");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(
        status.message().contains("bad.example"),
        "unhelpful: {status:?}"
    );

    // 'none' mixed with real codes is contradictory and likewise refused.
    let status = service
        .set_dnsbl_config(Request::new(proto::SetDnsblConfigRequest {
            enabled: true,
            providers: vec![proto::DnsblConfig {
                zone: "mixed.rbl".to_string(),
                enabled: true,
                refusal_codes: vec!["none".to_string(), "127.0.0.1".to_string()],
                refusal_cooldown_secs: 0,
            }],
            auth_token: String::new(),
            refusal_cooldown_secs: 0,
        }))
        .await
        .expect_err("'none' plus a code must not be guessed at");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

/// The rotated-out set is visible over the management API, so an operator can
/// see *which* provider went quiet and *why* without reading logs. A blocklist
/// that stops answering is otherwise indistinguishable from one that finds
/// nothing.
#[tokio::test]
async fn rotated_out_providers_are_reported_over_grpc() {
    let mock = MockBlocklist::start(Some(Ipv4Addr::new(127, 255, 255, 254))).await;
    let (service, dns_server, _) = grpc_service(&mock);

    service
        .set_dnsbl_config(Request::new(proto::SetDnsblConfigRequest {
            enabled: true,
            providers: vec![proto::DnsblConfig {
                zone: "dbl.test".to_string(),
                enabled: true,
                refusal_codes: vec![],
                refusal_cooldown_secs: 3600,
            }],
            auth_token: String::new(),
            refusal_cooldown_secs: 0,
        }))
        .await
        .unwrap();

    assert_eq!(
        rcode(&dns_server, "ads.example.com.").await,
        ResponseCode::ServFail
    );
    wait_for_queries(&mock, 1).await;

    let mut rotated = Vec::new();
    for _ in 0..250 {
        rotated = service
            .get_dnsbl_config(Request::new(proto::GetDnsblConfigRequest {
                auth_token: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .rotated_out;
        if !rotated.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(4)).await;
    }
    assert_eq!(rotated.len(), 1);
    assert_eq!(rotated[0].zone, "dbl.test");
    assert_eq!(rotated[0].code, "127.255.255.254");
    assert!(rotated[0].seconds_remaining > 3500);

    // Flushing the result cache is the operator's "re-check everything", so it
    // must also return the provider to rotation.
    service
        .flush_cache(Request::new(proto::FlushCacheRequest {
            auth_token: String::new(),
        }))
        .await
        .unwrap();
    let after = service
        .get_dnsbl_config(Request::new(proto::GetDnsblConfigRequest {
            auth_token: String::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(after.rotated_out.is_empty());
}
