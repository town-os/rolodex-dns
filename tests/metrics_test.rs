//! Prometheus metrics: end-to-end scrape and query-path instrumentation.
//!
//! These exercise the real listener over a real TCP socket rather than calling
//! `render()` directly, because the things most likely to break in production —
//! the route, the content type, and whether the scrape-time collector can read
//! the database without deadlocking against the query path — only exist above
//! the registry.
//!
//! The registry is a process-global (see `rolodex_dns::metrics`), so every
//! assertion about a counter here is a **delta** taken around the code under
//! test. Absolute values would depend on which other tests in this binary had
//! already run, and on the order the harness happened to run them in.
//!
//! Deltas alone are not enough, because the test harness runs these
//! concurrently: one test's query lands between another's before/after
//! readings and the arithmetic breaks. Each test therefore holds [`SERIAL`] for
//! its duration. Serializing rather than loosening the assertions to `>=` is
//! deliberate — exact equality is what catches an observation being recorded
//! *twice*, which is the likelier bug when instrumentation is threaded through
//! several transports onto one shared exit.

use std::net::SocketAddr;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use rolodex_dns::db::{Database, DnsRecord, RecordKind};
use rolodex_dns::dns_cache::DnsCache;
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::metrics::{MetricsState, Proto, build_router, metrics};
use rolodex_dns::rbl::{RblChecker, RblResolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Serializes access to the process-global registry; see the module docs.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// An RBL resolver that never lists anything, so the blocklist paths stay out of
/// the way of these tests.
struct NeverListedResolver;

#[async_trait::async_trait]
impl RblResolver for NeverListedResolver {
    async fn lookup_rbl(
        &self,
        _query: &str,
    ) -> Result<Option<rolodex_dns::rbl::RblAnswer>, anyhow::Error> {
        Ok(None)
    }
}

fn test_server() -> (Database, Arc<DnsServer>, Arc<RblChecker>, Arc<DnsCache>) {
    let db = Database::open_memory().expect("in-memory database");
    let rbl = Arc::new(RblChecker::with_resolver(
        false,
        vec![],
        Arc::new(NeverListedResolver),
    ));
    let cache = Arc::new(DnsCache::new(db.clone()));
    let dns_server = Arc::new(DnsServer::new_with_options(
        db.clone(),
        rbl.clone(),
        // No forwarders: nothing here should ever reach the network.
        vec![],
        Some(Arc::clone(&cache)),
        None,
        false,
    ));
    (db, dns_server, rbl, cache)
}

fn build_query(name: &str, rtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(0x4242);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(Name::from_ascii(name).expect("valid name"));
    q.set_query_type(rtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    msg.to_vec().expect("serialize query")
}

/// Serves the metrics router on an ephemeral port and returns its address.
async fn spawn_metrics(state: MetricsState) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, build_router(state)).await;
    });
    addr
}

/// Issues a bare HTTP/1.1 GET and returns `(status_line, headers, body)`.
///
/// Hand-rolled rather than pulling in an HTTP client: the point is to prove a
/// stock scraper speaking plain HTTP gets a well-formed response, and `reqwest`
/// would be a dependency added for one request.
async fn http_get(addr: SocketAddr, path: &str) -> (String, String, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .map(|(h, b)| (h.to_string(), b.to_string()))
        .unwrap_or((text.clone(), String::new()));
    let (status, headers) = head
        .split_once("\r\n")
        .map(|(s, h)| (s.to_string(), h.to_string()))
        .unwrap_or((head.clone(), String::new()));
    (status, headers, body)
}

/// Reads one unlabelled sample's value out of an exposition body.
fn sample(body: &str, name: &str) -> u64 {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix(name)
            && let Some(v) = rest.strip_prefix(' ')
        {
            return v.trim().parse().unwrap_or(0);
        }
    }
    panic!("no sample named {name} in:\n{body}");
}

#[tokio::test]
async fn scrape_serves_a_well_formed_exposition_body() {
    let _serial = SERIAL.lock().await;
    let (db, dns_server, rbl, cache) = test_server();
    let addr = spawn_metrics(MetricsState {
        db,
        dns_server,
        dns_cache: Some(cache),
        rbl,
    })
    .await;

    let (status, headers, body) = http_get(addr, "/metrics").await;
    assert!(status.contains("200"), "unexpected status: {status}");
    assert!(
        headers.to_lowercase().contains("text/plain"),
        "unexpected headers: {headers}"
    );

    // Metadata is what makes the output a valid scrape rather than a text dump.
    assert!(body.contains("# HELP rolodex_dns_queries_total"));
    assert!(body.contains("# TYPE rolodex_dns_queries_total counter"));
    assert!(body.contains("# TYPE rolodex_dns_query_duration_seconds histogram"));
    assert!(body.contains("# TYPE rolodex_dns_cache_entries gauge"));
    assert!(body.contains("rolodex_dns_build_info{version="));

    // Every non-comment line must be `name[{labels}] value`, with a numeric
    // value — a malformed line makes Prometheus reject the whole scrape.
    for line in body
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (_, value) = line
            .rsplit_once(' ')
            .unwrap_or_else(|| panic!("sample line has no value: {line}"));
        assert!(
            value.parse::<f64>().is_ok(),
            "non-numeric sample value in line: {line}"
        );
    }
}

#[tokio::test]
async fn index_points_at_the_metrics_path() {
    let _serial = SERIAL.lock().await;
    let (db, dns_server, rbl, cache) = test_server();
    let addr = spawn_metrics(MetricsState {
        db,
        dns_server,
        dns_cache: Some(cache),
        rbl,
    })
    .await;

    let (status, _, body) = http_get(addr, "/").await;
    assert!(status.contains("200"), "unexpected status: {status}");
    assert!(body.contains("/metrics"), "unexpected body: {body}");
}

#[tokio::test]
async fn scrape_counter_advances_per_scrape() {
    let _serial = SERIAL.lock().await;
    let (db, dns_server, rbl, cache) = test_server();
    let addr = spawn_metrics(MetricsState {
        db,
        dns_server,
        dns_cache: Some(cache),
        rbl,
    })
    .await;

    let (_, _, first) = http_get(addr, "/metrics").await;
    let before = sample(&first, "rolodex_dns_metrics_scrapes_total");
    let (_, _, second) = http_get(addr, "/metrics").await;
    let after = sample(&second, "rolodex_dns_metrics_scrapes_total");
    assert!(
        after > before,
        "scrape counter did not advance: {before} -> {after}"
    );
}

#[tokio::test]
async fn database_counts_are_sampled_at_scrape_time() {
    let _serial = SERIAL.lock().await;
    let (db, dns_server, rbl, cache) = test_server();
    let addr = spawn_metrics(MetricsState {
        db: db.clone(),
        dns_server,
        dns_cache: Some(cache),
        rbl,
    })
    .await;

    let (_, _, before) = http_get(addr, "/metrics").await;
    let records_before = sample(&before, "rolodex_dns_records");

    db.add_record(&DnsRecord {
        id: None,
        name: "metrics-gauge.example.com.".to_string(),
        record_type: RecordKind::A,
        value: "10.9.8.7".to_string(),
        ttl: 300,
        priority: 0,
    })
    .expect("add record");

    let (_, _, after) = http_get(addr, "/metrics").await;
    assert_eq!(
        sample(&after, "rolodex_dns_records"),
        records_before + 1,
        "the records gauge did not pick up the new row"
    );
    // The gauge is pulled at scrape time, so it must reflect a row added after
    // the listener started with no explicit notification.
    assert!(after.contains("rolodex_dns_managed_zones "));
}

#[tokio::test]
async fn a_local_hit_is_counted_against_its_transport_and_source() {
    let _serial = SERIAL.lock().await;
    let (db, dns_server, _rbl, _cache) = test_server();
    db.add_record(&DnsRecord {
        id: None,
        name: "counted.example.com.".to_string(),
        record_type: RecordKind::A,
        value: "192.0.2.10".to_string(),
        ttl: 300,
        priority: 0,
    })
    .expect("add record");

    let m = metrics();
    let queries_before = m.queries.get(
        Proto::Tcp.index(),
        rolodex_dns::metrics::rcode_index(ResponseCode::NoError),
    );
    let local_before = m
        .answer_source
        .get(rolodex_dns::metrics::AnswerSource::Local.index());
    let a_before = m
        .queries_by_type
        .get(rolodex_dns::metrics::qtype_index(RecordType::A));

    let query = build_query("counted.example.com.", RecordType::A);
    let response = dns_server
        .handle_query_proto(&query, None, None, Proto::Tcp)
        .await
        .expect("query");
    let msg = Message::from_bytes(&response).expect("parse response");
    assert_eq!(msg.response_code(), ResponseCode::NoError);
    assert_eq!(msg.answers().len(), 1);

    assert_eq!(
        m.queries.get(
            Proto::Tcp.index(),
            rolodex_dns::metrics::rcode_index(ResponseCode::NoError)
        ),
        queries_before + 1,
        "the tcp/NOERROR series did not advance"
    );
    assert_eq!(
        m.answer_source
            .get(rolodex_dns::metrics::AnswerSource::Local.index()),
        local_before + 1,
        "the answer was not attributed to the local database"
    );
    assert_eq!(
        m.queries_by_type
            .get(rolodex_dns::metrics::qtype_index(RecordType::A)),
        a_before + 1,
        "the A query-type series did not advance"
    );
}

#[tokio::test]
async fn a_malformed_query_is_counted_as_an_error() {
    let _serial = SERIAL.lock().await;
    let (_db, dns_server, _rbl, _cache) = test_server();
    let m = metrics();
    let before = m.malformed_queries.get();

    // Two bytes is a truncated header — unparseable.
    let response = dns_server
        .handle_query_proto(&[0x00, 0x01], None, None, Proto::Udp)
        .await
        .expect("handled");
    assert!(!response.is_empty());

    assert_eq!(
        m.malformed_queries.get(),
        before + 1,
        "a malformed query was not counted"
    );
}

#[tokio::test]
async fn an_unknown_query_type_folds_into_other() {
    let _serial = SERIAL.lock().await;
    let (_db, dns_server, _rbl, _cache) = test_server();
    let m = metrics();
    let other = rolodex_dns::metrics::qtype_index(RecordType::Unknown(4242));
    let before = m.queries_by_type.get(other);

    let query = build_query("no-such-type.example.com.", RecordType::Unknown(4242));
    dns_server
        .handle_query_proto(&query, None, None, Proto::Udp)
        .await
        .expect("query");

    assert_eq!(
        m.queries_by_type.get(other),
        before + 1,
        "an unrecognized query type must fold into OTHER, not mint a new series"
    );
    // And it must not have created a series of its own.
    assert!(!m.render().contains("qtype=\"TYPE4242\""));
}

#[tokio::test]
async fn an_authoritative_nxdomain_is_attributed_to_the_zone() {
    let _serial = SERIAL.lock().await;
    let (db, dns_server, _rbl, _cache) = test_server();
    // An explicitly declared authoritative zone, which is the other route to the
    // same attribution. (A zone that merely *has* records reaches it too, via
    // the implicit managed-zone path; declaring one here keeps this test about
    // the metric rather than about which route got there.)
    db.add_authoritative_zone("managed-zone.test.")
        .expect("declare authoritative zone");

    let m = metrics();
    let idx = rolodex_dns::metrics::AnswerSource::AuthoritativeNxdomain.index();
    let before = m.answer_source.get(idx);
    let nx_before = m.queries.get(
        Proto::Udp.index(),
        rolodex_dns::metrics::rcode_index(ResponseCode::NXDomain),
    );

    let query = build_query("absent.managed-zone.test.", RecordType::A);
    let response = dns_server
        .handle_query_proto(&query, None, None, Proto::Udp)
        .await
        .expect("query");
    let msg = Message::from_bytes(&response).expect("parse response");
    assert_eq!(msg.response_code(), ResponseCode::NXDomain);

    assert_eq!(
        m.answer_source.get(idx),
        before + 1,
        "the NXDOMAIN was not attributed to the managed zone"
    );
    assert_eq!(
        m.queries.get(
            Proto::Udp.index(),
            rolodex_dns::metrics::rcode_index(ResponseCode::NXDomain)
        ),
        nx_before + 1,
        "the udp/NXDOMAIN series did not advance"
    );
}

#[tokio::test]
async fn query_duration_and_sizes_are_observed() {
    let _serial = SERIAL.lock().await;
    let (db, dns_server, _rbl, _cache) = test_server();
    db.add_record(&DnsRecord {
        id: None,
        name: "sized.example.com.".to_string(),
        record_type: RecordKind::A,
        value: "192.0.2.12".to_string(),
        ttl: 300,
        priority: 0,
    })
    .expect("add record");

    let m = metrics();
    let sizes_before = m.query_size.count();
    let responses_before = m.response_size.count();

    let query = build_query("sized.example.com.", RecordType::A);
    dns_server
        .handle_query_proto(&query, None, None, Proto::Doh)
        .await
        .expect("query");

    assert_eq!(m.query_size.count(), sizes_before + 1);
    assert_eq!(m.response_size.count(), responses_before + 1);
    // The DoH series specifically must have advanced.
    assert!(
        m.render().lines().any(|l| l
            .starts_with("rolodex_dns_query_duration_seconds_count{proto=\"doh\"}")
            && !l.ends_with(" 0")),
        "no DoH duration observations recorded"
    );
}

#[tokio::test]
async fn cache_flushes_are_attributed_to_their_trigger() {
    let _serial = SERIAL.lock().await;
    let (_db, dns_server, _rbl, _cache) = test_server();
    let m = metrics();
    // Indices match rolodex_dns::metrics::FLUSH_REASONS.
    let mutation_before = m.cache_flushes.get(0);
    let explicit_before = m.cache_flushes.get(1);
    let tier_before = m.cache_flushes.get(2);

    dns_server.flush_cache();
    dns_server.flush_cache_explicit();
    dns_server.flush_upstream_state();

    assert_eq!(m.cache_flushes.get(0), mutation_before + 1);
    assert_eq!(m.cache_flushes.get(1), explicit_before + 1);
    assert_eq!(
        m.cache_flushes.get(2),
        tier_before + 1,
        "a tier-switch flush must not be counted as a mutation"
    );
}

/// A provider refusing our queries is a distinct signal from a provider finding
/// nothing, and it has to be visible as one: without the counter, "the blocklist
/// went quiet" and "the blocklist is clean" look identical from outside, and the
/// second is what an operator will assume.
#[tokio::test]
async fn a_refusal_is_counted_and_the_provider_shows_as_rotated_out() {
    let _serial = SERIAL.lock().await;

    /// Answers every lookup with Spamhaus's "excessive queries" code.
    struct RefusingResolver;
    #[async_trait::async_trait]
    impl RblResolver for RefusingResolver {
        async fn lookup_rbl(
            &self,
            _query: &str,
        ) -> Result<Option<rolodex_dns::rbl::RblAnswer>, anyhow::Error> {
            Ok(Some(rolodex_dns::rbl::RblAnswer::single(
                std::net::Ipv4Addr::new(127, 255, 255, 255),
                300,
            )))
        }
    }

    let rbl = Arc::new(RblChecker::with_resolver(
        true,
        vec![rolodex_dns::rbl::RblProvider {
            zone: "refusing.test".to_string(),
            enabled: true,
            cooldown: Some(std::time::Duration::from_secs(3600)),
            ..Default::default()
        }],
        Arc::new(RefusingResolver),
    ));

    let m = metrics();
    // Index 0 of BLOCK_KINDS is "rbl_provider"; index 3 of the lookup outcomes
    // is "refused".
    let refusals_before = m.blocklist_refusals.get(0);
    let refused_before = m.blocklist_lookups.get(0, 3);
    let listed_before = m.blocklist_lookups.get(0, 0);

    assert!(
        !rbl.is_listed(&std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)))
            .await,
        "a refusal code must never block"
    );
    for _ in 0..250 {
        if m.blocklist_refusals.get(0) > refusals_before {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    assert_eq!(m.blocklist_refusals.get(0), refusals_before + 1);
    assert_eq!(m.blocklist_lookups.get(0, 3), refused_before + 1);
    assert_eq!(
        m.blocklist_lookups.get(0, 0),
        listed_before,
        "a refusal must not also be counted as a listing"
    );

    // The gauge is pulled at scrape time from the checker.
    m.blocklist_rotated_out.set(rbl.rotated_out_count() as u64);
    assert_eq!(m.blocklist_rotated_out.get(), 1);
}

// ---------------------------------------------------------------------------
// Per-TLD isolation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_tracked_tld_gets_its_own_series_and_everything_else_folds_into_other() {
    let _serial = SERIAL.lock().await;
    let (db, dns_server, _rbl, _cache) = test_server();
    for name in ["box.tracked.test.", "host.untracked.test."] {
        db.add_record(&DnsRecord {
            id: None,
            name: name.to_string(),
            record_type: RecordKind::A,
            value: "192.0.2.20".to_string(),
            ttl: 300,
            priority: 0,
        })
        .expect("add record");
    }

    let m = metrics();
    // Only the first of the two TLDs is opted into.
    m.set_tracked_tlds(["tracked.test"]);
    let tracked_before = m.queries_by_tld.get("tracked.test.");
    let other_before = m.queries_by_tld.get(rolodex_dns::metrics::TLD_OTHER);

    for name in ["box.tracked.test.", "host.untracked.test."] {
        let query = build_query(name, RecordType::A);
        dns_server
            .handle_query_proto(&query, None, None, Proto::Udp)
            .await
            .expect("query");
    }

    assert_eq!(
        m.queries_by_tld.get("tracked.test."),
        tracked_before + 1,
        "the tracked TLD's series did not advance"
    );
    assert_eq!(
        m.queries_by_tld.get(rolodex_dns::metrics::TLD_OTHER),
        other_before + 1,
        "the untracked name was not folded into the catch-all"
    );
    // The control that makes the bound meaningful: the untracked TLD must not
    // have minted a series of its own.
    assert_eq!(
        m.queries_by_tld.get("untracked.test."),
        0,
        "an untracked TLD minted its own series — the cardinality bound is broken"
    );

    m.set_tracked_tlds(Vec::<String>::new());
}

#[tokio::test]
async fn an_owned_tld_is_tracked_without_being_configured() {
    let _serial = SERIAL.lock().await;
    let (db, dns_server, _rbl, _cache) = test_server();
    db.create_network_scope(&rolodex_dns::db::NetworkScope {
        name: "metricsnet".to_string(),
        home_domain: "metricsnet.home.".to_string(),
    })
    .expect("create scope");
    db.add_scope_tld("metricsnet", "ownedtld").expect("add tld");

    let m = metrics();
    // Nothing configured this TLD: ownership alone must be enough, because
    // requiring it to be named twice shows up as a silently missing series.
    m.set_tracked_tlds(Vec::<String>::new());
    rolodex_dns::metrics::refresh_tracked_tlds(&db);
    assert!(
        m.tracked_tlds().contains(&"ownedtld.".to_string()),
        "an owned TLD was not tracked automatically: {:?}",
        m.tracked_tlds()
    );
    assert!(
        m.tracked_tlds().contains(&"metricsnet.home.".to_string()),
        "a scope's implicit .home domain was not tracked automatically"
    );

    db.add_record(&DnsRecord {
        id: None,
        name: "svc.ownedtld.".to_string(),
        record_type: RecordKind::A,
        value: "192.0.2.21".to_string(),
        ttl: 300,
        priority: 0,
    })
    .expect("add record");

    let before = m.queries_by_tld.get("ownedtld.");
    let query = build_query("svc.ownedtld.", RecordType::A);
    dns_server
        .handle_query_proto(&query, None, None, Proto::Udp)
        .await
        .expect("query");
    assert_eq!(m.queries_by_tld.get("ownedtld."), before + 1);

    m.set_tracked_tlds(Vec::<String>::new());
}

// ---------------------------------------------------------------------------
// Traffic volume
// ---------------------------------------------------------------------------

#[tokio::test]
async fn traffic_bytes_and_records_served_track_the_wire() {
    let _serial = SERIAL.lock().await;
    let (db, dns_server, _rbl, _cache) = test_server();
    // Two A records at one name, so the answer count is provably not just "1
    // per query" — which is what a header-field misread would produce.
    for value in ["192.0.2.30", "192.0.2.31"] {
        db.add_record(&DnsRecord {
            id: None,
            name: "volume.example.com.".to_string(),
            record_type: RecordKind::A,
            value: value.to_string(),
            ttl: 300,
            priority: 0,
        })
        .expect("add record");
    }

    let m = metrics();
    let rx_before = m.traffic_bytes.get(rolodex_dns::metrics::TRAFFIC_RX);
    let tx_before = m.traffic_bytes.get(rolodex_dns::metrics::TRAFFIC_TX);
    let records_before = m.records_served.get();

    let query = build_query("volume.example.com.", RecordType::A);
    let response = dns_server
        .handle_query_proto(&query, None, None, Proto::Udp)
        .await
        .expect("query");
    let msg = Message::from_bytes(&response).expect("parse response");
    assert_eq!(msg.answers().len(), 2);

    assert_eq!(
        m.traffic_bytes.get(rolodex_dns::metrics::TRAFFIC_RX) - rx_before,
        query.len() as u64,
        "received bytes must be the query as it arrived"
    );
    assert_eq!(
        m.traffic_bytes.get(rolodex_dns::metrics::TRAFFIC_TX) - tx_before,
        response.len() as u64,
        "sent bytes must be the response as it leaves, after the family filter"
    );
    assert_eq!(
        m.records_served.get() - records_before,
        2,
        "records served must be the answer count, not the query count"
    );
}

#[tokio::test]
async fn an_empty_answer_serves_no_records_but_still_moves_bytes() {
    let _serial = SERIAL.lock().await;
    let (_db, dns_server, _rbl, _cache) = test_server();
    let m = metrics();
    let records_before = m.records_served.get();
    let rx_before = m.traffic_bytes.get(rolodex_dns::metrics::TRAFFIC_RX);

    // Nothing local, no forwarders: an answer with no records.
    let query = build_query("nothing-here.example.org.", RecordType::A);
    dns_server
        .handle_query_proto(&query, None, None, Proto::Udp)
        .await
        .expect("query");

    assert_eq!(
        m.records_served.get(),
        records_before,
        "an answerless response must not count records"
    );
    assert!(
        m.traffic_bytes.get(rolodex_dns::metrics::TRAFFIC_RX) > rx_before,
        "the query's bytes are traffic whether or not it was answered"
    );
}

// ---------------------------------------------------------------------------
// Blocklist attribution
// ---------------------------------------------------------------------------

/// Reads the allowlist counter for one [`rolodex_dns::metrics::ALLOWLIST_KINDS`]
/// index.
fn allowlisted(idx: usize) -> u64 {
    metrics().blocklist_allowlisted.get(idx)
}

#[tokio::test]
async fn an_allowlisted_forward_name_is_attributed_to_the_forward_gate() {
    let _serial = SERIAL.lock().await;
    let (db, dns_server, _rbl, _cache) = test_server();
    db.add_dnsbl_allowlist_entry("allowed.example.com", "false positive")
        .expect("allowlist");

    let before = allowlisted(0); // forward_name
    let reverse_before = allowlisted(1);
    let query = build_query("allowed.example.com.", RecordType::A);
    dns_server
        .handle_query_proto(&query, None, None, Proto::Udp)
        .await
        .expect("query");

    assert_eq!(allowlisted(0), before + 1, "forward gate did not advance");
    assert_eq!(
        allowlisted(1),
        reverse_before,
        "a forward-name exemption must not be attributed to the reverse gate"
    );
}

#[tokio::test]
async fn an_allowlisted_reverse_name_and_ip_literal_are_attributed_apart() {
    let _serial = SERIAL.lock().await;
    let (db, dns_server, _rbl, _cache) = test_server();
    // One address exempted by its reverse name, another by its literal — the two
    // spellings are matched by different rules (suffix vs. exact), so an
    // operator needs to see which one is actually firing.
    db.add_dnsbl_allowlist_entry("4.3.2.1.in-addr.arpa", "by reverse name")
        .expect("allowlist");
    db.add_dnsbl_allowlist_entry("192.0.2.55", "by literal")
        .expect("allowlist");

    let reverse_before = allowlisted(1);
    let literal_before = allowlisted(2);

    dns_server
        .handle_query_proto(
            &build_query("4.3.2.1.in-addr.arpa.", RecordType::PTR),
            None,
            None,
            Proto::Udp,
        )
        .await
        .expect("query");
    assert_eq!(
        allowlisted(1),
        reverse_before + 1,
        "the reverse-name gate did not advance"
    );
    assert_eq!(
        allowlisted(2),
        literal_before,
        "a reverse-name match must not be attributed to the literal gate"
    );

    dns_server
        .handle_query_proto(
            &build_query("55.2.0.192.in-addr.arpa.", RecordType::PTR),
            None,
            None,
            Proto::Udp,
        )
        .await
        .expect("query");
    assert_eq!(
        allowlisted(2),
        literal_before + 1,
        "the ip-literal gate did not advance"
    );
}

/// An RBL resolver that lists everything, so the blocklist paths fire.
struct AlwaysListedResolver;

#[async_trait::async_trait]
impl RblResolver for AlwaysListedResolver {
    async fn lookup_rbl(
        &self,
        _query: &str,
    ) -> Result<Option<rolodex_dns::rbl::RblAnswer>, anyhow::Error> {
        // 127.0.0.2 is the canonical "listed" code, and deliberately not one of
        // the refusal codes — a refusal would be a different verdict entirely.
        Ok(Some(rolodex_dns::rbl::RblAnswer::single(
            std::net::Ipv4Addr::new(127, 0, 0, 2),
            300,
        )))
    }
}

#[tokio::test]
async fn a_scope_opted_in_provider_is_attributed_apart_from_the_global_list() {
    let _serial = SERIAL.lock().await;
    let db = Database::open_memory().expect("in-memory database");
    // The global list is enabled but carries NO providers of its own, so any
    // block here can only have come from the scope's opted-in provider — which
    // is what makes the separate kind observable.
    let rbl = Arc::new(RblChecker::with_resolver(
        true,
        vec![],
        Arc::new(AlwaysListedResolver),
    ));
    let cache = Arc::new(DnsCache::new(db.clone()));
    let dns_server = Arc::new(DnsServer::new_with_options(
        db.clone(),
        rbl.clone(),
        vec![],
        Some(Arc::clone(&cache)),
        None,
        false,
    ));

    db.create_network_scope(&rolodex_dns::db::NetworkScope {
        name: "blocknet".to_string(),
        home_domain: "blocknet.home.".to_string(),
    })
    .expect("create scope");
    db.join_network(&rolodex_dns::db::NetworkAssociation {
        ip_address: "10.64.0.9".to_string(),
        scope_name: "blocknet".to_string(),
        ttl_seconds: 3600,
    })
    .expect("join");
    db.add_scope_rbl_provider(&rolodex_dns::db::ScopeRblProvider {
        scope_name: "blocknet".to_string(),
        zone: "scope-only.example.invalid".to_string(),
        enabled: true,
        refusal_codes: vec![],
        refusal_cooldown_secs: 0,
    })
    .expect("add scope provider");

    let m = metrics();
    const KIND_RBL_PROVIDER: usize = 0;
    const KIND_RBL_SCOPE_PROVIDER: usize = 3;
    let global_before = m.blocklist_blocks.get(KIND_RBL_PROVIDER);
    let scope_before = m.blocklist_blocks.get(KIND_RBL_SCOPE_PROVIDER);

    // Provider verdicts are filled fire-and-forget, so the first query answers
    // from a cold cache and the block lands on a later one. Retry rather than
    // sleeping a fixed interval.
    let query = build_query("50.2.0.192.in-addr.arpa.", RecordType::PTR);
    let mut rcode = ResponseCode::NoError;
    for _ in 0..50 {
        let response = dns_server
            .handle_query_proto(
                &query,
                Some("10.64.0.9".parse().expect("ip")),
                None,
                Proto::Udp,
            )
            .await
            .expect("query");
        rcode = Message::from_bytes(&response)
            .expect("parse response")
            .response_code();
        if rcode == ResponseCode::NXDomain {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        rcode,
        ResponseCode::NXDomain,
        "a scope-provider listing must still be an NXDOMAIN"
    );

    assert_eq!(
        m.blocklist_blocks.get(KIND_RBL_SCOPE_PROVIDER),
        scope_before + 1,
        "the scope-provider block was not attributed to rbl_scope_provider"
    );
    // The control: folded together, "this network's own blocklist broke this
    // network" and "the global list broke everyone" are indistinguishable.
    assert_eq!(
        m.blocklist_blocks.get(KIND_RBL_PROVIDER),
        global_before,
        "a scope-provider block must not be attributed to the global list"
    );
}
