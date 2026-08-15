//! Flush semantics: **who is allowed to wipe the delegation cache, and who is not.**
//!
//! This is the trap in this whole change. `DnsServer::flush_cache()` is called by
//! every gRPC zone/record/scope mutation — 15+ call sites. Hanging the delegation
//! cache off `DnsCache::flush()` (which would have been "free") therefore means
//! **adding a single package wipes every delegation**, sending the next lookup of
//! every name in the world back to the root servers.
//!
//! That is precisely the failure that motivated the delegation cache: the box fell
//! over right after a `.fart` network was created and a `gitea@2.0` package added.
//! Getting this wrong would have shipped the bug back under a new name.

use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rolodex_dns::db::{Database, DnsRecord, RecordKind};
use rolodex_dns::dns_cache::{DnsCache, NegativeKind};
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::dnsbl::DnsblChecker;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;

fn name(s: &str) -> Name {
    Name::from_str(s).expect("valid name")
}

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
}

fn make_server(db: Database) -> (Arc<DnsServer>, Arc<DnsCache>) {
    let cache = Arc::new(DnsCache::new(db.clone()));
    let rbl = Arc::new(DnsblChecker::new());
    let server = Arc::new(DnsServer::new_with_options(
        db,
        rbl,
        vec![],
        Some(Arc::clone(&cache)),
        None,
        true,
    ));
    (server, cache)
}

/// Prime the delegation cache the way a real resolution would.
fn prime_delegations(server: &DnsServer) {
    let resolver = server.resolver();
    resolver
        .delegations()
        .insert(&name("com."), vec![ip(1)], 172_800);
    resolver
        .delegations()
        .insert(&name("org."), vec![ip(2)], 172_800);
}

fn delegation_count(server: &DnsServer) -> usize {
    server.resolver().delegations().len()
}

/// **The regression test for the trap.**
///
/// A local record/zone mutation flushes the *answer* cache — and must leave the
/// delegation cache completely alone. Otherwise adding one package re-walks the
/// roots for every name afterwards, which is the original outage.
#[tokio::test]
async fn local_record_mutation_does_not_flush_delegations() {
    let db = Database::open_memory().unwrap();
    let (server, cache) = make_server(db);

    prime_delegations(&server);
    cache.insert(
        "example.com.",
        Some(RecordKind::A),
        vec![DnsRecord {
            id: None,
            name: "example.com.".to_string(),
            record_type: RecordKind::A,
            value: "203.0.113.1".to_string(),
            ttl: 300,
            priority: 0,
        }],
        300,
    );

    assert_eq!(delegation_count(&server), 2);

    // This is what every gRPC record/zone/scope mutation calls — i.e. what adding
    // a `gitea@2.0` package to a `.fart` network does.
    server.flush_cache();

    assert!(
        cache.lookup("example.com.", Some(RecordKind::A)).is_empty(),
        "the answer cache SHOULD be flushed by a local mutation"
    );
    assert_eq!(
        delegation_count(&server),
        2,
        "adding a local record must NOT discard learned delegations — \
         doing so sends every subsequent cold lookup back to the root servers"
    );
}

/// A tier switch, by contrast, *must* discard delegations: nameservers learned
/// while talking to one upstream must not steer queries on another, and after a
/// degrade (e.g. onto a network that filters :53) those addresses are unreachable
/// anyway.
#[tokio::test]
async fn tier_switch_flushes_delegations() {
    let db = Database::open_memory().unwrap();
    let (server, cache) = make_server(db);

    prime_delegations(&server);
    cache.insert(
        "example.com.",
        Some(RecordKind::A),
        vec![DnsRecord {
            id: None,
            name: "example.com.".to_string(),
            record_type: RecordKind::A,
            value: "203.0.113.1".to_string(),
            ttl: 300,
            priority: 0,
        }],
        300,
    );
    assert_eq!(delegation_count(&server), 2);

    server.flush_upstream_state();

    assert_eq!(
        delegation_count(&server),
        0,
        "a tier switch must discard delegations learned from the old tier"
    );
    assert!(
        cache.lookup("example.com.", Some(RecordKind::A)).is_empty(),
        "and the answers too"
    );
}

/// The two flushes are genuinely independent — flushing answers must not take
/// delegations with it.
#[tokio::test]
async fn answer_flush_and_delegation_flush_are_independent() {
    let db = Database::open_memory().unwrap();
    let (server, _cache) = make_server(db);

    prime_delegations(&server);
    assert_eq!(delegation_count(&server), 2);

    server.flush_cache();
    assert_eq!(
        delegation_count(&server),
        2,
        "answers flushed, delegations kept"
    );

    server.flush_upstream_state();
    assert_eq!(delegation_count(&server), 0, "now both are gone");
}

/// The record cache (glue, glueless NS lookups, CNAME hops) lives under the same
/// rule as the delegation cache: a local record mutation must not wipe it, a tier
/// switch must.
///
/// Same trap as `local_record_mutation_does_not_flush_delegations` — `flush_cache()`
/// is called from every gRPC mutation site, so wiring the record cache into it would
/// mean adding one package discards the whole recursion cache.
#[tokio::test]
async fn local_record_mutation_does_not_flush_the_record_cache() {
    let db = Database::open_memory().unwrap();
    let (server, _cache) = make_server(db);

    let resolver = server.resolver();
    resolver.records().insert(
        &name("ns1.example.net."),
        RecordType::A,
        vec![Record::from_rdata(
            name("ns1.example.net."),
            3600,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 50))),
        )],
    );
    assert_eq!(resolver.records().len(), 1);

    // What adding a package does.
    server.flush_cache();
    assert_eq!(
        server.resolver().records().len(),
        1,
        "a local record mutation must NOT discard cached glue/intermediates"
    );

    // What a tier switch does.
    server.flush_upstream_state();
    assert_eq!(
        server.resolver().records().len(),
        0,
        "a tier switch must discard records learned from the old tier"
    );
}

/// Root-hint changes must carry the delegation cache across, not silently drop it.
///
/// `set_root_hints` swaps the whole resolver behind an `ArcSwap`; rebuilding it
/// from scratch there would throw away everything learned so far.
#[tokio::test]
async fn set_root_hints_preserves_the_delegation_cache() {
    let db = Database::open_memory().unwrap();
    let (server, _cache) = make_server(db);

    prime_delegations(&server);
    assert_eq!(delegation_count(&server), 2);

    server.set_root_hints(vec![ip(200), ip(201)]);

    assert_eq!(
        delegation_count(&server),
        2,
        "changing root hints must not discard the delegation cache"
    );
    assert_eq!(
        server.resolver().root_hints().len(),
        2,
        "and the new hints must actually be in effect"
    );
}

/// A cached negative must be evicted when a local record for that name appears,
/// or a freshly-added package stays NXDOMAIN until the negative TTL runs out.
#[tokio::test]
async fn local_record_invalidates_a_cached_negative() {
    let db = Database::open_memory().unwrap();
    let (_server, cache) = make_server(db);

    cache.insert_negative(
        "gitea.default.fart.",
        Some(RecordKind::A),
        NegativeKind::NxDomain,
        3600,
    );
    assert_eq!(
        cache.lookup_negative("gitea.default.fart.", Some(RecordKind::A)),
        Some(NegativeKind::NxDomain)
    );

    // The package is created — a local record now exists for that name.
    cache.invalidate_negative("gitea.default.fart.");

    assert_eq!(
        cache.lookup_negative("gitea.default.fart.", Some(RecordKind::A)),
        None,
        "a newly-created name must not keep answering NXDOMAIN from cache"
    );
}

/// An expired negative is not served.
#[tokio::test]
async fn expired_negative_is_not_served() {
    let db = Database::open_memory().unwrap();
    let (_server, cache) = make_server(db);

    cache.insert_negative(
        "gone.example.com.",
        Some(RecordKind::A),
        NegativeKind::NxDomain,
        1,
    );
    assert!(
        cache
            .lookup_negative("gone.example.com.", Some(RecordKind::A))
            .is_some()
    );

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    assert_eq!(
        cache.lookup_negative("gone.example.com.", Some(RecordKind::A)),
        None,
        "negative TTL must be respected"
    );
}

/// NXDOMAIN and NODATA are cached distinctly and replay the right rcode.
#[tokio::test]
async fn nxdomain_and_nodata_are_cached_distinctly() {
    let db = Database::open_memory().unwrap();
    let (_server, cache) = make_server(db);

    cache.insert_negative(
        "nx.example.com.",
        Some(RecordKind::A),
        NegativeKind::NxDomain,
        300,
    );
    cache.insert_negative(
        "nd.example.com.",
        Some(RecordKind::A),
        NegativeKind::NoData,
        300,
    );

    assert_eq!(
        cache.lookup_negative("nx.example.com.", Some(RecordKind::A)),
        Some(NegativeKind::NxDomain)
    );
    assert_eq!(
        cache.lookup_negative("nd.example.com.", Some(RecordKind::A)),
        Some(NegativeKind::NoData)
    );
}

/// A local-mutation flush also clears negatives (a stale NXDOMAIN must never
/// shadow a name that was just created).
#[tokio::test]
async fn flush_clears_negatives() {
    let db = Database::open_memory().unwrap();
    let (server, cache) = make_server(db);

    cache.insert_negative(
        "nope.example.com.",
        Some(RecordKind::A),
        NegativeKind::NxDomain,
        3600,
    );
    assert_eq!(cache.negative_count(), 1);

    server.flush_cache();

    assert_eq!(cache.negative_count(), 0);
}
