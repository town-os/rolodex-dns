//! Persistence tests for the delegation cache, and for the answer cache's
//! boot-load — which never actually worked.

use hickory_proto::rr::Name;
use rolodex_dns::db::{Database, RecordKind};
use rolodex_dns::delegation_cache::{DEFAULT_PERSIST_MIN_TTL, DelegationCache};
use rolodex_dns::dns_cache::DnsCache;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;

fn name(s: &str) -> Name {
    Name::from_str(s).expect("valid name")
}

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
}

/// Lets the write-behind persist worker drain.
async fn settle() {
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
}

/// A delegation with a TTL above the threshold is persisted; one below it stays
/// in memory only.
#[tokio::test]
async fn only_long_lived_delegations_are_persisted() {
    let db = Database::open_memory().unwrap();
    let cache = DelegationCache::with_db(db.clone(), DEFAULT_PERSIST_MIN_TTL);

    // Well above the 300s default threshold — a real TLD NS set.
    cache.insert(&name("com."), vec![ip(1)], 172_800);
    // Below the threshold: memory only.
    cache.insert(&name("shortlived.test."), vec![ip(2)], 120);

    settle().await;

    let persisted = db.delegation_load_all().unwrap();
    let zones: Vec<&str> = persisted.iter().map(|(z, _, _)| z.as_str()).collect();

    assert!(
        zones.contains(&"com."),
        "long-lived delegation must persist"
    );
    assert!(
        !zones.contains(&"shortlived.test."),
        "a delegation below the TTL threshold must not be written to disk"
    );

    // Both are live in memory regardless.
    assert!(cache.best_match(&name("x.com.")).is_some());
    assert!(cache.best_match(&name("x.shortlived.test.")).is_some());
}

/// The threshold is configurable — the whole point of the knob.
#[tokio::test]
async fn persist_threshold_is_configurable() {
    let db = Database::open_memory().unwrap();
    // Lower the bar to 60s: a 120s delegation now qualifies.
    let cache = DelegationCache::with_db(db.clone(), 60);

    cache.insert(&name("shortlived.test."), vec![ip(2)], 120);
    settle().await;

    let zones: Vec<String> = db
        .delegation_load_all()
        .unwrap()
        .into_iter()
        .map(|(z, _, _)| z)
        .collect();
    assert!(
        zones.contains(&"shortlived.test.".to_string()),
        "with a 60s threshold, a 120s delegation must persist"
    );
}

/// A restart comes back warm: a fresh cache over the same database serves the
/// delegation without going anywhere near a root server.
#[tokio::test]
async fn delegations_survive_a_restart() {
    let db = Database::open_memory().unwrap();

    {
        let cache = DelegationCache::with_db(db.clone(), DEFAULT_PERSIST_MIN_TTL);
        cache.insert(&name("com."), vec![ip(1), ip(2)], 172_800);
        settle().await;
    }

    // "Restart": brand new cache, same DB.
    let reborn = DelegationCache::with_db(db.clone(), DEFAULT_PERSIST_MIN_TTL);

    let (zone, servers) = reborn
        .best_match(&name("www.example.com."))
        .expect("com. delegation must be restored from disk");
    assert_eq!(zone, "com.");
    assert_eq!(servers.len(), 2, "both nameservers restored");
    assert!(servers.contains(&ip(1)) && servers.contains(&ip(2)));
}

/// Expired rows are not resurrected at boot.
#[tokio::test]
async fn expired_delegations_are_not_loaded() {
    let db = Database::open_memory().unwrap();
    // Write a row directly with a TTL of 1s and a cached_at far in the past by
    // using a zero TTL — `delegation_load_all` filters on cached_at + ttl > now.
    db.delegation_insert("stale.test.", "192.0.2.9", 0).unwrap();

    let loaded = db.delegation_load_all().unwrap();
    assert!(
        loaded.is_empty(),
        "an already-expired row must not be loaded"
    );

    let cache = DelegationCache::with_db(db.clone(), DEFAULT_PERSIST_MIN_TTL);
    assert!(cache.best_match(&name("x.stale.test.")).is_none());
}

/// Re-learning a delegation upserts rather than appending.
///
/// The answer cache's `cache_insert` was a bare INSERT with no uniqueness
/// constraint, so it piled up a duplicate row on every refresh, forever. The
/// delegation table must not repeat that.
#[tokio::test]
async fn re_learning_a_delegation_upserts_instead_of_appending() {
    let db = Database::open_memory().unwrap();
    let cache = DelegationCache::with_db(db.clone(), DEFAULT_PERSIST_MIN_TTL);

    for _ in 0..100 {
        cache.insert(&name("com."), vec![ip(1)], 172_800);
    }
    settle().await;

    assert_eq!(
        db.delegation_count().unwrap(),
        1,
        "100 refreshes of one (zone, ns) pair must leave exactly one row"
    );
}

/// A shrinking nameserver set does not leave stale addresses behind.
#[tokio::test]
async fn replacing_a_delegation_drops_removed_nameservers() {
    let db = Database::open_memory().unwrap();
    let cache = DelegationCache::with_db(db.clone(), DEFAULT_PERSIST_MIN_TTL);

    cache.insert(&name("com."), vec![ip(1), ip(2), ip(3)], 172_800);
    settle().await;
    assert_eq!(db.delegation_count().unwrap(), 3);

    cache.insert(&name("com."), vec![ip(1)], 172_800);
    settle().await;
    assert_eq!(
        db.delegation_count().unwrap(),
        1,
        "the removed nameservers must be gone, not left behind"
    );
}

/// The answer cache now actually loads at boot.
///
/// `load_from_disk` called `cache_lookup("", None)`, which filters on
/// `WHERE name = ?1` — so it matched the empty name and loaded **nothing**, on
/// every boot, forever ("DNS cache loaded (0 entries)"). It also stamped a
/// fabricated 300s lifetime on anything it did load.
#[tokio::test]
async fn answer_cache_loads_from_disk_at_boot() {
    let db = Database::open_memory().unwrap();

    {
        let cache = DnsCache::new(db.clone());
        cache.insert(
            "example.com.",
            Some(RecordKind::A),
            vec![rolodex_dns::db::DnsRecord {
                id: None,
                name: "example.com.".to_string(),
                record_type: RecordKind::A,
                value: "203.0.113.1".to_string(),
                ttl: 3600,
                priority: 0,
            }],
            3600,
        );
        settle().await;
        assert!(db.cache_count().unwrap() > 0, "entry must reach the DB");
    }

    // "Restart" onto the same DB.
    let reborn = Arc::new(DnsCache::new(db.clone()));
    settle().await;

    let hits = reborn.lookup("example.com.", Some(RecordKind::A));
    assert!(
        !hits.is_empty(),
        "the answer cache must come back warm across a restart (it never did before)"
    );
    assert_eq!(hits[0].value, "203.0.113.1");
}

/// The restored TTL is the row's *remaining* lifetime, not a hard-coded 300s.
#[tokio::test]
async fn restored_answer_cache_ttl_reflects_the_stored_ttl() {
    let db = Database::open_memory().unwrap();
    db.cache_insert(
        "long.example.com.",
        "A",
        "203.0.113.2",
        7200,
        7200,
        "upstream",
    )
    .unwrap();

    let rows = db.cache_load_all().unwrap();
    let (rec, remaining) = rows
        .into_iter()
        .find(|(r, _)| r.name == "long.example.com.")
        .expect("row must load");

    assert!(
        remaining > 300,
        "remaining TTL must come from the stored TTL (got {remaining}), \
         not the old hard-coded 300s"
    );
    assert!(remaining <= 7200);
    assert_eq!(rec.ttl, remaining);
}

/// A cache flush clears the persisted delegations too.
#[tokio::test]
async fn flush_clears_persisted_delegations() {
    let db = Database::open_memory().unwrap();
    let cache = DelegationCache::with_db(db.clone(), DEFAULT_PERSIST_MIN_TTL);

    cache.insert(&name("com."), vec![ip(1)], 172_800);
    settle().await;
    assert_eq!(db.delegation_count().unwrap(), 1);

    cache.flush();
    assert!(cache.is_empty());
    assert_eq!(
        db.delegation_count().unwrap(),
        0,
        "flush must clear the persisted rows as well as memory"
    );
}
