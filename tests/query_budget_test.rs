//! Query budget: **one client lookup must cost a bounded number of upstream queries.**
//!
//! The per-dimension limits (`MAX_RESOLUTION_DEPTH`, `MAX_REFERRALS`,
//! `MAX_CNAME_CHAIN`, `MAX_GLUELESS_NS`) each bound one axis — but they *multiply*.
//! Glue-less NS resolution recurses, and every level of that recursion can fan out
//! across up to 4 nameservers, each of which may hit another glue-less delegation.
//! A zone that keeps referring without glue therefore costs
//! `O(4 ^ 16)` queries.
//!
//! This was not theoretical: a mock zone that referred glue-lessly to a nameserver
//! and then referred glue-lessly again when asked to resolve *that* nameserver made
//! the resolver emit **65,536 queries** for a single lookup, taking 42 seconds. That
//! is a self-inflicted DoS, and an amplifier aimed at whoever the delegation happens
//! to name.
//!
//! A single hard cap on total queries per resolution closes it.

mod mock_hierarchy;

use hickory_proto::rr::{DNSClass, RecordType};
use mock_hierarchy::{Behavior, bind_levels, name, serve};
use rolodex_dns::resolver::IterativeResolver;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// The pathological zone: it refers glue-lessly to `ns1.loop.test.`, and when asked
/// to resolve `ns1.loop.test.` it refers glue-lessly *again*. Each level fans out,
/// so without a total-query cap this explodes exponentially.
#[tokio::test]
async fn a_pathological_glueless_chain_cannot_explode() {
    let (port, mut socks) = bind_levels(&[ROOT_IP]).await;
    let root_sock = socks.pop().unwrap();

    let root = serve(
        root_sock,
        Behavior::ReferGlueless {
            zone: "loop.test.".to_string(),
            ns_name: "ns1.loop.test.".to_string(),
            ttl: 3600,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(200));

    let started = Instant::now();
    let result = resolver
        .resolve(&name("victim.loop.test."), RecordType::A, DNSClass::IN)
        .await;
    let elapsed = started.elapsed();

    assert!(
        result.is_err(),
        "a delegation chain that never terminates must fail, not spin"
    );

    // The cap is 64. Allow a little headroom for the retry-from-roots path, but
    // nothing remotely near the 65,536 this used to cost.
    let queries = root.hits();
    assert!(
        queries <= 200,
        "one lookup must not fan out into thousands of queries (it made {queries})"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "and it must fail fast, not grind for 42s (took {elapsed:?})"
    );
}

/// The budget must not interfere with an ordinary deep lookup. A healthy
/// root -> TLD -> authoritative walk costs a handful of queries and stays well
/// inside the cap.
#[tokio::test]
async fn a_healthy_lookup_is_unaffected_by_the_budget() {
    const TLD_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
    const AUTH_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);

    let (port, mut socks) = bind_levels(&[ROOT_IP, TLD_IP, AUTH_IP]).await;
    let auth_sock = socks.pop().unwrap();
    let tld_sock = socks.pop().unwrap();
    let root_sock = socks.pop().unwrap();

    let root = serve(
        root_sock,
        Behavior::Refer {
            zone: "com.".to_string(),
            next: TLD_IP,
            ttl: 3600,
        },
    );
    let tld = serve(
        tld_sock,
        Behavior::Refer {
            zone: "example.com.".to_string(),
            next: AUTH_IP,
            ttl: 3600,
        },
    );
    let auth = serve(
        auth_sock,
        Behavior::Answer {
            ip: Ipv4Addr::new(203, 0, 113, 10),
            ttl: 300,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(500));

    resolver
        .resolve(&name("host.example.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("a healthy three-hop walk must succeed");

    let total = root.hits() + tld.hits() + auth.hits();
    assert_eq!(total, 3, "root -> TLD -> auth, one query each");
}
