//! Root priming: ask the roots who the roots are.
//!
//! Without it the 13 compiled-in [`ROOT_HINTS`] addresses are the only root servers
//! rolodex ever knows about — a hardcoded list, never refreshed, with no TTL.
//! Priming makes the hints what they are supposed to be: a *bootstrap*, used once
//! to fetch the live root NS set (which arrives with a ~6-day TTL) and as the
//! fallback if that lookup fails.
//!
//! It runs **at startup, not on the query path**. Putting it inside `resolve()`
//! would hang an extra round trip off a user's first lookup for no benefit to that
//! lookup — and, worse, a *failed* prime caches nothing, so it would re-fire ahead
//! of every query forever on any network where priming does not work.

mod mock_hierarchy;

use hickory_proto::rr::{DNSClass, Name};
use mock_hierarchy::{Behavior, bind_levels, serve};
use rolodex_dns::resolver::IterativeResolver;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const PRIMED_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// A successful prime caches the live root NS set under `.`, so the resolver walks
/// from *those* servers rather than the static hints.
#[tokio::test]
async fn priming_caches_the_live_root_ns_set() {
    let (port, mut socks) = bind_levels(&[ROOT_IP, PRIMED_IP]).await;
    let _unused = socks.pop().unwrap();
    let root_sock = socks.pop().unwrap();

    let root = serve(
        root_sock,
        Behavior::RootNs {
            ns_addr: PRIMED_IP,
            ttl: 518_400,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(500));

    assert!(
        resolver.delegations().best_match(&Name::root()).is_none(),
        "nothing is primed until we ask"
    );

    resolver.prime_roots(DNSClass::IN).await;

    let (zone, servers) = resolver
        .delegations()
        .best_match(&Name::root())
        .expect("the root NS set must be cached after priming");
    assert_eq!(zone, ".");
    assert_eq!(
        servers,
        vec![IpAddr::V4(PRIMED_IP)],
        "the primed server, learned from the roots — not the static hint"
    );
    assert_eq!(root.hits(), 1, "priming is a single query");
}

/// Priming is attempted **once**, even when it fails.
///
/// A failed prime caches nothing, so keying off the cache alone would re-fire the
/// `. NS` query every time — a wasted round trip on every lookup, forever, on any
/// network where the root NS lookup does not work.
#[tokio::test]
async fn a_failed_prime_is_not_retried() {
    let (port, mut socks) = bind_levels(&[ROOT_IP]).await;
    let root_sock = socks.pop().unwrap();

    // Answers A records for anything — so a `. NS` query yields no usable NS set.
    let root = serve(
        root_sock,
        Behavior::Answer {
            ip: Ipv4Addr::new(203, 0, 113, 1),
            ttl: 300,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(300));

    resolver.prime_roots(DNSClass::IN).await;
    let after_first = root.hits();

    // Several more attempts must all be no-ops.
    for _ in 0..5 {
        resolver.prime_roots(DNSClass::IN).await;
    }

    assert!(
        resolver.delegations().best_match(&Name::root()).is_none(),
        "the prime failed, so nothing is cached"
    );
    assert_eq!(
        root.hits(),
        after_first,
        "a failed prime must not be retried — it would cost a query on every lookup"
    );
}

/// A dead root does not stop the resolver coming up: priming fails quietly and the
/// static hints remain in force.
#[tokio::test]
async fn priming_failure_leaves_the_static_hints_intact() {
    let (port, mut socks) = bind_levels(&[ROOT_IP]).await;
    let root_sock = socks.pop().unwrap();

    let root = serve(
        root_sock,
        Behavior::Answer {
            ip: Ipv4Addr::new(203, 0, 113, 1),
            ttl: 300,
        },
    );
    root.kill();

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(150));

    // Must not panic, hang, or otherwise take the resolver down.
    resolver.prime_roots(DNSClass::IN).await;

    assert!(resolver.delegations().best_match(&Name::root()).is_none());
    assert_eq!(
        resolver.root_hints(),
        &[IpAddr::V4(ROOT_IP)],
        "the hints stay in force as the fallback"
    );
}
