//! Root-server load balancing: **we must not get stuck on one root**.
//!
//! Round 1 fixed the fixed-order bug (every cold query led with `ROOT_HINTS[0]`,
//! a.root-servers.net, which rate-limited us) — but replaced it with sort-by-RTT,
//! which just pins every query on whichever root happens to be *fastest*. Still one
//! server carrying everything, still a rate-limit waiting to happen.
//!
//! The selection rule is now **lowest `hits * latency`**. That drives the product
//! toward equality across the group, which is exactly `hits ∝ 1 / latency`: fast
//! servers carry proportionally more, but every healthy server carries some.
//!
//! It also means nothing is pre-measured — an unqueried server has `hits == 0`, so
//! it scores 0 (the minimum) and is tried first, learning its latency from a query
//! that had to happen anyway.

mod mock_hierarchy;

use hickory_proto::rr::{DNSClass, RecordType};
use mock_hierarchy::{Behavior, bind_levels, name, serve, serve_with_delay};
use rolodex_dns::resolver::IterativeResolver;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

const A_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const B_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const C_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const ANSWER_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

fn answer() -> Behavior {
    Behavior::Answer {
        ip: ANSWER_IP,
        ttl: 300,
    }
}

/// Resolve `n` distinct names so nothing is served from a cache.
async fn resolve_n(resolver: &IterativeResolver, n: usize) {
    for i in 0..n {
        let host = format!("h{i}.example.com.");
        let _ = resolver
            .resolve(&name(&host), RecordType::A, DNSClass::IN)
            .await;
    }
}

/// **The headline test.** Three equal roots, and every one of them carries traffic.
///
/// With equal latencies `hits * latency` degenerates to plain round-robin, so the
/// split should be near-perfect thirds. Sort-by-RTT would have given one root ~100%.
#[tokio::test]
async fn equal_roots_share_the_load_evenly() {
    let (port, mut socks) = bind_levels(&[A_IP, B_IP, C_IP]).await;
    let c = socks.pop().unwrap();
    let b = socks.pop().unwrap();
    let a = socks.pop().unwrap();

    let root_a = serve(a, answer());
    let root_b = serve(b, answer());
    let root_c = serve(c, answer());

    let resolver =
        IterativeResolver::new(vec![IpAddr::V4(A_IP), IpAddr::V4(B_IP), IpAddr::V4(C_IP)])
            .with_port(port)
            .with_timeout(Duration::from_millis(500));

    resolve_n(&resolver, 90).await;

    let hits = [root_a.hits(), root_b.hits(), root_c.hits()];
    for (i, h) in hits.iter().enumerate() {
        assert!(
            *h > 0,
            "every root must carry traffic — root {i} got none (distribution: {hits:?})"
        );
        assert!(
            *h < 60,
            "no single root may carry the bulk of the load (distribution: {hits:?})"
        );
    }
}

/// A faster root takes the larger share — but the slower ones are **not** starved.
///
/// This is precisely the case sort-by-RTT got wrong: it handed the fastest server
/// 100% and the others nothing.
#[tokio::test]
async fn a_faster_root_takes_more_but_does_not_take_everything() {
    let (port, mut socks) = bind_levels(&[A_IP, B_IP, C_IP]).await;
    let slow_sock = socks.pop().unwrap();
    let mid_sock = socks.pop().unwrap();
    let fast_sock = socks.pop().unwrap();

    let fast = serve(fast_sock, answer());
    let mid = serve_with_delay(mid_sock, answer(), Duration::from_millis(40));
    let slow = serve_with_delay(slow_sock, answer(), Duration::from_millis(80));

    let resolver =
        IterativeResolver::new(vec![IpAddr::V4(A_IP), IpAddr::V4(B_IP), IpAddr::V4(C_IP)])
            .with_port(port)
            .with_timeout(Duration::from_millis(1000));

    resolve_n(&resolver, 60).await;

    let (f, m, s) = (fast.hits(), mid.hits(), slow.hits());
    assert!(
        f > 0 && m > 0 && s > 0,
        "all three roots must keep carrying traffic (fast={f}, mid={m}, slow={s})"
    );
    assert!(
        f > s,
        "the fast root should carry more than the slow one (fast={f}, slow={s})"
    );
    assert!(
        s * 2 <= f * 3,
        "the slow root must not be starved to nothing (fast={f}, slow={s})"
    );
}

/// Nothing is pre-measured: from a cold tracker, the first N queries across N
/// never-seen roots hit each exactly once.
///
/// An unqueried server has `hits == 0`, so its score is `0 * anything == 0` — the
/// minimum — and it is tried before any server that already has a measurement.
/// Latency is therefore learned from real traffic, never from a probe.
#[tokio::test]
async fn unqueried_roots_are_tried_first_without_probing() {
    let (port, mut socks) = bind_levels(&[A_IP, B_IP, C_IP]).await;
    let c = socks.pop().unwrap();
    let b = socks.pop().unwrap();
    let a = socks.pop().unwrap();

    let root_a = serve(a, answer());
    let root_b = serve(b, answer());
    let root_c = serve(c, answer());

    let resolver =
        IterativeResolver::new(vec![IpAddr::V4(A_IP), IpAddr::V4(B_IP), IpAddr::V4(C_IP)])
            .with_port(port)
            .with_timeout(Duration::from_millis(500));

    // Exactly as many queries as there are roots.
    resolve_n(&resolver, 3).await;

    let hits = [root_a.hits(), root_b.hits(), root_c.hits()];
    assert_eq!(
        hits,
        [1, 1, 1],
        "each unmeasured root must be tried exactly once before any is repeated \
         (distribution: {hits:?})"
    );
}

/// A dead root sinks to almost no traffic, and a revived one earns its share back.
///
/// Failures are tracked as an **explicit backoff**, not as a giant synthetic latency
/// folded into the EMA. Folding them in ties recovery to how fast the healthy peers
/// happen to be: against these loopback mocks (~0.3ms) a 10s failure penalty gave the
/// dead root a 1-in-33,000 share, so it was never retried and never came back. A
/// backoff recovers on a bounded clock whatever the peers' absolute speed.
#[tokio::test]
async fn a_dead_root_is_shed_and_a_revived_one_returns() {
    let (port, mut socks) = bind_levels(&[A_IP, B_IP]).await;
    let live_sock = socks.pop().unwrap();
    let flaky_sock = socks.pop().unwrap();

    let flaky = serve(flaky_sock, answer());
    let live = serve(live_sock, answer());
    flaky.kill();

    let resolver = IterativeResolver::new(vec![IpAddr::V4(A_IP), IpAddr::V4(B_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(150))
        // Short enough that the test doesn't sit out the production backoff.
        .with_failure_backoff(Duration::from_millis(100));

    resolve_n(&resolver, 40).await;

    let dead_share = flaky.hits();
    assert!(live.hits() >= 40, "the live root answers everything");
    assert!(
        dead_share < 15,
        "a dead root must be shed, not retried first every time (it took {dead_share})"
    );

    // It comes back. Once the backoff expires it re-enters the rotation, and with no
    // successful queries to its name it scores 0 — the minimum — so the very next
    // lookup tries it, re-measures it for real, and it rejoins. No probe, no timer.
    flaky.revive();
    flaky.reset();
    live.reset();
    tokio::time::sleep(Duration::from_millis(500)).await;
    resolve_n(&resolver, 120).await;

    assert!(
        flaky.hits() > 0,
        "a revived root must earn traffic back — recovery is automatic, not a probe"
    );
}
