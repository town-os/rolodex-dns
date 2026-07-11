//! Nameserver-selection tests.
//!
//! The resolver used to try nameservers **serially, in fixed order**, with a
//! 1500ms timeout. `servers` was always `ROOT_HINTS` in declaration order, so
//! every cold query in the system hit `198.41.0.4` (a.root-servers.net) first —
//! which duly rate-limited us, at which point every query paid the full timeout
//! before failing over to the next root. That is the multi-second tail we saw.
//!
//! These tests pin the three properties that fix it: a slow server is demoted, a
//! dead server is demoted, and IPv4 is *always* tried before IPv6.

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

async fn resolve_n(resolver: &IterativeResolver, n: usize) {
    for i in 0..n {
        let host = format!("h{i}.example.com.");
        let _ = resolver
            .resolve(&name(&host), RecordType::A, DNSClass::IN)
            .await;
    }
}

/// A slow nameserver is demoted: after a warm-up the fast one takes the large
/// majority of queries.
///
/// Asserted on the hit ratio, never on wall-clock — timing assertions in CI are
/// flaky and would prove nothing anyway.
#[tokio::test]
async fn slow_nameserver_is_demoted() {
    let (port, mut socks) = bind_levels(&[A_IP, B_IP]).await;
    let fast_sock = socks.pop().unwrap();
    let slow_sock = socks.pop().unwrap();

    // Both are authoritative roots that answer directly.
    let slow = serve_with_delay(
        slow_sock,
        Behavior::Answer {
            ip: ANSWER_IP,
            ttl: 300,
        },
        Duration::from_millis(200),
    );
    let fast = serve(
        fast_sock,
        Behavior::Answer {
            ip: ANSWER_IP,
            ttl: 300,
        },
    );

    // A_IP (slow) is listed FIRST — the old code would have pinned every query to
    // it forever.
    let resolver = IterativeResolver::new(vec![IpAddr::V4(A_IP), IpAddr::V4(B_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(1000));

    resolve_n(&resolver, 40).await;

    assert!(
        fast.hits() > slow.hits(),
        "the fast nameserver must take more traffic than the slow one \
         (fast={}, slow={})",
        fast.hits(),
        slow.hits()
    );
    assert!(
        fast.hits() >= 25,
        "the fast server should take the large majority of 40 queries, got {}",
        fast.hits()
    );
}

/// A dead nameserver is demoted rather than retried first on every query.
///
/// Under the old fixed ordering a dead `servers[0]` cost the full timeout on
/// *every single query*, forever. Here the dead server is listed first; after the
/// initial probe the resolver must stop leading with it.
#[tokio::test]
async fn dead_nameserver_is_demoted_after_first_failure() {
    let (port, mut socks) = bind_levels(&[A_IP, B_IP]).await;
    let live_sock = socks.pop().unwrap();
    let dead_sock = socks.pop().unwrap();

    let dead = serve(
        dead_sock,
        Behavior::Answer {
            ip: ANSWER_IP,
            ttl: 300,
        },
    );
    let live = serve(
        live_sock,
        Behavior::Answer {
            ip: ANSWER_IP,
            ttl: 300,
        },
    );
    dead.kill();

    let resolver = IterativeResolver::new(vec![IpAddr::V4(A_IP), IpAddr::V4(B_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(200));

    resolve_n(&resolver, 30).await;

    // Every query must still succeed via the live server.
    assert!(live.hits() >= 30, "the live server answers every query");

    // The dead one still gets the occasional exploration probe, but must not be
    // hit on every query the way fixed ordering would.
    assert!(
        dead.hits() < 30,
        "a dead nameserver must be demoted, not retried first on every query \
         (it took {} of 30)",
        dead.hits()
    );
}

/// IPv4 is always tried before IPv6.
///
/// This is a correctness constraint, not a preference: the dev box has no
/// routable IPv6 (rolodex's own probe logs `AAAA=false`), so a v6 nameserver
/// picked at random would burn the full query timeout every time. The delegation
/// glue lists the v6 server first on the wire — the resolver must still go v4.
#[tokio::test]
async fn ipv4_nameservers_are_always_tried_before_ipv6() {
    let (port, mut socks) = bind_levels(&[A_IP, B_IP]).await;
    let auth_sock = socks.pop().unwrap();
    let root_sock = socks.pop().unwrap();

    // The root refers example.com. to an NS set whose *v6* glue is listed first,
    // pointing at a documentation-range v6 address that nothing is listening on.
    let root = serve(
        root_sock,
        Behavior::ReferMixedFamily {
            zone: "example.com.".to_string(),
            v6: "2001:db8::1".parse().unwrap(),
            v4: B_IP,
            ttl: 3600,
        },
    );
    let auth = serve(
        auth_sock,
        Behavior::Answer {
            ip: ANSWER_IP,
            ttl: 300,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(A_IP)])
        .with_port(port)
        // Deliberately generous: if the resolver ever tried the v6 address first
        // it would stall here, and the v4 hit count would lag.
        .with_timeout(Duration::from_millis(400));

    for i in 0..20 {
        let host = format!("h{i}.example.com.");
        let res = resolver
            .resolve(&name(&host), RecordType::A, DNSClass::IN)
            .await;
        assert!(res.is_ok(), "must resolve via the v4 nameserver");
    }

    assert!(root.hits() >= 1);
    assert_eq!(
        auth.hits(),
        20,
        "every query must reach the v4 authoritative server directly; \
         a v6-first pick would have timed out instead"
    );
}

/// With several equal-latency roots and nothing cached, queries spread across
/// them instead of all landing on the first.
///
/// This is the a.root-servers.net hammering that earned the rate-limit: the old
/// code sent *every* cold query in the system to `servers[0]`.
#[tokio::test]
async fn queries_are_not_pinned_to_the_first_root() {
    let (port, mut socks) = bind_levels(&[A_IP, B_IP, C_IP]).await;
    let c = socks.pop().unwrap();
    let b = socks.pop().unwrap();
    let a = socks.pop().unwrap();

    let answer = Behavior::Answer {
        ip: ANSWER_IP,
        ttl: 300,
    };
    let root_a = serve(a, answer.clone());
    let root_b = serve(b, answer.clone());
    let root_c = serve(c, answer);

    let resolver =
        IterativeResolver::new(vec![IpAddr::V4(A_IP), IpAddr::V4(B_IP), IpAddr::V4(C_IP)])
            .with_port(port)
            .with_timeout(Duration::from_millis(500));

    resolve_n(&resolver, 60).await;

    let used = [root_a.hits(), root_b.hits(), root_c.hits()];
    let spread = used.iter().filter(|&&h| h > 0).count();

    assert_eq!(
        used.iter().sum::<usize>(),
        60,
        "every query is accounted for"
    );
    assert!(
        spread >= 2,
        "queries must not all be pinned to one root (distribution: {used:?}) — \
         the old fixed ordering sent every query to servers[0]"
    );
    assert!(
        used[0] < 60,
        "the first-listed root must not take literally every query"
    );
}

/// A never-measured nameserver still gets probed rather than starved behind an
/// entrenched favourite.
#[tokio::test]
async fn unmeasured_nameserver_still_gets_probed() {
    let (port, mut socks) = bind_levels(&[A_IP, B_IP]).await;
    let newcomer_sock = socks.pop().unwrap();
    let incumbent_sock = socks.pop().unwrap();

    let answer = Behavior::Answer {
        ip: ANSWER_IP,
        ttl: 300,
    };
    let incumbent = serve(incumbent_sock, answer.clone());
    let newcomer = serve(newcomer_sock, answer);

    let resolver = IterativeResolver::new(vec![IpAddr::V4(A_IP), IpAddr::V4(B_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(500));

    resolve_n(&resolver, 60).await;

    assert!(
        newcomer.hits() > 0,
        "an unmeasured server must receive some traffic (exploration), got 0"
    );
    assert!(incumbent.hits() > 0);
}
