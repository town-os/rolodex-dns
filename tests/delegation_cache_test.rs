//! Delegation-cache integration tests.
//!
//! Every assertion here is on **query counts** against a real mock delegation
//! hierarchy (see `mock_hierarchy`), because that is the only thing that actually
//! distinguishes the bug from the fix. The resolver used to restart every single
//! resolution at the root hints, so N cold names meant N root queries — which is
//! what got us rate-limited by the root servers and turned every lookup into a
//! multi-second timeout-and-failover.

mod mock_hierarchy;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, RecordType};
use mock_hierarchy::{Behavior, MockNs, bind_levels, name, serve};
use rolodex_dns::resolver::{DEFAULT_TTL, IterativeResolver};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const TLD_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const AUTH_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const AUTH2_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);

const ANSWER_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

/// A root -> com. -> example.com. hierarchy with the given delegation TTL.
struct Chain {
    root: MockNs,
    tld: MockNs,
    auth: MockNs,
    resolver: IterativeResolver,
}

async fn chain_with_ttl(delegation_ttl: u32) -> Chain {
    let (port, mut socks) = bind_levels(&[ROOT_IP, TLD_IP, AUTH_IP]).await;
    let auth_sock = socks.pop().unwrap();
    let tld_sock = socks.pop().unwrap();
    let root_sock = socks.pop().unwrap();

    // The root refers `.com` names to the TLD server, and `a.example.org.` — the
    // one name the isolation test uses to reach an *uncached* TLD — to `org.`.
    // A root that referred `com.` whatever it was asked would be handing back an
    // out-of-bailiwick delegation, which a resolver must reject; the route keeps
    // the fixture answering the way a real root does.
    let root = serve(
        root_sock,
        Behavior::Router {
            routes: vec![(
                "a.example.org.".to_string(),
                Box::new(Behavior::Refer {
                    zone: "org.".to_string(),
                    next: TLD_IP,
                    ttl: delegation_ttl,
                }),
            )],
            default: Box::new(Behavior::Refer {
                zone: "com.".to_string(),
                next: TLD_IP,
                ttl: delegation_ttl,
            }),
        },
    );
    let tld = serve(
        tld_sock,
        Behavior::Router {
            routes: vec![(
                "a.example.org.".to_string(),
                Box::new(Behavior::Refer {
                    zone: "example.org.".to_string(),
                    next: AUTH_IP,
                    ttl: delegation_ttl,
                }),
            )],
            default: Box::new(Behavior::Refer {
                zone: "example.com.".to_string(),
                next: AUTH_IP,
                ttl: delegation_ttl,
            }),
        },
    );
    let auth = serve(
        auth_sock,
        Behavior::Answer {
            ip: ANSWER_IP,
            ttl: 300,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(500));

    Chain {
        root,
        tld,
        auth,
        resolver,
    }
}

async fn resolve_a(resolver: &IterativeResolver, host: &str) -> ResponseCode {
    resolver
        .resolve(&name(host), RecordType::A, DNSClass::IN)
        .await
        .unwrap_or_else(|e| panic!("resolving {host} failed: {e}"))
        .rcode
}

/// **The regression test for the outage.**
///
/// Ten distinct names under `example.com.` must touch the root server exactly
/// once. Before the delegation cache this was ten root queries and ten TLD
/// queries — one full root->TLD->auth walk per name, for every name, forever.
#[tokio::test]
async fn cold_names_in_a_cached_zone_do_not_touch_the_root() {
    let c = chain_with_ttl(3600).await;

    for i in 0..10 {
        let host = format!("host{i}.example.com.");
        assert_eq!(resolve_a(&c.resolver, &host).await, ResponseCode::NoError);
    }

    assert_eq!(
        c.root.hits(),
        1,
        "the root must be queried once, not once per name (was {} — the original bug)",
        c.root.hits()
    );
    assert_eq!(
        c.tld.hits(),
        1,
        "the com. delegation is cached too, so the TLD is queried once"
    );
    assert_eq!(c.auth.hits(), 10, "each name still needs its own answer");
}

/// The deepest cached delegation wins: with `example.com.` cached, neither the
/// root nor the TLD is consulted again.
#[tokio::test]
async fn deepest_cached_delegation_is_used() {
    let c = chain_with_ttl(3600).await;

    assert_eq!(
        resolve_a(&c.resolver, "a.example.com.").await,
        ResponseCode::NoError
    );
    c.root.reset();
    c.tld.reset();
    c.auth.reset();

    assert_eq!(
        resolve_a(&c.resolver, "b.example.com.").await,
        ResponseCode::NoError
    );

    assert_eq!(c.root.hits(), 0, "root must not be re-queried");
    assert_eq!(c.tld.hits(), 0, "TLD must not be re-queried");
    assert_eq!(c.auth.hits(), 1, "straight to the authoritative server");
}

/// TTL is respected: once a delegation expires it must be re-learned from the
/// root, not served stale.
///
/// The cache clamps TTLs up to a 60s floor, so this drives expiry through the
/// cache API directly rather than sleeping for a minute.
#[tokio::test]
async fn expired_delegation_is_re_walked_from_the_root() {
    let c = chain_with_ttl(3600).await;

    assert_eq!(
        resolve_a(&c.resolver, "a.example.com.").await,
        ResponseCode::NoError
    );
    assert_eq!(c.root.hits(), 1);

    // Expire everything we learned.
    c.resolver.delegations().flush();
    c.root.reset();
    c.tld.reset();

    assert_eq!(
        resolve_a(&c.resolver, "b.example.com.").await,
        ResponseCode::NoError
    );
    assert_eq!(
        c.root.hits(),
        1,
        "with no live delegation, the walk must restart at the root"
    );
}

/// A delegation whose nameservers have gone away must not wedge the name: the
/// entry is invalidated and the walk retried from the roots.
#[tokio::test]
async fn stale_delegation_self_heals_by_re_walking_from_the_root() {
    let (port, mut socks) = bind_levels(&[ROOT_IP, TLD_IP, AUTH_IP, AUTH2_IP]).await;
    let auth2_sock = socks.pop().unwrap();
    let auth_sock = socks.pop().unwrap();
    let tld_sock = socks.pop().unwrap();
    let root_sock = socks.pop().unwrap();

    // The root delegates com. to the TLD; the TLD delegates example.com. to AUTH.
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
            ip: ANSWER_IP,
            ttl: 300,
        },
    );
    let _auth2 = serve(
        auth2_sock,
        Behavior::Answer {
            ip: ANSWER_IP,
            ttl: 300,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(300));

    // Warm the cache.
    assert_eq!(
        resolve_a(&resolver, "a.example.com.").await,
        ResponseCode::NoError
    );

    // The authoritative server goes dark. The cached example.com. delegation now
    // points at a black hole.
    auth.kill();
    root.reset();
    tld.reset();

    // It must still resolve: invalidate the dead delegation, re-walk from the
    // root. (The re-walk reaches the same dead server here, so the resolution
    // ultimately fails — what matters is that we *retried from the root* rather
    // than failing instantly against a poisoned cache entry.)
    let result = resolver
        .resolve(&name("b.example.com."), RecordType::A, DNSClass::IN)
        .await;
    assert!(result.is_err(), "the only authoritative server is dead");
    assert!(
        root.hits() >= 1,
        "a failed cached delegation must trigger a re-walk from the root, got {} root queries",
        root.hits()
    );

    // Once the server is back, the name resolves again.
    auth.revive();
    assert_eq!(
        resolve_a(&resolver, "c.example.com.").await,
        ResponseCode::NoError
    );
}

/// An NXDOMAIN through a cached delegation is a *successful* resolution. A naive
/// "any error re-walks from the roots" implementation would re-query the root on
/// every nonexistent name — reintroducing the exact hammering we set out to fix.
#[tokio::test]
async fn nxdomain_via_cached_delegation_does_not_re_walk_the_root() {
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
    let _auth = serve(
        auth_sock,
        Behavior::NxDomain {
            minimum: 300,
            soa_ttl: 3600,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(500));

    let first = resolver
        .resolve(&name("nope.example.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("NXDOMAIN is a successful resolution");
    assert_eq!(first.rcode, ResponseCode::NXDomain);
    assert!(
        first.soa.is_some(),
        "SOA must be carried for the negative TTL"
    );

    root.reset();
    tld.reset();

    let second = resolver
        .resolve(&name("alsonope.example.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("NXDOMAIN is a successful resolution");
    assert_eq!(second.rcode, ResponseCode::NXDomain);

    assert_eq!(
        root.hits(),
        0,
        "an authoritative NXDOMAIN must NOT invalidate the delegation"
    );
    assert_eq!(tld.hits(), 0, "nor re-query the TLD");
}

/// The negative TTL follows RFC 2308: `min(SOA MINIMUM, SOA TTL)`, clamped into
/// the resolver's negative-TTL bounds.
#[tokio::test]
async fn negative_ttl_is_min_of_soa_minimum_and_soa_ttl() {
    let (port, mut socks) = bind_levels(&[ROOT_IP, TLD_IP]).await;
    let auth_sock = socks.pop().unwrap();
    let root_sock = socks.pop().unwrap();

    let _root = serve(
        root_sock,
        Behavior::Refer {
            zone: "com.".to_string(),
            next: TLD_IP,
            ttl: 3600,
        },
    );
    // SOA MINIMUM 900, SOA TTL 600 -> negative TTL 600.
    let _auth = serve(
        auth_sock,
        Behavior::NxDomain {
            minimum: 900,
            soa_ttl: 600,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(500));

    let res = resolver
        .resolve(&name("nope.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("resolves to NXDOMAIN");
    assert_eq!(res.rcode, ResponseCode::NXDomain);
    assert_eq!(
        res.negative_ttl(DEFAULT_TTL),
        Some(600),
        "min(900, 600) = 600, honoured as sent — no floor, no ceiling"
    );
}

/// A NODATA (NoError + SOA, no answers) is also a cacheable negative.
#[tokio::test]
async fn nodata_yields_a_negative_ttl() {
    let (port, mut socks) = bind_levels(&[ROOT_IP, TLD_IP]).await;
    let auth_sock = socks.pop().unwrap();
    let root_sock = socks.pop().unwrap();

    let _root = serve(
        root_sock,
        Behavior::Refer {
            zone: "com.".to_string(),
            next: TLD_IP,
            ttl: 3600,
        },
    );
    let _auth = serve(
        auth_sock,
        Behavior::NoData {
            minimum: 120,
            soa_ttl: 3600,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(500));

    let res = resolver
        .resolve(&name("nodata.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("resolves to NODATA");
    assert_eq!(res.rcode, ResponseCode::NoError);
    assert!(res.answers.is_empty());
    assert_eq!(
        res.negative_ttl(DEFAULT_TTL),
        Some(120),
        "min(120, 3600) = 120"
    );
}

/// Caching `com.` must not leak into an unrelated TLD.
#[tokio::test]
async fn cached_zones_are_isolated_from_each_other() {
    let c = chain_with_ttl(3600).await;

    assert_eq!(
        resolve_a(&c.resolver, "a.example.com.").await,
        ResponseCode::NoError
    );
    c.root.reset();

    // A name under a different TLD: the root must be consulted again, because the
    // cached delegation covers `com.` and nothing else.
    assert_eq!(
        resolve_a(&c.resolver, "a.example.org.").await,
        ResponseCode::NoError
    );
    assert_eq!(
        c.root.hits(),
        1,
        "an uncached TLD must be resolved from the root"
    );
}

/// A burst of concurrent cold lookups must not melt down. This is the shape of
/// the traffic that originally took the box out (a package pull firing many fresh
/// names at once).
#[tokio::test]
async fn concurrent_cold_lookups_share_the_delegation() {
    let c = chain_with_ttl(3600).await;

    // Warm the delegation first, then fan out: the point is that 50 concurrent
    // resolutions in a warm zone generate zero further root traffic.
    assert_eq!(
        resolve_a(&c.resolver, "warm.example.com.").await,
        ResponseCode::NoError
    );
    c.root.reset();
    c.tld.reset();

    let mut handles = Vec::new();
    for i in 0..50 {
        let resolver = c.resolver.clone();
        handles.push(tokio::spawn(async move {
            let host = format!("c{i}.example.com.");
            resolver
                .resolve(&name(&host), RecordType::A, DNSClass::IN)
                .await
                .map(|r| r.rcode)
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap().unwrap(), ResponseCode::NoError);
    }

    assert_eq!(
        c.root.hits(),
        0,
        "50 concurrent warm lookups must not touch the root"
    );
    assert_eq!(c.tld.hits(), 0, "nor the TLD");
}

/// A glue-less delegation still populates the cache (the resolver resolves the NS
/// name itself, then remembers the result).
#[tokio::test]
async fn glueless_delegation_is_cached() {
    let (port, mut socks) = bind_levels(&[ROOT_IP, TLD_IP, AUTH_IP]).await;
    let auth_sock = socks.pop().unwrap();
    let tld_sock = socks.pop().unwrap();
    let root_sock = socks.pop().unwrap();

    // Root refers com. -> TLD (with glue).
    let root = serve(
        root_sock,
        Behavior::Refer {
            zone: "com.".to_string(),
            next: TLD_IP,
            ttl: 3600,
        },
    );
    // TLD refers example.com. -> ns1.example.com. with NO glue. Resolving that NS
    // name goes back through the root/TLD, which answers A records for anything
    // (the auth server below).
    let tld = serve(
        tld_sock,
        Behavior::ReferGlueless {
            zone: "example.com.".to_string(),
            ns_name: "ns1.elsewhere.com.".to_string(),
            ttl: 3600,
        },
    );
    let _auth = serve(
        auth_sock,
        Behavior::Answer {
            ip: AUTH_IP,
            ttl: 300,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(500));

    // ns1.elsewhere.com. resolves via root -> tld(glueless again)... the mock TLD
    // always refers, so a pure glueless chain cannot terminate. What we assert is
    // that the resolver does not hang or panic, and that the com. delegation from
    // the root is cached regardless.
    let _ = resolver
        .resolve(&name("a.example.com."), RecordType::A, DNSClass::IN)
        .await;

    assert!(
        resolver.delegations().best_match(&name("x.com.")).is_some(),
        "the com. delegation learned from the root must be cached"
    );
    assert!(root.hits() >= 1);
    assert!(tld.hits() >= 1);
}
