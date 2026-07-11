//! Glue and intermediate-record caching.
//!
//! The resolver used to discard everything it learned mid-walk. `collect_glue`
//! reduced the additional-section records to bare `Vec<IpAddr>` and the TTLs never
//! left the function; `resolve_ns_addresses` ran an entire sub-recursion to resolve
//! a glueless NS hostname and threw the result away; CNAME hops were accumulated
//! into the answer and forgotten. All of it arrived with a TTL saying exactly how
//! long it was good for.
//!
//! Asserted on **query counts** against the mock hierarchy, as everywhere else here
//! — a cache that "works" but still re-queries upstream is not working.

mod mock_hierarchy;

use hickory_proto::rr::{DNSClass, RecordType};
use mock_hierarchy::{Behavior, bind_levels, name, serve};
use rolodex_dns::resolver::IterativeResolver;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const TLD_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const AUTH_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const ANSWER_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

/// Glue records seen in a referral are cached under the NS hostname they describe,
/// with their TTL — rather than being reduced to bare addresses and dropped.
#[tokio::test]
async fn glue_records_are_cached_under_their_nameserver_name() {
    let (port, mut socks) = bind_levels(&[ROOT_IP, TLD_IP, AUTH_IP]).await;
    let auth_sock = socks.pop().unwrap();
    let tld_sock = socks.pop().unwrap();
    let root_sock = socks.pop().unwrap();

    let _root = serve(
        root_sock,
        Behavior::Refer {
            zone: "com.".to_string(),
            next: TLD_IP,
            ttl: 3600,
        },
    );
    let _tld = serve(
        tld_sock,
        Behavior::Refer {
            zone: "example.com.".to_string(),
            next: AUTH_IP,
            ttl: 3600,
        },
    );
    let _auth = serve(
        auth_sock,
        Behavior::Answer {
            ip: ANSWER_IP,
            ttl: 300,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(500));

    resolver
        .resolve(&name("a.example.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("resolves");

    // The mock names its nameservers ns1.<zone>. Both referrals carried glue.
    let com_glue = resolver.records().get(&name("ns1.com."), RecordType::A);
    let example_glue = resolver
        .records()
        .get(&name("ns1.example.com."), RecordType::A);

    assert!(
        com_glue.is_some(),
        "the root's glue for ns1.com. must be cached, not discarded"
    );
    assert!(
        example_glue.is_some(),
        "the TLD's glue for ns1.example.com. must be cached, not discarded"
    );
}

/// A glueless delegation resolves the NS hostname once. A second name in the same
/// zone must reuse it rather than re-running the whole sub-recursion.
#[tokio::test]
async fn a_glueless_nameserver_is_resolved_once_not_per_query() {
    let (port, mut socks) = bind_levels(&[ROOT_IP, TLD_IP, AUTH_IP]).await;
    let auth_sock = socks.pop().unwrap();
    let tld_sock = socks.pop().unwrap();
    let root_sock = socks.pop().unwrap();

    // Root refers com. -> TLD, with glue.
    let root = serve(
        root_sock,
        Behavior::Refer {
            zone: "com.".to_string(),
            next: TLD_IP,
            ttl: 3600,
        },
    );
    // TLD refers example.com. -> ns1.elsewhere.com. with NO glue, so resolving that
    // hostname is a whole sub-recursion — but it *answers* for the hostname itself,
    // as a real nameserver would. A level that referred glueless even when asked to
    // resolve its own NS name would send the resolver into an exponential
    // sub-recursion (which is how the query-budget cap got found).
    let tld = serve(
        tld_sock,
        Behavior::Router {
            routes: vec![(
                "ns1.elsewhere.com.".to_string(),
                Box::new(Behavior::Answer {
                    ip: AUTH_IP,
                    ttl: 3600,
                }),
            )],
            default: Box::new(Behavior::ReferGlueless {
                zone: "example.com.".to_string(),
                ns_name: "ns1.elsewhere.com.".to_string(),
                ttl: 3600,
            }),
        },
    );
    let _auth = serve(
        auth_sock,
        Behavior::Answer {
            ip: ANSWER_IP,
            ttl: 3600,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(300));

    let _ = resolver
        .resolve(&name("a.example.com."), RecordType::A, DNSClass::IN)
        .await;

    let root_after_first = root.hits();
    let tld_after_first = tld.hits();

    let _ = resolver
        .resolve(&name("b.example.com."), RecordType::A, DNSClass::IN)
        .await;

    assert_eq!(
        root.hits(),
        root_after_first,
        "the second query must not go back to the root"
    );
    assert_eq!(
        tld.hits(),
        tld_after_first,
        "nor re-resolve the glueless nameserver via the TLD"
    );
}

/// An already-resolved name is served from the record cache without touching the
/// network again — the mechanism CNAME chains and NS-name lookups ride on.
#[tokio::test]
async fn a_resolved_name_is_served_from_the_record_cache() {
    let (port, mut socks) = bind_levels(&[ROOT_IP, TLD_IP]).await;
    let auth_sock = socks.pop().unwrap();
    let root_sock = socks.pop().unwrap();

    let root = serve(
        root_sock,
        Behavior::Refer {
            zone: "com.".to_string(),
            next: TLD_IP,
            ttl: 3600,
        },
    );
    let auth = serve(
        auth_sock,
        Behavior::Answer {
            ip: ANSWER_IP,
            ttl: 3600,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(500));

    resolver
        .resolve(&name("host.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("resolves");

    root.reset();
    auth.reset();

    resolver
        .resolve(&name("host.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("resolves from cache");

    assert_eq!(root.hits(), 0, "no root traffic for a cached name");
    assert_eq!(auth.hits(), 0, "no authoritative traffic for a cached name");
}

/// Cached records are handed back with their **remaining** lifetime, not their
/// original TTL.
///
/// Without this decay a cached record would be re-cached upstream at full TTL each
/// time it was served, and a record with a 1h TTL would never actually expire.
#[tokio::test]
async fn cached_records_are_returned_with_a_decaying_ttl() {
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
        Behavior::Answer {
            ip: ANSWER_IP,
            ttl: 10,
        },
    );

    let resolver = IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(500));

    resolver
        .resolve(&name("host.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("resolves");

    tokio::time::sleep(Duration::from_millis(2100)).await;

    let cached = resolver
        .records()
        .get(&name("host.com."), RecordType::A)
        .expect("still live");
    let ttl = cached[0].ttl();
    assert!(
        ttl < 10,
        "the served TTL must have decayed from the original 10s, got {ttl}"
    );
    assert!(ttl > 0, "but the entry is still live");
}
