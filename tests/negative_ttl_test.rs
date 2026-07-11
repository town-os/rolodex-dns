//! Negative-TTL semantics.
//!
//! **The SOA is authoritative.** When a zone publishes an SOA, its negative TTL is
//! honoured exactly as sent — `min(SOA MINIMUM, SOA record TTL)` per RFC 2308, with
//! no floor and no ceiling. Clamping it (as an earlier pass did, into 60s..1h)
//! silently overrides what the zone actually asked for, which is the entire purpose
//! of publishing an SOA.
//!
//! `default_ttl` (300s, configurable) applies **only** when there is no SOA to
//! honour. Declining to cache such a negative would send every lookup of a
//! nonexistent name back to the root servers, forever.

mod mock_hierarchy;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, RecordType};
use mock_hierarchy::{Behavior, bind_levels, name, serve};
use rolodex_dns::resolver::{DEFAULT_TTL, IterativeResolver};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const AUTH_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// Stands up root -> auth, where auth answers every query with `behavior`.
async fn negative_chain(behavior: Behavior) -> IterativeResolver {
    let (port, mut socks) = bind_levels(&[ROOT_IP, AUTH_IP]).await;
    let auth_sock = socks.pop().unwrap();
    let root_sock = socks.pop().unwrap();

    let _root = serve(
        root_sock,
        Behavior::Refer {
            zone: "com.".to_string(),
            next: AUTH_IP,
            ttl: 3600,
        },
    );
    let _auth = serve(auth_sock, behavior);

    // Leak the mocks: they must outlive this function for the resolver to use them.
    std::mem::forget(_root);
    std::mem::forget(_auth);

    IterativeResolver::new(vec![IpAddr::V4(ROOT_IP)])
        .with_port(port)
        .with_timeout(Duration::from_millis(500))
}

/// A short SOA TTL is honoured, **not raised to a floor**.
///
/// The earlier 60s floor would have turned this into 60s, overriding a zone that
/// deliberately publishes a 30s negative TTL because its records churn.
#[tokio::test]
async fn a_short_soa_ttl_is_honoured_not_floored() {
    let resolver = negative_chain(Behavior::NxDomain {
        minimum: 30,
        soa_ttl: 7200,
    })
    .await;

    let res = resolver
        .resolve(&name("nope.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("NXDOMAIN resolves");

    assert_eq!(res.rcode, ResponseCode::NXDomain);
    assert_eq!(
        res.negative_ttl(DEFAULT_TTL),
        Some(30),
        "a 30s SOA MINIMUM must be honoured as sent, not raised to any floor"
    );
}

/// A long SOA TTL is honoured, **not capped**.
///
/// The earlier 1h ceiling would have truncated this to 3600.
#[tokio::test]
async fn a_long_soa_ttl_is_honoured_not_capped() {
    let resolver = negative_chain(Behavior::NxDomain {
        minimum: 86_400,
        soa_ttl: 86_400,
    })
    .await;

    let res = resolver
        .resolve(&name("nope.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("NXDOMAIN resolves");

    assert_eq!(
        res.negative_ttl(DEFAULT_TTL),
        Some(86_400),
        "a 1-day SOA TTL must be honoured as sent, not capped to an hour"
    );
}

/// RFC 2308: the negative TTL is the *lesser* of SOA MINIMUM and the SOA record's
/// own TTL.
#[tokio::test]
async fn the_lesser_of_soa_minimum_and_soa_ttl_wins() {
    let resolver = negative_chain(Behavior::NxDomain {
        minimum: 900,
        soa_ttl: 120,
    })
    .await;

    let res = resolver
        .resolve(&name("nope.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("NXDOMAIN resolves");

    assert_eq!(res.negative_ttl(DEFAULT_TTL), Some(120), "min(900, 120)");
}

/// **No SOA -> the default applies.** 300s out of the box.
#[tokio::test]
async fn an_nxdomain_without_an_soa_uses_the_default_ttl() {
    let resolver = negative_chain(Behavior::NxDomainNoSoa).await;

    let res = resolver
        .resolve(&name("nope.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("NXDOMAIN resolves");

    assert_eq!(res.rcode, ResponseCode::NXDomain);
    assert!(res.soa.is_none(), "the mock sent no SOA");
    assert_eq!(
        res.negative_ttl(DEFAULT_TTL),
        Some(DEFAULT_TTL),
        "with no SOA there is nothing to honour, so the default applies"
    );
    assert_eq!(DEFAULT_TTL, 300, "and the default is 5m");
}

/// The default is configurable.
#[tokio::test]
async fn the_default_negative_ttl_is_configurable() {
    let resolver = negative_chain(Behavior::NxDomainNoSoa).await;

    let res = resolver
        .resolve(&name("nope.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("NXDOMAIN resolves");

    assert_eq!(
        res.negative_ttl(45),
        Some(45),
        "the fallback TTL is whatever the operator configured"
    );
}

/// A positive answer has no negative TTL at all.
#[tokio::test]
async fn a_positive_answer_has_no_negative_ttl() {
    let resolver = negative_chain(Behavior::Answer {
        ip: Ipv4Addr::new(203, 0, 113, 10),
        ttl: 300,
    })
    .await;

    let res = resolver
        .resolve(&name("yes.com."), RecordType::A, DNSClass::IN)
        .await
        .expect("resolves");

    assert!(!res.answers.is_empty());
    assert_eq!(res.negative_ttl(DEFAULT_TTL), None);
}
