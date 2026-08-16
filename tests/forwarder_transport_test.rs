//! Typed forwarders: every transport is one `Forwarder`, and plaintext DNS is
//! the one with no encryption rather than a separate concept.
//!
//! These tests are about the two properties that unification is FOR, so each is
//! written with its control:
//!
//!   * **Tier membership is derived from the forwarder, not from the config key
//!     it arrived under.** A test that only checked "DoH lands in the encrypted
//!     tier" would pass against the old code, where DoH could only ever be
//!     written in `secure_upstreams:`. What distinguishes the two is a DoH entry
//!     typed into `forwarders:` — the list that used to be plaintext-only — so
//!     that is what is asserted.
//!   * **A forwarder that cannot answer stops being tried.** A test that a dead
//!     forwarder eventually SERVFAILs passes with or without the circuit
//!     breaker; the difference is *how many times it was dialled*, so the
//!     assertion is a connection count against a listener that never replies.
//!
//! Nothing here reaches the network. The plaintext upstreams are sockets bound
//! on loopback in-process, and the encrypted ones are never dialled — the
//! encrypted-tier assertions are about where a forwarder is filed and whether it
//! is attempted, both of which are decided before a packet is sent.

use rolodex_dns::forwarder::{Forwarder, Preference, Transport, by_preference, carry_health};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn parse(spec: &str) -> Forwarder {
    Forwarder::parse(spec).unwrap_or_else(|e| panic!("parse {spec}: {e}"))
}

/// A UDP socket that accepts a query and never answers, counting what arrived.
///
/// This is the black hole the circuit breaker exists for. A closed port would
/// not do: it produces an ICMP unreachable and fails fast, which is the one
/// case that never needed a breaker. A silent socket is what a filtered
/// network looks like, and is what makes every query pay the full timeout.
async fn black_hole() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind black hole");
    let addr = socket.local_addr().expect("black hole addr");
    let hits = Arc::new(AtomicUsize::new(0));

    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((_, _)) = socket.recv_from(&mut buf).await {
            counter.fetch_add(1, Ordering::Relaxed);
            // Deliberately no reply.
        }
    });

    (addr, hits)
}

#[test]
fn a_bare_address_is_still_a_plaintext_forwarder() {
    let f = parse("8.8.8.8:53");
    assert_eq!(f.transport, Transport::Do53Udp);
    assert_eq!(f.label, "8.8.8.8:53");
    assert!(!f.transport.is_encrypted());
}

/// The assertion that separates unified forwarders from what they replaced.
///
/// Under the old shape an encrypted upstream could only be written in
/// `secure_upstreams:`, so "DoH is in the encrypted tier" was true by
/// construction and proved nothing. Here every one of these arrives through the
/// list that used to accept plaintext socket addresses only.
#[test]
fn encrypted_forwarders_reach_the_encrypted_tier_from_the_plaintext_list() {
    let forwarders: Vec<Forwarder> = [
        "8.8.8.8:53",
        "https://cloudflare-dns.com@1.1.1.1/dns-query",
        "tls://dns.google@8.8.8.8:853",
        "quic://dns.adguard.com@94.140.14.14:853",
        "192.168.122.1:53",
    ]
    .iter()
    .map(|s| parse(s))
    .collect();

    let [encrypted, private, public] = by_preference(&forwarders);

    assert_eq!(
        encrypted
            .iter()
            .map(|f| f.label.as_str())
            .collect::<Vec<_>>(),
        [
            "https://cloudflare-dns.com",
            "tls://dns.google",
            "quic://dns.adguard.com"
        ],
        "every encrypted transport belongs to the encrypted tier"
    );
    assert_eq!(
        private.iter().map(|f| f.label.as_str()).collect::<Vec<_>>(),
        ["192.168.122.1:53"]
    );
    assert_eq!(
        public.iter().map(|f| f.label.as_str()).collect::<Vec<_>>(),
        ["8.8.8.8:53"]
    );
}

/// The control for the test above: derivation must not collapse everything into
/// one tier. Plaintext to a private address and plaintext to a public one are
/// different tiers, and that difference is what makes the gateway preferred
/// over a public resolver on a network that filters :53.
#[test]
fn plaintext_is_split_by_where_it_points() {
    assert_eq!(
        parse("192.168.122.1:53").preference(),
        Preference::PlaintextPrivate
    );
    assert_eq!(
        parse("10.0.0.53:53").preference(),
        Preference::PlaintextPrivate
    );
    assert_eq!(
        parse("8.8.8.8:53").preference(),
        Preference::PlaintextPublic
    );
    assert_eq!(
        parse("1.1.1.1:53").preference(),
        Preference::PlaintextPublic
    );
}

/// A DoT server on the LAN is encrypted, so it outranks the plaintext gateway
/// beside it. Deriving the tier from the destination instead of the transport
/// would get this backwards.
#[test]
fn encryption_outranks_locality() {
    let lan_dot = parse("tls://dns.home@192.168.1.5:853");
    let lan_plain = parse("192.168.1.5:53");
    assert_eq!(lan_dot.preference(), Preference::Encrypted);
    assert_eq!(lan_plain.preference(), Preference::PlaintextPrivate);
    assert!(lan_dot.preference() < lan_plain.preference());
}

/// A dead forwarder must stop being dialled.
///
/// The tier chain is walked on every query, so without a breaker a black-holed
/// forwarder is dialled once per query forever, each time for the full timeout.
/// Ten queries against a socket that never answers must not produce ten dials.
#[tokio::test]
async fn a_black_holed_forwarder_stops_being_dialled() {
    let (addr, hits) = black_hole().await;
    let forwarder = parse(&addr.to_string());

    // Drive the breaker directly rather than through a whole server: what is
    // being asserted is that `is_usable` gates the dial, and the query path
    // consults it before sending. Simulating that consultation keeps the test
    // about the breaker instead of about how a DnsServer is assembled.
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client socket");
    for _ in 0..10 {
        if !forwarder.is_usable() {
            continue;
        }
        socket.send_to(&[0u8; 12], addr).await.expect("send");
        // No answer will come; that is a transport failure.
        forwarder.health.record_failure();
    }

    let dialled = hits.load(Ordering::Relaxed);
    assert!(
        dialled < 10,
        "black-holed forwarder was dialled {dialled} times across 10 queries; \
         the circuit breaker never opened"
    );
    assert!(
        !forwarder.is_usable(),
        "forwarder should be circuit-broken after repeated failures"
    );
}

/// The control for the test above: a forwarder that works must keep being used.
/// A breaker that opened on healthy traffic would be strictly worse than none.
#[tokio::test]
async fn a_working_forwarder_is_never_skipped() {
    let forwarder = parse("127.0.0.1:5353");

    for _ in 0..50 {
        assert!(
            forwarder.is_usable(),
            "a forwarder that keeps answering must never be skipped"
        );
        forwarder.health.record_success();
    }
}

/// An intermittent forwarder must not be evicted by a blip. Failures short of
/// the threshold, interrupted by a success, leave it in service.
#[tokio::test]
async fn an_intermittent_forwarder_stays_in_service() {
    let forwarder = parse("127.0.0.1:5353");

    for _ in 0..20 {
        forwarder.health.record_failure();
        forwarder.health.record_failure();
        forwarder.health.record_success();
        assert!(
            forwarder.is_usable(),
            "two failures and a success must not open the breaker"
        );
    }
}

/// Health has to survive the controller re-pushing an identical list, which it
/// does every few seconds. Without that the breaker resets faster than it can
/// trip and none of the tests above describe the running system.
#[test]
fn health_survives_reprogramming() {
    let installed = vec![parse("8.8.8.8:53")];
    for _ in 0..3 {
        installed[0].health.record_failure();
    }
    assert!(!installed[0].is_usable(), "breaker should be open");

    let mut pushed = vec![parse("8.8.8.8:53"), parse("1.1.1.1:53")];
    carry_health(&installed, &mut pushed);

    assert!(
        !pushed[0].is_usable(),
        "an identical re-push reset the breaker"
    );
    assert!(
        pushed[1].is_usable(),
        "an unrelated forwarder inherited someone else's health"
    );
}

/// A forwarder spec that will not parse must be refused rather than dropped.
///
/// Silently skipping it would leave the caller believing it configured an
/// upstream that is not there — and on the encrypted transports, the difference
/// between a validated name and a typo is the difference between an
/// authenticated upstream and none.
#[test]
fn malformed_specs_are_refused() {
    for spec in [
        "",
        "gopher://8.8.8.8:53",
        "udp://not-an-ip",
        "tls://@8.8.8.8:853",
        "udp://name@8.8.8.8:53",
    ] {
        assert!(
            Forwarder::parse(spec).is_err(),
            "expected {spec:?} to be refused"
        );
    }
}

/// What an API reports has to be something it would accept again, or an
/// operator reading their configuration back cannot re-apply it.
#[test]
fn specs_round_trip() {
    for spec in [
        "8.8.8.8:53",
        "tcp://8.8.8.8:53",
        "tls://dns.google@8.8.8.8:853",
        "https://cloudflare-dns.com@1.1.1.1:443/dns-query",
        "quic://dns.adguard.com@94.140.14.14:853",
    ] {
        let first = parse(spec);
        let second = parse(&first.to_spec());
        assert_eq!(second.transport, first.transport, "{spec}");
        assert_eq!(second.addr, first.addr, "{spec}");
        assert_eq!(second.label, first.label, "{spec}");
        assert_eq!(second.preference(), first.preference(), "{spec}");
    }
}
