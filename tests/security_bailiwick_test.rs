//! Security regression tests for delegation and glue bailiwick enforcement.
//!
//! These assert behaviour the iterative resolver *should* have and are expected
//! to FAIL against the current implementation. Do not weaken an assertion to
//! make one pass.
//!
//! `classify` (`src/resolver.rs`) takes the referral zone from the owner name of
//! whatever NS record happens to be first in the authority section, and never
//! checks that it is at or below the name being resolved — or below the zone
//! whose servers just answered. `walk` then writes it straight into the
//! delegation cache, and `cache_glue` writes the additional-section addresses
//! into the record cache keyed by their own owner names.
//!
//! Neither has a bailiwick check, so **any** nameserver the resolver ever talks
//! to can answer a query about its own zone with a delegation for someone else's:
//!
//! ```text
//! ;; QUESTION     victim.attacker.test.  A
//! ;; AUTHORITY    com.                   NS  ns.attacker.test.
//! ;; ADDITIONAL   ns.attacker.test.      A   127.0.0.1
//! ```
//!
//! Each test walks the resolver **down to the attacker's zone first**, through an
//! honest root referral, before the hostile response is served. That matters:
//! from the root, everything is in bailiwick, so an attack staged at the root
//! hints would prove nothing about the check. The attacker here holds exactly
//! what a real one holds — one delegated zone — and the question is whether the
//! resolver keeps them inside it.
//!
//! `com. -> attacker` lands in the delegation cache, `best_match` walks suffixes,
//! and every subsequent `.com` lookup starts at the attacker's server. The
//! resolver only has to be *asked* for a name in a zone the attacker controls,
//! which is one ad domain or one link away. Worse, a delegation whose TTL exceeds
//! `resolution.delegation_persist_min_ttl` is written to the `delegation_cache`
//! table and reloaded at boot, so the hijack survives a restart.
//!
//! The rule these pin is the standard one: a referral is usable only if the zone
//! it delegates is at or below the name being resolved, and glue is usable only
//! for names inside the delegated zone. Everything else is out of bailiwick and
//! must be discarded — not merely un-followed, but never cached.
//!
//! The assertions are on the **caches**, not on what the lookup returned. Whether
//! one poisoned resolution produces a wrong answer depends on what else is in
//! flight; whether a forged delegation was retained is not ambiguous, and it is
//! the durable half of the damage.
//!
//! Everything is loopback and in-process; the host is untouched.

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rolodex_dns::resolver::IterativeResolver;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;

const SERVER_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
/// The address the forged delegation points at. Any address works; this one is
/// recognizable in a failure message.
const FORGED_NS_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 66);

/// The zone the attacker actually controls — the one a client legitimately asked
/// about, which is all it takes to get the resolver talking to them.
const ATTACKER_ZONE: &str = "attacker.test.";
const ATTACKER_NS: &str = "ns.attacker.test.";

fn name(s: &str) -> Name {
    Name::from_str(s).expect("valid name")
}

/// What the hostile nameserver tries to inject.
#[derive(Clone, Copy)]
enum Injection {
    /// A delegation for a zone the attacker has nothing to do with.
    ForeignZoneDelegation,
    /// A delegation for the root, which sits above everything.
    RootDelegation,
    /// An in-bailiwick delegation carrying glue for a foreign nameserver name.
    ForeignGlue,
}

/// The name the client asks for, which decides which delegation could legitimately
/// cover it.
fn queried_name(injection: Injection) -> Name {
    match injection {
        Injection::ForeignZoneDelegation | Injection::RootDelegation => {
            name("victim.attacker.test.")
        }
        // One label deeper, so the in-bailiwick delegation below actually covers
        // it and the referral is accepted — leaving the additional section as the
        // only thing under test.
        Injection::ForeignGlue => name("victim.sub.attacker.test."),
    }
}

/// The zone the hostile server claims a delegation for.
fn claimed_zone(injection: Injection) -> Name {
    match injection {
        Injection::ForeignZoneDelegation => name("com."),
        Injection::RootDelegation => Name::root(),
        // In bailiwick: a real delegation below the attacker's own zone, covering
        // the queried name. The abuse is in the additional section.
        Injection::ForeignGlue => name("sub.attacker.test."),
    }
}

/// The NS hostname the delegation names, and therefore the owner of the glue.
fn ns_target(injection: Injection) -> Name {
    match injection {
        Injection::ForeignZoneDelegation | Injection::RootDelegation => name(ATTACKER_NS),
        // A hostname in someone else's zone: the glue for it must not be cached
        // on this server's say-so.
        Injection::ForeignGlue => name("ns1.example.com."),
    }
}

/// Builds the hostile referral described in the module docs.
fn build_referral(query: &Message, injection: Injection) -> Vec<u8> {
    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_response_code(ResponseCode::NoError);
    if let Some(q) = query.queries().first() {
        resp.add_query(q.clone());
    }

    let zone = claimed_zone(injection);
    let target = ns_target(injection);

    // A long TTL, so a cached delegation would also be persisted to SQLite.
    resp.add_name_server(Record::from_rdata(
        zone,
        86400,
        RData::NS(rdata::NS(target.clone())),
    ));
    resp.add_additional(Record::from_rdata(
        target,
        86400,
        RData::A(rdata::A(FORGED_NS_ADDR)),
    ));

    resp.to_bytes().unwrap_or_default()
}

/// The honest root referral that delegates `attacker.test.` to a nameserver
/// inside it. This is what puts the resolver's "current zone" at the attacker's
/// zone, which is the state every attack below is staged from.
fn build_honest_delegation(query: &Message) -> Vec<u8> {
    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_response_code(ResponseCode::NoError);
    if let Some(q) = query.queries().first() {
        resp.add_query(q.clone());
    }
    resp.add_name_server(Record::from_rdata(
        name(ATTACKER_ZONE),
        3600,
        RData::NS(rdata::NS(name(ATTACKER_NS))),
    ));
    resp.add_additional(Record::from_rdata(
        name(ATTACKER_NS),
        3600,
        RData::A(rdata::A(SERVER_IP)),
    ));
    resp.to_bytes().unwrap_or_default()
}

/// An authoritative NXDOMAIN, so a walk that rejects the referral terminates
/// instead of timing out.
fn build_nxdomain(query: &Message) -> Vec<u8> {
    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_authoritative(true);
    resp.set_response_code(ResponseCode::NXDomain);
    if let Some(q) = query.queries().first() {
        resp.add_query(q.clone());
    }
    resp.to_bytes().unwrap_or_default()
}

/// A hostile nameserver. Returns `(port, hit counter)`.
///
/// Every nameserver the resolver contacts shares one port (`with_port`), so one
/// socket plays every role in the hierarchy. It answers in three stages:
///
/// 1. as the root, an **honest** referral delegating `attacker.test.` with glue
///    for a nameserver inside it — so the resolver arrives at the attacker's
///    zone the way it would in production;
/// 2. as the attacker's own server, the forged referral;
/// 3. NXDOMAIN, so the walk ends promptly however the forgery was treated.
async fn spawn_hostile_server(injection: Injection) -> (u16, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind((SERVER_IP, 0))
        .await
        .expect("bind hostile nameserver");
    let port = socket.local_addr().expect("addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let seen = counter.fetch_add(1, Ordering::SeqCst);
            let Ok(query) = Message::from_bytes(&buf[..len]) else {
                continue;
            };
            let reply = match seen {
                0 => build_honest_delegation(&query),
                1 => build_referral(&query, injection),
                _ => build_nxdomain(&query),
            };
            if socket.send_to(&reply, peer).await.is_err() {
                return;
            }
        }
    });

    (port, hits)
}

/// A resolver whose only root hint is the hostile server.
fn resolver_for(port: u16) -> IterativeResolver {
    IterativeResolver::new(vec![IpAddr::V4(SERVER_IP)])
        .with_port(port)
        // Short: a rejected referral should end the lookup promptly rather than
        // making the test wait out the default budget.
        .with_timeout(Duration::from_millis(400))
}

/// Drives one lookup against a hostile server and hands back the resolver so the
/// caches can be inspected.
async fn resolve_against(injection: Injection) -> (IterativeResolver, Arc<AtomicUsize>) {
    let (port, hits) = spawn_hostile_server(injection).await;
    let resolver = resolver_for(port);
    // The result is deliberately ignored: whether this particular lookup
    // succeeded is not the property under test.
    let _unused = resolver
        .resolve(&queried_name(injection), RecordType::A, DNSClass::IN)
        .await;
    assert!(
        hits.load(Ordering::SeqCst) > 1,
        "the resolver never got past the honest root referral to the attacker's \
         own server; the test proved nothing"
    );
    (resolver, hits)
}

// ============================================================================
// Out-of-bailiwick delegations
// ============================================================================

/// Asking about a name in the attacker's own zone must not let them install a
/// delegation for a zone above it. `com.` is not below `victim.attacker.test.`,
/// so the referral is out of bailiwick and must be discarded.
///
/// If it is cached, `best_match` finds it for every `.com` name — the resolver
/// has been handed to the attacker, and `delegation_persist_min_ttl` means the
/// handover outlives a restart.
#[tokio::test]
async fn a_foreign_zone_delegation_is_not_cached() {
    let (resolver, _hits) = resolve_against(Injection::ForeignZoneDelegation).await;

    let hijacked = resolver.delegations().best_match(&name("www.example.com."));
    assert!(
        hijacked.is_none(),
        "a nameserver for {} installed a delegation covering www.example.com. \
         ({:?}); a referral must be at or below the name being resolved",
        ATTACKER_ZONE,
        hijacked
    );
}

/// The same attack aimed at the root. `.` sits above every name, so a cached
/// root delegation redirects the entire namespace — including the next attempt
/// to re-learn the roots.
#[tokio::test]
async fn a_root_delegation_is_not_cached_from_a_leaf_zone() {
    let (resolver, _hits) = resolve_against(Injection::RootDelegation).await;

    let root = resolver.delegations().best_match(&Name::root());
    let hijacked = root
        .as_ref()
        .is_some_and(|(_, servers)| servers.contains(&IpAddr::V4(FORGED_NS_ADDR)));
    assert!(
        !hijacked,
        "a nameserver for {} installed a delegation for the root zone ({:?}); \
         no leaf zone may redelegate the namespace above it",
        ATTACKER_ZONE, root
    );
}

// ============================================================================
// Out-of-bailiwick glue
// ============================================================================

/// Glue is only meaningful for nameservers inside the zone being delegated —
/// that is the whole reason it needs to travel in the referral. An address
/// record for a hostname in someone else's zone is unverifiable, and caching it
/// lets any zone dictate where `ns1.example.com` lives for every later glue-less
/// lookup.
///
/// The authority section here is a genuine, in-bailiwick delegation, so this
/// isolates the additional section: a server can be telling the truth about its
/// own subzone and still be lying about a foreign nameserver's address.
#[tokio::test]
async fn glue_for_a_foreign_nameserver_is_not_cached() {
    let (resolver, _hits) = resolve_against(Injection::ForeignGlue).await;

    let cached = resolver
        .records()
        .get(&name("ns1.example.com."), RecordType::A);
    assert!(
        cached.is_none(),
        "a nameserver for {} planted an address for ns1.example.com. ({:?}); \
         glue is only usable for names inside the delegated zone",
        ATTACKER_ZONE,
        cached.map(|r| r.len())
    );
}

// ============================================================================
// Control: legitimate delegation still works
// ============================================================================

/// The mirror invariant, and the reason this cannot simply be "trust no
/// referral": a delegation *below* the queried name is exactly how iterative
/// resolution proceeds, and its glue is exactly what makes it usable. A fix that
/// rejects this has broken the resolver.
#[tokio::test]
async fn an_in_bailiwick_delegation_is_still_followed() {
    let socket = UdpSocket::bind((SERVER_IP, 0))
        .await
        .expect("bind honest nameserver");
    let port = socket.local_addr().expect("addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let seen = counter.fetch_add(1, Ordering::SeqCst);
            let Ok(query) = Message::from_bytes(&buf[..len]) else {
                continue;
            };
            let Some(asked) = query.queries().first().cloned() else {
                continue;
            };

            let mut resp = Message::new();
            resp.set_id(query.id());
            resp.set_message_type(MessageType::Response);
            resp.set_op_code(OpCode::Query);
            resp.set_response_code(ResponseCode::NoError);
            resp.add_query(asked.clone());

            if seen == 0 {
                // Root refers down to the zone containing the name, with glue.
                let zone = name(ATTACKER_ZONE);
                let ns = name("ns.attacker.test.");
                resp.add_name_server(Record::from_rdata(
                    zone,
                    3600,
                    RData::NS(rdata::NS(ns.clone())),
                ));
                resp.add_additional(Record::from_rdata(ns, 3600, RData::A(rdata::A(SERVER_IP))));
            } else {
                resp.set_authoritative(true);
                resp.add_answer(Record::from_rdata(
                    asked.name().clone(),
                    300,
                    RData::A(rdata::A(Ipv4Addr::new(198, 51, 100, 20))),
                ));
            }

            if socket
                .send_to(&resp.to_bytes().unwrap_or_default(), peer)
                .await
                .is_err()
            {
                return;
            }
        }
    });

    let resolver = resolver_for(port);
    let resolution = resolver
        .resolve(&name("victim.attacker.test."), RecordType::A, DNSClass::IN)
        .await
        .expect("an in-bailiwick delegation must resolve");

    assert!(
        resolution.answers.iter().any(|r| matches!(
            r.data(),
            RData::A(rdata::A(ip)) if *ip == Ipv4Addr::new(198, 51, 100, 20)
        )),
        "the answer behind a legitimate delegation must still be returned"
    );
    assert!(
        resolver
            .delegations()
            .best_match(&name("victim.attacker.test."))
            .is_some(),
        "a legitimate delegation must still be cached, or every lookup in the \
         zone walks from the root again"
    );
}
