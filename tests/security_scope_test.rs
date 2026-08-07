//! Security regression tests for network-scope source classification.
//!
//! These assert behaviour the classifier *should* have and are expected to FAIL
//! against the current implementation. Do not weaken an assertion to make one
//! pass.
//!
//! `IpCidr::contains` deliberately returns false across address families
//! (`src/cidr.rs`), and nothing anywhere in the tree calls `to_canonical()` or
//! `to_ipv4_mapped()`. On a dual-stack listener — `[::]:53`, a documented and
//! supported bind form, and the default behaviour on Linux where
//! `net.ipv6.bindv6only=0` — a query from the IPv4 overlay peer `10.64.0.1`
//! arrives with source `::ffff:10.64.0.1`.
//!
//! That address is an `IpAddr::V6`, so `is_overlay_peer` returns false and the
//! peer is classified as a *trusted local source*. Both halves of the
//! split-horizon then break:
//!
//! - an overlay peer joined to no scope is no longer REFUSED, and
//! - a peer that *did* `JoinNetwork` loses its scope, because the association
//!   was stored under the plain IPv4 form.
//!
//! The fix is to canonicalize the source address once, before classification.
//! Each test states the invariant for the mapped form and pins the plain IPv4
//! form alongside it as a control, so a regression in either is visible.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rolodex_dns::db::{Database, DnsRecord, NetworkAssociation, NetworkScope, RecordKind};
use rolodex_dns::dns_server::{DnsServer, ResolutionMode};
use rolodex_dns::rbl::RblChecker;
use std::net::IpAddr;
use std::sync::Arc;

/// The overlay peer used throughout, in both spellings.
const PEER_V4: &str = "10.64.0.1";
const PEER_V4_MAPPED: &str = "::ffff:10.64.0.1";

fn build_query(name: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(0x7777);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(Name::from_ascii(name).unwrap());
    q.set_query_type(qtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    msg.to_bytes().unwrap()
}

/// A server with one network scope defined.
///
/// Resolution is pinned to `forward` with an empty forwarder list so a name that
/// escapes local lookup SERVFAILs immediately. Without that the default `auto`
/// mode would walk the real root servers — these tests are about classification,
/// and must not depend on (or touch) the network.
fn make_scoped_server() -> (Arc<DnsServer>, Database) {
    let db = Database::open_memory().unwrap();
    db.create_network_scope(&NetworkScope {
        name: "office".to_string(),
        home_domain: "office.home.".to_string(),
    })
    .unwrap();
    let rbl = Arc::new(RblChecker::new(false, vec![]));
    let server = Arc::new(DnsServer::new(db.clone(), rbl, vec![]));
    server.set_resolution_mode(ResolutionMode::Forward);
    (server, db)
}

async fn rcode_from(server: &DnsServer, source: &str, name: &str) -> ResponseCode {
    let ip: IpAddr = source.parse().unwrap();
    let query = build_query(name, RecordType::A);
    let wire = server.handle_query_from(&query, ip).await.unwrap();
    Message::from_bytes(&wire).unwrap().response_code()
}

/// Returns the A record served to `source` for `name`, if any.
async fn answer_from(server: &DnsServer, source: &str, name: &str) -> Option<String> {
    let ip: IpAddr = source.parse().unwrap();
    let query = build_query(name, RecordType::A);
    let wire = server.handle_query_from(&query, ip).await.unwrap();
    let msg = Message::from_bytes(&wire).unwrap();
    msg.answers().iter().find_map(|r| match r.data() {
        RData::A(a) => Some(a.0.to_string()),
        _ => None,
    })
}

// ============================================================================
// Unjoined overlay peers must be refused, in either spelling
// ============================================================================

/// An overlay peer that has joined no network is REFUSED — it is not a member of
/// anything, so it gets no view. Written in plain IPv4 this works today; this is
/// the control that proves the harness exercises the enforcement path.
#[tokio::test]
async fn unjoined_overlay_peer_is_refused_ipv4() {
    let (server, _db) = make_scoped_server();
    assert_eq!(
        rcode_from(&server, PEER_V4, "anything.example.").await,
        ResponseCode::Refused,
        "an overlay peer joined to no scope must be refused"
    );
}

/// The same peer, same packet, arriving on a dual-stack listener. The mapped
/// form must be classified identically — otherwise every overlay peer bypasses
/// scope enforcement simply because the socket was bound `[::]` instead of
/// `0.0.0.0`, and reaches the global namespace it was meant to be partitioned
/// away from.
#[tokio::test]
async fn unjoined_overlay_peer_is_refused_ipv4_mapped() {
    let (server, _db) = make_scoped_server();
    assert_eq!(
        rcode_from(&server, PEER_V4_MAPPED, "anything.example.").await,
        ResponseCode::Refused,
        "an IPv4-mapped overlay peer ({}) must be classified as an overlay peer, \
         not as a trusted local source",
        PEER_V4_MAPPED
    );
}

// ============================================================================
// Joined overlay peers must keep their scope, in either spelling
// ============================================================================

/// A peer that joined a scope resolves that scope's records. Plain IPv4 control.
#[tokio::test]
async fn joined_overlay_peer_sees_scoped_record_ipv4() {
    let (server, db) = make_scoped_server();
    db.join_network(&NetworkAssociation {
        ip_address: PEER_V4.to_string(),
        scope_name: "office".to_string(),
        ttl_seconds: 300,
    })
    .unwrap();
    db.add_scoped_record(
        "office",
        &DnsRecord {
            id: None,
            name: "printer.office.home.".to_string(),
            record_type: RecordKind::A,
            value: "10.64.0.50".to_string(),
            ttl: 300,
            priority: 0,
        },
    )
    .unwrap();

    assert_eq!(
        answer_from(&server, PEER_V4, "printer.office.home.").await,
        Some("10.64.0.50".to_string()),
        "a joined overlay peer must resolve its scope's records"
    );
}

/// The same joined peer arriving in mapped form must resolve the same scoped
/// record. Today the association lookup misses, so the peer silently loses its
/// split-horizon view — the failure is a wrong answer rather than an error,
/// which is why it needs pinning.
#[tokio::test]
async fn joined_overlay_peer_sees_scoped_record_ipv4_mapped() {
    let (server, db) = make_scoped_server();
    db.join_network(&NetworkAssociation {
        ip_address: PEER_V4.to_string(),
        scope_name: "office".to_string(),
        ttl_seconds: 300,
    })
    .unwrap();
    db.add_scoped_record(
        "office",
        &DnsRecord {
            id: None,
            name: "printer.office.home.".to_string(),
            record_type: RecordKind::A,
            value: "10.64.0.50".to_string(),
            ttl: 300,
            priority: 0,
        },
    )
    .unwrap();

    assert_eq!(
        answer_from(&server, PEER_V4_MAPPED, "printer.office.home.").await,
        Some("10.64.0.50".to_string()),
        "a joined overlay peer arriving as {} must resolve the same scoped record \
         as {}; the source address must be canonicalized before the association \
         lookup",
        PEER_V4_MAPPED,
        PEER_V4
    );
}

// ============================================================================
// Genuine local sources stay trusted, in either spelling
// ============================================================================

/// The mirror invariant: canonicalizing the source must not start refusing real
/// local traffic. A LAN address outside the overlay range is a trusted local
/// source whether it arrives as IPv4 or IPv4-mapped, and a real IPv6 loopback
/// client is trusted too.
#[tokio::test]
async fn local_sources_remain_trusted_in_both_spellings() {
    let (server, _db) = make_scoped_server();
    for source in ["192.168.1.10", "::ffff:192.168.1.10", "::1", "127.0.0.1"] {
        let rcode = rcode_from(&server, source, "anything.example.").await;
        assert_ne!(
            rcode,
            ResponseCode::Refused,
            "{} is not an overlay address and must remain a trusted local source",
            source
        );
    }
}
