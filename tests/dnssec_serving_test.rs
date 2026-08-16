//! DNSSEC on the **serving** side: signatures must reach the client, and a
//! negative must arrive with a proof a validator can check.
//!
//! `tests/dnssec_signing_test.rs` pins that `SignZone` produces verifiable
//! RRSIGs. That is a statement about the database. This file is the other half —
//! whether any of it reaches the wire — and until recently the answer was no:
//! signing stored RRSIG rows that no query path ever fetched, so a signed zone
//! answered every positive query bare and every negative one with a naked rcode.
//! A validating resolver reads a missing signature in a zone that publishes
//! DNSKEYs as *stripped*, not as unsigned, so the zone was bogus on every
//! answer while every signing test stayed green.
//!
//! The invariant here is that a response is **checkable by its recipient**.
//! Asserting that an RRSIG or an NSEC appeared would pass for a signature over
//! the wrong bytes or a proof covering the wrong range, and both of those fail
//! at a resolver rather than here. So the tests re-derive verification from the
//! published DNSKEY, and check NSEC ranges against the name actually asked
//! about — the same two things a validator does.
//!
//! Every case carries its control. A server that attached signatures to
//! everything would satisfy "the answer is signed"; one that never withheld a
//! stale proof would satisfy "a proof is present". The pairs are: a DO client
//! against a non-DO client, a signed zone against an unsigned one, and a proof
//! served against a proof deliberately withheld.

use rolodex_dns::db::{Database, DnsRecord, RecordKind};
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::dnsbl::{DnsblChecker, DnsblResolver};
use rolodex_dns::dnssec::{self, DnssecAlgorithm, KeyType, Nsec, Rrsig};
use rolodex_dns::grpc_service::proto;
use rolodex_dns::grpc_service::proto::rolodex_dns_service_server::RolodexDnsService;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

const ZONE: &str = "example.com.";

// ========================================================
// Harness
// ========================================================

struct NeverListedResolver;

#[async_trait::async_trait]
impl DnsblResolver for NeverListedResolver {
    async fn lookup(
        &self,
        _query: &str,
    ) -> Result<Option<rolodex_dns::dnsbl::DnsblAnswer>, anyhow::Error> {
        Ok(None)
    }
}

fn make_service() -> (
    rolodex_dns::grpc_service::RolodexDnsGrpcService,
    Database,
    Arc<DnsServer>,
) {
    let db = Database::open_memory().expect("open memory db");
    let rbl = Arc::new(DnsblChecker::with_resolver(Arc::new(NeverListedResolver)));
    let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
    let service = rolodex_dns::grpc_service::RolodexDnsGrpcService::new(
        db.clone(),
        dns_server.clone(),
        rbl,
        String::new(),
        true,
    );
    (service, db, dns_server)
}

fn record(name: &str, kind: RecordKind, value: &str) -> DnsRecord {
    DnsRecord {
        id: None,
        name: name.to_string(),
        record_type: kind,
        value: value.to_string(),
        ttl: 300,
        priority: 0,
    }
}

async fn generate_key(
    service: &rolodex_dns::grpc_service::RolodexDnsGrpcService,
    zone: &str,
    key_type: &str,
) {
    let resp = service
        .generate_dnssec_key(tonic::Request::new(proto::GenerateDnssecKeyRequest {
            zone: zone.to_string(),
            algorithm: "ED25519".to_string(),
            key_type: key_type.to_string(),
            auth_token: String::new(),
        }))
        .await
        .expect("generate_dnssec_key transport")
        .into_inner();
    assert!(resp.success, "key generation failed: {}", resp.message);
}

async fn sign_zone(service: &rolodex_dns::grpc_service::RolodexDnsGrpcService, zone: &str) {
    let resp = service
        .sign_zone(tonic::Request::new(proto::SignZoneRequest {
            zone: zone.to_string(),
            auth_token: String::new(),
        }))
        .await
        .expect("sign_zone transport")
        .into_inner();
    assert!(resp.success, "sign_zone failed: {}", resp.message);
}

/// A query, with the DO bit set or not. `dnssec_ok` is the whole difference
/// between the two halves of every control pair here.
fn build_query(name: &str, qtype: RecordType, dnssec_ok: bool) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(rand::random::<u16>());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut query = Query::new();
    query.set_name(Name::from_ascii(name).expect("name"));
    query.set_query_type(qtype);
    query.set_query_class(DNSClass::IN);
    msg.add_query(query);

    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(4096);
    edns.set_dnssec_ok(dnssec_ok);
    edns.set_version(0);
    msg.set_edns(edns);

    msg.to_bytes().expect("encode query")
}

async fn ask(server: &Arc<DnsServer>, name: &str, qtype: RecordType, dnssec_ok: bool) -> Message {
    let wire = server
        .handle_query(&build_query(name, qtype, dnssec_ok))
        .await
        .expect("handle_query");
    Message::from_bytes(&wire).expect("parse response")
}

/// The zone every test starts from: an apex with SOA, one v4-only host, and a
/// TLSA under a `_tcp` label so the chain has an empty non-terminal in it.
async fn signed_zone() -> (
    rolodex_dns::grpc_service::RolodexDnsGrpcService,
    Database,
    Arc<DnsServer>,
) {
    let (service, db, server) = make_service();
    db.add_authoritative_zone(ZONE).expect("declare zone");
    for r in [
        record(
            ZONE,
            RecordKind::SOA,
            "ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 900",
        ),
        record("host.example.com.", RecordKind::A, "192.0.2.10"),
        record(
            "_443._tcp.host.example.com.",
            RecordKind::TLSA,
            "3 1 1 abcdef0123456789",
        ),
    ] {
        db.add_record(&r).expect("add record");
    }
    generate_key(&service, ZONE, "KSK").await;
    generate_key(&service, ZONE, "ZSK").await;
    sign_zone(&service, ZONE).await;
    (service, db, server)
}

fn records_of(section: &[Record], rtype: RecordType) -> Vec<&Record> {
    section
        .iter()
        .filter(|r| r.record_type() == rtype)
        .collect()
}

/// Re-derives verification the way a validator does: from the published DNSKEY
/// RRset alone, never from the private keys.
fn verify_against_published_keys(
    db: &Database,
    owner: &str,
    covered: RecordKind,
    rrset: &[DnsRecord],
) -> bool {
    let sigs = db
        .rrsigs_covering(owner, covered)
        .expect("rrsigs_covering")
        .into_iter()
        .filter_map(|r| Rrsig::parse(&r.value).ok())
        .collect::<Vec<_>>();
    assert!(!sigs.is_empty(), "no RRSIG covering {owner} {covered:?}");

    let keys = db.lookup(ZONE, Some(RecordKind::DNSKEY)).expect("DNSKEY");
    for sig in &sigs {
        for key in &keys {
            let fields: Vec<&str> = key.value.split_whitespace().collect();
            let flags: u16 = fields[0].parse().expect("flags");
            let algorithm = DnssecAlgorithm::parse(fields[2]).expect("algorithm");
            let public_key =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, fields[3])
                    .expect("base64");
            let key_type = if flags == 257 {
                KeyType::KSK
            } else {
                KeyType::ZSK
            };
            if dnssec::compute_key_tag(algorithm, key_type, &public_key) != sig.key_tag {
                continue;
            }
            // Re-render the RRSIG rather than reusing the stored string, so the
            // stored form is proven to round-trip through parse/encode intact.
            if dnssec::verify_rrsig(&sig.to_value(), owner, rrset, &public_key).is_ok() {
                return true;
            }
        }
    }
    false
}

// ========================================================
// Positive answers
// ========================================================

/// A signed zone answers a DO client with the RRSIG beside the record, and that
/// signature verifies against the DNSKEY the zone publishes.
///
/// The control is the same query without DO: the answer must carry the record
/// and *not* the signature. Without it, a server that attached RRSIGs to every
/// answer regardless would pass — and that is not a harmless difference, since a
/// signed A answer is roughly three times the size of a bare one and a large
/// answer to a small question is the amplification shape the recursion CIDRs
/// exist to close.
#[tokio::test]
async fn a_signed_answer_carries_a_verifiable_signature_only_for_do_clients() {
    let (_service, db, server) = signed_zone().await;

    let with_do = ask(&server, "host.example.com.", RecordType::A, true).await;
    assert_eq!(with_do.response_code(), ResponseCode::NoError);
    assert_eq!(
        records_of(with_do.answers(), RecordType::A).len(),
        1,
        "the record itself is still answered"
    );
    assert_eq!(
        records_of(with_do.answers(), RecordType::RRSIG).len(),
        1,
        "a DO client must receive the signature with the record"
    );

    assert!(
        verify_against_published_keys(
            &db,
            "host.example.com.",
            RecordKind::A,
            &db.lookup("host.example.com.", Some(RecordKind::A))
                .expect("lookup A"),
        ),
        "the served signature must verify against the published DNSKEY"
    );

    let without_do = ask(&server, "host.example.com.", RecordType::A, false).await;
    assert_eq!(
        records_of(without_do.answers(), RecordType::A).len(),
        1,
        "the control still gets its answer"
    );
    assert!(
        records_of(without_do.answers(), RecordType::RRSIG).is_empty(),
        "a client that did not set DO asked for no signatures"
    );
}

/// An **unsigned** zone answers a DO client with no signature and no proof.
///
/// This is the control for the whole file: without it, every assertion below
/// would also be satisfied by a server that emitted DNSSEC records
/// indiscriminately.
#[tokio::test]
async fn an_unsigned_zone_carries_no_dnssec_records() {
    let (_service, db, server) = make_service();
    db.add_authoritative_zone(ZONE).expect("declare zone");
    db.add_record(&record("host.example.com.", RecordKind::A, "192.0.2.10"))
        .expect("add record");

    let positive = ask(&server, "host.example.com.", RecordType::A, true).await;
    assert_eq!(records_of(positive.answers(), RecordType::A).len(), 1);
    assert!(
        records_of(positive.answers(), RecordType::RRSIG).is_empty(),
        "an unsigned zone has no signature to attach"
    );

    let negative = ask(&server, "absent.example.com.", RecordType::A, true).await;
    assert_eq!(negative.response_code(), ResponseCode::NXDomain);
    assert!(
        records_of(negative.name_servers(), RecordType::NSEC).is_empty(),
        "an unsigned zone has no chain to prove anything with"
    );
}

// ========================================================
// Negative answers
// ========================================================

/// NODATA arrives with the name's own NSEC, and that NSEC's type bitmap is the
/// proof: it lists the types that *are* there, and the absence of the queried
/// one from that list is what a validator checks.
///
/// So this asserts on the bitmap contents rather than on the record's presence.
/// An NSEC that claimed AAAA would be a proof of the opposite of what the
/// response says, and merely counting records would not notice.
#[tokio::test]
async fn nodata_proves_the_type_absent_via_the_bitmap() {
    let (_service, db, server) = signed_zone().await;

    let resp = ask(&server, "host.example.com.", RecordType::AAAA, true).await;
    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert!(resp.answers().is_empty(), "NODATA carries no answer");

    let nsecs = records_of(resp.name_servers(), RecordType::NSEC);
    assert_eq!(nsecs.len(), 1, "NODATA needs exactly the name's own NSEC");
    assert_eq!(
        nsecs[0].name().to_string(),
        "host.example.com.",
        "the proof is the NSEC at the queried name"
    );

    let stored = db
        .lookup("host.example.com.", Some(RecordKind::NSEC))
        .expect("lookup NSEC");
    let nsec = Nsec::parse(&stored[0].value).expect("parse NSEC");
    assert!(
        nsec.types.contains(&RecordKind::A),
        "the bitmap must claim the type that IS present"
    );
    assert!(
        !nsec.types.contains(&RecordKind::AAAA),
        "and must not claim the type the response says is absent"
    );

    // The SOA rides along with its own signature: a validator authenticates the
    // negative TTL from the same section it reads it in.
    assert_eq!(records_of(resp.name_servers(), RecordType::SOA).len(), 1);
    assert!(
        records_of(resp.name_servers(), RecordType::RRSIG).len() >= 2,
        "both the SOA and the NSEC must be signed, got {:?}",
        resp.name_servers()
    );

    assert!(
        verify_against_published_keys(&db, "host.example.com.", RecordKind::NSEC, &stored),
        "the served NSEC must verify against the published DNSKEY"
    );
}

/// NXDOMAIN arrives with an NSEC whose range actually covers the queried name,
/// checked by re-deriving the range rather than trusting that a record appeared.
///
/// A proof that covers the wrong interval is the failure mode that matters: it
/// looks identical in the response and is rejected at every validator.
#[tokio::test]
async fn nxdomain_proves_the_name_absent_with_a_covering_nsec() {
    let (_service, _db, server) = signed_zone().await;

    let resp = ask(&server, "nothere.example.com.", RecordType::A, true).await;
    assert_eq!(resp.response_code(), ResponseCode::NXDomain);

    let nsecs = records_of(resp.name_servers(), RecordType::NSEC);
    assert!(!nsecs.is_empty(), "NXDOMAIN must carry a denial proof");

    let covers_qname = nsecs.iter().any(|rec| {
        let Some(nsec) = nsec_from_wire(rec) else {
            return false;
        };
        dnssec::nsec_covers(
            &rec.name().to_string(),
            &nsec.next_owner,
            "nothere.example.com.",
        )
    });
    assert!(
        covers_qname,
        "no served NSEC covers the queried name: {:?}",
        nsecs
    );

    // The wildcard denial: without it a validator cannot rule out that a
    // wildcard would have synthesized an answer, and RFC 4035 §5.4 has it
    // reject the whole response.
    let covers_wildcard = nsecs.iter().any(|rec| {
        let Some(nsec) = nsec_from_wire(rec) else {
            return false;
        };
        dnssec::nsec_covers(&rec.name().to_string(), &nsec.next_owner, "*.example.com.")
    });
    assert!(
        covers_wildcard,
        "no served NSEC denies the wildcard: {:?}",
        nsecs
    );
}

/// The chain includes empty non-terminals, so a query at one gets NODATA with a
/// proof rather than NXDOMAIN.
///
/// `_tcp.host.example.com.` holds no records while `_443._tcp.host.example.com.`
/// holds a TLSA. Leaving the parent out of the chain would put it inside another
/// link's range — a signed assertion that it does not exist, contradicting the
/// child that proves it does.
#[tokio::test]
async fn an_empty_non_terminal_has_no_nsec_but_is_still_proved() {
    let (_service, db, server) = signed_zone().await;

    // RFC 4035 §2.3: an NSEC goes at each name with authoritative data, and must
    // never be the only RRset at a name. An ENT has neither, so it gets none —
    // inserting them is an NSEC3 rule (RFC 5155 §7.1), not an NSEC one.
    let stored = db
        .lookup_no_wildcard("_tcp.host.example.com.", Some(RecordKind::NSEC))
        .expect("lookup NSEC");
    assert!(
        stored.is_empty(),
        "an empty non-terminal must not be given an NSEC of its own"
    );

    // The control: a name that DOES hold data has one.
    assert_eq!(
        db.lookup_no_wildcard("host.example.com.", Some(RecordKind::NSEC))
            .expect("lookup NSEC")
            .len(),
        1,
        "a name with authoritative data is chained"
    );

    // It still exists, so the answer is NODATA — proved by the link covering it.
    let resp = ask(&server, "_tcp.host.example.com.", RecordType::A, true).await;
    assert_eq!(
        resp.response_code(),
        ResponseCode::NoError,
        "an empty non-terminal exists, so this is NODATA"
    );
    let nsecs = records_of(resp.name_servers(), RecordType::NSEC);
    assert_eq!(nsecs.len(), 1, "the covering link is the proof");
    assert_ne!(
        nsecs[0].name().to_string(),
        "_tcp.host.example.com.",
        "and it is a link at some other owner, not one invented for the ENT"
    );
}

/// A name a wildcard matches is established by it (RFC 4592 §2.2.1), so a type
/// the wildcard lacks is NODATA — and the proof is the **wildcard's** NSEC,
/// because the queried name is not literally in the chain and has none.
///
/// NXDOMAIN here would be unprovable as well as wrong: that proof needs an NSEC
/// covering `*.example.com.`, and no such record can exist while the wildcard
/// does, so the response would go out a record short and be rejected.
#[tokio::test]
async fn a_wildcard_matched_name_is_proved_through_the_wildcards_nsec() {
    let (service, db, server) = make_service();
    db.add_authoritative_zone(ZONE).expect("declare zone");
    for r in [
        record(
            ZONE,
            RecordKind::SOA,
            "ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 900",
        ),
        record("*.example.com.", RecordKind::A, "192.0.2.99"),
    ] {
        db.add_record(&r).expect("add record");
    }
    generate_key(&service, ZONE, "KSK").await;
    generate_key(&service, ZONE, "ZSK").await;
    sign_zone(&service, ZONE).await;

    // The control: the wildcard answers for this name.
    let a = ask(&server, "anything.example.com.", RecordType::A, true).await;
    assert_eq!(a.response_code(), ResponseCode::NoError);
    assert_eq!(
        records_of(a.answers(), RecordType::A).len(),
        1,
        "the wildcard synthesizes an A"
    );

    let aaaa = ask(&server, "anything.example.com.", RecordType::AAAA, true).await;
    assert_eq!(
        aaaa.response_code(),
        ResponseCode::NoError,
        "a wildcard-established name is NODATA for a type it lacks"
    );

    // RFC 4035 §3.1.3.4 requires TWO records here, and only sending the first is
    // a proof a validator rejects: the wildcard's own NSEC (showing it carries
    // no record of the queried type) AND one proving no closer match exists —
    // without which a name between the wildcard and the query could have won.
    let nsecs = records_of(aaaa.name_servers(), RecordType::NSEC);
    let owners: Vec<String> = nsecs.iter().map(|r| r.name().to_string()).collect();
    assert!(
        owners.contains(&"*.example.com.".to_string()),
        "the wildcard's own NSEC must be present: {owners:?}"
    );
    let proves_no_closer_match = nsecs.iter().any(|rec| {
        nsec_from_wire(rec).is_some_and(|nsec| {
            dnssec::nsec_covers(
                &rec.name().to_string(),
                &nsec.next_owner,
                "anything.example.com.",
            )
        })
    });
    assert!(
        proves_no_closer_match,
        "no served NSEC rules out a closer match than the wildcard: {owners:?}"
    );

    let stored = db
        .lookup("*.example.com.", Some(RecordKind::NSEC))
        .expect("lookup NSEC");
    let nsec = Nsec::parse(&stored[0].value).expect("parse");
    assert!(
        nsec.types.contains(&RecordKind::A),
        "the bitmap claims what the wildcard carries"
    );
    assert!(
        !nsec.types.contains(&RecordKind::AAAA),
        "and not the type the response denies"
    );
}

/// The address-family filter takes an RRSIG with the RRset it covers.
///
/// On a v4-only box the filter drops AAAA records from the answer section. If
/// the signature stayed behind, a validator would receive an RRSIG covering an
/// RRset that is not in the message — indistinguishable from a stripping attack,
/// and *bogus* rather than merely unsigned. Filtering breaks the signature
/// either way (RFC 4035 wants the whole RRset), so the honest outcome is no
/// signature at all.
///
/// The control is the A record in the same response: it and its RRSIG both
/// survive, so this is not "the filter deletes signatures".
#[tokio::test]
async fn the_family_filter_takes_the_signature_with_the_rrset() {
    let (service, db, server) = make_service();
    db.add_authoritative_zone(ZONE).expect("declare zone");
    for r in [
        record(
            ZONE,
            RecordKind::SOA,
            "ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 900",
        ),
        record("dual.example.com.", RecordKind::A, "192.0.2.10"),
        record("dual.example.com.", RecordKind::AAAA, "2001:db8::1"),
    ] {
        db.add_record(&r).expect("add record");
    }
    generate_key(&service, ZONE, "KSK").await;
    generate_key(&service, ZONE, "ZSK").await;
    sign_zone(&service, ZONE).await;

    // The control: with both families served, the AAAA and its signature ride.
    let both = ask(&server, "dual.example.com.", RecordType::AAAA, true).await;
    assert_eq!(records_of(both.answers(), RecordType::AAAA).len(), 1);
    assert_eq!(
        records_of(both.answers(), RecordType::RRSIG).len(),
        1,
        "the control: a signed AAAA normally carries its RRSIG"
    );

    // Now serve v4 only.
    server.set_answer_families(true, false);

    let filtered = ask(&server, "dual.example.com.", RecordType::AAAA, true).await;
    assert!(
        records_of(filtered.answers(), RecordType::AAAA).is_empty(),
        "the v6 answer is filtered out"
    );
    assert!(
        records_of(filtered.answers(), RecordType::RRSIG).is_empty(),
        "and its signature must not be left behind without it"
    );

    // The other control: the A record and its signature are untouched by a
    // v4-only filter, so the rule is about the dropped family and not about
    // signatures in general.
    let kept = ask(&server, "dual.example.com.", RecordType::A, true).await;
    assert_eq!(records_of(kept.answers(), RecordType::A).len(), 1);
    assert_eq!(
        records_of(kept.answers(), RecordType::RRSIG).len(),
        1,
        "the surviving family keeps its signature"
    );
}

/// An oversized UDP response sets TC and sheds its authority section.
///
/// RFC 4035 §3.1.3 ends each denial rule with "if space does not permit
/// inclusion of these NSEC and RRSIG RRs, the name server MUST set the TC bit".
/// This server set TC nowhere at all, while `edns.rs` echoes the client's stated
/// payload size straight back at it — so a signed NXDOMAIN (measurably over 512
/// bytes) went out oversized against a stated 512-byte limit. The client does
/// not get a bigger answer; it gets a dropped datagram and a timeout, with
/// nothing to tell it a larger answer exists over TCP.
///
/// The control is the same query at the default 4096, where everything fits and
/// TC stays clear — so this is not "the server always truncates".
#[tokio::test]
async fn an_oversized_udp_answer_sets_tc_instead_of_overflowing() {
    // A zone of long names, rather than the shared fixture.
    //
    // The proof for a three-name zone signed with Ed25519 comes to a little
    // UNDER 512 bytes, so against that fixture this test asserted truncation of
    // a response that legitimately fit — and a server correct enough not to set
    // TC on it failed here. Long owner names put the answer unambiguously over
    // the limit (each NSEC carries a 60-octet owner and a 60-octet next name,
    // twice, plus their signatures), so what is being measured is the server's
    // behaviour rather than the fixture's incidental size.
    let (service, db, server) = make_service();
    db.add_authoritative_zone(ZONE).expect("declare zone");
    let long = |c: char| {
        format!(
            "{}.example.com.",
            std::iter::repeat_n(c, 60).collect::<String>()
        )
    };
    let absent = long('n');
    for r in [
        record(
            ZONE,
            RecordKind::SOA,
            "ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 900",
        ),
        record(&long('a'), RecordKind::A, "192.0.2.10"),
        record(&long('m'), RecordKind::A, "192.0.2.11"),
        record(&long('z'), RecordKind::A, "192.0.2.12"),
    ] {
        db.add_record(&r).expect("add record");
    }
    generate_key(&service, ZONE, "KSK").await;
    generate_key(&service, ZONE, "ZSK").await;
    sign_zone(&service, ZONE).await;

    let roomy = ask(&server, &absent, RecordType::A, true).await;
    assert!(
        !roomy.truncated(),
        "the control: it fits in the advertised 4096"
    );
    assert!(
        !records_of(roomy.name_servers(), RecordType::NSEC).is_empty(),
        "and carries its proof"
    );

    // The same query, from a client that says it can take only 512.
    let mut msg = Message::from_bytes(&build_query(&absent, RecordType::A, true)).expect("parse");
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(512);
    edns.set_dnssec_ok(true);
    edns.set_version(0);
    msg.set_edns(edns);
    let wire = server
        .handle_query_proto(
            &msg.to_bytes().expect("encode"),
            None,
            None,
            rolodex_dns::metrics::Proto::Udp,
        )
        .await
        .expect("handle_query_proto");
    let tight = Message::from_bytes(&wire).expect("parse response");

    assert!(
        wire.len() <= 512,
        "a response to a 512-byte client must fit in 512, got {}",
        wire.len()
    );
    assert!(
        tight.truncated(),
        "and must say so, or the client waits out a timeout instead of retrying over TCP"
    );
    assert_eq!(
        tight.response_code(),
        ResponseCode::NXDomain,
        "the rcode survives; it is the authority section that is shed"
    );
}

// ========================================================
// Staleness
// ========================================================

/// A record added after signing must not be denied by the old chain.
///
/// This is the sharp edge of signing being a snapshot: the new name falls inside
/// an existing link's range, so serving that link is a *signed proof that the
/// record just created does not exist*. The proof is withheld instead — the
/// negative still goes out, unsigned, which leaves a validator at "insecure"
/// where a stale proof would leave it at "bogus" and take the zone down.
#[tokio::test]
async fn a_stale_chain_is_withheld_rather_than_served() {
    let (_service, db, server) = signed_zone().await;

    // Control: before the mutation, the zone proves things.
    let before = ask(&server, "nothere.example.com.", RecordType::A, true).await;
    assert!(
        !records_of(before.name_servers(), RecordType::NSEC).is_empty(),
        "the zone proves denials before it is touched"
    );

    db.add_record(&record("fresh.example.com.", RecordKind::A, "192.0.2.20"))
        .expect("add record");
    assert!(
        db.zone_signatures_stale("fresh.example.com."),
        "a mutation to a signed zone must mark it for re-signing"
    );

    let after = ask(&server, "stillnothere.example.com.", RecordType::A, true).await;
    assert_eq!(after.response_code(), ResponseCode::NXDomain);
    assert!(
        records_of(after.name_servers(), RecordType::NSEC).is_empty(),
        "a chain that predates the mutation must not be served as proof"
    );

    // And crucially: the freshly added name is not denied.
    let fresh = ask(&server, "fresh.example.com.", RecordType::A, true).await;
    assert_eq!(
        fresh.response_code(),
        ResponseCode::NoError,
        "the new record answers"
    );
    assert_eq!(records_of(fresh.answers(), RecordType::A).len(), 1);
}

/// The re-sign pass restores the proof, and the new chain covers the name that
/// was added — which is the whole reason the pass exists.
#[tokio::test]
async fn re_signing_restores_the_proof_and_covers_the_new_name() {
    let (_service, db, server) = signed_zone().await;

    db.add_record(&record("fresh.example.com.", RecordKind::A, "192.0.2.20"))
        .expect("add record");
    assert!(db.zone_signatures_stale("fresh.example.com."));

    server.resign_once();
    assert!(
        !db.zone_signatures_stale("fresh.example.com."),
        "a successful pass clears the mark"
    );

    // The new name is now in the chain, with its own NSEC.
    let stored = db
        .lookup("fresh.example.com.", Some(RecordKind::NSEC))
        .expect("lookup NSEC");
    assert_eq!(stored.len(), 1, "the new name joined the chain");

    // Proofs are served again.
    let resp = ask(&server, "stillnothere.example.com.", RecordType::A, true).await;
    assert_eq!(resp.response_code(), ResponseCode::NXDomain);
    assert!(
        !records_of(resp.name_servers(), RecordType::NSEC).is_empty(),
        "the refreshed chain proves denials again"
    );

    // And the new record answers with a signature that verifies.
    assert!(
        verify_against_published_keys(
            &db,
            "fresh.example.com.",
            RecordKind::A,
            &db.lookup("fresh.example.com.", Some(RecordKind::A))
                .expect("lookup A"),
        ),
        "the re-signed record must carry a verifiable signature"
    );
}

/// Acquiring keys schedules the first signing pass.
///
/// `GenerateDnssecKey` flips the zone to "signed" for the answer path, which
/// then expects signatures that do not exist yet. Without the mark, nothing
/// would produce them until an operator remembered to call `SignZone` by hand —
/// and in the meantime every answer would go out bare from a zone advertising
/// DNSKEYs, which is *bogus* rather than unsigned.
#[tokio::test]
async fn generating_a_key_schedules_the_first_signing_pass() {
    let (service, db, _server) = make_service();
    db.add_authoritative_zone(ZONE).expect("declare zone");
    db.add_record(&record("host.example.com.", RecordKind::A, "192.0.2.10"))
        .expect("add record");

    // The control: an unsigned zone schedules nothing.
    assert!(
        !db.zone_signatures_stale("host.example.com."),
        "a zone with no keys has nothing to sign"
    );

    generate_key(&service, ZONE, "ZSK").await;
    assert!(
        db.zone_signatures_stale("host.example.com."),
        "acquiring a key must schedule the pass that produces the signatures"
    );
}

/// Deleting a key schedules a pass too. Until one runs, the revoked key's
/// DNSKEY and every RRSIG it made stay published — so revocation would have no
/// effect on what the server actually serves.
#[tokio::test]
async fn deleting_a_key_schedules_a_republish() {
    let (service, db, server) = signed_zone().await;
    server.resign_once();
    assert!(!db.zone_signatures_stale("host.example.com."));

    let keys = db.list_dnssec_keys(ZONE).expect("list keys");
    let victim = keys.first().expect("at least one key");
    let resp = service
        .delete_dnssec_key(tonic::Request::new(proto::DeleteDnssecKeyRequest {
            key_id: victim.id,
            auth_token: String::new(),
        }))
        .await
        .expect("delete transport")
        .into_inner();
    assert!(resp.success, "delete failed: {}", resp.message);

    assert!(
        db.zone_signatures_stale("host.example.com."),
        "revoking a key must schedule the republish that drops its DNSKEY"
    );
}

/// A restart must not turn "withhold the proof" into "serve an authenticated
/// lie".
///
/// The pending set lives only in memory. A mutation that lands seconds before a
/// restart — or anything that edits the database while the process is down —
/// would otherwise come back as a zone that believes itself current and serves a
/// **validly signed** proof that its own newest record does not exist. That is
/// strictly worse than the unauthenticated staleness this mechanism replaced,
/// so every signed zone is marked at startup.
///
/// Simulated by loading a fresh `Database` over the same file, which is what a
/// restart is.
#[tokio::test]
async fn a_restart_re_marks_every_signed_zone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rolodex.db");

    {
        let db = Database::open(&path).expect("open");
        let rbl = Arc::new(DnsblChecker::with_resolver(Arc::new(NeverListedResolver)));
        let dns = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
        let service = rolodex_dns::grpc_service::RolodexDnsGrpcService::new(
            db.clone(),
            dns.clone(),
            rbl,
            String::new(),
            true,
        );
        db.add_authoritative_zone(ZONE).expect("declare zone");
        db.add_record(&record("host.example.com.", RecordKind::A, "192.0.2.10"))
            .expect("add record");
        generate_key(&service, ZONE, "ZSK").await;
        sign_zone(&service, ZONE).await;
        dns.resign_once();
        assert!(
            !db.zone_signatures_stale("host.example.com."),
            "the control: a freshly signed zone is not stale"
        );
    }

    // The restart.
    let reopened = Database::open(&path).expect("reopen");
    assert!(
        reopened.zone_signatures_stale("host.example.com."),
        "a signed zone must come back marked, since the pending set did not survive"
    );

    // The control: an unsigned zone in the same database is not marked, so this
    // is not "everything is stale after a restart".
    assert!(
        !reopened.zone_signatures_stale("elsewhere.invalid."),
        "a name in no signed zone is never stale"
    );
}

/// Publishing signatures is not itself a zone change, or the loop would never
/// settle: every pass would dirty the zone it had just cleaned.
#[tokio::test]
async fn signing_does_not_dirty_the_zone_it_just_signed() {
    let (_service, db, server) = signed_zone().await;
    assert!(
        !db.zone_signatures_stale("host.example.com."),
        "signing must leave the zone clean"
    );

    server.resign_once();
    assert!(
        !db.zone_signatures_stale("host.example.com."),
        "and a redundant pass must not dirty it either"
    );
}

/// Reads an NSEC back out of a served record, through the wire encoding rather
/// than the stored string — this is what the client actually received.
fn nsec_from_wire(rec: &Record) -> Option<Nsec> {
    // hickory decodes NSEC natively when a response is parsed back off the
    // wire, so this is the form that actually arrives. Reading only the opaque
    // one made every range check here answer `None`, which the callers read as
    // "no NSEC covers the name" — the test failed while the server was right.
    if let Some(nsec) = rec.data().as_dnssec().and_then(|d| d.as_nsec()) {
        return Some(Nsec {
            next_owner: nsec.next_domain_name().to_string(),
            types: Vec::new(),
        });
    }
    let rdata = match rec.data() {
        hickory_proto::rr::RData::Unknown { rdata, .. } => rdata.anything(),
        _ => return None,
    };
    // The next owner name is an uncompressed wire name; decode just far enough
    // to read it back, which is all the range check needs.
    let mut labels = Vec::new();
    let mut i = 0usize;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        if len == 0 {
            break;
        }
        let start = i + 1;
        let end = start + len;
        if end > rdata.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&rdata[start..end]).to_string());
        i = end;
    }
    Some(Nsec {
        next_owner: format!("{}.", labels.join(".")),
        types: Vec::new(),
    })
}
