//! ZONEMD (RFC 8976): storage, wire encoding, serving, and signing.
//!
//! ZONEMD was the one record type in the advertised set with **no test at any
//! layer** — not storage, not `canonical_rdata`, not serving, not signing. That
//! matters more for this type than for most, because ZONEMD is itself a zone
//! integrity digest: a record whose entire purpose is to be parsed and compared
//! byte-for-byte by something else. An encoding that is merely self-consistent
//! is a wrong answer that only a third party ever discovers.
//!
//! The encoder is shared. `dnssec::canonical_rdata` produces both the bytes the
//! signer hashes and — via `opaque_rdata` in `src/dns_server.rs` — the RDATA put
//! on the wire, so one bug shows up as two different failures at a validator: a
//! signature that will not verify, and a record a client cannot parse. Tests
//! here therefore pin the byte layout **against the RFC's field order**, spelled
//! out longhand, rather than against whatever the encoder currently emits:
//! comparing the encoder to itself would ratify the bug.
//!
//! RFC 8976 §2.2 gives the RDATA as:
//!
//! ```text
//!     Serial          4 octets, network order
//!     Scheme          1 octet
//!     Hash Algorithm  1 octet
//!     Digest          at least 12 octets, raw (not hex)
//! ```
//!
//! and the stored presentation form here is `"serial scheme hash_algorithm
//! hex_digest"`, matching how every other numeric-field type in this database is
//! stored.
//!
//! Everything is in-memory; the host is untouched.

use rolodex_dns::db::{Database, DnsRecord, RecordKind};
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::dnsbl::{DnsblChecker, DnsblResolver};
use rolodex_dns::dnssec::{self, DnssecAlgorithm, KeyType, Rrsig};
use rolodex_dns::grpc_service::proto;
use rolodex_dns::grpc_service::proto::rolodex_dns_service_server::RolodexDnsService;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

/// A SHA-384 digest (RFC 8976 hash algorithm 1), 48 octets, as hex.
const SHA384_DIGEST_HEX: &str = "\
1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809\
1a2b3c4d5e6f708192a3b4c5d6e7f809";

/// A SHA-512 digest (hash algorithm 2), 64 octets, as hex — the longer of the
/// two registered algorithms, used to prove nothing truncates.
const SHA512_DIGEST_HEX: &str = "\
00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\
00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

const ZONE: &str = "example.com.";

/// ZONEMD as a query type.
///
/// `hickory_proto` has no `RecordType::ZONEMD` variant, so it travels as
/// `Unknown(63)` — the same shape `opaque_rdata` puts on the wire. The 63 is
/// written out here rather than taken from `RecordKind::ZONEMD.wire_type()` so
/// these tests do not agree with the encoder by construction.
const ZONEMD_TYPE: RecordType = RecordType::Unknown(63);

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
    let dnsbl = Arc::new(DnsblChecker::with_resolver(Arc::new(NeverListedResolver)));
    let dns_server = Arc::new(DnsServer::new(db.clone(), dnsbl.clone(), vec![]));
    let service = rolodex_dns::grpc_service::RolodexDnsGrpcService::new(
        db.clone(),
        dns_server.clone(),
        dnsbl,
        String::new(),
        true,
    );
    (service, db, dns_server)
}

fn zonemd(name: &str, value: &str) -> DnsRecord {
    DnsRecord {
        id: None,
        name: name.to_string(),
        record_type: RecordKind::ZONEMD,
        value: value.to_string(),
        ttl: 300,
        priority: 0,
    }
}

fn build_query(name: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(0x2D2D);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut query = Query::new();
    query.set_name(Name::from_ascii(name).expect("name"));
    query.set_query_type(qtype);
    query.set_query_class(DNSClass::IN);
    msg.add_query(query);
    msg.to_bytes().expect("encode query")
}

// ============================================================================
// Type identity
// ============================================================================

/// ZONEMD is type 63 (RFC 8976 §2). The wire type is what the signer writes into
/// the RRSIG's Type Covered field and what a client's question is matched
/// against, so a wrong constant here is invisible locally and fatal remotely.
#[test]
fn zonemd_is_wire_type_63() {
    assert_eq!(
        RecordKind::ZONEMD.wire_type(),
        63,
        "ZONEMD must be IANA type 63"
    );
}

/// The presentation name round-trips, so a record stored by the CLI or gRPC
/// comes back as the same kind rather than falling through to an untyped path.
#[test]
fn the_zonemd_type_name_round_trips() {
    assert_eq!(RecordKind::ZONEMD.as_str(), "ZONEMD");
    assert_eq!(
        RecordKind::parse("ZONEMD"),
        Some(RecordKind::ZONEMD),
        "the stored type name does not parse back to ZONEMD"
    );
    assert_eq!(
        RecordKind::parse("zonemd"),
        Some(RecordKind::ZONEMD),
        "type-name parsing must be case-insensitive"
    );
}

/// The proto enum discriminant round-trips both ways. gRPC carries the type as
/// an integer, so a one-sided mapping turns every ZONEMD record added over the
/// API into a different type on the way back out.
#[test]
fn the_zonemd_proto_discriminant_round_trips() {
    let code = RecordKind::ZONEMD.to_proto_i32();
    assert_eq!(
        RecordKind::from_proto_i32(code),
        Some(RecordKind::ZONEMD),
        "ZONEMD's proto discriminant {code} does not map back to ZONEMD"
    );
}

// ============================================================================
// Wire encoding
// ============================================================================

/// The load-bearing test: the RDATA layout, spelled out field by field from
/// RFC 8976 §2.2 rather than taken from the encoder.
///
/// The digest is checked to be the **raw** bytes, not the hex text. Storing hex
/// and emitting hex is the natural mistake — the value round-trips through the
/// database perfectly and looks right in `list-records` — and it doubles the
/// RDATA length while making the digest compare unequal at every consumer.
#[test]
fn zonemd_rdata_follows_the_rfc_8976_field_order() {
    let record = zonemd(ZONE, &format!("2024010101 1 1 {SHA384_DIGEST_HEX}"));
    let encoded = dnssec::canonical_rdata(&record).expect("ZONEMD must encode");

    let digest = hex::decode(SHA384_DIGEST_HEX).expect("test digest is hex");

    let mut expected = Vec::new();
    expected.extend_from_slice(&2024010101u32.to_be_bytes()); // Serial
    expected.push(1); // Scheme: SIMPLE
    expected.push(1); // Hash Algorithm: SHA-384
    expected.extend_from_slice(&digest); // Digest, raw

    assert_eq!(
        encoded, expected,
        "ZONEMD RDATA does not match the RFC 8976 §2.2 field order"
    );
    assert_eq!(
        encoded.len(),
        4 + 1 + 1 + 48,
        "ZONEMD RDATA is {} octets; a SHA-384 digest gives 4+1+1+48",
        encoded.len()
    );
    assert_eq!(
        &encoded[6..],
        digest.as_slice(),
        "the digest was not encoded as raw octets"
    );
}

/// A serial above `i32::MAX` must survive. Serials are unsigned 32-bit and real
/// zones do exceed it (a date-based serial passes 2^31 in 2038, and
/// seconds-since-epoch serials passed it in 2038 terms long ago); parsing into a
/// signed type would wrap or fail on exactly the zones that are hardest to
/// debug.
#[test]
fn a_serial_above_i32_max_encodes_intact() {
    let serial: u32 = 4_294_967_295;
    let record = zonemd(ZONE, &format!("{serial} 1 1 {SHA384_DIGEST_HEX}"));
    let encoded = dnssec::canonical_rdata(&record).expect("ZONEMD must encode");

    assert_eq!(
        &encoded[..4],
        &serial.to_be_bytes(),
        "a serial above i32::MAX did not survive encoding"
    );
}

/// SHA-512 (hash algorithm 2) produces a 64-octet digest. Encoding must carry it
/// whole rather than truncating to the SHA-384 length or to the RFC's 12-octet
/// minimum.
#[test]
fn a_sha512_digest_is_not_truncated() {
    let record = zonemd(ZONE, &format!("2024010101 1 2 {SHA512_DIGEST_HEX}"));
    let encoded = dnssec::canonical_rdata(&record).expect("ZONEMD must encode");

    assert_eq!(encoded[5], 2, "the hash algorithm octet is not SHA-512");
    assert_eq!(
        encoded.len(),
        4 + 1 + 1 + 64,
        "a SHA-512 ZONEMD encoded to {} octets rather than 70",
        encoded.len()
    );
    assert_eq!(
        &encoded[6..],
        hex::decode(SHA512_DIGEST_HEX).expect("hex").as_slice(),
        "the SHA-512 digest was altered in encoding"
    );
}

/// A malformed value must encode to nothing rather than to something.
///
/// This is the failure mode the signer's "unencodable types are skipped, not
/// approximated" rule exists for: a digest that is not hex, a missing field, or
/// a non-numeric serial has no canonical encoding, and inventing one produces a
/// signature that fails at every validator instead of leaving the record
/// unsigned. `None` here is what makes that skip happen.
#[test]
fn a_malformed_zonemd_value_does_not_encode() {
    for (label, value) in [
        ("missing the digest", "2024010101 1 1"),
        ("missing scheme and algorithm", "2024010101"),
        ("empty", ""),
        (
            "a non-hex digest",
            "2024010101 1 1 not-hex-at-all-not-hex-at-all",
        ),
        (
            "an odd-length hex digest",
            "2024010101 1 1 1a2b3c4d5e6f708192a3b4c5d6e7f80",
        ),
        ("a non-numeric serial", "serial 1 1 1a2b3c4d5e6f7081"),
        (
            "a scheme that is not an octet",
            "2024010101 999 1 1a2b3c4d5e6f7081",
        ),
    ] {
        assert!(
            dnssec::canonical_rdata(&zonemd(ZONE, value)).is_none(),
            "a ZONEMD value {label} produced an encoding: {value:?}"
        );
    }
}

// ============================================================================
// Storage
// ============================================================================

/// A ZONEMD record added over gRPC comes back as a ZONEMD record with its value
/// intact. The type crosses the API as an integer and the value as a string, so
/// this is where a mismapped discriminant or a mangled value would land.
#[tokio::test]
async fn a_zonemd_record_round_trips_through_grpc() {
    let (service, _db, _server) = make_service();
    let value = format!("2024010101 1 1 {SHA384_DIGEST_HEX}");

    let added = service
        .add_record(tonic::Request::new(proto::AddRecordRequest {
            record: Some(proto::DnsRecord {
                name: ZONE.to_string(),
                record_type: RecordKind::ZONEMD.to_proto_i32(),
                value: value.clone(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: String::new(),
        }))
        .await
        .expect("add_record transport")
        .into_inner();
    assert!(
        added.success,
        "adding a ZONEMD record failed: {}",
        added.message
    );

    let listed = service
        .list_records(tonic::Request::new(proto::ListRecordsRequest {
            name_filter: ZONE.to_string(),
            record_type_filter: RecordKind::ZONEMD.to_proto_i32(),
            filter_by_type: true,
            auth_token: String::new(),
        }))
        .await
        .expect("list_records transport")
        .into_inner();

    assert_eq!(listed.records.len(), 1, "the ZONEMD record was not listed");
    assert_eq!(
        listed.records[0].record_type,
        RecordKind::ZONEMD.to_proto_i32(),
        "the listed record came back as a different type"
    );
    assert_eq!(
        listed.records[0].value, value,
        "the ZONEMD value was altered in storage"
    );
}

// ============================================================================
// Serving
// ============================================================================

/// A ZONEMD query must be answered with a ZONEMD record under type 63, carrying
/// the encoded RDATA — not with a TXT holding the presentation string, which is
/// what an unhandled type falls back to and which no ZONEMD consumer can use.
#[tokio::test]
async fn a_zonemd_query_is_answered_under_its_own_type() {
    let (_service, db, server) = make_service();
    let value = format!("2024010101 1 1 {SHA384_DIGEST_HEX}");
    db.add_record(&zonemd(ZONE, &value)).expect("add ZONEMD");

    let response = Message::from_bytes(
        &server
            .handle_query(&build_query(ZONE, ZONEMD_TYPE))
            .await
            .expect("ZONEMD query"),
    )
    .expect("parse response");

    assert_eq!(
        response.response_code(),
        ResponseCode::NoError,
        "a stored ZONEMD answered {:?}",
        response.response_code()
    );
    assert_eq!(response.answers().len(), 1, "one ZONEMD was stored");
    assert_eq!(
        response.answers()[0].record_type(),
        ZONEMD_TYPE,
        "a ZONEMD query was answered with {:?}",
        response.answers()[0].record_type()
    );
}

/// What is served must be byte-identical to what the signer hashes. The two come
/// from the same encoder today; this pins that they stay that way, because a
/// zone whose served RDATA and signed RDATA differ validates correctly in
/// isolation on both halves and fails only when a resolver checks one against
/// the other.
#[tokio::test]
async fn served_zonemd_rdata_matches_the_signed_bytes() {
    let (_service, db, server) = make_service();
    let value = format!("2024010101 1 1 {SHA384_DIGEST_HEX}");
    db.add_record(&zonemd(ZONE, &value)).expect("add ZONEMD");

    let stored = db.lookup(ZONE, Some(RecordKind::ZONEMD)).expect("lookup");
    assert_eq!(stored.len(), 1);
    let expected = dnssec::canonical_rdata(&stored[0]).expect("canonical rdata");

    let response = Message::from_bytes(
        &server
            .handle_query(&build_query(ZONE, ZONEMD_TYPE))
            .await
            .expect("ZONEMD query"),
    )
    .expect("parse response");
    let served = response.answers()[0]
        .data()
        .to_bytes()
        .expect("encode served rdata");

    assert_eq!(
        served, expected,
        "served ZONEMD RDATA is not the bytes the signer would hash"
    );
}

/// A stored ZONEMD whose value cannot be encoded must not be served as some
/// other shape. Dropping it leaves the name answering NODATA, which is a
/// truthful "there is nothing usable here"; serving a TXT or a zero-length
/// record would be a lie a consumer acts on.
#[tokio::test]
async fn an_unencodable_zonemd_is_not_served() {
    let (_service, db, server) = make_service();
    db.add_record(&zonemd(ZONE, "2024010101 1 1 not-hex"))
        .expect("add malformed ZONEMD");

    let response = Message::from_bytes(
        &server
            .handle_query(&build_query(ZONE, ZONEMD_TYPE))
            .await
            .expect("ZONEMD query"),
    )
    .expect("parse response");

    for answer in response.answers() {
        assert_ne!(
            answer.record_type(),
            RecordType::TXT,
            "an unencodable ZONEMD was served as a TXT record"
        );
    }
    assert!(
        response.answers().is_empty(),
        "an unencodable ZONEMD was served as {} record(s)",
        response.answers().len()
    );
}

// ============================================================================
// Signing
// ============================================================================

/// A ZONEMD RRset is signable, and its signature must verify against the
/// published DNSKEY like any other RRset.
///
/// The RRSIG's Type Covered is checked explicitly: a signature that verifies but
/// claims to cover the wrong type is not a signature over the ZONEMD as far as a
/// validator is concerned.
#[tokio::test]
async fn a_zonemd_rrset_is_signed_and_verifies() {
    let (service, db, _server) = make_service();

    assert!(
        service
            .generate_dnssec_key(tonic::Request::new(proto::GenerateDnssecKeyRequest {
                zone: ZONE.to_string(),
                algorithm: "ed25519".to_string(),
                key_type: "KSK".to_string(),
                auth_token: String::new(),
            }))
            .await
            .expect("generate_dnssec_key transport")
            .into_inner()
            .success,
        "key generation failed"
    );

    db.add_record(&zonemd(
        ZONE,
        &format!("2024010101 1 1 {SHA384_DIGEST_HEX}"),
    ))
    .expect("add ZONEMD");

    let signed = service
        .sign_zone(tonic::Request::new(proto::SignZoneRequest {
            zone: ZONE.to_string(),
            auth_token: String::new(),
        }))
        .await
        .expect("sign_zone transport")
        .into_inner();
    assert!(signed.success, "sign_zone failed: {}", signed.message);

    let sigs: Vec<Rrsig> = db
        .list_records(&format!("*.{ZONE}"), Some(RecordKind::RRSIG))
        .expect("list RRSIGs")
        .iter()
        .map(|rec| Rrsig::parse(&rec.value).expect("parse RRSIG"))
        .collect();

    let zonemd_sig = sigs
        .iter()
        .find(|s| s.type_covered == RecordKind::ZONEMD)
        .expect("no RRSIG covers the ZONEMD RRset");

    // Rebuild the key from the *published* DNSKEY, as a validator would.
    let published = db.lookup(ZONE, Some(RecordKind::DNSKEY)).expect("DNSKEY");
    assert_eq!(published.len(), 1, "one DNSKEY was published");
    let fields: Vec<&str> = published[0].value.split_whitespace().collect();
    let algorithm = DnssecAlgorithm::parse(fields[2]).expect("algorithm");
    let public_key = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, fields[3])
        .expect("base64 public key");
    let key_type = if fields[0] == "257" {
        KeyType::KSK
    } else {
        KeyType::ZSK
    };
    assert_eq!(
        zonemd_sig.key_tag,
        dnssec::compute_key_tag(algorithm, key_type, &public_key),
        "the ZONEMD RRSIG names a key tag that is not in the DNSKEY RRset"
    );

    let rrset = db.lookup(ZONE, Some(RecordKind::ZONEMD)).expect("lookup");
    dnssec::verify_rrsig(&zonemd_sig.to_value(), ZONE, &rrset, &public_key)
        .expect("the ZONEMD RRSIG does not verify against the published DNSKEY");
}

/// A ZONEMD whose value cannot be encoded must be **skipped and reported**, not
/// signed over an invented encoding. Reported matters as much as skipped: a
/// silent skip leaves an operator believing a zone is fully signed when one
/// RRset is not.
#[tokio::test]
async fn an_unencodable_zonemd_is_skipped_and_reported() {
    let (service, db, _server) = make_service();

    service
        .generate_dnssec_key(tonic::Request::new(proto::GenerateDnssecKeyRequest {
            zone: ZONE.to_string(),
            algorithm: "ed25519".to_string(),
            key_type: "KSK".to_string(),
            auth_token: String::new(),
        }))
        .await
        .expect("generate_dnssec_key transport");

    db.add_record(&zonemd(ZONE, "2024010101 1 1 not-hex"))
        .expect("add malformed ZONEMD");

    let signed = service
        .sign_zone(tonic::Request::new(proto::SignZoneRequest {
            zone: ZONE.to_string(),
            auth_token: String::new(),
        }))
        .await
        .expect("sign_zone transport")
        .into_inner();

    let covered: Vec<RecordKind> = db
        .list_records(&format!("*.{ZONE}"), Some(RecordKind::RRSIG))
        .expect("list RRSIGs")
        .iter()
        .map(|rec| Rrsig::parse(&rec.value).expect("parse RRSIG").type_covered)
        .collect();

    assert!(
        !covered.contains(&RecordKind::ZONEMD),
        "an unencodable ZONEMD RRset was signed anyway"
    );
    assert!(
        signed.message.to_uppercase().contains("ZONEMD"),
        "the skipped ZONEMD RRset was not named in the response: {:?}",
        signed.message
    );
}
