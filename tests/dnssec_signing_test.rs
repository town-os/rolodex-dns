//! Zone signing: `SignZone` must actually produce RRSIGs, and those RRSIGs must
//! verify against the DNSKEY the same call publishes.
//!
//! The invariant these tests pin is that a signature is *checkable*. Asserting
//! that RRSIG rows appeared would pass just as happily for a signature computed
//! over the wrong bytes, the wrong owner name, or with a key that is not the one
//! advertised — and every one of those failures surfaces at a validating
//! resolver rather than here. So the central test re-derives the signing input
//! from the published DNSKEY RRset and verifies, which is the same thing a
//! validator does with the zone.
//!
//! `SignZone` previously published DNSKEY records and nothing else while the
//! documentation described it as producing RRSIGs; the key generator separately
//! produced Ed25519 keys labelled as whatever algorithm was asked for. A failure
//! here is that regression returning, not a broken test.

use rolodex_dns::db::{Database, DnsRecord, RecordKind};
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::dnssec::{self, DnssecAlgorithm, KeyType, Rrsig, SigningKey};
use rolodex_dns::grpc_service::proto;
use rolodex_dns::grpc_service::proto::rolodex_dns_service_server::RolodexDnsService;
use rolodex_dns::rbl::{RblChecker, RblResolver};
use std::collections::HashMap;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

// ========================================================
// Helpers
// ========================================================

struct NeverListedResolver;

#[async_trait::async_trait]
impl RblResolver for NeverListedResolver {
    async fn lookup_rbl(
        &self,
        _query: &str,
    ) -> Result<Option<rolodex_dns::rbl::RblAnswer>, anyhow::Error> {
        Ok(None)
    }
}

fn make_rbl() -> Arc<RblChecker> {
    Arc::new(RblChecker::with_resolver(
        false,
        vec![],
        Arc::new(NeverListedResolver),
    ))
}

/// Builds a service over an in-memory database, handing back both so tests can
/// drive the RPC and then inspect what actually landed on disk.
fn make_service() -> (
    rolodex_dns::grpc_service::RolodexDnsGrpcService,
    Database,
    Arc<DnsServer>,
) {
    let db = Database::open_memory().expect("open memory db");
    let rbl = make_rbl();
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
    algorithm: &str,
    key_type: &str,
) -> proto::GenerateDnssecKeyResponse {
    service
        .generate_dnssec_key(tonic::Request::new(proto::GenerateDnssecKeyRequest {
            zone: zone.to_string(),
            algorithm: algorithm.to_string(),
            key_type: key_type.to_string(),
            auth_token: String::new(),
        }))
        .await
        .expect("generate_dnssec_key transport")
        .into_inner()
}

async fn sign_zone(
    service: &rolodex_dns::grpc_service::RolodexDnsGrpcService,
    zone: &str,
) -> proto::SignZoneResponse {
    service
        .sign_zone(tonic::Request::new(proto::SignZoneRequest {
            zone: zone.to_string(),
            auth_token: String::new(),
        }))
        .await
        .expect("sign_zone transport")
        .into_inner()
}

/// A DNSKEY as published at the zone apex, reduced to what verification needs.
struct PublishedKey {
    key_tag: u16,
    algorithm: DnssecAlgorithm,
    public_key: Vec<u8>,
}

/// Parses the apex DNSKEY RRset back out of the database.
///
/// Deliberately re-parses the stored presentation form rather than reaching for
/// the private key rows: a validator only ever has the DNSKEY, so if the
/// signature cannot be checked from this alone, it cannot be checked at all.
fn published_keys(db: &Database, zone: &str) -> Vec<PublishedKey> {
    db.lookup(zone, Some(RecordKind::DNSKEY))
        .expect("lookup DNSKEY")
        .iter()
        .map(|rec| {
            let fields: Vec<&str> = rec.value.split_whitespace().collect();
            assert_eq!(fields.len(), 4, "DNSKEY value {:?}", rec.value);
            let flags: u16 = fields[0].parse().expect("flags");
            assert_eq!(fields[1], "3", "DNSKEY protocol must be 3");
            let algorithm = DnssecAlgorithm::parse(fields[2]).expect("algorithm");
            let public_key =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, fields[3])
                    .expect("base64 public key");
            let key_type = match flags {
                257 => KeyType::KSK,
                _ => KeyType::ZSK,
            };
            PublishedKey {
                key_tag: dnssec::compute_key_tag(algorithm, key_type, &public_key),
                algorithm,
                public_key,
            }
        })
        .collect()
}

/// Every RRSIG in the zone, grouped by the owner name it sits at.
fn rrsigs_in_zone(db: &Database, zone: &str) -> Vec<(String, Rrsig)> {
    db.list_records(&format!("*.{}", zone), Some(RecordKind::RRSIG))
        .expect("list RRSIGs")
        .iter()
        .map(|rec| {
            (
                rec.name.clone(),
                Rrsig::parse(&rec.value).expect("parse RRSIG"),
            )
        })
        .collect()
}

fn build_query(name: &str, qtype: RecordType) -> Vec<u8> {
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
    msg.to_bytes().expect("encode query")
}

// ========================================================
// Signing
// ========================================================

/// The core claim: after `SignZone`, every RRSIG in the zone verifies against
/// the DNSKEY RRset that the same call published.
///
/// This runs across all three supported algorithms and both key types, and over
/// a zone containing multi-record RRsets, embedded names, and out-of-band
/// priorities — the places a canonical-form bug hides.
#[tokio::test]
async fn every_published_rrsig_verifies_against_the_published_dnskey() {
    for algorithm in ["ed25519", "ecdsa-p256", "ecdsa-p384"] {
        let (service, db, _server) = make_service();
        let zone = "example.com.";

        assert!(
            generate_key(&service, zone, algorithm, "KSK").await.success,
            "{algorithm} KSK generation"
        );
        assert!(
            generate_key(&service, zone, algorithm, "ZSK").await.success,
            "{algorithm} ZSK generation"
        );

        for rec in [
            record("example.com.", RecordKind::A, "192.0.2.1"),
            record("www.example.com.", RecordKind::A, "192.0.2.10"),
            record("www.example.com.", RecordKind::A, "192.0.2.11"),
            record("www.example.com.", RecordKind::AAAA, "2001:db8::1"),
            record("alias.example.com.", RecordKind::CNAME, "www.example.com."),
            record("example.com.", RecordKind::NS, "ns1.example.com."),
            record("example.com.", RecordKind::TXT, "v=spf1 -all"),
            record(
                "example.com.",
                RecordKind::SOA,
                "ns1.example.com. admin.example.com. 42 7200 3600 1209600 300",
            ),
        ] {
            db.add_record(&rec).expect("add record");
        }
        let mut mx = record("example.com.", RecordKind::MX, "mail.example.com.");
        mx.priority = 10;
        db.add_record(&mx).expect("add MX");
        let mut srv = record(
            "_sip._tcp.example.com.",
            RecordKind::SRV,
            "5 5060 sip.example.com.",
        );
        srv.priority = 20;
        db.add_record(&srv).expect("add SRV");

        let resp = sign_zone(&service, zone).await;
        assert!(
            resp.success,
            "{algorithm}: sign_zone failed: {}",
            resp.message
        );

        let keys = published_keys(&db, zone);
        assert_eq!(keys.len(), 2, "{algorithm}: KSK and ZSK must be published");
        let by_tag: HashMap<u16, &PublishedKey> = keys.iter().map(|k| (k.key_tag, k)).collect();

        let sigs = rrsigs_in_zone(&db, zone);
        assert!(!sigs.is_empty(), "{algorithm}: no RRSIGs were produced");

        for (owner, rrsig) in &sigs {
            let key = by_tag.get(&rrsig.key_tag).unwrap_or_else(|| {
                panic!("{algorithm}: RRSIG at {owner} names key tag {} which is not in the DNSKEY RRset", rrsig.key_tag)
            });
            assert_eq!(
                rrsig.algorithm, key.algorithm,
                "{algorithm}: RRSIG algorithm must match its DNSKEY"
            );
            assert_eq!(rrsig.signer_name, zone, "{algorithm}: signer name");

            let rrset = db
                .lookup(owner, Some(rrsig.type_covered))
                .expect("lookup covered RRset");
            assert!(
                !rrset.is_empty(),
                "{algorithm}: RRSIG at {owner} covers {} but no such RRset exists",
                rrsig.type_covered.as_str()
            );

            // Re-render the RRSIG rather than reusing the stored string, so the
            // stored form is proven to round-trip through parse/encode intact.
            dnssec::verify_rrsig(&rrsig.to_value(), owner, &rrset, &key.public_key).unwrap_or_else(
                |e| {
                    panic!(
                        "{algorithm}: RRSIG at {owner} covering {} does not verify: {e}",
                        rrsig.type_covered.as_str()
                    )
                },
            );
        }

        // Every signable RRset must have a signature, not just some of them.
        for kind in [
            RecordKind::A,
            RecordKind::AAAA,
            RecordKind::CNAME,
            RecordKind::NS,
            RecordKind::TXT,
            RecordKind::SOA,
            RecordKind::MX,
            RecordKind::SRV,
            RecordKind::DNSKEY,
        ] {
            assert!(
                sigs.iter().any(|(_, s)| s.type_covered == kind),
                "{algorithm}: nothing signed the {} RRset",
                kind.as_str()
            );
        }
    }
}

/// A multi-record RRset gets one signature covering the whole set, not one per
/// record — and that signature must verify against the complete set.
#[tokio::test]
async fn a_multi_record_rrset_is_signed_as_one_set() {
    let (service, db, _server) = make_service();
    let zone = "example.com.";
    generate_key(&service, zone, "ed25519", "ZSK").await;

    for value in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        db.add_record(&record("www.example.com.", RecordKind::A, value))
            .expect("add record");
    }

    assert!(sign_zone(&service, zone).await.success);

    let sigs: Vec<_> = rrsigs_in_zone(&db, zone)
        .into_iter()
        .filter(|(owner, s)| owner == "www.example.com." && s.type_covered == RecordKind::A)
        .collect();
    assert_eq!(sigs.len(), 1, "three A records are one RRset, one RRSIG");

    let keys = published_keys(&db, zone);
    let rrset = db
        .lookup("www.example.com.", Some(RecordKind::A))
        .expect("lookup");
    assert_eq!(rrset.len(), 3);
    dnssec::verify_rrsig(
        &sigs[0].1.to_value(),
        "www.example.com.",
        &rrset,
        &keys[0].public_key,
    )
    .expect("multi-record RRset must verify");

    // Dropping one record must break the signature: if it does not, the
    // signature is not actually covering the set.
    let partial = &rrset[..2];
    assert!(
        dnssec::verify_rrsig(
            &sigs[0].1.to_value(),
            "www.example.com.",
            partial,
            &keys[0].public_key
        )
        .is_err(),
        "a signature over three records must not verify over two"
    );
}

/// RFC 4035 §2.1: the DNSKEY RRset is signed by the KSK, other RRsets by the
/// ZSK. That split is the whole point of having two key types — the KSK is what
/// the parent's DS commits to, and it should be usable offline.
#[tokio::test]
async fn the_ksk_signs_the_dnskey_rrset_and_the_zsk_signs_the_data() {
    let (service, db, _server) = make_service();
    let zone = "example.com.";
    let ksk = generate_key(&service, zone, "ed25519", "KSK").await;
    let zsk = generate_key(&service, zone, "ed25519", "ZSK").await;
    let ksk_tag = ksk.key.expect("ksk").key_tag as u16;
    let zsk_tag = zsk.key.expect("zsk").key_tag as u16;
    assert_ne!(ksk_tag, zsk_tag);

    db.add_record(&record("www.example.com.", RecordKind::A, "192.0.2.1"))
        .expect("add record");
    assert!(sign_zone(&service, zone).await.success);

    let sigs = rrsigs_in_zone(&db, zone);
    let dnskey_sigs: Vec<_> = sigs
        .iter()
        .filter(|(_, s)| s.type_covered == RecordKind::DNSKEY)
        .collect();
    assert_eq!(dnskey_sigs.len(), 1);
    assert_eq!(
        dnskey_sigs[0].1.key_tag, ksk_tag,
        "the DNSKEY RRset must be signed by the KSK"
    );

    let a_sigs: Vec<_> = sigs
        .iter()
        .filter(|(_, s)| s.type_covered == RecordKind::A)
        .collect();
    assert_eq!(a_sigs.len(), 1);
    assert_eq!(
        a_sigs[0].1.key_tag, zsk_tag,
        "data RRsets must be signed by the ZSK"
    );
}

/// With only one key present it signs everything — a single-key zone is a
/// legitimate configuration and must not silently leave the DNSKEY unsigned.
#[tokio::test]
async fn a_single_key_signs_both_the_dnskey_rrset_and_the_data() {
    let (service, db, _server) = make_service();
    let zone = "example.com.";
    generate_key(&service, zone, "ed25519", "ZSK").await;
    db.add_record(&record("www.example.com.", RecordKind::A, "192.0.2.1"))
        .expect("add record");

    assert!(sign_zone(&service, zone).await.success);

    let sigs = rrsigs_in_zone(&db, zone);
    assert!(
        sigs.iter()
            .any(|(_, s)| s.type_covered == RecordKind::DNSKEY)
    );
    assert!(sigs.iter().any(|(_, s)| s.type_covered == RecordKind::A));

    let keys = published_keys(&db, zone);
    let dnskey_rrset = db.lookup(zone, Some(RecordKind::DNSKEY)).expect("lookup");
    let (owner, dnskey_sig) = sigs
        .iter()
        .find(|(_, s)| s.type_covered == RecordKind::DNSKEY)
        .expect("DNSKEY signature");
    dnssec::verify_rrsig(
        &dnskey_sig.to_value(),
        owner,
        &dnskey_rrset,
        &keys[0].public_key,
    )
    .expect("the DNSKEY RRset must verify against itself");
}

/// The zone boundary is a label boundary. `notexample.com.` merely ends with
/// the same text as `example.com.`, and signing it would mean this zone's key
/// claiming authority over a zone it does not hold.
#[tokio::test]
async fn signing_stops_at_the_zone_boundary() {
    let (service, db, _server) = make_service();
    let zone = "example.com.";
    generate_key(&service, zone, "ed25519", "ZSK").await;

    db.add_record(&record("www.example.com.", RecordKind::A, "192.0.2.1"))
        .expect("in zone");
    db.add_record(&record("www.notexample.com.", RecordKind::A, "192.0.2.2"))
        .expect("out of zone");
    db.add_record(&record("other.test.", RecordKind::A, "192.0.2.3"))
        .expect("unrelated");

    assert!(sign_zone(&service, zone).await.success);

    let all = db
        .list_records("", Some(RecordKind::RRSIG))
        .expect("list all RRSIGs");
    for sig in &all {
        assert!(
            sig.name == "example.com." || sig.name.ends_with(".example.com."),
            "signed a record outside the zone: {}",
            sig.name
        );
    }
    assert!(
        !all.iter().any(|s| s.name == "www.notexample.com."),
        "notexample.com. is a different zone"
    );
}

/// Re-signing replaces signatures rather than accumulating them, and a record
/// deleted between runs must not keep its old signature behind.
#[tokio::test]
async fn resigning_replaces_signatures_and_drops_stale_ones() {
    let (service, db, _server) = make_service();
    let zone = "example.com.";
    generate_key(&service, zone, "ed25519", "ZSK").await;

    db.add_record(&record("keep.example.com.", RecordKind::A, "192.0.2.1"))
        .expect("add");
    db.add_record(&record("gone.example.com.", RecordKind::A, "192.0.2.2"))
        .expect("add");

    assert!(sign_zone(&service, zone).await.success);
    let first = rrsigs_in_zone(&db, zone);
    assert!(first.iter().any(|(n, _)| n == "gone.example.com."));

    assert!(sign_zone(&service, zone).await.success);
    let second = rrsigs_in_zone(&db, zone);
    assert_eq!(
        first.len(),
        second.len(),
        "signing twice must not double the RRSIGs"
    );

    db.remove_records("gone.example.com.", Some(RecordKind::A), "")
        .expect("remove");
    assert!(sign_zone(&service, zone).await.success);

    let third = rrsigs_in_zone(&db, zone);
    assert!(
        !third.iter().any(|(n, _)| n == "gone.example.com."),
        "a deleted record must not keep its signature"
    );
    assert!(third.iter().any(|(n, _)| n == "keep.example.com."));

    // And the DNSKEY RRset is republished, not duplicated.
    assert_eq!(published_keys(&db, zone).len(), 1);
}

/// Signature validity must bracket the present, with the inception backdated so
/// a validator whose clock runs slightly behind ours still accepts it.
#[tokio::test]
async fn signature_validity_brackets_now_with_skew_tolerance() {
    let (service, db, _server) = make_service();
    let zone = "example.com.";
    generate_key(&service, zone, "ed25519", "ZSK").await;
    db.add_record(&record("www.example.com.", RecordKind::A, "192.0.2.1"))
        .expect("add");
    assert!(sign_zone(&service, zone).await.success);

    let now = dnssec::now_secs().expect("clock");
    let sigs = rrsigs_in_zone(&db, zone);
    assert!(!sigs.is_empty());
    for (owner, sig) in &sigs {
        assert!(sig.inception < now, "inception must be in the past");
        assert!(
            now - sig.inception >= dnssec::RRSIG_INCEPTION_BACKDATE_SECS as u32 - 5,
            "inception must be backdated for clock skew"
        );
        assert!(sig.expiration > now, "expiration must be in the future");

        // The original TTL must be the covered RRset's own TTL, not a constant:
        // a validator reconstructs the signed bytes using this value, so a
        // mismatch with the served record breaks verification after any cache
        // has decayed the live TTL.
        let rrset = db.lookup(owner, Some(sig.type_covered)).expect("lookup");
        let expected = rrset.iter().map(|r| r.ttl).min().expect("non-empty RRset");
        assert_eq!(
            sig.original_ttl,
            expected,
            "{owner} {}: original TTL must match the RRset",
            sig.type_covered.as_str()
        );
    }
}

/// An RRset whose type has no canonical wire form is reported as skipped rather
/// than signed over an invented encoding — a bogus signature fails closed at
/// every validator, where no signature merely leaves the name unsigned.
#[tokio::test]
async fn unencodable_types_are_skipped_and_reported() {
    let (service, db, _server) = make_service();
    let zone = "example.com.";
    generate_key(&service, zone, "ed25519", "ZSK").await;

    db.add_record(&record("www.example.com.", RecordKind::A, "192.0.2.1"))
        .expect("add");
    db.add_record(&record(
        "nsec.example.com.",
        RecordKind::NSEC,
        "next.example.com. A RRSIG",
    ))
    .expect("add NSEC");

    let resp = sign_zone(&service, zone).await;
    assert!(resp.success);
    assert!(
        resp.message.contains("nsec.example.com.") && resp.message.contains("skipped"),
        "the skip must be reported, got {:?}",
        resp.message
    );

    let sigs = rrsigs_in_zone(&db, zone);
    assert!(!sigs.iter().any(|(_, s)| s.type_covered == RecordKind::NSEC));
    assert!(sigs.iter().any(|(_, s)| s.type_covered == RecordKind::A));
}

#[tokio::test]
async fn signing_a_zone_with_no_keys_fails_without_publishing_anything() {
    let (service, db, _server) = make_service();
    db.add_record(&record("www.example.com.", RecordKind::A, "192.0.2.1"))
        .expect("add");

    let resp = sign_zone(&service, "example.com.").await;
    assert!(!resp.success);
    assert!(resp.message.contains("no DNSSEC keys"));
    assert!(rrsigs_in_zone(&db, "example.com.").is_empty());
    assert!(published_keys(&db, "example.com.").is_empty());
}

// ========================================================
// Serving
// ========================================================

/// A DNSKEY query must be answered with a DNSKEY record and an RRSIG query with
/// an RRSIG record. These were previously served as TXT carrying the stored
/// string, which is unparseable to any DNSSEC-aware client, and made the
/// published signatures unusable no matter how correct they were.
#[tokio::test]
async fn dnssec_records_are_served_under_their_own_type() {
    let (service, db, server) = make_service();
    let zone = "example.com.";
    generate_key(&service, zone, "ed25519", "KSK").await;
    db.add_record(&record("www.example.com.", RecordKind::A, "192.0.2.1"))
        .expect("add");
    assert!(sign_zone(&service, zone).await.success);

    let response = Message::from_bytes(
        &server
            .handle_query(&build_query(zone, RecordType::DNSKEY))
            .await
            .expect("DNSKEY query"),
    )
    .expect("parse response");
    let answers = response.answers();
    assert_eq!(answers.len(), 1, "one DNSKEY was published");
    assert_eq!(
        answers[0].record_type(),
        RecordType::DNSKEY,
        "a DNSKEY query must be answered with a DNSKEY, not a TXT"
    );

    let response = Message::from_bytes(
        &server
            .handle_query(&build_query("www.example.com.", RecordType::RRSIG))
            .await
            .expect("RRSIG query"),
    )
    .expect("parse response");
    let answers = response.answers();
    assert!(!answers.is_empty(), "www has a signed A RRset");
    for answer in answers {
        assert_eq!(answer.record_type(), RecordType::RRSIG);
    }
}

/// What goes on the wire must be the bytes that were signed. A DNSKEY served
/// with different RDATA than the signer hashed is a zone that fails validation
/// even though both halves look right in isolation.
#[tokio::test]
async fn served_rdata_matches_what_was_signed() {
    let (service, db, server) = make_service();
    let zone = "example.com.";
    generate_key(&service, zone, "ed25519", "KSK").await;
    assert!(sign_zone(&service, zone).await.success);

    let stored = db.lookup(zone, Some(RecordKind::DNSKEY)).expect("lookup");
    assert_eq!(stored.len(), 1);
    let expected = dnssec::canonical_rdata(&stored[0]).expect("canonical rdata");

    let response = Message::from_bytes(
        &server
            .handle_query(&build_query(zone, RecordType::DNSKEY))
            .await
            .expect("query"),
    )
    .expect("parse");
    let served = response.answers()[0]
        .data()
        .to_bytes()
        .expect("encode served rdata");

    assert_eq!(
        served, expected,
        "served DNSKEY RDATA must be byte-identical to what was signed"
    );
}

// ========================================================
// Key generation
// ========================================================

/// The generator must not hand back key material of one algorithm labelled as
/// another. The old behaviour generated Ed25519 for every request and relabelled
/// it, producing a DNSKEY, DS and RRSIG set that disagreed with each other in a
/// way only a resolver would ever notice.
#[tokio::test]
async fn generated_keys_carry_the_algorithm_they_claim() {
    for (requested, expected, algorithm) in [
        ("ed25519", "Ed25519", DnssecAlgorithm::Ed25519),
        (
            "ecdsa-p256",
            "ECDSA-P256-SHA256",
            DnssecAlgorithm::EcdsaP256Sha256,
        ),
        (
            "ecdsa-p384",
            "ECDSA-P384-SHA384",
            DnssecAlgorithm::EcdsaP384Sha384,
        ),
    ] {
        let (service, db, _server) = make_service();
        let resp = generate_key(&service, "example.com.", requested, "ZSK").await;
        assert!(resp.success, "{requested} must generate");
        assert_eq!(resp.key.expect("key").algorithm, expected);

        // The stored private key must load *as the algorithm it is stored
        // under*. Ed25519 material labelled P-256 fails this.
        let stored = db
            .list_dnssec_keys("example.com.")
            .expect("list keys")
            .pop()
            .expect("one key");
        let loaded = SigningKey::from_pkcs8(algorithm, KeyType::ZSK, &stored.private_key)
            .unwrap_or_else(|e| panic!("{requested} key must load as {expected}: {e}"));
        assert_eq!(
            loaded.public_key(),
            stored.public_key.as_slice(),
            "{requested}: stored public key must be the one the private key derives"
        );
    }
}

/// RSA is refused at generation rather than substituted, because `ring` cannot
/// generate RSA keys and a key we cannot make is one we must not advertise.
#[tokio::test]
async fn rsa_key_generation_is_refused() {
    let (service, db, _server) = make_service();
    let err = service
        .generate_dnssec_key(tonic::Request::new(proto::GenerateDnssecKeyRequest {
            zone: "example.com.".to_string(),
            algorithm: "rsa-sha256".to_string(),
            key_type: "ZSK".to_string(),
            auth_token: String::new(),
        }))
        .await
        .expect_err("RSA must be refused");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        db.list_dnssec_keys("example.com.")
            .expect("list")
            .is_empty(),
        "a refused generation must not store a key"
    );
}

/// The DS record published for a KSK must be computed over the same DNSKEY that
/// is served, so the parent delegation and the zone agree.
#[tokio::test]
async fn ds_records_match_the_published_dnskey() {
    let (service, db, _server) = make_service();
    let zone = "example.com.";
    let generated = generate_key(&service, zone, "ed25519", "KSK").await;
    let key_tag = generated.key.expect("key").key_tag as u16;
    assert!(sign_zone(&service, zone).await.success);

    let ds = service
        .get_ds_records(tonic::Request::new(proto::GetDsRecordsRequest {
            zone: zone.to_string(),
            auth_token: String::new(),
        }))
        .await
        .expect("get_ds_records")
        .into_inner();
    assert!(!ds.ds_records.is_empty());

    let published = published_keys(&db, zone);
    assert_eq!(published.len(), 1);
    assert_eq!(
        published[0].key_tag, key_tag,
        "the published DNSKEY must have the key tag the DS commits to"
    );
    let expected = dnssec::compute_ds_sha256(
        zone,
        published[0].key_tag,
        published[0].algorithm,
        &published[0].public_key,
        KeyType::KSK,
    );
    assert!(
        ds.ds_records.iter().any(|r| r.contains(&expected)),
        "DS {:?} must cover the published DNSKEY digest {expected}",
        ds.ds_records
    );
}
