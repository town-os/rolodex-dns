//! A **DNSSEC-signed** mock delegation hierarchy: signed root -> signed TLD ->
//! signed zone, over real UDP sockets.
//!
//! [`crate::mock_hierarchy`](../mock_hierarchy/mod.rs) proves query *counts*;
//! this one proves *verdicts*. The distinction matters because almost every way
//! of getting DNSSEC wrong still returns the right records — a validator that
//! skips the expiry check, or believes an unsigned NSEC, or accepts any signer
//! name, resolves the whole internet correctly right up until someone attacks
//! it. So the assertions here are all of the form "this response, which carries
//! exactly the records a real attacker could produce, must come back Bogus".
//!
//! Each zone is a real nameserver that signs what it serves with its own
//! Ed25519 key, publishes a DNSKEY RRset at its apex, and hands out a DS for
//! each signed child. The resolver walks it with no special casing: it fetches
//! DNSKEYs, verifies DS records, and builds the chain exactly as it would
//! against the real root.
//!
//! [`Tamper`] is the point of the harness. Each variant is one specific attack
//! or one specific broken zone, applied at serving time *after* the zone has
//! been correctly constructed — so the test is not "we built something invalid
//! and it was rejected", it is "we built something valid and then did to it
//! precisely what an on-path attacker does".
//!
//! As with the counting hierarchy, the levels share one port across distinct
//! `127.0.0.x` addresses, because glue is an address and the resolver's port is
//! fixed.

#![allow(dead_code)]

use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS, NSEC, RRSIG};
use hickory_proto::dnssec::{Algorithm, DigestType, PublicKey as _, PublicKeyBuf, TBS};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, NS, SOA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::UdpSocket;

/// Seconds of validity a correctly-signed RRSIG is given.
const SIG_VALIDITY: u32 = 30 * 86_400;
/// How far back a correct RRSIG's inception is set, for clock skew.
const SIG_BACKDATE: u32 = 3_600;
/// TTL used throughout. Long enough that nothing expires mid-test, short enough
/// that a cache entry leaking between tests would be visible.
pub const TTL: u32 = 3_600;

pub fn name(s: &str) -> Name {
    Name::from_str(s).expect("valid name")
}

fn now() -> u32 {
    u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs(),
    )
    .expect("clock within u32")
}

/// One zone's signing key, and the DNSKEY it publishes.
pub struct ZoneKey {
    keypair: Ed25519KeyPair,
    public: PublicKeyBuf,
    pub dnskey: DNSKEY,
    pub tag: u16,
}

impl ZoneKey {
    pub fn generate() -> Arc<Self> {
        let pkcs8 =
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate Ed25519 key");
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load Ed25519 key");
        let public = PublicKeyBuf::new(keypair.public_key().as_ref().to_vec(), Algorithm::ED25519);
        // zone_key + secure entry point: flags 257, the spelling a KSK uses and
        // the one the DS digest below is computed over.
        let dnskey = DNSKEY::new(true, true, false, public.clone());
        let tag = dnskey.calculate_key_tag().expect("key tag");
        Arc::new(Self {
            keypair,
            public,
            dnskey,
            tag,
        })
    }

    /// The trust-anchor string for this key, in the `dnssec.trust_anchors`
    /// spelling.
    pub fn anchor_string(&self) -> String {
        use base64::Engine as _;
        format!(
            "257 3 15 {}",
            base64::engine::general_purpose::STANDARD
                .encode(self.dnskey.public_key().public_bytes())
        )
    }

    /// The DS this key's parent should publish for a zone at `apex`.
    pub fn ds_for(&self, apex: &Name) -> DS {
        let digest = self
            .dnskey
            .to_digest(apex, DigestType::SHA256)
            .expect("DS digest");
        DS::new(
            self.tag,
            Algorithm::ED25519,
            DigestType::SHA256,
            digest.as_ref().to_vec(),
        )
    }

    pub fn public(&self) -> &PublicKeyBuf {
        &self.public
    }
}

/// One thing done to a zone's responses after they are correctly built.
///
/// Every variant is an attack an on-path adversary can mount with no key
/// material at all, or a zone that has broken its own signing — which is why
/// "the records look right" is never sufficient evidence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Tamper {
    /// Serve the zone exactly as signed.
    #[default]
    None,
    /// Remove every RRSIG from the response. The classic downgrade: if a
    /// validator reads "unsigned" as "insecure", every signed zone on the
    /// internet can be turned off by deleting records in transit.
    StripSignatures,
    /// Sign with a key that is real but is not the one the DNSKEY RRset (and
    /// hence the parent's DS) publishes.
    SignWithForeignKey,
    /// Emit signatures whose validity window closed a year ago — a captured
    /// response replayed after the fact.
    ExpiredSignatures,
    /// Emit signatures whose validity window has not opened yet.
    PrematureSignatures,
    /// Claim the RRSIG was made by some other zone, and supply that zone's key
    /// material. Arithmetically valid, and meaningless: the signer is not the
    /// zone the data lives in.
    ForeignSignerName(Name),
    /// Rewrite the signer name on the *answer* section only, leaving everything
    /// this zone says about its own delegations honestly signed.
    ///
    /// This is what an on-path adversary actually gets to do. Forging one answer
    /// packet does not let them forge the DS lookup or the delegation proof that
    /// a resolver makes afterwards — those still come from the real server —
    /// so a tamper that rewrites every signature the zone emits would be tested
    /// against an attacker far more powerful than the real one, and would hide
    /// whether the answer was refused on its own merits.
    AnswerSignerName(Name),
    /// Alter the record data after signing it. Signature intact, data changed.
    MutateAfterSigning,
    /// Delegate without a DS *and* without the NSEC that proves there is none.
    /// This is the delegation-level downgrade, and it is the single most
    /// important thing in the suite to reject.
    OmitNoDsProof,
    /// Answer negatively with a correct SOA but no NSEC at all.
    OmitDenialProof,
}

/// A delegation from this zone to a child.
#[derive(Clone)]
pub struct Delegation {
    pub child: Name,
    pub ns_ip: Ipv4Addr,
    /// `None` for an unsigned child, which then needs `no_ds_nsec`.
    pub ds: Option<DS>,
    /// The NSEC at the delegation point proving no DS exists. Its bitmap must
    /// contain NS and must not contain DS or SOA.
    pub no_ds_nsec: Option<NsecSpec>,
}

/// An NSEC record to be served: owner, next name, and the types asserted.
#[derive(Clone)]
pub struct NsecSpec {
    pub owner: Name,
    pub next: Name,
    pub types: Vec<RecordType>,
}

impl NsecSpec {
    pub fn new(owner: &str, next: &str, types: &[RecordType]) -> Self {
        Self {
            owner: name(owner),
            next: name(next),
            types: types.to_vec(),
        }
    }

    fn record(&self) -> Record {
        Record::from_rdata(
            self.owner.clone(),
            TTL,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                self.next.clone(),
                self.types.clone(),
            ))),
        )
    }
}

/// A signed zone served by one mock nameserver.
#[derive(Clone)]
pub struct Zone {
    pub apex: Name,
    pub key: Arc<ZoneKey>,
    /// Exact `(owner, type) -> records` answers, unsigned; the harness signs.
    pub answers: Vec<(Name, RecordType, Vec<Record>)>,
    pub delegations: Vec<Delegation>,
    /// NSEC records offered with negative answers. The harness picks the ones
    /// whose owner matches or whose range covers the queried name.
    pub nsecs: Vec<NsecSpec>,
    pub tamper: Tamper,
}

impl Zone {
    pub fn new(apex: &str, key: Arc<ZoneKey>) -> Self {
        Self {
            apex: name(apex),
            key,
            answers: Vec::new(),
            delegations: Vec::new(),
            nsecs: Vec::new(),
            tamper: Tamper::None,
        }
    }

    /// Adds an A record answer.
    pub fn with_a(mut self, owner: &str, ip: Ipv4Addr) -> Self {
        let owner = name(owner);
        let record = Record::from_rdata(owner.clone(), TTL, RData::A(A(ip)));
        self.answers.push((owner, RecordType::A, vec![record]));
        self
    }

    /// Adds a TXT record answer, used where a second type at one name is needed
    /// to make NODATA distinguishable from NXDOMAIN.
    pub fn with_txt(mut self, owner: &str, value: &str) -> Self {
        let owner = name(owner);
        let record = Record::from_rdata(
            owner.clone(),
            TTL,
            RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![value.to_string()])),
        );
        self.answers.push((owner, RecordType::TXT, vec![record]));
        self
    }

    /// Adds a signed delegation: the child's DS is published and signed here.
    pub fn with_signed_child(mut self, child: &str, ns_ip: Ipv4Addr, key: &ZoneKey) -> Self {
        let child = name(child);
        let ds = key.ds_for(&child);
        self.delegations.push(Delegation {
            child,
            ns_ip,
            ds: Some(ds),
            no_ds_nsec: None,
        });
        self
    }

    /// Adds an unsigned delegation, with the NSEC that proves it carries no DS.
    pub fn with_unsigned_child(mut self, child: &str, ns_ip: Ipv4Addr, next: &str) -> Self {
        let child = name(child);
        self.delegations.push(Delegation {
            child: child.clone(),
            ns_ip,
            ds: None,
            no_ds_nsec: Some(NsecSpec {
                owner: child,
                next: name(next),
                // NS present, DS and SOA absent: a delegation point in *this*
                // zone, with nothing signed beneath it.
                types: vec![RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            }),
        });
        self
    }

    pub fn with_nsec(mut self, spec: NsecSpec) -> Self {
        self.nsecs.push(spec);
        self
    }

    pub fn with_tamper(mut self, tamper: Tamper) -> Self {
        self.tamper = tamper;
        self
    }

    fn soa(&self) -> Record {
        Record::from_rdata(
            self.apex.clone(),
            TTL,
            RData::SOA(SOA::new(
                name(&format!("ns1.{}", self.apex)),
                name(&format!("hostmaster.{}", self.apex)),
                1,
                7_200,
                3_600,
                1_209_600,
                300,
            )),
        )
    }
}

/// Changes what a running nameserver does to its responses, without restarting
/// it.
///
/// Needed by anything that tests a server's *history* — blame, backoff,
/// recovery. Restarting the server to make it stop lying would give it a new
/// socket, and a new socket is a new address, which is a different server as far
/// as any per-server state is concerned. `None` means "whatever the zone was
/// built with".
#[derive(Clone, Default)]
pub struct TamperSwitch(Arc<std::sync::Mutex<Option<Tamper>>>);

impl TamperSwitch {
    /// Makes the server behave as `tamper` from the next query onwards.
    pub fn set(&self, tamper: Tamper) {
        match self.0.lock() {
            Ok(mut slot) => *slot = Some(tamper),
            Err(poisoned) => *poisoned.into_inner() = Some(tamper),
        }
    }

    /// Restores the zone's own tamper setting.
    pub fn clear(&self) {
        match self.0.lock() {
            Ok(mut slot) => *slot = None,
            Err(poisoned) => *poisoned.into_inner() = None,
        }
    }

    fn get(&self) -> Option<Tamper> {
        match self.0.lock() {
            Ok(slot) => slot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

/// A running signed nameserver.
pub struct SignedNs {
    ip: Ipv4Addr,
    queries: Arc<AtomicUsize>,
}

impl SignedNs {
    pub fn hits(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }
}

/// Binds one UDP socket per loopback IP on a single shared port.
///
/// The same constraint the counting hierarchy has: the resolver reaches a
/// nameserver at `(glue_ip, fixed_port)`, so levels are distinguished by address
/// and not by port.
pub async fn bind_levels(ips: &[Ipv4Addr]) -> (u16, Vec<UdpSocket>) {
    for _ in 0..64 {
        let probe = UdpSocket::bind((ips[0], 0)).await.expect("probe bind");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);

        let mut sockets = Vec::with_capacity(ips.len());
        let mut ok = true;
        for ip in ips {
            match UdpSocket::bind((*ip, port)).await {
                Ok(s) => sockets.push(s),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            return (port, sockets);
        }
    }
    panic!("could not find a port free on all signed hierarchy IPs");
}

/// Starts serving several zones from one socket — one nameserver authoritative
/// for a parent *and* a child of it.
///
/// This is the shape that hides a zone cut. A server that holds both sides of a
/// delegation never refers a query across it: asked for a name in the child it
/// answers from the child zone, authoritatively and signed by the child's key,
/// and the referral that would have told a resolver the cut exists is never
/// sent. `cdnjs.cloudflare.com.` on `cloudflare.com.`'s nameservers is the
/// commonplace real example. The DS stays where a DS belongs — in the parent —
/// so a resolver that goes looking for it can still find one.
pub fn serve_zones(socket: UdpSocket, zones: Vec<Zone>) -> SignedNs {
    let ip = match socket.local_addr().expect("local addr").ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!("signed hierarchy is IPv4"),
    };
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&queries);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let Ok(query) = Message::from_bytes(&buf[..len]) else {
                continue;
            };
            let response = build_multi_response(&query, &zones);
            if let Ok(bytes) = response.to_bytes() {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    });

    SignedNs { ip, queries }
}

/// Picks the zone that answers `qname` — the deepest apex that encloses it,
/// which is what makes a server holding both sides of a cut answer from the
/// child instead of referring to it.
fn zone_for<'a>(zones: &'a [Zone], qname: &Name) -> Option<&'a Zone> {
    zones
        .iter()
        .filter(|z| z.apex.zone_of(qname))
        .max_by_key(|z| z.apex.num_labels())
}

/// Picks the zone on the *parent* side of a cut at `qname`: the deepest apex
/// that strictly encloses it. A DS lives in the parent, never in the child.
fn parent_zone_for<'a>(zones: &'a [Zone], qname: &Name) -> Option<&'a Zone> {
    zones
        .iter()
        .filter(|z| z.apex.zone_of(qname) && &z.apex != qname)
        .max_by_key(|z| z.apex.num_labels())
}

fn build_multi_response(query: &Message, zones: &[Zone]) -> Message {
    let Some(question) = query.queries().first() else {
        return build_response(query, &zones[0]);
    };
    let qname = question.name().clone();
    let qtype = question.query_type();

    // A DS query is answered by the parent, from the parent's own copy of the
    // delegation, with the DS in the *answer* section — not as the referral a
    // query for a name below the cut would get.
    if qtype == RecordType::DS
        && let Some(parent) = parent_zone_for(zones, &qname)
    {
        let mut resp = Message::new();
        resp.set_id(query.id());
        resp.set_message_type(MessageType::Response);
        resp.set_op_code(OpCode::Query);
        resp.add_query(question.clone());
        resp.set_authoritative(true);

        let delegation = parent.delegations.iter().find(|d| d.child == qname);
        match delegation.and_then(|d| d.ds.clone()) {
            Some(ds) => {
                let record =
                    Record::from_rdata(qname.clone(), TTL, RData::DNSSEC(DNSSECRData::DS(ds)));
                let mut answers = Vec::new();
                push_signed(parent, vec![record], RecordType::DS, &mut answers);
                for record in answers {
                    resp.add_answer(record);
                }
            }
            // No DS: NODATA, proven by the parent's signed NSEC at the
            // delegation point, exactly as a referral would have proven it.
            None => {
                let mut authority = Vec::new();
                push_signed(parent, vec![parent.soa()], RecordType::SOA, &mut authority);
                if let Some(nsec) = delegation.and_then(|d| d.no_ds_nsec.clone()) {
                    push_signed(
                        parent,
                        vec![nsec.record()],
                        RecordType::NSEC,
                        &mut authority,
                    );
                }
                for record in authority {
                    resp.add_name_server(record);
                }
            }
        }
        return resp;
    }

    match zone_for(zones, &qname) {
        Some(zone) => build_response(query, zone),
        None => build_response(query, &zones[0]),
    }
}

/// Starts serving `zone` on `socket`.
pub fn serve(socket: UdpSocket, zone: Zone) -> SignedNs {
    serve_switchable(socket, zone).0
}

/// Starts serving `zone` on `socket`, with a handle that changes its tampering
/// while it runs. See [`TamperSwitch`].
pub fn serve_switchable(socket: UdpSocket, zone: Zone) -> (SignedNs, TamperSwitch) {
    let ip = match socket.local_addr().expect("local addr").ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!("signed hierarchy is IPv4"),
    };
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&queries);
    let switch = TamperSwitch::default();
    let serving = switch.clone();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let Ok(query) = Message::from_bytes(&buf[..len]) else {
                continue;
            };
            let response = match serving.get() {
                Some(tamper) => {
                    let mut overridden = zone.clone();
                    overridden.tamper = tamper;
                    build_response(&query, &overridden)
                }
                None => build_response(&query, &zone),
            };
            if let Ok(bytes) = response.to_bytes() {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    });

    (SignedNs { ip, queries }, switch)
}

/// The signing key actually used for a response, which is the zone's own key
/// unless the test asked for a foreign one.
fn signing_key(zone: &Zone) -> Arc<ZoneKey> {
    match zone.tamper {
        // A real, well-formed key that the DNSKEY RRset does not publish. The
        // signature verifies against itself and against nothing the chain knows.
        Tamper::SignWithForeignKey => ZoneKey::generate(),
        _ => Arc::clone(&zone.key),
    }
}

/// Produces the RRSIG covering `records`, honouring the zone's tamper setting.
fn sign(zone: &Zone, owner: &Name, rtype: RecordType, records: &[Record]) -> Option<Record> {
    if zone.tamper == Tamper::StripSignatures {
        return None;
    }

    let key = signing_key(zone);
    let signer = match &zone.tamper {
        Tamper::ForeignSignerName(other) => other.clone(),
        _ => zone.apex.clone(),
    };
    let (inception, expiration) = match zone.tamper {
        Tamper::ExpiredSignatures => (now() - 2 * SIG_VALIDITY, now() - SIG_VALIDITY),
        Tamper::PrematureSignatures => (now() + SIG_VALIDITY, now() + 2 * SIG_VALIDITY),
        _ => (now() - SIG_BACKDATE, now() + SIG_VALIDITY),
    };

    let unsigned = RRSIG::new(
        rtype,
        Algorithm::ED25519,
        owner.num_labels(),
        TTL,
        expiration,
        inception,
        key.tag,
        signer.clone(),
        Vec::new(),
    );
    let tbs = TBS::from_sig(owner, DNSClass::IN, &unsigned, records.iter()).ok()?;
    let signature = key.keypair.sign(tbs.as_ref()).as_ref().to_vec();

    Some(Record::from_rdata(
        owner.clone(),
        TTL,
        RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::new(
            rtype,
            Algorithm::ED25519,
            owner.num_labels(),
            TTL,
            expiration,
            inception,
            key.tag,
            signer,
            signature,
        ))),
    ))
}

/// Rewrites the signer name of an RRSIG record, leaving the signature bytes and
/// every other field alone. Non-RRSIG records pass through untouched.
fn restamp_signer(record: Record, signer: &Name) -> Record {
    let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = record.data() else {
        return record;
    };
    Record::from_rdata(
        record.name().clone(),
        record.ttl(),
        RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::new(
            sig.type_covered(),
            sig.algorithm(),
            sig.num_labels(),
            sig.original_ttl(),
            sig.sig_expiration().get(),
            sig.sig_inception().get(),
            sig.key_tag(),
            signer.clone(),
            sig.sig().to_vec(),
        ))),
    )
}

/// Appends an RRset and its signature to a section.
fn push_signed(zone: &Zone, records: Vec<Record>, rtype: RecordType, into: &mut Vec<Record>) {
    let Some(owner) = records.first().map(Record::name).cloned() else {
        return;
    };
    let signature = sign(zone, &owner, rtype, &records);

    // Mutating *after* signing is the case where every signature in the packet
    // is genuine and the data is not — the failure a validator that only checks
    // "is there an RRSIG" waves straight through.
    let emitted = if zone.tamper == Tamper::MutateAfterSigning {
        records
            .into_iter()
            .map(|mut record| {
                if let RData::A(A(_)) = record.data() {
                    record.set_data(RData::A(A(Ipv4Addr::new(203, 0, 113, 66))));
                }
                record
            })
            .collect()
    } else {
        records
    };

    into.extend(emitted);
    if let Some(signature) = signature {
        into.push(signature);
    }
}

fn build_response(query: &Message, zone: &Zone) -> Message {
    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);

    let Some(question) = query.queries().first() else {
        resp.set_response_code(ResponseCode::FormErr);
        return resp;
    };
    resp.add_query(question.clone());
    let qname = question.name().clone();
    let qtype = question.query_type();

    // The DNSKEY RRset at the apex: the thing the chain of trust is fetched for.
    if qtype == RecordType::DNSKEY && qname == zone.apex {
        resp.set_authoritative(true);
        let dnskey = Record::from_rdata(
            zone.apex.clone(),
            TTL,
            RData::DNSSEC(DNSSECRData::DNSKEY(zone.key.dnskey.clone())),
        );
        let mut answers = Vec::new();
        push_signed(zone, vec![dnskey], RecordType::DNSKEY, &mut answers);
        for record in answers {
            resp.add_answer(record);
        }
        return resp;
    }

    // A delegation covering the queried name takes precedence over everything
    // else in the zone, exactly as it does in a real authoritative server.
    if let Some(delegation) = zone
        .delegations
        .iter()
        .find(|d| d.child.zone_of(&qname) || d.child == qname)
    {
        let ns_name = name(&format!("ns1.{}", delegation.child));
        // The NS RRset at a delegation point lives in the *child* and is not
        // signed by the parent, so it goes in unsigned — as it does for real.
        resp.add_name_server(Record::from_rdata(
            delegation.child.clone(),
            TTL,
            RData::NS(NS(ns_name.clone())),
        ));
        resp.add_additional(Record::from_rdata(
            ns_name,
            TTL,
            RData::A(A(delegation.ns_ip)),
        ));

        let mut authority = Vec::new();
        match (&delegation.ds, &delegation.no_ds_nsec, &zone.tamper) {
            (_, _, Tamper::OmitNoDsProof) => {
                // Neither a DS nor a proof: the downgrade attempt.
            }
            (Some(ds), _, _) => {
                let record = Record::from_rdata(
                    delegation.child.clone(),
                    TTL,
                    RData::DNSSEC(DNSSECRData::DS(ds.clone())),
                );
                push_signed(zone, vec![record], RecordType::DS, &mut authority);
            }
            (None, Some(nsec), _) => {
                push_signed(zone, vec![nsec.record()], RecordType::NSEC, &mut authority);
            }
            (None, None, _) => {}
        }
        for record in authority {
            resp.add_name_server(record);
        }
        return resp;
    }

    // An exact answer.
    if let Some((owner, rtype, records)) = zone
        .answers
        .iter()
        .find(|(owner, rtype, _)| *owner == qname && *rtype == qtype)
    {
        resp.set_authoritative(true);
        let mut answers = Vec::new();
        push_signed(zone, records.clone(), *rtype, &mut answers);
        let _ = owner;
        if let Tamper::AnswerSignerName(signer) = &zone.tamper {
            answers = answers
                .into_iter()
                .map(|record| restamp_signer(record, signer))
                .collect();
        }
        for record in answers {
            resp.add_answer(record);
        }
        return resp;
    }

    // The name exists with some other type: NODATA.
    let exists = zone.answers.iter().any(|(owner, _, _)| *owner == qname);
    resp.set_authoritative(true);
    if !exists {
        resp.set_response_code(ResponseCode::NXDomain);
    }

    let mut authority = Vec::new();
    push_signed(zone, vec![zone.soa()], RecordType::SOA, &mut authority);
    if zone.tamper != Tamper::OmitDenialProof {
        for nsec in &zone.nsecs {
            push_signed(zone, vec![nsec.record()], RecordType::NSEC, &mut authority);
        }
    }
    for record in authority {
        resp.add_name_server(record);
    }
    resp
}
