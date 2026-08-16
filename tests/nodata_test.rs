//! End-to-end tests for the negative-answer contract:
//!
//! > **NXDOMAIN asserts that the NAME does not exist. It is correct only when
//! > nothing lives at the name or beneath it. Every other authoritative miss is
//! > NODATA — NOERROR with an empty answer section — and both carry the zone's
//! > SOA in the authority section.**
//!
//! RFC 1035 §3.1 and RFC 2308 §2 give the two negatives different meanings, and
//! the server used to collapse them: every authoritative miss left as NXDOMAIN,
//! because the only lookup on the path was keyed by *(name, type)* and a typed
//! miss was indistinguishable from an absent name. A host with an A record and
//! no AAAA therefore answered NOERROR and NXDOMAIN for the same name in the same
//! breath — which is what `host dns.home` prints as two NXDOMAIN lines under one
//! successful address.
//!
//! The damage is not confined to the queried name. Under RFC 8020 a resolver
//! that caches NXDOMAIN for a name may synthesize NXDOMAIN for every name
//! beneath it, so one AAAA query for a v4-only host is enough to erase its whole
//! subtree from that resolver's view.
//!
//! Five code paths in `resolve_query` produce an authoritative negative — a
//! scope-owned TLD, a scoped managed zone, the LAN fallback into an owning
//! scope, a global managed zone and a global authoritative zone — and the unit
//! tests in `src/dns_server.rs` pin the decision itself. These run the whole
//! stack: a mutation over the **gRPC control plane**, then a query over a **real
//! UDP or TCP socket**, asserting what a client actually receives. That is the
//! part unit tests cannot show, because the decision sits behind the local
//! lookup and ahead of the forwarding gate, and a regression that moved it would
//! leave the unit tests green.
//!
//! Every test carries its own control. A server that answered NODATA for
//! everything satisfies "a name that exists is not denied" on its own, and would
//! be a worse bug than the one being fixed: it would claim every name in the
//! zone exists. The paired assertion — a name with nothing at or beneath it is
//! *still* NXDOMAIN — is what makes the first one mean anything.

use rolodex_dns::db::{Database, RecordKind};
use rolodex_dns::dns_server::{DnsServer, ResolutionMode};
use rolodex_dns::dnsbl::DnsblChecker;
use rolodex_dns::grpc_service::RolodexDnsGrpcService;
use rolodex_dns::grpc_service::proto::rolodex_dns_service_server::RolodexDnsService;
use rolodex_dns::grpc_service::proto::{
    AddAuthoritativeZoneRequest, AddRecordRequest, AddScopedRecordRequest,
    CreateNetworkScopeRequest, JoinNetworkRequest,
};
use rolodex_dns::metrics::metrics;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tonic::Request;

const AUTH: &str = "test-secret";
const ZONE: &str = "home.";

/// The metric registry is a process-wide singleton, and these tests assert exact
/// deltas on it. Every test in this file takes the lock so a concurrent one
/// cannot bump a counter mid-measurement.
static SERIAL: Mutex<()> = Mutex::const_new(());

// ========================================================
// Harness
// ========================================================

struct Stack {
    dns: Arc<DnsServer>,
    grpc: RolodexDnsGrpcService,
}

/// Database, DNS server and gRPC service over one shared database handle, which
/// is what makes a control-plane mutation visible to the query path the way it
/// is in the real server.
///
/// Resolution is pinned to `forward` with no forwarders configured, so a name
/// that escapes local lookup fails immediately instead of walking the real root
/// servers. These tests are about what the authoritative path decides, and must
/// neither depend on nor touch the network.
fn make_stack() -> Stack {
    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(DnsblChecker::new());
    let dns = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
    dns.set_resolution_mode(ResolutionMode::Forward);
    let grpc = RolodexDnsGrpcService::new(db, dns.clone(), rbl, AUTH.to_string(), false);
    Stack { dns, grpc }
}

impl Stack {
    async fn add_zone(&self, zone: &str) {
        let resp = self
            .grpc
            .add_authoritative_zone(Request::new(AddAuthoritativeZoneRequest {
                zone: zone.to_string(),
                auth_token: AUTH.to_string(),
            }))
            .await
            .expect("add_authoritative_zone transport")
            .into_inner();
        assert!(resp.success, "add zone {zone}: {}", resp.message);
    }

    async fn add_record(&self, name: &str, kind: RecordKind, value: &str) {
        let resp = self
            .grpc
            .add_record(Request::new(AddRecordRequest {
                record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
                    name: name.to_string(),
                    record_type: kind.to_proto_i32(),
                    value: value.to_string(),
                    ttl: 300,
                    priority: 0,
                }),
                auth_token: AUTH.to_string(),
            }))
            .await
            .expect("add_record transport")
            .into_inner();
        assert!(resp.success, "add record {name}: {}", resp.message);
    }

    async fn add_scope(&self, name: &str, home_domain: &str) {
        let resp = self
            .grpc
            .create_network_scope(Request::new(CreateNetworkScopeRequest {
                scope: Some(rolodex_dns::grpc_service::proto::NetworkScope {
                    name: name.to_string(),
                    home_domain: home_domain.to_string(),
                    tlds: Vec::new(),
                }),
                auth_token: AUTH.to_string(),
            }))
            .await
            .expect("create_network_scope transport")
            .into_inner();
        assert!(resp.success, "create scope {name}: {}", resp.message);
    }

    async fn add_scoped_record(&self, scope: &str, name: &str, kind: RecordKind, value: &str) {
        let resp = self
            .grpc
            .add_scoped_record(Request::new(AddScopedRecordRequest {
                scope_name: scope.to_string(),
                record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
                    name: name.to_string(),
                    record_type: kind.to_proto_i32(),
                    value: value.to_string(),
                    ttl: 300,
                    priority: 0,
                }),
                auth_token: AUTH.to_string(),
            }))
            .await
            .expect("add_scoped_record transport")
            .into_inner();
        assert!(resp.success, "add scoped record {name}: {}", resp.message);
    }

    async fn join(&self, ip: &str, scope: &str) {
        let resp = self
            .grpc
            .join_network(Request::new(JoinNetworkRequest {
                ip_address: ip.to_string(),
                scope_name: scope.to_string(),
                ttl_seconds: 600,
                auth_token: AUTH.to_string(),
            }))
            .await
            .expect("join_network transport")
            .into_inner();
        assert!(resp.success, "join {ip} to {scope}: {}", resp.message);
    }

    /// Queries as a client at `source`, without going through a socket. Used for
    /// the scoped paths, where the source address *is* the thing under test.
    async fn ask_from(&self, source: &str, name: &str, qtype: RecordType) -> Message {
        let ip: IpAddr = source.parse().unwrap();
        let wire = self
            .dns
            .handle_query_from(&build_query(name, qtype), ip)
            .await
            .unwrap();
        Message::from_bytes(&wire).unwrap()
    }
}

fn build_query(name: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(rand::random::<u16>());
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

/// Starts the real UDP listener on an ephemeral port. Going through `serve_udp`
/// rather than calling `handle_query` directly exercises the socket, the
/// per-query task and the source-address classification a client's packet
/// actually goes through.
async fn serve_udp(dns: Arc<DnsServer>) -> SocketAddr {
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let bind = addr.to_string();
    tokio::spawn(async move {
        let _ = dns.serve_udp(&bind).await;
    });

    // UDP `send_to` succeeds whether or not anything is listening, so readiness
    // has to be a query that comes back. The name is deliberately outside every
    // zone these tests create.
    let ready = build_query("readiness.probe.invalid.", RecordType::A);
    for _ in 0..200 {
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&ready, addr).await.unwrap();
        let mut buf = vec![0u8; 4096];
        if tokio::time::timeout(Duration::from_millis(25), client.recv_from(&mut buf))
            .await
            .is_ok()
        {
            return addr;
        }
    }
    panic!("UDP listener never came up on {addr}");
}

async fn serve_tcp(dns: Arc<DnsServer>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let bind = addr.to_string();
    tokio::spawn(async move {
        let _ = dns.serve_tcp(&bind).await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("TCP listener never came up on {addr}");
}

async fn udp_query(server: SocketAddr, name: &str, qtype: RecordType) -> Message {
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&build_query(name, qtype), server)
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .expect("no UDP reply")
        .unwrap();
    Message::from_bytes(&buf[..len]).unwrap()
}

async fn tcp_query(server: SocketAddr, name: &str, qtype: RecordType) -> Message {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let query = build_query(name, qtype);
    let mut stream = tokio::net::TcpStream::connect(server).await.unwrap();
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&query).await.unwrap();

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.unwrap();
    let mut buf = vec![0u8; u16::from_be_bytes(len_buf) as usize];
    stream.read_exact(&mut buf).await.unwrap();
    Message::from_bytes(&buf).unwrap()
}

/// A zone with an SOA at the apex and one v4-only host under it — the shape that
/// produced the original report.
async fn v4_only_host_zone() -> Stack {
    let stack = make_stack();
    stack.add_zone(ZONE).await;
    stack
        .add_record(
            ZONE,
            RecordKind::SOA,
            "ns1.home. hostmaster.home. 1 7200 3600 1209600 3600",
        )
        .await;
    stack
        .add_record("dns.home.", RecordKind::A, "192.168.122.50")
        .await;
    stack
}

/// The value of one labelled counter series in an exposition body.
fn series(body: &str, name: &str, label: &str, value: &str) -> u64 {
    let prefix = format!("{name}{{{label}=\"{value}\"}}");
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix(&prefix)
            && let Some(v) = rest.strip_prefix(' ')
        {
            return v.trim().parse().unwrap_or(0);
        }
    }
    panic!("no series {prefix} in:\n{body}");
}

fn soa_names(msg: &Message) -> Vec<String> {
    msg.name_servers()
        .iter()
        .filter(|r| r.record_type() == RecordType::SOA)
        .map(|r| r.name().to_string())
        .collect()
}

// ========================================================
// The global authoritative path, over a real socket
// ========================================================

/// The reported bug, end to end. `host dns.home` issues A, AAAA and MX; the A
/// answers and the other two must not deny the name the A just proved real.
#[tokio::test]
async fn a_v4_only_host_answers_nodata_for_aaaa_and_mx_over_udp() {
    let _serial = SERIAL.lock().await;
    let stack = v4_only_host_zone().await;
    let addr = serve_udp(stack.dns.clone()).await;

    let a = udp_query(addr, "dns.home.", RecordType::A).await;
    assert_eq!(a.response_code(), ResponseCode::NoError);
    assert_eq!(a.answers().len(), 1, "the control: the name does exist");

    for qtype in [RecordType::AAAA, RecordType::MX] {
        let resp = udp_query(addr, "dns.home.", qtype).await;
        assert_eq!(
            resp.response_code(),
            ResponseCode::NoError,
            "{qtype:?} at a name with an A record is NODATA, not NXDOMAIN"
        );
        assert!(resp.answers().is_empty(), "{qtype:?} NODATA has no answers");
    }
}

/// The control, on the same socket and the same zone: a name with nothing at or
/// beneath it is still NXDOMAIN. Without this, a server that answered NOERROR
/// for every name in the zone would pass the test above.
#[tokio::test]
async fn an_absent_name_is_still_nxdomain_over_udp() {
    let _serial = SERIAL.lock().await;
    let stack = v4_only_host_zone().await;
    let addr = serve_udp(stack.dns.clone()).await;

    for qtype in [RecordType::A, RecordType::AAAA, RecordType::MX] {
        let resp = udp_query(addr, "absent.home.", qtype).await;
        assert_eq!(
            resp.response_code(),
            ResponseCode::NXDomain,
            "{qtype:?} at an absent name stays NXDOMAIN"
        );
    }
}

/// The same decision reaches TCP. The gate sits in `resolve_query`, which every
/// transport shares, and a regression that wired one transport past it would
/// leave the UDP tests green.
#[tokio::test]
async fn the_same_decision_reaches_tcp() {
    let _serial = SERIAL.lock().await;
    let stack = v4_only_host_zone().await;
    let addr = serve_tcp(stack.dns.clone()).await;

    let nodata = tcp_query(addr, "dns.home.", RecordType::AAAA).await;
    assert_eq!(nodata.response_code(), ResponseCode::NoError);
    assert!(nodata.answers().is_empty());

    let nxdomain = tcp_query(addr, "absent.home.", RecordType::AAAA).await;
    assert_eq!(nxdomain.response_code(), ResponseCode::NXDomain);
}

/// The apex is the sharpest form of the contradiction: `home. SOA` answers while
/// `home. A` denied that `home.` existed at all.
#[tokio::test]
async fn the_zone_apex_does_not_deny_itself() {
    let _serial = SERIAL.lock().await;
    let stack = v4_only_host_zone().await;
    let addr = serve_udp(stack.dns.clone()).await;

    let soa = udp_query(addr, ZONE, RecordType::SOA).await;
    assert_eq!(soa.response_code(), ResponseCode::NoError);
    assert_eq!(soa.answers().len(), 1, "the control: the apex has an SOA");

    let a = udp_query(addr, ZONE, RecordType::A).await;
    assert_eq!(
        a.response_code(),
        ResponseCode::NoError,
        "an apex serving an SOA cannot answer NXDOMAIN for its own name"
    );
    assert!(a.answers().is_empty());
}

/// A query type that maps to no storable record kind used to skip the database
/// entirely, so the name was never looked up before being denied. CAA is the one
/// that bites: an ACME client reads it before issuing, and "this name does not
/// exist" is a different answer from "this name publishes no CAA policy".
#[tokio::test]
async fn an_unsupported_query_type_does_not_deny_the_name() {
    let _serial = SERIAL.lock().await;
    let stack = v4_only_host_zone().await;
    let addr = serve_udp(stack.dns.clone()).await;

    let present = udp_query(addr, "dns.home.", RecordType::CAA).await;
    assert_eq!(
        present.response_code(),
        ResponseCode::NoError,
        "CAA maps to no record kind, but the name still exists"
    );
    assert!(present.answers().is_empty());

    let absent = udp_query(addr, "absent.home.", RecordType::CAA).await;
    assert_eq!(
        absent.response_code(),
        ResponseCode::NXDomain,
        "the control: an unsupported type at an absent name is NXDOMAIN"
    );
}

/// An alias answers every type asked at its name, over a real socket.
///
/// RFC 1034 §3.6.2 makes a CNAME the answer to any query type except CNAME
/// itself — the alias belongs to the NAME, not to the type. The whole local
/// lookup is gated on a mapped `RecordKind`, so CAA and NAPTR skipped the CNAME
/// check with it: an ACME client reading CAA at an aliased name was told the
/// name published no policy, rather than being sent to the target that holds
/// one. The control is a mapped type, which followed the alias all along.
#[tokio::test]
async fn an_unsupported_query_type_still_follows_a_cname() {
    let _serial = SERIAL.lock().await;
    let stack = make_stack();
    stack.add_zone(ZONE).await;
    stack
        .add_record("alias.home.", RecordKind::CNAME, "target.home.")
        .await;
    let addr = serve_udp(stack.dns.clone()).await;

    let a = udp_query(addr, "alias.home.", RecordType::A).await;
    assert_eq!(a.response_code(), ResponseCode::NoError);
    assert_eq!(
        a.answers().len(),
        1,
        "the control: a mapped type follows it"
    );
    assert_eq!(a.answers()[0].record_type(), RecordType::CNAME);

    let caa = udp_query(addr, "alias.home.", RecordType::CAA).await;
    assert_eq!(caa.response_code(), ResponseCode::NoError);
    assert_eq!(
        caa.answers().len(),
        1,
        "CAA at an aliased name is answered with the alias"
    );
    assert_eq!(caa.answers()[0].record_type(), RecordType::CNAME);

    // The control that keeps this from meaning "CAA always answers something":
    // an unaliased name in the same zone still gets an empty NODATA.
    stack
        .add_record("plain.home.", RecordKind::A, "192.0.2.7")
        .await;
    let plain = udp_query(addr, "plain.home.", RecordType::CAA).await;
    assert_eq!(plain.response_code(), ResponseCode::NoError);
    assert!(plain.answers().is_empty(), "no alias, no answer");
}

/// An empty non-terminal exists by virtue of its descendants. `_tcp.gitea.home.`
/// holds nothing while `_https._tcp.gitea.home.` holds a TLSA, and NXDOMAIN for
/// the parent tells an RFC 8020 resolver the child cannot exist — erasing the
/// very record that proves the parent real.
#[tokio::test]
async fn an_empty_non_terminal_is_nodata() {
    let _serial = SERIAL.lock().await;
    let stack = make_stack();
    stack.add_zone(ZONE).await;
    stack
        .add_record(
            "_https._tcp.gitea.home.",
            RecordKind::TLSA,
            "3 1 1 abcdef0123456789",
        )
        .await;
    let addr = serve_udp(stack.dns.clone()).await;

    let ent = udp_query(addr, "_tcp.gitea.home.", RecordType::A).await;
    assert_eq!(
        ent.response_code(),
        ResponseCode::NoError,
        "a name with descendants exists even holding no records itself"
    );

    let absent = udp_query(addr, "_udp.gitea.home.", RecordType::A).await;
    assert_eq!(
        absent.response_code(),
        ResponseCode::NXDomain,
        "the control: a sibling with neither records nor descendants"
    );
}

/// RFC 2308 §3: both negatives carry the zone's SOA in the authority section,
/// and it is the zone's SOA rather than anything derived from the queried name.
/// Its MINIMUM is how a resolver learns how long the absence may be cached; with
/// no SOA the response carried no negative TTL at all and every resolver picked
/// its own.
#[tokio::test]
async fn both_negatives_carry_the_zone_soa() {
    let _serial = SERIAL.lock().await;
    let stack = v4_only_host_zone().await;
    let addr = serve_udp(stack.dns.clone()).await;

    for (name, expected) in [
        ("dns.home.", ResponseCode::NoError),
        ("absent.home.", ResponseCode::NXDomain),
    ] {
        let resp = udp_query(addr, name, RecordType::AAAA).await;
        assert_eq!(resp.response_code(), expected, "{name}");
        assert_eq!(
            soa_names(&resp),
            vec![ZONE.to_string()],
            "{name} must carry exactly the zone SOA in AUTHORITY"
        );
    }

    // The control: a positive answer is not a negative and carries no SOA.
    let positive = udp_query(addr, "dns.home.", RecordType::A).await;
    assert_eq!(positive.response_code(), ResponseCode::NoError);
    assert!(
        soa_names(&positive).is_empty(),
        "a positive answer carries no negative-caching SOA"
    );
}

/// Both negatives stay authoritative. The AA bit is what tells a resolver the
/// negative is worth believing rather than worth asking someone else about.
#[tokio::test]
async fn both_negatives_stay_authoritative() {
    let _serial = SERIAL.lock().await;
    let stack = v4_only_host_zone().await;
    let addr = serve_udp(stack.dns.clone()).await;

    assert!(
        udp_query(addr, "dns.home.", RecordType::AAAA)
            .await
            .authoritative()
    );
    assert!(
        udp_query(addr, "absent.home.", RecordType::AAAA)
            .await
            .authoritative()
    );
}

// ========================================================
// The scoped paths
// ========================================================

/// A scope that owns a TLD makes the same distinction inside its own partition.
/// This is a separate code path from the global one — it reads the scoped record
/// cache rather than SQLite — and had the same collapse.
#[tokio::test]
async fn a_scope_owned_tld_distinguishes_nodata_from_nxdomain() {
    let _serial = SERIAL.lock().await;
    let stack = make_stack();
    stack.add_scope("office", "office.home").await;
    stack
        .add_scoped_record("office", "gitea.office.home.", RecordKind::A, "10.0.0.9")
        .await;
    stack.join("10.0.0.5", "office").await;

    let a = stack
        .ask_from("10.0.0.5", "gitea.office.home.", RecordType::A)
        .await;
    assert_eq!(a.response_code(), ResponseCode::NoError);
    assert_eq!(a.answers().len(), 1, "the control: the name does exist");

    let nodata = stack
        .ask_from("10.0.0.5", "gitea.office.home.", RecordType::AAAA)
        .await;
    assert_eq!(
        nodata.response_code(),
        ResponseCode::NoError,
        "a scoped name that exists is not denied for a missing type"
    );

    let nxdomain = stack
        .ask_from("10.0.0.5", "absent.office.home.", RecordType::AAAA)
        .await;
    assert_eq!(
        nxdomain.response_code(),
        ResponseCode::NXDomain,
        "the control: an absent scoped name stays NXDOMAIN"
    );
}

/// The LAN fallback resolves a network's TLD for a trusted local client, and
/// decides the negative inside the owning scope. A LAN client sees the same
/// NODATA/NXDOMAIN split an overlay peer does.
#[tokio::test]
async fn the_lan_fallback_distinguishes_nodata_from_nxdomain() {
    let _serial = SERIAL.lock().await;
    let stack = make_stack();
    stack.add_scope("office", "office.home").await;
    stack
        .add_scoped_record("office", "gitea.office.home.", RecordKind::A, "10.0.0.9")
        .await;

    let nodata = stack
        .ask_from("127.0.0.1", "gitea.office.home.", RecordType::AAAA)
        .await;
    assert_eq!(
        nodata.response_code(),
        ResponseCode::NoError,
        "the LAN sees a name that exists in the owning scope"
    );

    let nxdomain = stack
        .ask_from("127.0.0.1", "absent.office.home.", RecordType::AAAA)
        .await;
    assert_eq!(
        nxdomain.response_code(),
        ResponseCode::NXDomain,
        "the control: absent in the owning scope too"
    );
}

/// A **dual-homed** name — a global LAN-facing record plus a scoped overlay one,
/// the shape resolution step 5 exists for — exists in either half, and the LAN
/// fallback has to consult both before denying it.
///
/// This is the case a scope-only existence check gets wrong. The LAN client
/// reaches the fallback only *after* the global lookup missed, and that lookup
/// was keyed by type: asking AAAA for a name whose global record is an A misses
/// globally, misses in the scope, and would be called nonexistent — while the
/// very next query returns its A from the global table.
#[tokio::test]
async fn the_lan_fallback_sees_a_globally_recorded_name_under_an_owned_tld() {
    let _serial = SERIAL.lock().await;
    let stack = make_stack();
    stack.add_scope("office", "office.home").await;
    // Global only: no scoped record for this name at all.
    stack
        .add_record("nas.office.home.", RecordKind::A, "192.168.1.20")
        .await;

    let a = stack
        .ask_from("127.0.0.1", "nas.office.home.", RecordType::A)
        .await;
    assert_eq!(a.response_code(), ResponseCode::NoError);
    assert_eq!(
        a.answers().len(),
        1,
        "the control: the LAN resolves this name from the global table"
    );

    let nodata = stack
        .ask_from("127.0.0.1", "nas.office.home.", RecordType::AAAA)
        .await;
    assert_eq!(
        nodata.response_code(),
        ResponseCode::NoError,
        "a name the global table serves must not be denied by the scope alone"
    );
    assert!(nodata.answers().is_empty());

    let nxdomain = stack
        .ask_from("127.0.0.1", "absent.office.home.", RecordType::AAAA)
        .await;
    assert_eq!(
        nxdomain.response_code(),
        ResponseCode::NXDomain,
        "the control: absent in both halves"
    );
}

/// **The partition wins over the RFC.** A TLD owned by a *different* scope is
/// answered NXDOMAIN whether or not the name exists over there — this is the one
/// place the server deliberately denies a name it knows about.
///
/// NODATA would assert that the name is real and only the type is missing, and
/// that assertion is exactly what split horizon withholds: a scope could
/// enumerate a sibling network's names by watching which ones came back NODATA
/// instead of NXDOMAIN. The control is the identical query from inside the
/// owning scope, which *does* get NODATA — so this test cannot pass merely
/// because the record was never created.
#[tokio::test]
async fn a_foreign_scopes_tld_is_denied_even_when_the_name_exists() {
    let _serial = SERIAL.lock().await;
    let stack = make_stack();
    stack.add_scope("office", "office.home").await;
    stack.add_scope("lab", "lab.home").await;
    stack
        .add_scoped_record("lab", "gitea.lab.home.", RecordKind::A, "10.1.0.9")
        .await;
    stack.join("10.0.0.5", "office").await;
    stack.join("10.1.0.5", "lab").await;

    let inside = stack
        .ask_from("10.1.0.5", "gitea.lab.home.", RecordType::AAAA)
        .await;
    assert_eq!(
        inside.response_code(),
        ResponseCode::NoError,
        "the control: inside the owning scope the name exists, so NODATA"
    );

    let outside = stack
        .ask_from("10.0.0.5", "gitea.lab.home.", RecordType::AAAA)
        .await;
    assert_eq!(
        outside.response_code(),
        ResponseCode::NXDomain,
        "a sibling scope must not learn the name exists"
    );
}

// ========================================================
// Metrics
// ========================================================

/// The two negatives are counted apart, under `answers_total{source}` and under
/// the reason family. Counting them together — as one `authoritative_nxdomain`
/// bucket — is how the original bug stayed invisible: the rate of authoritative
/// negatives never changed, only their meaning.
#[tokio::test]
async fn negatives_are_counted_by_kind_and_by_reason() {
    let _serial = SERIAL.lock().await;
    let stack = v4_only_host_zone().await;
    let addr = serve_udp(stack.dns.clone()).await;

    let before = metrics().render();
    let nodata_before = series(
        &before,
        "rolodex_dns_answers_total",
        "source",
        "authoritative_nodata",
    );
    let nxdomain_before = series(
        &before,
        "rolodex_dns_answers_total",
        "source",
        "authoritative_nxdomain",
    );
    let type_absent_before = series(
        &before,
        "rolodex_dns_authoritative_negative_total",
        "reason",
        "type_absent",
    );
    let name_absent_before = series(
        &before,
        "rolodex_dns_authoritative_negative_total",
        "reason",
        "name_absent",
    );

    udp_query(addr, "dns.home.", RecordType::AAAA).await;
    udp_query(addr, "absent.home.", RecordType::AAAA).await;

    let after = metrics().render();
    assert_eq!(
        series(
            &after,
            "rolodex_dns_answers_total",
            "source",
            "authoritative_nodata"
        ),
        nodata_before + 1,
        "the NODATA answer is counted as NODATA"
    );
    assert_eq!(
        series(
            &after,
            "rolodex_dns_answers_total",
            "source",
            "authoritative_nxdomain"
        ),
        nxdomain_before + 1,
        "and the NXDOMAIN answer separately as NXDOMAIN"
    );
    assert_eq!(
        series(
            &after,
            "rolodex_dns_authoritative_negative_total",
            "reason",
            "type_absent",
        ),
        type_absent_before + 1,
    );
    assert_eq!(
        series(
            &after,
            "rolodex_dns_authoritative_negative_total",
            "reason",
            "name_absent",
        ),
        name_absent_before + 1,
    );
}

/// The unsupported-type reason is its own bucket, because it is the one negative
/// that is a property of the QUESTION rather than of the zone. An operator
/// watching it climb is watching for a record type the server ought to support —
/// which is invisible if it folds into `name_absent`.
#[tokio::test]
async fn an_unsupported_type_is_counted_under_its_own_reason() {
    let _serial = SERIAL.lock().await;
    let stack = v4_only_host_zone().await;
    let addr = serve_udp(stack.dns.clone()).await;

    let before = metrics().render();
    let unsupported_before = series(
        &before,
        "rolodex_dns_authoritative_negative_total",
        "reason",
        "unsupported_type",
    );
    let type_absent_before = series(
        &before,
        "rolodex_dns_authoritative_negative_total",
        "reason",
        "type_absent",
    );

    udp_query(addr, "dns.home.", RecordType::CAA).await;

    let after = metrics().render();
    assert_eq!(
        series(
            &after,
            "rolodex_dns_authoritative_negative_total",
            "reason",
            "unsupported_type",
        ),
        unsupported_before + 1,
    );
    assert_eq!(
        series(
            &after,
            "rolodex_dns_authoritative_negative_total",
            "reason",
            "type_absent",
        ),
        type_absent_before,
        "the control: a CAA miss is not a type_absent miss"
    );
}

/// A cross-scope denial is counted as such rather than as a missing name. The
/// two are the same rcode on the wire and mean entirely different things: one is
/// a name nobody has, the other is a name being deliberately withheld.
#[tokio::test]
async fn a_hidden_foreign_tld_is_counted_as_hidden() {
    let _serial = SERIAL.lock().await;
    let stack = make_stack();
    stack.add_scope("office", "office.home").await;
    stack.add_scope("lab", "lab.home").await;
    stack
        .add_scoped_record("lab", "gitea.lab.home.", RecordKind::A, "10.1.0.9")
        .await;
    stack.join("10.0.0.5", "office").await;

    let before = metrics().render();
    let hidden_before = series(
        &before,
        "rolodex_dns_authoritative_negative_total",
        "reason",
        "scope_hidden",
    );
    let name_absent_before = series(
        &before,
        "rolodex_dns_authoritative_negative_total",
        "reason",
        "name_absent",
    );

    stack
        .ask_from("10.0.0.5", "gitea.lab.home.", RecordType::A)
        .await;

    let after = metrics().render();
    assert_eq!(
        series(
            &after,
            "rolodex_dns_authoritative_negative_total",
            "reason",
            "scope_hidden",
        ),
        hidden_before + 1,
    );
    assert_eq!(
        series(
            &after,
            "rolodex_dns_authoritative_negative_total",
            "reason",
            "name_absent",
        ),
        name_absent_before,
        "the control: a withheld name is not an absent one"
    );
}
