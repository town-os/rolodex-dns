//! End-to-end tests for the blocklist contract:
//!
//! > **Every blocklist positive is answered NXDOMAIN, and an allowlist entry is
//! > the only thing that suppresses one.**
//!
//! Five lists can produce a positive — an IP-based RBL provider, a provider a
//! *scope* opted into, a domain (DNSBL) provider, a local entry naming an IP,
//! and a local entry naming a DNS name — reached through two different gates
//! (resolution step 2 for reverse-DNS names, step 7 for forward names) on two
//! code paths (scoped and global). The unit tests in `src/dns_server.rs` pin
//! each gate; these run the whole stack: a mutation over the **gRPC control
//! plane**, then a query over a **real UDP or TCP socket**, asserting what a
//! client actually receives.
//!
//! That combination is the part unit tests cannot show. The blocklist gates sit
//! at specific points in `resolve_query`, ahead of the response cache but behind
//! the local-record lookup, and they are reached identically from every
//! transport. A regression that moved a gate — or that wired one transport
//! straight to the resolver — would leave every unit test green.
//!
//! Each test carries its own control. A gate that blocks everything satisfies
//! "positives are NXDOMAIN" and a gate that blocks nothing satisfies "the
//! allowlist exempts"; only the pair together says anything.

use rolodex_dns::db::{Database, DnsRecord, NetworkAssociation, NetworkScope, RecordKind};
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::grpc_service::RolodexDnsGrpcService;
use rolodex_dns::grpc_service::proto::rolodex_dns_service_server::RolodexDnsService;
use rolodex_dns::grpc_service::proto::{
    AddDnsblAllowlistEntryRequest, AddLocalRblEntryRequest, AddScopeRblProviderRequest,
    DnsblAllowlistEntry, LocalRblEntry, ScopeRblProvider,
};
use rolodex_dns::rbl::{RblChecker, RblProvider, RblResolver};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tonic::Request;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

// ========================================================
// Harness
// ========================================================

/// Lists nothing: the control resolver, so a block can only come from the local
/// tables.
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

/// Lists everything, so any name reaching a provider is a positive. Paired with
/// an allowlist, "not blocked" can then only mean "never reached a provider".
struct AlwaysListedResolver;

#[async_trait::async_trait]
impl RblResolver for AlwaysListedResolver {
    async fn lookup_rbl(
        &self,
        _query: &str,
    ) -> Result<Option<rolodex_dns::rbl::RblAnswer>, anyhow::Error> {
        Ok(Some(rolodex_dns::rbl::RblAnswer::listed(300)))
    }
}

const AUTH: &str = "test-secret";

struct Stack {
    db: Database,
    dns: Arc<DnsServer>,
    grpc: RolodexDnsGrpcService,
}

/// Builds the full stack — database, DNS server, gRPC service — sharing one
/// database handle, which is what makes a control-plane mutation visible to the
/// query path the way it is in the real server.
fn make_stack(rbl: Arc<RblChecker>) -> Stack {
    let db = Database::open_memory().unwrap();
    let dns = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
    let grpc = RolodexDnsGrpcService::new(db.clone(), dns.clone(), rbl, AUTH.to_string(), false);
    Stack { db, dns, grpc }
}

/// The IP-based RBL, enabled, with one global provider backed by `resolver`.
fn rbl_with_provider(resolver: Arc<dyn RblResolver>) -> Arc<RblChecker> {
    Arc::new(RblChecker::with_resolver(
        true,
        vec![RblProvider::new("ip.test", true)],
        resolver,
    ))
}

/// The domain blocklist, enabled, with one provider backed by `resolver`. The
/// IP-based RBL is left off so a block can only be the DNSBL.
async fn rbl_with_dnsbl(resolver: Arc<dyn RblResolver>) -> Arc<RblChecker> {
    let rbl = Arc::new(RblChecker::with_resolver(false, vec![], resolver));
    rbl.set_dnsbl_config(true, vec![RblProvider::new("dbl.test", true)])
        .await;
    rbl
}

/// Neither list enabled: only the local tables can block.
fn rbl_local_only() -> Arc<RblChecker> {
    Arc::new(RblChecker::with_resolver(
        false,
        vec![],
        Arc::new(NeverListedResolver),
    ))
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

/// Starts the real UDP listener on an ephemeral port and returns its address.
/// Going through `serve_udp` rather than calling `handle_query` directly is the
/// point: it exercises the socket, the per-query task, and the source-address
/// classification a client's packet actually goes through.
async fn serve_udp(dns: Arc<DnsServer>) -> SocketAddr {
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let bind = addr.to_string();
    tokio::spawn(async move {
        let _ = dns.serve_udp(&bind).await;
    });

    // UDP `send_to` succeeds whether or not anything is listening, so readiness
    // has to be a query that comes *back*. The name is deliberately unrelated to
    // anything a test asserts on.
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

/// Sends `query` over UDP and returns the parsed reply.
async fn udp_query(server: SocketAddr, query: &[u8]) -> Message {
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(query, server).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .expect("no UDP reply")
        .unwrap();
    Message::from_bytes(&buf[..len]).unwrap()
}

/// Sends `query` over TCP with the 2-byte length prefix and returns the reply.
async fn tcp_query(server: SocketAddr, query: &[u8]) -> Message {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(server).await.unwrap();
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(query).await.unwrap();

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.unwrap();
    let mut buf = vec![0u8; u16::from_be_bytes(len_buf) as usize];
    stream.read_exact(&mut buf).await.unwrap();
    Message::from_bytes(&buf).unwrap()
}

async fn serve_tcp(dns: Arc<DnsServer>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let bind = addr.to_string();
    tokio::spawn(async move {
        let _ = dns.serve_tcp(&bind).await;
    });
    // A TCP connect fails outright until the listener is bound, so it is its own
    // readiness check.
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("TCP listener never came up on {addr}");
}

/// Polls a UDP query until it is answered NXDOMAIN.
///
/// Provider verdicts are filled asynchronously — the first query for a cold name
/// primes the cache and is answered without waiting on the network — so the
/// block lands on a later query. Returns the last reply seen if it never does,
/// letting the caller's `assert_eq!` report the real rcode.
async fn udp_until_blocked(server: SocketAddr, query: &[u8]) -> Message {
    let mut last = udp_query(server, query).await;
    for _ in 0..200 {
        if last.response_code() == ResponseCode::NXDomain {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        last = udp_query(server, query).await;
    }
    last
}

/// Fails if `query` is ever answered NXDOMAIN. The counterpart to
/// [`udp_until_blocked`]: an exemption that only delayed a block would satisfy a
/// single non-NXDOMAIN answer, because the provider cache starts cold.
async fn udp_never_blocked(server: SocketAddr, query: &[u8], what: &str) {
    for _ in 0..40 {
        let resp = udp_query(server, query).await;
        assert_ne!(
            resp.response_code(),
            ResponseCode::NXDomain,
            "{what} must never be blocked"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn allowlist_req(name: &str) -> Request<AddDnsblAllowlistEntryRequest> {
    Request::new(AddDnsblAllowlistEntryRequest {
        entry: Some(DnsblAllowlistEntry {
            name: name.to_string(),
            reason: "false positive".to_string(),
        }),
        auth_token: AUTH.to_string(),
    })
}

fn local_rbl_req(name: &str) -> Request<AddLocalRblEntryRequest> {
    Request::new(AddLocalRblEntryRequest {
        entry: Some(LocalRblEntry {
            name: name.to_string(),
            reason: "listed".to_string(),
        }),
        auth_token: AUTH.to_string(),
    })
}

// ========================================================
// Local blocklist entries, over the wire
// ========================================================

/// A local entry naming an IP blocks its reverse lookup with NXDOMAIN, over a
/// real socket. The control address proves the listener is not simply refusing
/// every reverse query.
#[tokio::test]
async fn test_local_rbl_ip_entry_is_nxdomain_over_udp() {
    let stack = make_stack(rbl_local_only());
    stack
        .grpc
        .add_local_rbl_entry(local_rbl_req("192.168.1.100"))
        .await
        .unwrap();
    let addr = serve_udp(stack.dns.clone()).await;

    let blocked = udp_query(
        addr,
        &build_query("100.1.168.192.in-addr.arpa.", RecordType::PTR),
    )
    .await;
    assert_eq!(blocked.response_code(), ResponseCode::NXDomain);
    assert!(blocked.answers().is_empty());

    let allowed = udp_query(
        addr,
        &build_query("101.1.168.192.in-addr.arpa.", RecordType::PTR),
    )
    .await;
    assert_eq!(
        allowed.response_code(),
        ResponseCode::Refused,
        "an unlisted reverse name is not blocked — it is REFUSED because `arpa.` \
         is never resolved off this box, and specifically not NXDOMAIN, which is \
         what a blocklist that blocked everything would return"
    );
}

/// The same entry written the other way — as the reverse name `dig -x` prints —
/// blocks identically. An operator should not have to hand-reverse octets for
/// their blocklist entry to mean anything.
#[tokio::test]
async fn test_local_rbl_reverse_name_entry_is_nxdomain_over_udp() {
    let stack = make_stack(rbl_local_only());
    stack
        .grpc
        .add_local_rbl_entry(local_rbl_req("100.1.168.192.in-addr.arpa"))
        .await
        .unwrap();
    let addr = serve_udp(stack.dns.clone()).await;

    let blocked = udp_query(
        addr,
        &build_query("100.1.168.192.in-addr.arpa.", RecordType::PTR),
    )
    .await;
    assert_eq!(blocked.response_code(), ResponseCode::NXDomain);

    let allowed = udp_query(
        addr,
        &build_query("101.1.168.192.in-addr.arpa.", RecordType::PTR),
    )
    .await;
    assert_eq!(
        allowed.response_code(),
        ResponseCode::Refused,
        "an unlisted reverse name is not blocked — it is REFUSED because `arpa.` \
         is never resolved off this box, and specifically not NXDOMAIN, which is \
         what a blocklist that blocked everything would return"
    );
}

/// A local entry naming a forward name blocks it (step 7), and the same gate
/// applies on TCP — the two transports funnel through one resolution path, and
/// a blocklist that only covered UDP would be trivially bypassed by `dig +tcp`.
#[tokio::test]
async fn test_local_rbl_forward_name_is_nxdomain_on_udp_and_tcp() {
    let stack = make_stack(rbl_local_only());
    stack
        .grpc
        .add_local_rbl_entry(local_rbl_req("tracker.example.com"))
        .await
        .unwrap();
    let udp = serve_udp(stack.dns.clone()).await;
    let tcp = serve_tcp(stack.dns.clone()).await;

    let query = build_query("tracker.example.com.", RecordType::A);
    assert_eq!(
        udp_query(udp, &query).await.response_code(),
        ResponseCode::NXDomain
    );
    assert_eq!(
        tcp_query(tcp, &query).await.response_code(),
        ResponseCode::NXDomain
    );

    let control = build_query("safe.example.com.", RecordType::A);
    assert_eq!(
        udp_query(udp, &control).await.response_code(),
        ResponseCode::ServFail
    );
    assert_eq!(
        tcp_query(tcp, &control).await.response_code(),
        ResponseCode::ServFail
    );
}

// ========================================================
// Provider positives, over the wire
// ========================================================

/// An IP-based provider positive is NXDOMAIN over a real socket.
#[tokio::test]
async fn test_rbl_provider_positive_is_nxdomain_over_udp() {
    let stack = make_stack(rbl_with_provider(Arc::new(AlwaysListedResolver)));
    let addr = serve_udp(stack.dns.clone()).await;

    let resp = udp_until_blocked(
        addr,
        &build_query("100.1.168.192.in-addr.arpa.", RecordType::PTR),
    )
    .await;
    assert_eq!(resp.response_code(), ResponseCode::NXDomain);
    assert!(resp.answers().is_empty());
}

/// A domain provider positive is NXDOMAIN over a real socket, and it beats a
/// previously-cached upstream answer because the gate sits ahead of the cache.
#[tokio::test]
async fn test_dnsbl_provider_positive_is_nxdomain_over_udp() {
    let stack = make_stack(rbl_with_dnsbl(Arc::new(AlwaysListedResolver)).await);
    let addr = serve_udp(stack.dns.clone()).await;

    let resp = udp_until_blocked(addr, &build_query("ads.example.net.", RecordType::A)).await;
    assert_eq!(resp.response_code(), ResponseCode::NXDomain);
    assert!(resp.answers().is_empty());
}

/// A provider a *scope* opted into blocks inside that scope. Registered over
/// gRPC, exactly as an operator would, because the failure this pins was a
/// configuration that stored and listed back correctly while never being
/// consulted on the query path.
#[tokio::test]
async fn test_scope_rbl_provider_positive_is_nxdomain() {
    // Global RBL enabled but with no providers of its own: any block is the
    // scope's list.
    let rbl = Arc::new(RblChecker::with_resolver(
        true,
        vec![],
        Arc::new(AlwaysListedResolver),
    ));
    let stack = make_stack(rbl);
    stack
        .db
        .create_network_scope(&NetworkScope {
            name: "office".to_string(),
            home_domain: "office.home".to_string(),
        })
        .unwrap();
    stack
        .db
        .join_network(&NetworkAssociation {
            ip_address: "127.0.0.1".to_string(),
            scope_name: "office".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();
    stack
        .grpc
        .add_scope_rbl_provider(Request::new(AddScopeRblProviderRequest {
            provider: Some(ScopeRblProvider {
                scope_name: "office".to_string(),
                zone: "office.rbl".to_string(),
                enabled: true,
                ..Default::default()
            }),
            auth_token: AUTH.to_string(),
        }))
        .await
        .unwrap();

    let addr = serve_udp(stack.dns.clone()).await;
    let resp = udp_until_blocked(
        addr,
        &build_query("100.1.168.192.in-addr.arpa.", RecordType::PTR),
    )
    .await;
    assert_eq!(resp.response_code(), ResponseCode::NXDomain);
}

// ========================================================
// The allowlist is the exemption — for every list
// ========================================================

/// An allowlist entry added over gRPC exempts a reverse lookup from the IP-based
/// RBL, and takes effect on the next query: the gate runs ahead of the response
/// cache, so no flush is needed. The control address stays blocked.
#[tokio::test]
async fn test_allowlist_exempts_reverse_lookup_from_rbl_provider() {
    let stack = make_stack(rbl_with_provider(Arc::new(AlwaysListedResolver)));
    let addr = serve_udp(stack.dns.clone()).await;

    // Blocked first, so the exemption below is a change and not a starting state.
    let blocked = build_query("100.1.168.192.in-addr.arpa.", RecordType::PTR);
    assert_eq!(
        udp_until_blocked(addr, &blocked).await.response_code(),
        ResponseCode::NXDomain
    );

    stack
        .grpc
        .add_dnsbl_allowlist_entry(allowlist_req("192.168.1.100"))
        .await
        .unwrap();

    udp_never_blocked(addr, &blocked, "an allowlisted address").await;

    let other = build_query("101.1.168.192.in-addr.arpa.", RecordType::PTR);
    assert_eq!(
        udp_until_blocked(addr, &other).await.response_code(),
        ResponseCode::NXDomain
    );
}

/// The reverse *name* is the other accepted spelling of that exemption, and
/// being a DNS name it is suffix-matched: one entry lifts a block on a whole
/// reverse zone.
#[tokio::test]
async fn test_allowlist_reverse_zone_exempts_whole_subtree() {
    let stack = make_stack(rbl_with_provider(Arc::new(AlwaysListedResolver)));
    stack
        .grpc
        .add_dnsbl_allowlist_entry(allowlist_req("1.168.192.in-addr.arpa"))
        .await
        .unwrap();
    let addr = serve_udp(stack.dns.clone()).await;

    for name in ["100.1.168.192.in-addr.arpa.", "7.1.168.192.in-addr.arpa."] {
        udp_never_blocked(addr, &build_query(name, RecordType::PTR), name).await;
    }

    // A different /24 is untouched.
    let other = build_query("100.2.168.192.in-addr.arpa.", RecordType::PTR);
    assert_eq!(
        udp_until_blocked(addr, &other).await.response_code(),
        ResponseCode::NXDomain
    );
}

/// The allowlist overrides a local entry too — under either spelling — because
/// a false positive in the local table is as much an operator problem as one at
/// a provider.
#[tokio::test]
async fn test_allowlist_overrides_local_entries_over_udp() {
    for entry in ["192.168.1.100", "100.1.168.192.in-addr.arpa"] {
        let stack = make_stack(rbl_local_only());
        stack
            .grpc
            .add_local_rbl_entry(local_rbl_req(entry))
            .await
            .unwrap();
        let addr = serve_udp(stack.dns.clone()).await;

        let query = build_query("100.1.168.192.in-addr.arpa.", RecordType::PTR);
        assert_eq!(
            udp_query(addr, &query).await.response_code(),
            ResponseCode::NXDomain,
            "local entry {entry} must block before the allowlist is added"
        );

        stack
            .grpc
            .add_dnsbl_allowlist_entry(allowlist_req("100.1.168.192.in-addr.arpa"))
            .await
            .unwrap();
        assert_eq!(
            udp_query(addr, &query).await.response_code(),
            ResponseCode::Refused,
            "the allowlist must lift local entry {entry} — the name is then no \
             longer blocked, and is REFUSED because `arpa.` is never resolved \
             off this box"
        );
    }
}

/// The allowlist reaches the scoped path. Which lists apply to a source is the
/// scope's business; whether the escape hatch exists is not.
#[tokio::test]
async fn test_allowlist_exempts_inside_a_scope() {
    let rbl = Arc::new(RblChecker::with_resolver(
        true,
        vec![],
        Arc::new(AlwaysListedResolver),
    ));
    let stack = make_stack(rbl);
    stack
        .db
        .create_network_scope(&NetworkScope {
            name: "office".to_string(),
            home_domain: "office.home".to_string(),
        })
        .unwrap();
    stack
        .db
        .join_network(&NetworkAssociation {
            ip_address: "127.0.0.1".to_string(),
            scope_name: "office".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();
    stack
        .grpc
        .add_scope_rbl_provider(Request::new(AddScopeRblProviderRequest {
            provider: Some(ScopeRblProvider {
                scope_name: "office".to_string(),
                zone: "office.rbl".to_string(),
                enabled: true,
                ..Default::default()
            }),
            auth_token: AUTH.to_string(),
        }))
        .await
        .unwrap();
    stack
        .grpc
        .add_dnsbl_allowlist_entry(allowlist_req("192.168.1.100"))
        .await
        .unwrap();

    let addr = serve_udp(stack.dns.clone()).await;
    let exempt = build_query("100.1.168.192.in-addr.arpa.", RecordType::PTR);
    udp_never_blocked(addr, &exempt, "an allowlisted address inside a scope").await;

    let blocked = build_query("101.1.168.192.in-addr.arpa.", RecordType::PTR);
    assert_eq!(
        udp_until_blocked(addr, &blocked).await.response_code(),
        ResponseCode::NXDomain
    );
}

/// The forward-name exemption over both transports, for completeness alongside
/// the reverse cases above.
#[tokio::test]
async fn test_allowlist_exempts_forward_name_on_udp_and_tcp() {
    let stack = make_stack(rbl_with_dnsbl(Arc::new(AlwaysListedResolver)).await);
    stack
        .grpc
        .add_dnsbl_allowlist_entry(allowlist_req("vendor.example.com"))
        .await
        .unwrap();
    let udp = serve_udp(stack.dns.clone()).await;
    let tcp = serve_tcp(stack.dns.clone()).await;

    let exempt = build_query("cdn.vendor.example.com.", RecordType::A);
    udp_never_blocked(udp, &exempt, "an allowlisted forward name").await;
    assert_eq!(
        tcp_query(tcp, &exempt).await.response_code(),
        ResponseCode::ServFail
    );

    let blocked = build_query("ads.example.net.", RecordType::A);
    assert_eq!(
        udp_until_blocked(udp, &blocked).await.response_code(),
        ResponseCode::NXDomain
    );
}

// ========================================================
// What the allowlist must NOT do
// ========================================================

/// An IP literal is matched exactly. Addresses are written
/// most-significant-octet first, so a trailing run of octets is not a parent:
/// allowlisting `1.100` must not exempt `192.168.1.100`.
#[tokio::test]
async fn test_allowlist_ip_literal_does_not_suffix_match() {
    let stack = make_stack(rbl_with_provider(Arc::new(AlwaysListedResolver)));
    stack
        .grpc
        .add_dnsbl_allowlist_entry(allowlist_req("1.100"))
        .await
        .unwrap();
    let addr = serve_udp(stack.dns.clone()).await;

    let resp = udp_until_blocked(
        addr,
        &build_query("100.1.168.192.in-addr.arpa.", RecordType::PTR),
    )
    .await;
    assert_eq!(resp.response_code(), ResponseCode::NXDomain);
}

/// A near-miss of a forward-name entry is not exempt: matching is on label
/// boundaries, not string suffixes.
#[tokio::test]
async fn test_allowlist_forward_name_does_not_over_match() {
    let stack = make_stack(rbl_with_dnsbl(Arc::new(AlwaysListedResolver)).await);
    stack
        .grpc
        .add_dnsbl_allowlist_entry(allowlist_req("example.com"))
        .await
        .unwrap();
    let addr = serve_udp(stack.dns.clone()).await;

    let resp = udp_until_blocked(addr, &build_query("notexample.com.", RecordType::A)).await;
    assert_eq!(resp.response_code(), ResponseCode::NXDomain);
}

/// A blocklist never gates local data: a name this server is authoritative for
/// resolves from the database even while a provider lists it. The blocklist
/// gates *external* resolution, and inverting that would let a third-party
/// listing take out an internal service.
#[tokio::test]
async fn test_blocklist_does_not_shadow_local_records() {
    let stack = make_stack(rbl_with_dnsbl(Arc::new(AlwaysListedResolver)).await);
    stack
        .db
        .add_record(&DnsRecord {
            id: None,
            name: "gitea.default.home.".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.5".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
    let addr = serve_udp(stack.dns.clone()).await;

    // The provider lists everything, so an external name is NXDOMAIN…
    let blocked = build_query("ads.example.net.", RecordType::A);
    assert_eq!(
        udp_until_blocked(addr, &blocked).await.response_code(),
        ResponseCode::NXDomain
    );

    // …while the local record keeps resolving.
    let local = udp_query(addr, &build_query("gitea.default.home.", RecordType::A)).await;
    assert_eq!(local.response_code(), ResponseCode::NoError);
    assert_eq!(local.answers().len(), 1);
}
