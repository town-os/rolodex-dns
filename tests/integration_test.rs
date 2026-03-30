use rolodex_dns::db::{Database, DnsRecord, RecordKind};
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::grpc_service::RolodexDnsGrpcService;
use rolodex_dns::grpc_service::proto::rolodex_dns_service_server::RolodexDnsService;
use rolodex_dns::grpc_service::proto::{
    AddRecordRequest, AddScopedRecordRequest, CreateNetworkScopeRequest, DeleteNetworkScopeRequest,
    FlushCacheRequest, GetNetworkAssociationsRequest, GetRblConfigRequest, GetSearchDomainsRequest,
    JoinNetworkRequest, LeaveNetworkRequest, ListNetworkScopesRequest, ListRecordsRequest,
    ListScopedRecordsRequest, RemoveRecordRequest, RemoveScopedRecordRequest, SetForwarderRequest,
    SetRblConfigRequest,
};
use rolodex_dns::rbl::{RblChecker, RblProvider, RblResolver};
use std::sync::Arc;
use tonic::Request;

struct NeverListedResolver;

#[async_trait::async_trait]
impl RblResolver for NeverListedResolver {
    async fn lookup_rbl(&self, _query: &str) -> Result<Option<u32>, anyhow::Error> {
        Ok(None)
    }
}

struct AlwaysListedResolver;

#[async_trait::async_trait]
impl RblResolver for AlwaysListedResolver {
    async fn lookup_rbl(&self, _query: &str) -> Result<Option<u32>, anyhow::Error> {
        Ok(Some(300))
    }
}

fn make_test_stack() -> (
    Database,
    Arc<DnsServer>,
    Arc<RblChecker>,
    RolodexDnsGrpcService,
) {
    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(RblChecker::with_resolver(
        false,
        vec![],
        Arc::new(NeverListedResolver),
    ));
    let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
    let service = RolodexDnsGrpcService::new(
        db.clone(),
        dns_server.clone(),
        rbl.clone(),
        "test-secret".to_string(),
        false,
    );
    (db, dns_server, rbl, service)
}

// ========================================================
// Integration: gRPC add record -> DNS query sees it
// ========================================================

#[tokio::test]
async fn test_grpc_add_then_dns_query() {
    let (_db, dns_server, _rbl, service) = make_test_stack();

    // Add a record via gRPC
    let add_req = Request::new(AddRecordRequest {
        record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
            name: "integration.test.".to_string(),
            record_type: 0, // A
            value: "10.20.30.40".to_string(),
            ttl: 600,
            priority: 0,
        }),
        auth_token: "test-secret".to_string(),
    });
    let resp = service.add_record(add_req).await.unwrap();
    assert!(resp.into_inner().success);

    // Query via DNS server
    let query = build_dns_query("integration.test.", hickory_proto::rr::RecordType::A);
    let response_bytes = dns_server.handle_query(&query).await.unwrap();
    let response = hickory_proto::op::Message::from_bytes(&response_bytes).unwrap();

    assert_eq!(
        response.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );
    assert_eq!(response.answers().len(), 1);
    assert_eq!(response.answers()[0].ttl(), 600);
}

// ========================================================
// Integration: gRPC remove record -> DNS no longer sees it
// ========================================================

#[tokio::test]
async fn test_grpc_remove_then_dns_query() {
    let (_db, dns_server, _rbl, service) = make_test_stack();

    // Add a record
    let add_req = Request::new(AddRecordRequest {
        record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
            name: "remove-test.local.".to_string(),
            record_type: 0,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            priority: 0,
        }),
        auth_token: "test-secret".to_string(),
    });
    service.add_record(add_req).await.unwrap();

    // Verify it exists
    let query = build_dns_query("remove-test.local.", hickory_proto::rr::RecordType::A);
    let resp_bytes = dns_server.handle_query(&query).await.unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp.answers().len(), 1);

    // Remove it via gRPC
    let remove_req = Request::new(RemoveRecordRequest {
        name: "remove-test.local.".to_string(),
        record_type: 0,
        value: String::new(),
        auth_token: "test-secret".to_string(),
    });
    let remove_resp = service.remove_record(remove_req).await.unwrap();
    assert!(remove_resp.into_inner().success);

    // Verify DNS no longer returns it (should SERVFAIL since no forwarders)
    let resp_bytes = dns_server.handle_query(&query).await.unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp.answers().len(), 0);
}

// ========================================================
// Integration: gRPC list records with filters
// ========================================================

#[tokio::test]
async fn test_grpc_list_with_filters() {
    let (_db, _dns_server, _rbl, service) = make_test_stack();

    // Add multiple records
    for (name, rtype, value) in &[
        ("host1.example.com.", 0i32, "10.0.0.1"),
        ("host2.example.com.", 0i32, "10.0.0.2"),
        ("host1.example.com.", 1i32, "::1"), // AAAA
        ("other.test.com.", 0i32, "172.16.0.1"),
    ] {
        let req = Request::new(AddRecordRequest {
            record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
                name: name.to_string(),
                record_type: *rtype,
                value: value.to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "test-secret".to_string(),
        });
        service.add_record(req).await.unwrap();
    }

    // List all
    let list_req = Request::new(ListRecordsRequest {
        name_filter: String::new(),
        record_type_filter: 0,
        filter_by_type: false,
        auth_token: "test-secret".to_string(),
    });
    let resp = service.list_records(list_req).await.unwrap();
    assert_eq!(resp.into_inner().records.len(), 4);

    // List by wildcard
    let list_req = Request::new(ListRecordsRequest {
        name_filter: "*.example.com.".to_string(),
        record_type_filter: 0,
        filter_by_type: false,
        auth_token: "test-secret".to_string(),
    });
    let resp = service.list_records(list_req).await.unwrap();
    assert_eq!(resp.into_inner().records.len(), 3); // host1 A + AAAA, host2 A

    // List by type
    let list_req = Request::new(ListRecordsRequest {
        name_filter: String::new(),
        record_type_filter: 1, // AAAA
        filter_by_type: true,
        auth_token: "test-secret".to_string(),
    });
    let resp = service.list_records(list_req).await.unwrap();
    assert_eq!(resp.into_inner().records.len(), 1);
}

// ========================================================
// Integration: gRPC set forwarders -> DNS uses them
// ========================================================

#[tokio::test]
async fn test_grpc_set_forwarders() {
    let (_db, dns_server, _rbl, service) = make_test_stack();

    // Initially no forwarders
    let forwarders = dns_server.get_forwarders().await;
    assert!(forwarders.is_empty());

    // Set forwarders via gRPC
    let req = Request::new(SetForwarderRequest {
        forwarders: vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()],
        auth_token: "test-secret".to_string(),
    });
    let resp = service.set_forwarders(req).await.unwrap();
    assert!(resp.into_inner().success);

    // Verify DNS server has forwarders
    let forwarders = dns_server.get_forwarders().await;
    assert_eq!(forwarders.len(), 2);
}

// ========================================================
// Integration: RBL config via gRPC -> affects DNS resolution
// ========================================================

#[tokio::test]
async fn test_rbl_integration() {
    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(RblChecker::with_resolver(
        true,
        vec![RblProvider {
            zone: "test.rbl".to_string(),
            enabled: true,
        }],
        Arc::new(AlwaysListedResolver),
    ));
    let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
    let service = RolodexDnsGrpcService::new(
        db.clone(),
        dns_server.clone(),
        rbl.clone(),
        "test-secret".to_string(),
        false,
    );

    // Query for a reverse DNS name should be blocked
    let query = build_dns_query("4.3.2.1.in-addr.arpa.", hickory_proto::rr::RecordType::PTR);
    let resp_bytes = dns_server.handle_query(&query).await.unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::NXDomain
    );

    // Disable RBL via gRPC
    let rbl_req = Request::new(SetRblConfigRequest {
        enabled: false,
        providers: vec![],
        auth_token: "test-secret".to_string(),
    });
    service.set_rbl_config(rbl_req).await.unwrap();

    // Now query should not be blocked (will SERVFAIL because no forwarders)
    let resp_bytes = dns_server.handle_query(&query).await.unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_ne!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::NXDomain
    );
}

// ========================================================
// Integration: RBL config get/set roundtrip
// ========================================================

#[tokio::test]
async fn test_rbl_config_roundtrip() {
    let (_db, _dns_server, _rbl, service) = make_test_stack();

    // Set RBL config
    let req = Request::new(SetRblConfigRequest {
        enabled: true,
        providers: vec![
            rolodex_dns::grpc_service::proto::RblConfig {
                zone: "zen.spamhaus.org".to_string(),
                enabled: true,
            },
            rolodex_dns::grpc_service::proto::RblConfig {
                zone: "bl.spamcop.net".to_string(),
                enabled: false,
            },
        ],
        auth_token: "test-secret".to_string(),
    });
    service.set_rbl_config(req).await.unwrap();

    // Get config back
    let get_req = Request::new(GetRblConfigRequest {
        auth_token: "test-secret".to_string(),
    });
    let resp = service.get_rbl_config(get_req).await.unwrap();
    let config = resp.into_inner();
    assert!(config.enabled);
    assert_eq!(config.providers.len(), 2);
    assert_eq!(config.providers[0].zone, "zen.spamhaus.org");
    assert!(config.providers[0].enabled);
    assert_eq!(config.providers[1].zone, "bl.spamcop.net");
    assert!(!config.providers[1].enabled);
}

// ========================================================
// Integration: Flush cache via gRPC
// ========================================================

#[tokio::test]
async fn test_flush_cache_integration() {
    let (_db, _dns_server, _rbl, service) = make_test_stack();

    let req = Request::new(FlushCacheRequest {
        auth_token: "test-secret".to_string(),
    });
    let resp = service.flush_cache(req).await.unwrap();
    assert!(resp.into_inner().success);
}

// ========================================================
// Integration: Split-horizon - local overrides forwarding
// ========================================================

#[tokio::test]
async fn test_split_horizon_overlay() {
    let (_db, dns_server, _rbl, service) = make_test_stack();

    // Add a local record that overrides public DNS
    let add_req = Request::new(AddRecordRequest {
        record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
            name: "www.google.com.".to_string(),
            record_type: 0, // A
            value: "10.0.0.99".to_string(),
            ttl: 300,
            priority: 0,
        }),
        auth_token: "test-secret".to_string(),
    });
    service.add_record(add_req).await.unwrap();

    // DNS query should return our local record, not the real one
    let query = build_dns_query("www.google.com.", hickory_proto::rr::RecordType::A);
    let resp_bytes = dns_server.handle_query(&query).await.unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();

    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );
    assert_eq!(resp.answers().len(), 1);
    if let hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(ip)) = resp.answers()[0].data() {
        assert_eq!(*ip, std::net::Ipv4Addr::new(10, 0, 0, 99));
    } else {
        panic!("expected A record");
    }
}

// ========================================================
// Integration: TLD-level record
// ========================================================

#[tokio::test]
async fn test_tld_level_record() {
    let (_db, dns_server, _rbl, service) = make_test_stack();

    // Add a TLD-level record
    let add_req = Request::new(AddRecordRequest {
        record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
            name: "internal.".to_string(),
            record_type: 0,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        }),
        auth_token: "test-secret".to_string(),
    });
    service.add_record(add_req).await.unwrap();

    // DNS query for the TLD
    let query = build_dns_query("internal.", hickory_proto::rr::RecordType::A);
    let resp_bytes = dns_server.handle_query(&query).await.unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();

    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );
    assert_eq!(resp.answers().len(), 1);
}

// ========================================================
// Integration: Multiple record types for same name
// ========================================================

#[tokio::test]
async fn test_multiple_record_types_same_name() {
    let (_db, dns_server, _rbl, service) = make_test_stack();

    // Add A and AAAA for same name
    let add_a = Request::new(AddRecordRequest {
        record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
            name: "dual-stack.local.".to_string(),
            record_type: 0, // A
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        }),
        auth_token: "test-secret".to_string(),
    });
    service.add_record(add_a).await.unwrap();

    let add_aaaa = Request::new(AddRecordRequest {
        record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
            name: "dual-stack.local.".to_string(),
            record_type: 1, // AAAA
            value: "fd00::1".to_string(),
            ttl: 300,
            priority: 0,
        }),
        auth_token: "test-secret".to_string(),
    });
    service.add_record(add_aaaa).await.unwrap();

    // Query for A should only return A records
    let query_a = build_dns_query("dual-stack.local.", hickory_proto::rr::RecordType::A);
    let resp_bytes = dns_server.handle_query(&query_a).await.unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp.answers().len(), 1);
    assert_eq!(
        resp.answers()[0].record_type(),
        hickory_proto::rr::RecordType::A
    );

    // Query for AAAA should only return AAAA records
    let query_aaaa = build_dns_query("dual-stack.local.", hickory_proto::rr::RecordType::AAAA);
    let resp_bytes = dns_server.handle_query(&query_aaaa).await.unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp.answers().len(), 1);
    assert_eq!(
        resp.answers()[0].record_type(),
        hickory_proto::rr::RecordType::AAAA
    );
}

// ========================================================
// Integration: DNS UDP server accepts connections
// ========================================================

#[tokio::test]
async fn test_dns_udp_server() {
    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(RblChecker::with_resolver(
        false,
        vec![],
        Arc::new(NeverListedResolver),
    ));
    let dns_server = Arc::new(DnsServer::new(db.clone(), rbl, vec![]));

    // Add a test record
    db.add_record(&DnsRecord {
        id: None,
        name: "udp-test.local.".to_string(),
        record_type: RecordKind::A,
        value: "172.16.0.1".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();

    // Start UDP server on a random port
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();

    let server = dns_server.clone();
    let server_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        // Handle one query then exit
        let (len, src) = socket.recv_from(&mut buf).await.unwrap();
        let response = server.handle_query(&buf[..len]).await.unwrap();
        socket.send_to(&response, src).await.unwrap();
    });

    // Send a DNS query
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = build_dns_query("udp-test.local.", hickory_proto::rr::RecordType::A);
    client_socket.send_to(&query, server_addr).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client_socket.recv_from(&mut buf),
    )
    .await
    .unwrap()
    .unwrap();

    let response = hickory_proto::op::Message::from_bytes(&buf[..len]).unwrap();
    assert_eq!(
        response.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );
    assert_eq!(response.answers().len(), 1);

    server_handle.await.unwrap();
}

// ========================================================
// Integration: DNS TCP server accepts connections
// ========================================================

#[tokio::test]
async fn test_dns_tcp_server() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(RblChecker::with_resolver(
        false,
        vec![],
        Arc::new(NeverListedResolver),
    ));
    let dns_server = Arc::new(DnsServer::new(db.clone(), rbl, vec![]));

    // Add a test record
    db.add_record(&DnsRecord {
        id: None,
        name: "tcp-test.local.".to_string(),
        record_type: RecordKind::A,
        value: "172.16.0.2".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();

    // Start TCP server on a random port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server = dns_server.clone();
    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut reader, mut writer) = stream.into_split();
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await.unwrap();
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        let mut msg_buf = vec![0u8; msg_len];
        reader.read_exact(&mut msg_buf).await.unwrap();
        let response = server.handle_query(&msg_buf).await.unwrap();
        let resp_len = (response.len() as u16).to_be_bytes();
        writer.write_all(&resp_len).await.unwrap();
        writer.write_all(&response).await.unwrap();
    });

    // Send a DNS query over TCP
    let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let query = build_dns_query("tcp-test.local.", hickory_proto::rr::RecordType::A);
    let len = (query.len() as u16).to_be_bytes();
    stream.write_all(&len).await.unwrap();
    stream.write_all(&query).await.unwrap();

    // Read response
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await.unwrap();

    let response = hickory_proto::op::Message::from_bytes(&resp_buf).unwrap();
    assert_eq!(
        response.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );
    assert_eq!(response.answers().len(), 1);

    server_handle.await.unwrap();
}

// ========================================================
// Integration: Multiple UDP bind addresses serve queries
// ========================================================

#[tokio::test]
async fn test_multi_bind_udp_serves_all_addresses() {
    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(RblChecker::with_resolver(
        false,
        vec![],
        Arc::new(NeverListedResolver),
    ));
    let dns_server = Arc::new(DnsServer::new(db.clone(), rbl, vec![]));

    db.add_record(&DnsRecord {
        id: None,
        name: "multi-udp.test.".to_string(),
        record_type: RecordKind::A,
        value: "10.0.0.42".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();

    // Find two free ports
    let port1 = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };
    let port2 = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };

    let addr1 = format!("127.0.0.1:{}", port1);
    let addr2 = format!("127.0.0.1:{}", port2);

    // Spawn serve_udp on both addresses (same pattern as main.rs loop)
    let server1 = Arc::clone(&dns_server);
    let bind1 = addr1.clone();
    let handle1 = tokio::spawn(async move {
        let _ = server1.serve_udp(&bind1).await;
    });

    let server2 = Arc::clone(&dns_server);
    let bind2 = addr2.clone();
    let handle2 = tokio::spawn(async move {
        let _ = server2.serve_udp(&bind2).await;
    });

    // Give listeners time to bind
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Query both addresses and verify both respond
    let query = build_dns_query("multi-udp.test.", hickory_proto::rr::RecordType::A);

    for addr in &[&addr1, &addr2] {
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&query, addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_from(&mut buf),
        )
        .await
        .expect("timeout waiting for UDP response")
        .unwrap();

        let response = hickory_proto::op::Message::from_bytes(&buf[..len]).unwrap();
        assert_eq!(
            response.response_code(),
            hickory_proto::op::ResponseCode::NoError,
            "query to {} failed",
            addr,
        );
        assert_eq!(response.answers().len(), 1, "no answer from {}", addr);
    }

    handle1.abort();
    handle2.abort();
}

// ========================================================
// Integration: Multiple TCP bind addresses serve queries
// ========================================================

#[tokio::test]
async fn test_multi_bind_tcp_serves_all_addresses() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(RblChecker::with_resolver(
        false,
        vec![],
        Arc::new(NeverListedResolver),
    ));
    let dns_server = Arc::new(DnsServer::new(db.clone(), rbl, vec![]));

    db.add_record(&DnsRecord {
        id: None,
        name: "multi-tcp.test.".to_string(),
        record_type: RecordKind::A,
        value: "10.0.0.43".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();

    // Find two free ports
    let port1 = {
        let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };
    let port2 = {
        let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };

    let addr1 = format!("127.0.0.1:{}", port1);
    let addr2 = format!("127.0.0.1:{}", port2);

    // Spawn serve_tcp on both addresses
    let server1 = Arc::clone(&dns_server);
    let bind1 = addr1.clone();
    let handle1 = tokio::spawn(async move {
        let _ = server1.serve_tcp(&bind1).await;
    });

    let server2 = Arc::clone(&dns_server);
    let bind2 = addr2.clone();
    let handle2 = tokio::spawn(async move {
        let _ = server2.serve_tcp(&bind2).await;
    });

    // Give listeners time to bind
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Query both addresses over TCP
    let query = build_dns_query("multi-tcp.test.", hickory_proto::rr::RecordType::A);

    for addr in &[&addr1, &addr2] {
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .expect("timeout connecting to TCP")
        .unwrap();

        // Send with 2-byte length prefix
        let len_bytes = (query.len() as u16).to_be_bytes();
        stream.write_all(&len_bytes).await.unwrap();
        stream.write_all(&query).await.unwrap();

        // Read response
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await.unwrap();

        let response = hickory_proto::op::Message::from_bytes(&resp_buf).unwrap();
        assert_eq!(
            response.response_code(),
            hickory_proto::op::ResponseCode::NoError,
            "query to {} failed",
            addr,
        );
        assert_eq!(response.answers().len(), 1, "no answer from {}", addr);
    }

    handle1.abort();
    handle2.abort();
}

// ========================================================
// Integration: Database persistence
// ========================================================

#[tokio::test]
async fn test_database_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    // Create and populate database
    {
        let db = Database::open(&db_path).unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "persist.test.".to_string(),
            record_type: RecordKind::A,
            value: "10.10.10.10".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
    }

    // Reopen and verify data is still there
    {
        let db = Database::open(&db_path).unwrap();
        let records = db.lookup("persist.test.", Some(RecordKind::A)).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "10.10.10.10");
    }
}

// ========================================================
// Integration: Auth enforcement on TCP gRPC
// ========================================================

#[tokio::test]
async fn test_auth_enforcement() {
    let (_db, _dns_server, _rbl, service) = make_test_stack();

    // Try with wrong token
    let req = Request::new(ListRecordsRequest {
        name_filter: String::new(),
        record_type_filter: 0,
        filter_by_type: false,
        auth_token: "wrong-secret".to_string(),
    });
    let result = service.list_records(req).await;
    assert!(result.is_err());

    // Try with correct token
    let req = Request::new(ListRecordsRequest {
        name_filter: String::new(),
        record_type_filter: 0,
        filter_by_type: false,
        auth_token: "test-secret".to_string(),
    });
    let result = service.list_records(req).await;
    assert!(result.is_ok());
}

// ========================================================
// Integration: Unix socket bypasses auth
// ========================================================

#[tokio::test]
async fn test_unix_socket_bypasses_auth() {
    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(RblChecker::with_resolver(
        false,
        vec![],
        Arc::new(NeverListedResolver),
    ));
    let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
    let service = RolodexDnsGrpcService::new(
        db.clone(),
        dns_server.clone(),
        rbl.clone(),
        "test-secret".to_string(),
        true, // Unix socket mode
    );

    // Any token should work
    let req = Request::new(ListRecordsRequest {
        name_filter: String::new(),
        record_type_filter: 0,
        filter_by_type: false,
        auth_token: "completely-wrong".to_string(),
    });
    let result = service.list_records(req).await;
    assert!(result.is_ok());
}

// ========================================================
// Integration: Config serialization
// ========================================================

#[test]
fn test_config_roundtrip() {
    let config = rolodex_dns::config::Config::default();
    let yaml_str = serde_yaml_ng::to_string(&config).unwrap();
    let deserialized: rolodex_dns::config::Config = serde_yaml_ng::from_str(&yaml_str).unwrap();

    assert_eq!(config.dns.udp_bind, deserialized.dns.udp_bind);
    assert_eq!(config.dns.tcp_bind, deserialized.dns.tcp_bind);
    assert_eq!(config.grpc.tcp_bind, deserialized.grpc.tcp_bind);
    assert_eq!(config.forwarders.len(), deserialized.forwarders.len());
    assert_eq!(config.rbl.enabled, deserialized.rbl.enabled);
    assert_eq!(config.rbl.providers.len(), deserialized.rbl.providers.len());
}

// ========================================================
// Integration: Dev config file is valid YAML
// ========================================================

#[test]
fn test_dev_config_parses() {
    let content = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/dev.yml")).unwrap();
    let config: rolodex_dns::config::Config = serde_yaml_ng::from_str(&content).unwrap();
    assert_eq!(config.dns.udp_bind, vec!["127.0.0.1:5300"]);
    assert_eq!(config.dns.tcp_bind, vec!["127.0.0.1:5300"]);
    assert_eq!(config.database_path, "/tmp/rolodex-dns-dev.db");
    assert!(config.grpc.tcp_bind.is_empty());
    assert_eq!(config.grpc.unix_socket, "/tmp/rolodex-dns.sock");
    assert!(!config.rbl.enabled);
}

// ========================================================
// Helper functions
// ========================================================

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

fn build_dns_query(name: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(rand::random::<u16>());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);

    let mut query = Query::new();
    query.set_name(Name::from_ascii(name).unwrap());
    query.set_query_type(qtype);
    query.set_query_class(DNSClass::IN);
    msg.add_query(query);

    msg.to_bytes().unwrap()
}

// ========================================================
// Integration: Network Scope lifecycle
// ========================================================

#[tokio::test]
async fn test_network_scope_lifecycle() {
    let (_db, _dns_server, _rbl, service) = make_test_stack();

    // Create scope
    let req = Request::new(CreateNetworkScopeRequest {
        scope: Some(rolodex_dns::grpc_service::proto::NetworkScope {
            name: "testnet".to_string(),
            home_domain: "testnet.home".to_string(),
        }),
        auth_token: "test-secret".to_string(),
    });
    let resp = service.create_network_scope(req).await.unwrap();
    assert!(resp.into_inner().success);

    // List scopes
    let list_req = Request::new(ListNetworkScopesRequest {
        auth_token: "test-secret".to_string(),
    });
    let resp = service.list_network_scopes(list_req).await.unwrap();
    assert_eq!(resp.into_inner().scopes.len(), 1);

    // Delete scope
    let del_req = Request::new(DeleteNetworkScopeRequest {
        name: "testnet".to_string(),
        auth_token: "test-secret".to_string(),
    });
    let resp = service.delete_network_scope(del_req).await.unwrap();
    assert!(resp.into_inner().success);

    // Verify deleted
    let list_req = Request::new(ListNetworkScopesRequest {
        auth_token: "test-secret".to_string(),
    });
    let resp = service.list_network_scopes(list_req).await.unwrap();
    assert!(resp.into_inner().scopes.is_empty());
}

// ========================================================
// Integration: Join network, add scoped record, DNS query
// ========================================================

#[tokio::test]
async fn test_scoped_dns_resolution_integration() {
    let (_db, dns_server, _rbl, service) = make_test_stack();

    // Create scope
    let req = Request::new(CreateNetworkScopeRequest {
        scope: Some(rolodex_dns::grpc_service::proto::NetworkScope {
            name: "corp".to_string(),
            home_domain: "corp.home".to_string(),
        }),
        auth_token: "test-secret".to_string(),
    });
    service.create_network_scope(req).await.unwrap();

    // Join network
    let join_req = Request::new(JoinNetworkRequest {
        ip_address: "192.168.1.10".to_string(),
        scope_name: "corp".to_string(),
        ttl_seconds: 3600,
        auth_token: "test-secret".to_string(),
    });
    service.join_network(join_req).await.unwrap();

    // Add scoped record
    let add_req = Request::new(AddScopedRecordRequest {
        scope_name: "corp".to_string(),
        record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
            name: "intranet.corp.home.".to_string(),
            record_type: 0,
            value: "10.10.0.1".to_string(),
            ttl: 300,
            priority: 0,
        }),
        auth_token: "test-secret".to_string(),
    });
    service.add_scoped_record(add_req).await.unwrap();

    // DNS query from associated IP
    let query = build_dns_query("intranet.corp.home.", hickory_proto::rr::RecordType::A);
    let resp_bytes = dns_server
        .handle_query_from(&query, "192.168.1.10".parse().unwrap())
        .await
        .unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );
    assert_eq!(resp.answers().len(), 1);

    // DNS query from unassociated IP should be refused
    let resp_bytes = dns_server
        .handle_query_from(&query, "192.168.1.99".parse().unwrap())
        .await
        .unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::Refused
    );
}

// ========================================================
// Integration: Scoped records are isolated between scopes
// ========================================================

#[tokio::test]
async fn test_scope_isolation_integration() {
    let (_db, dns_server, _rbl, service) = make_test_stack();

    // Create two scopes
    for (name, domain) in &[("dev", "dev.home"), ("prod", "prod.home")] {
        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(rolodex_dns::grpc_service::proto::NetworkScope {
                name: name.to_string(),
                home_domain: domain.to_string(),
            }),
            auth_token: "test-secret".to_string(),
        });
        service.create_network_scope(req).await.unwrap();
    }

    // Add same record name with different values in each scope
    for (scope, ip) in &[("dev", "10.0.0.1"), ("prod", "10.0.0.2")] {
        let req = Request::new(AddScopedRecordRequest {
            scope_name: scope.to_string(),
            record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
                name: "api.internal.".to_string(),
                record_type: 0,
                value: ip.to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "test-secret".to_string(),
        });
        service.add_scoped_record(req).await.unwrap();
    }

    // Associate IPs with different scopes
    for (ip, scope) in &[("192.168.1.1", "dev"), ("192.168.2.1", "prod")] {
        let req = Request::new(JoinNetworkRequest {
            ip_address: ip.to_string(),
            scope_name: scope.to_string(),
            ttl_seconds: 3600,
            auth_token: "test-secret".to_string(),
        });
        service.join_network(req).await.unwrap();
    }

    let query = build_dns_query("api.internal.", hickory_proto::rr::RecordType::A);

    // Query from dev scope
    let resp_bytes = dns_server
        .handle_query_from(&query, "192.168.1.1".parse().unwrap())
        .await
        .unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );
    if let hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(ip)) = resp.answers()[0].data() {
        assert_eq!(*ip, std::net::Ipv4Addr::new(10, 0, 0, 1));
    } else {
        panic!("expected A record");
    }

    // Query from prod scope
    let resp_bytes = dns_server
        .handle_query_from(&query, "192.168.2.1".parse().unwrap())
        .await
        .unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );
    if let hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(ip)) = resp.answers()[0].data() {
        assert_eq!(*ip, std::net::Ipv4Addr::new(10, 0, 0, 2));
    } else {
        panic!("expected A record");
    }
}

// ========================================================
// Integration: Search domains via gRPC
// ========================================================

#[tokio::test]
async fn test_search_domains_integration() {
    let (_db, _dns_server, _rbl, service) = make_test_stack();

    // Create scope
    let req = Request::new(CreateNetworkScopeRequest {
        scope: Some(rolodex_dns::grpc_service::proto::NetworkScope {
            name: "homenet".to_string(),
            home_domain: "myhome.local".to_string(),
        }),
        auth_token: "test-secret".to_string(),
    });
    service.create_network_scope(req).await.unwrap();

    // Join network
    let join_req = Request::new(JoinNetworkRequest {
        ip_address: "192.168.0.100".to_string(),
        scope_name: "homenet".to_string(),
        ttl_seconds: 3600,
        auth_token: "test-secret".to_string(),
    });
    service.join_network(join_req).await.unwrap();

    // Get search domains
    let sd_req = Request::new(GetSearchDomainsRequest {
        ip_address: "192.168.0.100".to_string(),
        auth_token: "test-secret".to_string(),
    });
    let resp = service.get_search_domains(sd_req).await.unwrap();
    let domains = resp.into_inner().search_domains;
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0], "myhome.local.");

    // Unassociated IP gets no search domains
    let sd_req = Request::new(GetSearchDomainsRequest {
        ip_address: "192.168.0.200".to_string(),
        auth_token: "test-secret".to_string(),
    });
    let resp = service.get_search_domains(sd_req).await.unwrap();
    assert!(resp.into_inner().search_domains.is_empty());
}

// ========================================================
// Integration: Scoped record CRUD via gRPC
// ========================================================

#[tokio::test]
async fn test_scoped_record_crud_integration() {
    let (_db, _dns_server, _rbl, service) = make_test_stack();

    // Create scope
    let req = Request::new(CreateNetworkScopeRequest {
        scope: Some(rolodex_dns::grpc_service::proto::NetworkScope {
            name: "crud".to_string(),
            home_domain: "crud.home".to_string(),
        }),
        auth_token: "test-secret".to_string(),
    });
    service.create_network_scope(req).await.unwrap();

    // Add records
    for (name, value) in &[
        ("host1.crud.home.", "10.0.0.1"),
        ("host2.crud.home.", "10.0.0.2"),
    ] {
        let req = Request::new(AddScopedRecordRequest {
            scope_name: "crud".to_string(),
            record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
                name: name.to_string(),
                record_type: 0,
                value: value.to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "test-secret".to_string(),
        });
        service.add_scoped_record(req).await.unwrap();
    }

    // List all scoped records
    let list_req = Request::new(ListScopedRecordsRequest {
        scope_name: "crud".to_string(),
        name_filter: String::new(),
        record_type_filter: 0,
        filter_by_type: false,
        auth_token: "test-secret".to_string(),
    });
    let resp = service.list_scoped_records(list_req).await.unwrap();
    assert_eq!(resp.into_inner().records.len(), 2);

    // Remove one record
    let rm_req = Request::new(RemoveScopedRecordRequest {
        scope_name: "crud".to_string(),
        name: "host1.crud.home.".to_string(),
        record_type: 0,
        value: String::new(),
        auth_token: "test-secret".to_string(),
    });
    let resp = service.remove_scoped_record(rm_req).await.unwrap();
    assert_eq!(resp.into_inner().removed_count, 1);

    // Verify one remains
    let list_req = Request::new(ListScopedRecordsRequest {
        scope_name: "crud".to_string(),
        name_filter: String::new(),
        record_type_filter: 0,
        filter_by_type: false,
        auth_token: "test-secret".to_string(),
    });
    let resp = service.list_scoped_records(list_req).await.unwrap();
    assert_eq!(resp.into_inner().records.len(), 1);
}

// ========================================================
// Integration: Leave network and association cleanup
// ========================================================

#[tokio::test]
async fn test_leave_network_integration() {
    let (_db, dns_server, _rbl, service) = make_test_stack();

    // Create scope and join
    let req = Request::new(CreateNetworkScopeRequest {
        scope: Some(rolodex_dns::grpc_service::proto::NetworkScope {
            name: "leavenet".to_string(),
            home_domain: "leavenet.home".to_string(),
        }),
        auth_token: "test-secret".to_string(),
    });
    service.create_network_scope(req).await.unwrap();

    let join_req = Request::new(JoinNetworkRequest {
        ip_address: "192.168.1.50".to_string(),
        scope_name: "leavenet".to_string(),
        ttl_seconds: 3600,
        auth_token: "test-secret".to_string(),
    });
    service.join_network(join_req).await.unwrap();

    // Add scoped record
    let add_req = Request::new(AddScopedRecordRequest {
        scope_name: "leavenet".to_string(),
        record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
            name: "server.leavenet.home.".to_string(),
            record_type: 0,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        }),
        auth_token: "test-secret".to_string(),
    });
    service.add_scoped_record(add_req).await.unwrap();

    // Can resolve while joined
    let query = build_dns_query("server.leavenet.home.", hickory_proto::rr::RecordType::A);
    let resp_bytes = dns_server
        .handle_query_from(&query, "192.168.1.50".parse().unwrap())
        .await
        .unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );

    // Leave network
    let leave_req = Request::new(LeaveNetworkRequest {
        ip_address: "192.168.1.50".to_string(),
        auth_token: "test-secret".to_string(),
    });
    service.leave_network(leave_req).await.unwrap();

    // Can no longer resolve (refused)
    let resp_bytes = dns_server
        .handle_query_from(&query, "192.168.1.50".parse().unwrap())
        .await
        .unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::Refused
    );
}

// ========================================================
// Integration: Global records accessible from scoped IPs
// ========================================================

#[tokio::test]
async fn test_global_records_accessible_from_scope() {
    let (_db, dns_server, _rbl, service) = make_test_stack();

    // Create scope and join
    let req = Request::new(CreateNetworkScopeRequest {
        scope: Some(rolodex_dns::grpc_service::proto::NetworkScope {
            name: "globaltest".to_string(),
            home_domain: "globaltest.home".to_string(),
        }),
        auth_token: "test-secret".to_string(),
    });
    service.create_network_scope(req).await.unwrap();

    let join_req = Request::new(JoinNetworkRequest {
        ip_address: "192.168.1.1".to_string(),
        scope_name: "globaltest".to_string(),
        ttl_seconds: 3600,
        auth_token: "test-secret".to_string(),
    });
    service.join_network(join_req).await.unwrap();

    // Add global record
    let add_req = Request::new(AddRecordRequest {
        record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
            name: "public.test.".to_string(),
            record_type: 0,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            priority: 0,
        }),
        auth_token: "test-secret".to_string(),
    });
    service.add_record(add_req).await.unwrap();

    // Query from scoped IP should still see global records
    let query = build_dns_query("public.test.", hickory_proto::rr::RecordType::A);
    let resp_bytes = dns_server
        .handle_query_from(&query, "192.168.1.1".parse().unwrap())
        .await
        .unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );
    assert_eq!(resp.answers().len(), 1);
}

// ========================================================
// Integration: Delete scope cascades to records and assocs
// ========================================================

#[tokio::test]
async fn test_delete_scope_cascade() {
    let (_db, _dns_server, _rbl, service) = make_test_stack();

    // Create scope, add records, add associations
    let req = Request::new(CreateNetworkScopeRequest {
        scope: Some(rolodex_dns::grpc_service::proto::NetworkScope {
            name: "cascade".to_string(),
            home_domain: "cascade.home".to_string(),
        }),
        auth_token: "test-secret".to_string(),
    });
    service.create_network_scope(req).await.unwrap();

    let add_req = Request::new(AddScopedRecordRequest {
        scope_name: "cascade".to_string(),
        record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
            name: "host.cascade.home.".to_string(),
            record_type: 0,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        }),
        auth_token: "test-secret".to_string(),
    });
    service.add_scoped_record(add_req).await.unwrap();

    let join_req = Request::new(JoinNetworkRequest {
        ip_address: "192.168.1.1".to_string(),
        scope_name: "cascade".to_string(),
        ttl_seconds: 3600,
        auth_token: "test-secret".to_string(),
    });
    service.join_network(join_req).await.unwrap();

    // Delete scope
    let del_req = Request::new(DeleteNetworkScopeRequest {
        name: "cascade".to_string(),
        auth_token: "test-secret".to_string(),
    });
    service.delete_network_scope(del_req).await.unwrap();

    // Records should be gone
    let list_req = Request::new(ListScopedRecordsRequest {
        scope_name: "cascade".to_string(),
        name_filter: String::new(),
        record_type_filter: 0,
        filter_by_type: false,
        auth_token: "test-secret".to_string(),
    });
    let resp = service.list_scoped_records(list_req).await.unwrap();
    assert!(resp.into_inner().records.is_empty());

    // Associations should be gone
    let assoc_req = Request::new(GetNetworkAssociationsRequest {
        scope_name: "cascade".to_string(),
        auth_token: "test-secret".to_string(),
    });
    let resp = service.get_network_associations(assoc_req).await.unwrap();
    assert!(resp.into_inner().associations.is_empty());
}

// ========================================================
// Integration: RBL with network scoping
// ========================================================

#[tokio::test]
async fn test_rbl_with_scoping() {
    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(RblChecker::with_resolver(
        true,
        vec![RblProvider {
            zone: "test.rbl".to_string(),
            enabled: true,
        }],
        Arc::new(AlwaysListedResolver),
    ));
    let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));

    // Create scope and associate IP
    db.create_network_scope(&rolodex_dns::db::NetworkScope {
        name: "rblscoped".to_string(),
        home_domain: "rblscoped.home".to_string(),
    })
    .unwrap();

    db.join_network(&rolodex_dns::db::NetworkAssociation {
        ip_address: "192.168.1.1".to_string(),
        scope_name: "rblscoped".to_string(),
        ttl_seconds: 3600,
    })
    .unwrap();

    // Reverse DNS query from scoped IP should be blocked by RBL
    let query = build_dns_query("4.3.2.1.in-addr.arpa.", hickory_proto::rr::RecordType::PTR);
    let resp_bytes = dns_server
        .handle_query_from(&query, "192.168.1.1".parse().unwrap())
        .await
        .unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::NXDomain
    );
}

// ========================================================
// Integration: Scoped managed zone returns NXDOMAIN
// ========================================================

#[tokio::test]
async fn test_scoped_managed_zone_nxdomain_integration() {
    let (_db, dns_server, _rbl, service) = make_test_stack();

    // Create scope and add records to establish the managed zone
    let req = Request::new(CreateNetworkScopeRequest {
        scope: Some(rolodex_dns::grpc_service::proto::NetworkScope {
            name: "zonenet".to_string(),
            home_domain: "zonenet.home".to_string(),
        }),
        auth_token: "test-secret".to_string(),
    });
    service.create_network_scope(req).await.unwrap();

    // Add a record at the zone level to make it authoritative
    let zone_req = Request::new(AddScopedRecordRequest {
        scope_name: "zonenet".to_string(),
        record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
            name: "zonenet.home.".to_string(),
            record_type: 0,
            value: "10.0.0.99".to_string(),
            ttl: 300,
            priority: 0,
        }),
        auth_token: "test-secret".to_string(),
    });
    service.add_scoped_record(zone_req).await.unwrap();

    let add_req = Request::new(AddScopedRecordRequest {
        scope_name: "zonenet".to_string(),
        record: Some(rolodex_dns::grpc_service::proto::DnsRecord {
            name: "known.zonenet.home.".to_string(),
            record_type: 0,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        }),
        auth_token: "test-secret".to_string(),
    });
    service.add_scoped_record(add_req).await.unwrap();

    let join_req = Request::new(JoinNetworkRequest {
        ip_address: "192.168.1.1".to_string(),
        scope_name: "zonenet".to_string(),
        ttl_seconds: 3600,
        auth_token: "test-secret".to_string(),
    });
    service.join_network(join_req).await.unwrap();

    // Query known name should succeed
    let query = build_dns_query("known.zonenet.home.", hickory_proto::rr::RecordType::A);
    let resp_bytes = dns_server
        .handle_query_from(&query, "192.168.1.1".parse().unwrap())
        .await
        .unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::NoError
    );

    // Query unknown name under same zone should get NXDOMAIN
    let query = build_dns_query("unknown.zonenet.home.", hickory_proto::rr::RecordType::A);
    let resp_bytes = dns_server
        .handle_query_from(&query, "192.168.1.1".parse().unwrap())
        .await
        .unwrap();
    let resp = hickory_proto::op::Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(
        resp.response_code(),
        hickory_proto::op::ResponseCode::NXDomain
    );
}
