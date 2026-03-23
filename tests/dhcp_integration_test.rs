/// Integration tests for the DHCP server.
///
/// Tests the full DHCP message flow (DISCOVER→OFFER→REQUEST→ACK→RELEASE)
/// using the refactored handlers that return messages directly,
/// and verifies DNS registration, lease management, and cleanup.
use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use rolodex_dns::config::DhcpConfig;
use rolodex_dns::db::{Database, DhcpCertOption, DhcpPool, NetworkScope};
use rolodex_dns::dhcp::DhcpServer;
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::rbl::{RblChecker, RblResolver};
use std::net::Ipv4Addr;
use std::sync::Arc;

struct NeverListedResolver;

#[async_trait::async_trait]
impl RblResolver for NeverListedResolver {
    async fn lookup_rbl(&self, _query: &str) -> Result<Option<u32>, anyhow::Error> {
        Ok(None)
    }
}

fn make_dhcp_config() -> DhcpConfig {
    DhcpConfig {
        bind: "127.0.0.1:0".to_string(),
        default_lease_duration: 3600,
        reclaim_timeout: 86400,
        sweep_interval: 60,
        tld: "example.com".to_string(),
    }
}

fn make_test_dhcp_server() -> (Database, Arc<DnsServer>, DhcpServer) {
    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(RblChecker::with_resolver(
        false,
        vec![],
        Arc::new(NeverListedResolver),
    ));
    let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
    let config = make_dhcp_config();
    let dhcp = DhcpServer::new(db.clone(), dns_server.clone(), rbl, &config);
    (db, dns_server, dhcp)
}

fn setup_scope_and_pool(db: &Database) {
    let scope = NetworkScope {
        name: "testnet".to_string(),
        home_domain: "testnet.home.".to_string(),
    };
    db.create_network_scope(&scope).unwrap();

    let pool = DhcpPool {
        id: 0,
        scope_name: "testnet".to_string(),
        range_start: "192.168.1.100".to_string(),
        range_end: "192.168.1.110".to_string(),
        gateway: Some("192.168.1.1".to_string()),
        subnet_mask: "255.255.255.0".to_string(),
        dns_servers: Some("192.168.1.1".to_string()),
    };
    db.add_dhcp_pool(&pool).unwrap();
}

fn build_discover(mac: &[u8; 6]) -> Message {
    let mut msg = Message::default();
    msg.set_opcode(Opcode::BootRequest);
    msg.set_xid(1234);
    msg.set_chaddr(mac);
    msg.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Discover));
    msg
}

fn build_request(mac: &[u8; 6], ip: Ipv4Addr, hostname: Option<&str>) -> Message {
    let mut msg = Message::default();
    msg.set_opcode(Opcode::BootRequest);
    msg.set_xid(1234);
    msg.set_chaddr(mac);
    msg.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Request));
    msg.opts_mut()
        .insert(DhcpOption::RequestedIpAddress(ip));
    if let Some(h) = hostname {
        msg.opts_mut()
            .insert(DhcpOption::Hostname(h.to_string()));
    }
    msg
}

fn build_release(mac: &[u8; 6], ip: Ipv4Addr) -> Message {
    let mut msg = Message::default();
    msg.set_opcode(Opcode::BootRequest);
    msg.set_xid(1234);
    msg.set_chaddr(mac);
    msg.set_ciaddr(ip);
    msg.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Release));
    msg
}

#[test]
fn test_dhcp_discover_allocates_ip() {
    let (db, _dns, dhcp) = make_test_dhcp_server();
    setup_scope_and_pool(&db);

    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
    let discover = build_discover(&mac);
    let offer = dhcp.handle_discover(&discover, "aa:bb:cc:dd:ee:01").unwrap();

    assert!(offer.is_some(), "Expected OFFER reply");
    let offer = offer.unwrap();
    assert_eq!(offer.opcode(), Opcode::BootReply);
    assert!(!offer.yiaddr().is_unspecified(), "Expected offered IP");

    // Verify IP is in the pool range
    let offered_ip: u32 = offer.yiaddr().into();
    let start: u32 = "192.168.1.100".parse::<Ipv4Addr>().unwrap().into();
    let end: u32 = "192.168.1.110".parse::<Ipv4Addr>().unwrap().into();
    assert!(offered_ip >= start && offered_ip <= end, "Offered IP out of range");

    // Verify DHCP options
    assert!(offer.opts().get(OptionCode::SubnetMask).is_some());
    assert!(offer.opts().get(OptionCode::Router).is_some());
    assert!(offer.opts().get(OptionCode::AddressLeaseTime).is_some());
}

#[test]
fn test_dhcp_discover_no_pools_returns_none() {
    let (_db, _dns, dhcp) = make_test_dhcp_server();
    // No pools configured
    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
    let discover = build_discover(&mac);
    let offer = dhcp.handle_discover(&discover, "aa:bb:cc:dd:ee:01").unwrap();
    assert!(offer.is_none());
}

#[test]
fn test_dhcp_request_creates_lease_and_dns() {
    let (db, _dns, dhcp) = make_test_dhcp_server();
    setup_scope_and_pool(&db);

    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02];
    let mac_str = "aa:bb:cc:dd:ee:02";

    // DISCOVER
    let offer = dhcp.handle_discover(&build_discover(&mac), mac_str).unwrap().unwrap();
    let offered_ip = offer.yiaddr();

    // REQUEST with hostname
    let request = build_request(&mac, offered_ip, Some("myhost"));
    let ack = dhcp.handle_request(&request, mac_str).unwrap();
    assert!(ack.is_some(), "Expected ACK reply");
    let ack = ack.unwrap();
    assert_eq!(ack.yiaddr(), offered_ip);

    // Verify lease exists
    let lease = db.get_lease_by_mac(mac_str).unwrap();
    assert!(lease.is_some(), "Lease should exist");
    let lease = lease.unwrap();
    assert_eq!(lease.ip, offered_ip.to_string());
    assert_eq!(lease.scope_name, "testnet");
    assert_eq!(lease.hostname.as_deref(), Some("myhost"));
    assert_eq!(lease.state, "active");

    // Verify network association
    let scope = db.get_scope_for_ip(&offered_ip.to_string());
    assert_eq!(scope, Some("testnet".to_string()));

    // Verify DNS A record
    let records = db
        .list_scoped_records("testnet", "myhost.lan.example.com.", None)
        .unwrap();
    assert!(!records.is_empty(), "A record should exist");
    assert!(records.iter().any(|r| r.value == offered_ip.to_string()));

    // Verify PTR record
    let octets = offered_ip.octets();
    let ptr_name = format!(
        "{}.{}.{}.{}.in-addr.arpa.",
        octets[3], octets[2], octets[1], octets[0]
    );
    let ptr_records = db.list_scoped_records("testnet", &ptr_name, None).unwrap();
    assert!(!ptr_records.is_empty(), "PTR record should exist");
}

#[tokio::test]
async fn test_dhcp_release_cleans_up() {
    let (db, _dns, dhcp) = make_test_dhcp_server();
    setup_scope_and_pool(&db);

    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03];
    let mac_str = "aa:bb:cc:dd:ee:03";

    // DISCOVER + REQUEST
    let offer = dhcp.handle_discover(&build_discover(&mac), mac_str).unwrap().unwrap();
    let offered_ip = offer.yiaddr();
    let request = build_request(&mac, offered_ip, Some("releasehost"));
    dhcp.handle_request(&request, mac_str).unwrap();

    // RELEASE
    let release = build_release(&mac, offered_ip);
    dhcp.handle_release(&release, mac_str).await.unwrap();

    // Verify lease state is released
    let lease = db.get_lease_by_mac(mac_str).unwrap().unwrap();
    assert_eq!(lease.state, "released");

    // Verify DNS records removed
    let records = db
        .list_scoped_records("testnet", "releasehost.lan.example.com.", None)
        .unwrap();
    assert!(records.is_empty(), "A record should be removed after release");

    // Verify network association removed
    let scope = db.get_scope_for_ip(&offered_ip.to_string());
    assert!(scope.is_none(), "Network association should be removed");
}

#[test]
fn test_dhcp_sticky_binding() {
    let (db, _dns, dhcp) = make_test_dhcp_server();
    setup_scope_and_pool(&db);

    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x04];
    let mac_str = "aa:bb:cc:dd:ee:04";

    // First allocation
    let offer1 = dhcp.handle_discover(&build_discover(&mac), mac_str).unwrap().unwrap();
    let ip1 = offer1.yiaddr();

    // REQUEST to create lease
    let request = build_request(&mac, ip1, None);
    dhcp.handle_request(&request, mac_str).unwrap();

    // Second DISCOVER with same MAC — should get same IP
    let offer2 = dhcp.handle_discover(&build_discover(&mac), mac_str).unwrap().unwrap();
    let ip2 = offer2.yiaddr();

    assert_eq!(ip1, ip2, "Sticky binding: same MAC should get same IP");
}

#[test]
fn test_dhcp_multiple_clients() {
    let (db, _dns, dhcp) = make_test_dhcp_server();
    setup_scope_and_pool(&db);

    let mac_a = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0a];
    let mac_b = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0b];

    // Client A: full DISCOVER+REQUEST to lock in lease
    let offer_a = dhcp
        .handle_discover(&build_discover(&mac_a), "aa:bb:cc:dd:ee:0a")
        .unwrap()
        .unwrap();
    let ip_a = offer_a.yiaddr();
    dhcp.handle_request(&build_request(&mac_a, ip_a, None), "aa:bb:cc:dd:ee:0a")
        .unwrap();

    // Client B: DISCOVER after A's lease is committed
    let offer_b = dhcp
        .handle_discover(&build_discover(&mac_b), "aa:bb:cc:dd:ee:0b")
        .unwrap()
        .unwrap();

    assert_ne!(
        ip_a,
        offer_b.yiaddr(),
        "Different MACs should get different IPs"
    );
}

#[test]
fn test_dhcp_pool_exhaustion() {
    let (db, _dns, dhcp) = make_test_dhcp_server();

    // Create scope with a tiny pool (2 IPs)
    let scope = NetworkScope {
        name: "tiny".to_string(),
        home_domain: "tiny.home.".to_string(),
    };
    db.create_network_scope(&scope).unwrap();
    let pool = DhcpPool {
        id: 0,
        scope_name: "tiny".to_string(),
        range_start: "10.0.0.1".to_string(),
        range_end: "10.0.0.2".to_string(),
        gateway: None,
        subnet_mask: "255.255.255.0".to_string(),
        dns_servers: None,
    };
    db.add_dhcp_pool(&pool).unwrap();

    // Allocate both IPs
    let mac1 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x01];
    let mac2 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x02];
    let mac3 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x03];

    let offer1 = dhcp.handle_discover(&build_discover(&mac1), "01:02:03:04:05:01").unwrap();
    assert!(offer1.is_some());
    // REQUEST to lock in the allocation
    let ip1 = offer1.unwrap().yiaddr();
    dhcp.handle_request(&build_request(&mac1, ip1, None), "01:02:03:04:05:01").unwrap();

    let offer2 = dhcp.handle_discover(&build_discover(&mac2), "01:02:03:04:05:02").unwrap();
    assert!(offer2.is_some());
    let ip2 = offer2.unwrap().yiaddr();
    dhcp.handle_request(&build_request(&mac2, ip2, None), "01:02:03:04:05:02").unwrap();

    // Third should fail
    let offer3 = dhcp.handle_discover(&build_discover(&mac3), "01:02:03:04:05:03").unwrap();
    assert!(offer3.is_none(), "Pool exhausted — should return None");
}

#[test]
fn test_dhcp_cert_option_delivery() {
    let (db, _dns, dhcp) = make_test_dhcp_server();
    setup_scope_and_pool(&db);

    // Set a cert option
    let cert = DhcpCertOption {
        scope_name: "testnet".to_string(),
        option_code: 224,
        cert_data: b"test-certificate-data".to_vec(),
        description: Some("Test cert".to_string()),
    };
    db.set_dhcp_cert_option(&cert).unwrap();

    // DISCOVER
    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x05];
    let offer = dhcp
        .handle_discover(&build_discover(&mac), "aa:bb:cc:dd:ee:05")
        .unwrap()
        .unwrap();

    // Verify cert option is present in OFFER
    let cert_opt = offer.opts().get(OptionCode::from(224u8));
    assert!(cert_opt.is_some(), "Certificate option 224 should be in OFFER");
}

#[test]
fn test_dhcp_lease_sweep_removes_dns() {
    let (db, _dns, dhcp) = make_test_dhcp_server();
    setup_scope_and_pool(&db);

    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x06];
    let mac_str = "aa:bb:cc:dd:ee:06";

    // DISCOVER + REQUEST
    let offer = dhcp.handle_discover(&build_discover(&mac), mac_str).unwrap().unwrap();
    let offered_ip = offer.yiaddr();
    let request = build_request(&mac, offered_ip, Some("sweephost"));
    dhcp.handle_request(&request, mac_str).unwrap();

    // Manually backdate the lease to simulate expiry (well past both lease duration and reclaim timeout)
    {
        let conn = db.conn();
        let conn = conn.lock().unwrap();
        conn.execute(
            "UPDATE dhcp_leases SET lease_start = lease_start - 200000 WHERE mac = ?1",
            rusqlite::params![mac_str],
        )
        .unwrap();
    }

    // Sweep with short reclaim timeout so the expired lease is returned for cleanup
    let expired = db.sweep_expired_leases(1).unwrap();
    assert!(!expired.is_empty(), "Should find expired leases");

    // Cleanup the expired lease
    for lease in &expired {
        dhcp.cleanup_lease(lease);
    }

    // Verify DNS records removed
    let records = db
        .list_scoped_records("testnet", "sweephost.lan.example.com.", None)
        .unwrap();
    assert!(records.is_empty(), "DNS records should be removed after sweep");
}

#[tokio::test]
async fn test_dhcp_udp_full_flow() {
    let (db, dns_server, _) = {
        let db = Database::open_memory().unwrap();
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
        let config = make_dhcp_config();
        let dhcp = DhcpServer::new(db.clone(), dns_server.clone(), rbl, &config);
        (db, dns_server, dhcp)
    };

    // Setup scope and pool
    setup_scope_and_pool(&db);

    // Re-create DHCP server for the spawned task
    let rbl2 = Arc::new(RblChecker::with_resolver(
        false,
        vec![],
        Arc::new(NeverListedResolver),
    ));
    let config = make_dhcp_config();
    let dhcp_server = Arc::new(DhcpServer::new(
        db.clone(),
        dns_server.clone(),
        rbl2,
        &config,
    ));

    // Bind DHCP to a random high port
    let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    server_socket.set_broadcast(true).unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    // Spawn the DHCP server read loop (simplified — process one message at a time)
    let dhcp_clone = Arc::clone(&dhcp_server);
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        // Process up to 3 messages (DISCOVER, REQUEST, RELEASE)
        for _ in 0..3 {
            let timeout = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                server_socket.recv_from(&mut buf),
            );
            match timeout.await {
                Ok(Ok((len, src))) => {
                    let data = &buf[..len];
                    if let Ok(msg) = Message::decode(&mut Decoder::new(data)) {
                        // Extract message type
                        let msg_type = msg.opts().get(OptionCode::MessageType).and_then(|opt| {
                            match opt {
                                DhcpOption::MessageType(mt) => Some(*mt),
                                _ => None,
                            }
                        });
                        let mac = rolodex_dns::dhcp::format_mac(msg.chaddr());

                        let reply = match msg_type {
                            Some(MessageType::Discover) => {
                                dhcp_clone.handle_discover(&msg, &mac).unwrap()
                            }
                            Some(MessageType::Request) => {
                                dhcp_clone.handle_request(&msg, &mac).unwrap()
                            }
                            Some(MessageType::Release) => {
                                // handle_release is async
                                // For simplicity, just process the release via DB
                                if let Ok(Some(lease)) = dhcp_clone.db().release_lease(&mac) {
                                    dhcp_clone.cleanup_lease(&lease);
                                }
                                None
                            }
                            _ => None,
                        };

                        if let Some(reply) = reply {
                            let mut resp_buf = Vec::with_capacity(1500);
                            let mut encoder = Encoder::new(&mut resp_buf);
                            reply.encode(&mut encoder).unwrap();
                            let _ = server_socket.send_to(&resp_buf, src).await;
                        }
                    }
                }
                _ => break,
            }
        }
    });

    // Client socket
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut recv_buf = vec![0u8; 1500];

    // --- DISCOVER ---
    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let discover = build_discover(&mac);
    let mut send_buf = Vec::with_capacity(1500);
    discover.encode(&mut Encoder::new(&mut send_buf)).unwrap();
    client_socket.send_to(&send_buf, server_addr).await.unwrap();

    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client_socket.recv_from(&mut recv_buf),
    )
    .await
    .expect("timeout waiting for OFFER")
    .expect("recv error");

    let offer = Message::decode(&mut Decoder::new(&recv_buf[..len])).unwrap();
    assert_eq!(offer.opcode(), Opcode::BootReply);
    let offered_ip = offer.yiaddr();
    assert!(!offered_ip.is_unspecified());

    // --- REQUEST ---
    let request = build_request(&mac, offered_ip, Some("udphost"));
    send_buf.clear();
    request.encode(&mut Encoder::new(&mut send_buf)).unwrap();
    client_socket.send_to(&send_buf, server_addr).await.unwrap();

    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client_socket.recv_from(&mut recv_buf),
    )
    .await
    .expect("timeout waiting for ACK")
    .expect("recv error");

    let ack = Message::decode(&mut Decoder::new(&recv_buf[..len])).unwrap();
    assert_eq!(ack.yiaddr(), offered_ip);

    // Verify lease was created
    let lease = db.get_lease_by_mac("aa:bb:cc:dd:ee:ff").unwrap();
    assert!(lease.is_some());
    assert_eq!(lease.unwrap().ip, offered_ip.to_string());

    // Verify DNS record was created
    let records = db
        .list_scoped_records("testnet", "udphost.lan.example.com.", None)
        .unwrap();
    assert!(!records.is_empty());

    // --- RELEASE ---
    let release = build_release(&mac, offered_ip);
    send_buf.clear();
    release.encode(&mut Encoder::new(&mut send_buf)).unwrap();
    client_socket.send_to(&send_buf, server_addr).await.unwrap();

    // Give server a moment to process
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify cleanup
    let lease = db.get_lease_by_mac("aa:bb:cc:dd:ee:ff").unwrap().unwrap();
    assert_eq!(lease.state, "released");

    let records = db
        .list_scoped_records("testnet", "udphost.lan.example.com.", None)
        .unwrap();
    assert!(records.is_empty(), "DNS records should be cleaned up");

    // Cleanup
    handle.abort();
}
