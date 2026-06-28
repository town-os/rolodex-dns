use criterion::{Criterion, black_box, criterion_group, criterion_main};
use hickory_proto::serialize::binary::BinEncodable;
use rolodex_dns::db::{Database, DnsRecord, NetworkAssociation, NetworkScope, RecordKind};
use rolodex_dns::dns_cache::{DnsCache, cache_key};
use rolodex_dns::dns_server::{DnsServer, randomize_qname_case};
use rolodex_dns::rbl::RblChecker;
use std::net::IpAddr;
use std::sync::Arc;

fn build_dns_query(name: &str) -> Vec<u8> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{DNSClass, Name, RecordType};

    let mut msg = Message::new();
    msg.set_id(1234);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);

    let mut query = Query::new();
    query.set_name(Name::from_ascii(name).unwrap());
    query.set_query_type(RecordType::A);
    query.set_query_class(DNSClass::IN);
    msg.add_query(query);

    msg.to_bytes().unwrap()
}

fn build_dns_query_typed(name: &str, qtype: hickory_proto::rr::RecordType) -> Vec<u8> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{DNSClass, Name};

    let mut msg = Message::new();
    msg.set_id(1234);
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

/// Creates a DnsServer with an in-memory DB and no-op RBL (no upstream forwarders).
fn make_bench_server(db: Database) -> Arc<DnsServer> {
    let rbl = Arc::new(RblChecker::new(false, vec![]));
    Arc::new(DnsServer::new(db, rbl, vec![]))
}

/// Creates a DnsServer with an in-memory DB, no-op RBL, and DNS cache enabled.
fn make_bench_server_with_cache(db: Database) -> Arc<DnsServer> {
    let cache_db = Database::open_memory().unwrap();
    let cache = Arc::new(DnsCache::new(cache_db));
    let rbl = Arc::new(RblChecker::new(false, vec![]));
    Arc::new(DnsServer::new_with_options(
        db,
        rbl,
        vec![],
        Some(cache),
        None,
        false,
    ))
}

// ================================================================
// Internal function benchmarks
// ================================================================

fn bench_qname_randomization(c: &mut Criterion) {
    let query = build_dns_query("www.example.com.");

    c.bench_function("qname_randomize", |b| {
        b.iter(|| randomize_qname_case(black_box(&query)))
    });
}

fn bench_qname_randomization_long(c: &mut Criterion) {
    let query = build_dns_query("very.deep.subdomain.of.a.long.domain.name.example.com.");

    c.bench_function("qname_randomize_long_name", |b| {
        b.iter(|| randomize_qname_case(black_box(&query)))
    });
}

fn bench_cache_key(c: &mut Criterion) {
    c.bench_function("cache_key_with_type", |b| {
        b.iter(|| {
            cache_key(
                black_box("www.example.com."),
                black_box(Some(RecordKind::A)),
            )
        })
    });
}

fn bench_cache_key_none(c: &mut Criterion) {
    c.bench_function("cache_key_wildcard", |b| {
        b.iter(|| cache_key(black_box("www.example.com."), black_box(None)))
    });
}

fn bench_lookup_with_fallbacks(c: &mut Criterion) {
    let db = Database::open_memory().unwrap();
    for i in 0..100 {
        db.add_record(&DnsRecord {
            id: None,
            name: format!("host{}.example.com.", i),
            record_type: RecordKind::A,
            value: format!("10.0.0.{}", i % 256),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
    }
    db.add_record(&DnsRecord {
        id: None,
        name: "*.wildcard.com.".to_string(),
        record_type: RecordKind::A,
        value: "10.10.10.10".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();

    c.bench_function("lookup_with_fallbacks_exact_hit", |b| {
        b.iter(|| {
            db.lookup_with_fallbacks(black_box("host50.example.com."), black_box(RecordKind::A))
        })
    });

    c.bench_function("lookup_with_fallbacks_miss", |b| {
        b.iter(|| {
            db.lookup_with_fallbacks(
                black_box("nonexistent.example.com."),
                black_box(RecordKind::A),
            )
        })
    });

    c.bench_function("lookup_with_fallbacks_wildcard", |b| {
        b.iter(|| {
            db.lookup_with_fallbacks(black_box("sub.wildcard.com."), black_box(RecordKind::A))
        })
    });
}

fn bench_lookup_original(c: &mut Criterion) {
    let db = Database::open_memory().unwrap();
    for i in 0..100 {
        db.add_record(&DnsRecord {
            id: None,
            name: format!("host{}.example.com.", i),
            record_type: RecordKind::A,
            value: format!("10.0.0.{}", i % 256),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
    }

    c.bench_function("lookup_original_exact_hit", |b| {
        b.iter(|| {
            db.lookup(
                black_box("host50.example.com."),
                black_box(Some(RecordKind::A)),
            )
        })
    });

    c.bench_function("lookup_original_miss", |b| {
        b.iter(|| {
            db.lookup(
                black_box("nonexistent.example.com."),
                black_box(Some(RecordKind::A)),
            )
        })
    });
}

fn bench_zone_matching(c: &mut Criterion) {
    let db = Database::open_memory().unwrap();
    for i in 0..50 {
        db.add_record(&DnsRecord {
            id: None,
            name: format!("host.zone{}.com.", i),
            record_type: RecordKind::A,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
    }
    for i in 0..50 {
        db.add_authoritative_zone(&format!("auth{}.org.", i))
            .unwrap();
    }

    c.bench_function("find_managed_zone_hit", |b| {
        b.iter(|| db.find_managed_zone(black_box("sub.zone25.com.")))
    });

    c.bench_function("find_managed_zone_miss", |b| {
        b.iter(|| db.find_managed_zone(black_box("sub.nonexistent.com.")))
    });

    c.bench_function("find_authoritative_zone_hit", |b| {
        b.iter(|| db.find_authoritative_zone(black_box("sub.auth25.org.")))
    });

    c.bench_function("find_authoritative_zone_miss", |b| {
        b.iter(|| db.find_authoritative_zone(black_box("sub.nonexistent.org.")))
    });

    c.bench_function("is_authoritative_zone_hit", |b| {
        b.iter(|| db.is_authoritative_zone(black_box("sub.auth25.org.")))
    });

    c.bench_function("is_authoritative_zone_miss", |b| {
        b.iter(|| db.is_authoritative_zone(black_box("sub.nonexistent.org.")))
    });
}

fn bench_dns_cache_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let db = Database::open_memory().unwrap();
    let cache = rt.block_on(async { DnsCache::new(db) });

    let records = vec![DnsRecord {
        id: None,
        name: "cached.example.com.".to_string(),
        record_type: RecordKind::A,
        value: "1.2.3.4".to_string(),
        ttl: 300,
        priority: 0,
    }];
    cache.insert_local("cached.example.com.", Some(RecordKind::A), records.clone());
    cache.insert("upstream.example.com.", Some(RecordKind::A), records, 300);

    c.bench_function("cache_lookup_local_hit", |b| {
        b.iter(|| {
            cache.lookup(
                black_box("cached.example.com."),
                black_box(Some(RecordKind::A)),
            )
        })
    });

    c.bench_function("cache_lookup_upstream_hit", |b| {
        b.iter(|| {
            cache.lookup(
                black_box("upstream.example.com."),
                black_box(Some(RecordKind::A)),
            )
        })
    });

    c.bench_function("cache_lookup_miss", |b| {
        b.iter(|| {
            cache.lookup(
                black_box("miss.example.com."),
                black_box(Some(RecordKind::A)),
            )
        })
    });

    c.bench_function("cache_insert_local", |b| {
        let records = vec![DnsRecord {
            id: None,
            name: "bench.example.com.".to_string(),
            record_type: RecordKind::A,
            value: "5.6.7.8".to_string(),
            ttl: 300,
            priority: 0,
        }];
        b.iter(|| {
            cache.insert_local(
                black_box("bench.example.com."),
                black_box(Some(RecordKind::A)),
                black_box(records.clone()),
            )
        })
    });
}

// ================================================================
// Query pipeline benchmarks (handle_query end-to-end, no sockets)
// ================================================================

fn bench_handle_query_local_hit(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let db = Database::open_memory().unwrap();
    db.add_record(&DnsRecord {
        id: None,
        name: "bench.local.".to_string(),
        record_type: RecordKind::A,
        value: "192.168.1.1".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();

    let server = make_bench_server(db);
    let query = build_dns_query("bench.local.");

    c.bench_function("handle_query_local_hit", |b| {
        b.iter(|| rt.block_on(server.handle_query(black_box(&query))))
    });
}

fn bench_handle_query_local_nxdomain(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let db = Database::open_memory().unwrap();
    // Add a record so the zone is "managed", then query a non-existent name in it
    db.add_record(&DnsRecord {
        id: None,
        name: "exists.bench.local.".to_string(),
        record_type: RecordKind::A,
        value: "1.2.3.4".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();

    let server = make_bench_server(db);
    let query = build_dns_query("missing.bench.local.");

    c.bench_function("handle_query_local_nxdomain", |b| {
        b.iter(|| rt.block_on(server.handle_query(black_box(&query))))
    });
}

fn bench_handle_query_with_cache(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let db = Database::open_memory().unwrap();
    db.add_record(&DnsRecord {
        id: None,
        name: "cached.bench.local.".to_string(),
        record_type: RecordKind::A,
        value: "10.0.0.1".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();

    let server = rt.block_on(async { make_bench_server_with_cache(db) });
    let query = build_dns_query("cached.bench.local.");

    // Prime the cache with a first query
    rt.block_on(server.handle_query(&query)).unwrap();

    c.bench_function("handle_query_cached_hit", |b| {
        b.iter(|| rt.block_on(server.handle_query(black_box(&query))))
    });
}

fn bench_handle_query_various_types(c: &mut Criterion) {
    use hickory_proto::rr::RecordType;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let db = Database::open_memory().unwrap();
    db.add_record(&DnsRecord {
        id: None,
        name: "types.bench.local.".to_string(),
        record_type: RecordKind::A,
        value: "1.2.3.4".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();
    db.add_record(&DnsRecord {
        id: None,
        name: "types.bench.local.".to_string(),
        record_type: RecordKind::AAAA,
        value: "::1".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();
    db.add_record(&DnsRecord {
        id: None,
        name: "types.bench.local.".to_string(),
        record_type: RecordKind::TXT,
        value: "v=spf1 include:example.com ~all".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();
    db.add_record(&DnsRecord {
        id: None,
        name: "types.bench.local.".to_string(),
        record_type: RecordKind::MX,
        value: "mail.bench.local.".to_string(),
        ttl: 300,
        priority: 10,
    })
    .unwrap();

    let server = make_bench_server(db);

    let query_a = build_dns_query_typed("types.bench.local.", RecordType::A);
    c.bench_function("handle_query_A", |b| {
        b.iter(|| rt.block_on(server.handle_query(black_box(&query_a))))
    });

    let query_aaaa = build_dns_query_typed("types.bench.local.", RecordType::AAAA);
    c.bench_function("handle_query_AAAA", |b| {
        b.iter(|| rt.block_on(server.handle_query(black_box(&query_aaaa))))
    });

    let query_txt = build_dns_query_typed("types.bench.local.", RecordType::TXT);
    c.bench_function("handle_query_TXT", |b| {
        b.iter(|| rt.block_on(server.handle_query(black_box(&query_txt))))
    });

    let query_mx = build_dns_query_typed("types.bench.local.", RecordType::MX);
    c.bench_function("handle_query_MX", |b| {
        b.iter(|| rt.block_on(server.handle_query(black_box(&query_mx))))
    });
}

fn bench_handle_query_scoped(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let db = Database::open_memory().unwrap();
    db.create_network_scope(&NetworkScope {
        name: "bench-scope".to_string(),
        home_domain: "bench-scope.home.".to_string(),
    })
    .unwrap();
    db.add_scoped_record(
        "bench-scope",
        &DnsRecord {
            id: None,
            name: "scoped.bench.local.".to_string(),
            record_type: RecordKind::A,
            value: "172.16.0.1".to_string(),
            ttl: 300,
            priority: 0,
        },
    )
    .unwrap();
    db.join_network(&NetworkAssociation {
        ip_address: "10.0.0.1".to_string(),
        scope_name: "bench-scope".to_string(),
        ttl_seconds: 3600,
    })
    .unwrap();

    let server = make_bench_server(db);
    let query = build_dns_query("scoped.bench.local.");
    let source_ip: IpAddr = "10.0.0.1".parse().unwrap();

    c.bench_function("handle_query_scoped_hit", |b| {
        b.iter(|| rt.block_on(server.handle_query_from(black_box(&query), black_box(source_ip))))
    });
}

// ================================================================
// UDP round-trip benchmark
// ================================================================

fn bench_udp_round_trip(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Start a UDP DNS server on a random port
    let db = Database::open_memory().unwrap();
    db.add_record(&DnsRecord {
        id: None,
        name: "udp.bench.local.".to_string(),
        record_type: RecordKind::A,
        value: "192.168.1.1".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();
    let server = make_bench_server(db);

    let server_addr = rt.block_on(async {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();

        let srv = Arc::clone(&server);
        let sock = Arc::clone(&socket);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (len, src) = match sock.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                let data = buf[..len].to_vec();
                let s = Arc::clone(&srv);
                let sk = Arc::clone(&sock);
                tokio::spawn(async move {
                    if let Ok(resp) = s.handle_query(&data).await {
                        let _ = sk.send_to(&resp, src).await;
                    }
                });
            }
        });

        addr
    });

    let query = build_dns_query("udp.bench.local.");

    c.bench_function("udp_round_trip", |b| {
        b.iter(|| {
            rt.block_on(async {
                let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                client
                    .send_to(black_box(&query), server_addr)
                    .await
                    .unwrap();
                let mut buf = vec![0u8; 4096];
                client.recv_from(&mut buf).await.unwrap();
            })
        })
    });
}

fn bench_udp_round_trip_reuse_socket(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let db = Database::open_memory().unwrap();
    db.add_record(&DnsRecord {
        id: None,
        name: "udp2.bench.local.".to_string(),
        record_type: RecordKind::A,
        value: "192.168.1.2".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();
    let server = make_bench_server(db);

    let (server_addr, client_socket) = rt.block_on(async {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();

        let srv = Arc::clone(&server);
        let sock = Arc::clone(&socket);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (len, src) = match sock.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                let data = buf[..len].to_vec();
                let s = Arc::clone(&srv);
                let sk = Arc::clone(&sock);
                tokio::spawn(async move {
                    if let Ok(resp) = s.handle_query(&data).await {
                        let _ = sk.send_to(&resp, src).await;
                    }
                });
            }
        });

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        (addr, client)
    });

    let query = build_dns_query("udp2.bench.local.");

    c.bench_function("udp_round_trip_reuse_socket", |b| {
        b.iter(|| {
            rt.block_on(async {
                client_socket
                    .send_to(black_box(&query), server_addr)
                    .await
                    .unwrap();
                let mut buf = vec![0u8; 4096];
                client_socket.recv_from(&mut buf).await.unwrap();
            })
        })
    });
}

// ================================================================
// TCP round-trip benchmark
// ================================================================

fn bench_tcp_round_trip(c: &mut Criterion) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let db = Database::open_memory().unwrap();
    db.add_record(&DnsRecord {
        id: None,
        name: "tcp.bench.local.".to_string(),
        record_type: RecordKind::A,
        value: "192.168.1.3".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();
    let server = make_bench_server(db);

    let server_addr = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                let _ = stream.set_nodelay(true);
                let s = Arc::clone(&srv);
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.into_split();
                    loop {
                        let mut len_buf = [0u8; 2];
                        if reader.read_exact(&mut len_buf).await.is_err() {
                            break;
                        }
                        let msg_len = u16::from_be_bytes(len_buf) as usize;
                        let mut msg_buf = vec![0u8; msg_len];
                        if reader.read_exact(&mut msg_buf).await.is_err() {
                            break;
                        }
                        if let Ok(resp) = s.handle_query(&msg_buf).await {
                            let resp_len = (resp.len() as u16).to_be_bytes();
                            if writer.write_all(&resp_len).await.is_err() {
                                break;
                            }
                            if writer.write_all(&resp).await.is_err() {
                                break;
                            }
                        }
                    }
                });
            }
        });

        addr
    });

    let query = build_dns_query("tcp.bench.local.");

    // Benchmark with a new TCP connection per query
    c.bench_function("tcp_round_trip_new_conn", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
                stream.set_nodelay(true).unwrap();
                let len = (query.len() as u16).to_be_bytes();
                stream.write_all(&len).await.unwrap();
                stream.write_all(black_box(&query)).await.unwrap();

                let mut resp_len_buf = [0u8; 2];
                stream.read_exact(&mut resp_len_buf).await.unwrap();
                let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
                let mut resp_buf = vec![0u8; resp_len];
                stream.read_exact(&mut resp_buf).await.unwrap();
            })
        })
    });
}

fn bench_tcp_round_trip_reuse_conn(c: &mut Criterion) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let db = Database::open_memory().unwrap();
    db.add_record(&DnsRecord {
        id: None,
        name: "tcp2.bench.local.".to_string(),
        record_type: RecordKind::A,
        value: "192.168.1.4".to_string(),
        ttl: 300,
        priority: 0,
    })
    .unwrap();
    let server = make_bench_server(db);

    let (server_addr, stream) = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                let _ = stream.set_nodelay(true);
                let s = Arc::clone(&srv);
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.into_split();
                    loop {
                        let mut len_buf = [0u8; 2];
                        if reader.read_exact(&mut len_buf).await.is_err() {
                            break;
                        }
                        let msg_len = u16::from_be_bytes(len_buf) as usize;
                        let mut msg_buf = vec![0u8; msg_len];
                        if reader.read_exact(&mut msg_buf).await.is_err() {
                            break;
                        }
                        if let Ok(resp) = s.handle_query(&msg_buf).await {
                            let resp_len = (resp.len() as u16).to_be_bytes();
                            if writer.write_all(&resp_len).await.is_err() {
                                break;
                            }
                            if writer.write_all(&resp).await.is_err() {
                                break;
                            }
                        }
                    }
                });
            }
        });

        // Pre-establish the connection with TCP_NODELAY to avoid Nagle buffering
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.set_nodelay(true).unwrap();
        (addr, stream)
    });

    let query = build_dns_query("tcp2.bench.local.");
    // Hold the stream in an Option so each iteration can take it out for the
    // duration of its awaits and put it back, rather than holding a RefCell
    // borrow guard across the await points.
    let stream = std::cell::RefCell::new(Some(stream));

    // Benchmark reusing the same TCP connection (pipelining)
    c.bench_function("tcp_round_trip_reuse_conn", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut s = stream.borrow_mut().take().unwrap();
                let len = (query.len() as u16).to_be_bytes();
                s.write_all(&len).await.unwrap();
                s.write_all(black_box(&query)).await.unwrap();

                let mut resp_len_buf = [0u8; 2];
                s.read_exact(&mut resp_len_buf).await.unwrap();
                let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
                let mut resp_buf = vec![0u8; resp_len];
                s.read_exact(&mut resp_buf).await.unwrap();
                *stream.borrow_mut() = Some(s);
            })
        })
    });

    // Prevent unused variable warning for server_addr
    let _ = server_addr;
}

criterion_group!(
    benches,
    bench_qname_randomization,
    bench_qname_randomization_long,
    bench_cache_key,
    bench_cache_key_none,
    bench_lookup_with_fallbacks,
    bench_lookup_original,
    bench_zone_matching,
    bench_dns_cache_operations,
    bench_handle_query_local_hit,
    bench_handle_query_local_nxdomain,
    bench_handle_query_with_cache,
    bench_handle_query_various_types,
    bench_handle_query_scoped,
    bench_udp_round_trip,
    bench_udp_round_trip_reuse_socket,
    bench_tcp_round_trip,
    bench_tcp_round_trip_reuse_conn,
);
criterion_main!(benches);
