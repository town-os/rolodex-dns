use criterion::{Criterion, black_box, criterion_group, criterion_main};
use hickory_proto::serialize::binary::BinEncodable;
use rolodex_dns::db::{Database, DnsRecord, RecordKind};
use rolodex_dns::dns_cache::cache_key;
use rolodex_dns::dns_server::randomize_qname_case;

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
    // Populate with records
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
    // Add records to populate managed zones cache
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
    // Add authoritative zones
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
    let cache = rt.block_on(async { rolodex_dns::dns_cache::DnsCache::new(db) });

    // Pre-populate cache
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
);
criterion_main!(benches);
