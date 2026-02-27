use crate::db::{Database, RecordKind};
use crate::rbl::RblChecker;
use anyhow::{Context, Result};
use hickory_proto::op::{MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Maximum UDP DNS message size.
const MAX_UDP_SIZE: usize = 4096;
/// Maximum TCP DNS message size (with 2-byte length prefix).
const MAX_TCP_SIZE: usize = 65535;

/// The DNS server handles both UDP and TCP DNS queries.
/// It performs split-horizon resolution: local database records are preferred,
/// and unmatched queries are forwarded to upstream resolvers.
pub struct DnsServer {
    db: Database,
    rbl: Arc<RblChecker>,
    forwarders: Arc<RwLock<Vec<SocketAddr>>>,
}

impl DnsServer {
    pub fn new(db: Database, rbl: Arc<RblChecker>, forwarders: Vec<SocketAddr>) -> Self {
        Self {
            db,
            rbl,
            forwarders: Arc::new(RwLock::new(forwarders)),
        }
    }

    /// Updates the upstream forwarder list.
    pub async fn set_forwarders(&self, forwarders: Vec<SocketAddr>) {
        *self.forwarders.write().await = forwarders;
    }

    /// Returns the current forwarder list.
    pub async fn get_forwarders(&self) -> Vec<SocketAddr> {
        self.forwarders.read().await.clone()
    }

    /// Starts the UDP DNS listener.
    pub async fn serve_udp(self: Arc<Self>, bind_addr: &str) -> Result<()> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind UDP socket to {}", bind_addr))?;
        info!("DNS UDP server listening on {}", bind_addr);

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    error!("UDP recv error: {}", e);
                    continue;
                }
            };

            let data = buf[..len].to_vec();
            let socket_ref = &socket;
            let server = Arc::clone(&self);

            let response = server.handle_query(&data).await;
            match response {
                Ok(resp) => {
                    if let Err(e) = socket_ref.send_to(&resp, src).await {
                        error!("UDP send error to {}: {}", src, e);
                    }
                }
                Err(e) => {
                    warn!("Failed to handle DNS query from {}: {}", src, e);
                }
            }
        }
    }

    /// Starts the TCP DNS listener.
    pub async fn serve_tcp(self: Arc<Self>, bind_addr: &str) -> Result<()> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind TCP listener to {}", bind_addr))?;
        info!("DNS TCP server listening on {}", bind_addr);

        loop {
            let (stream, src) = match listener.accept().await {
                Ok(r) => r,
                Err(e) => {
                    error!("TCP accept error: {}", e);
                    continue;
                }
            };

            let server = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = server.handle_tcp_connection(stream, src).await {
                    debug!("TCP connection error from {}: {}", src, e);
                }
            });
        }
    }

    async fn handle_tcp_connection(
        &self,
        stream: tokio::net::TcpStream,
        src: SocketAddr,
    ) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut reader, mut writer) = stream.into_split();

        loop {
            // Read 2-byte length prefix
            let mut len_buf = [0u8; 2];
            match reader.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e.into()),
            }
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            if msg_len > MAX_TCP_SIZE {
                warn!("TCP message too large from {}: {} bytes", src, msg_len);
                return Ok(());
            }

            let mut msg_buf = vec![0u8; msg_len];
            reader.read_exact(&mut msg_buf).await?;

            let response = self.handle_query(&msg_buf).await?;
            let resp_len = (response.len() as u16).to_be_bytes();
            writer.write_all(&resp_len).await?;
            writer.write_all(&response).await?;
        }
    }

    /// Handles a raw DNS query and returns the raw response bytes.
    pub async fn handle_query(&self, query_data: &[u8]) -> Result<Vec<u8>> {
        let message = match hickory_proto::op::Message::from_bytes(query_data) {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to parse DNS query: {}", e);
                return Ok(make_error_response(query_data, ResponseCode::FormErr));
            }
        };

        if message.message_type() != MessageType::Query {
            return Ok(make_error_response(query_data, ResponseCode::NotImp));
        }

        if message.op_code() != OpCode::Query {
            return Ok(make_error_response(query_data, ResponseCode::NotImp));
        }

        let questions = message.queries();
        if questions.is_empty() {
            return Ok(make_error_response(query_data, ResponseCode::FormErr));
        }

        let question = &questions[0];
        let qname = question.name().to_string();
        let qtype = question.query_type();

        debug!("DNS query: {} {:?}", qname, qtype);

        // Check RBL for the source IP if it's an A or AAAA query
        if let Some(ip) = extract_ip_from_name(&qname) {
            if self.rbl.is_listed(&ip).await {
                debug!("RBL block: {} is blacklisted", qname);
                return Ok(build_response(&message, ResponseCode::NXDomain, vec![]));
            }
        }

        // Try local database first (split-horizon: local records take priority)
        let record_kind = map_query_type_to_kind(qtype);
        if let Some(kind) = record_kind {
            let local_records = self.db.lookup(&qname, Some(kind));
            if let Ok(records) = local_records {
                if !records.is_empty() {
                    debug!(
                        "Local hit for {} {:?}: {} records",
                        qname,
                        qtype,
                        records.len()
                    );
                    let dns_records = records
                        .iter()
                        .filter_map(|r| db_record_to_dns_record(r))
                        .collect();
                    return Ok(build_response(
                        &message,
                        ResponseCode::NoError,
                        dns_records,
                    ));
                }
            }
        }

        // Also check without type filter for CNAME chains
        if record_kind.is_some() {
            let cname_records = self.db.lookup(&qname, Some(RecordKind::CNAME));
            if let Ok(records) = cname_records {
                if !records.is_empty() {
                    let dns_records = records
                        .iter()
                        .filter_map(|r| db_record_to_dns_record(r))
                        .collect();
                    return Ok(build_response(
                        &message,
                        ResponseCode::NoError,
                        dns_records,
                    ));
                }
            }
        }

        // Check if this name falls under a managed zone
        // If the zone exists in our DB but the specific name doesn't,
        // still return NXDOMAIN from local (split-horizon behavior)
        if let Ok(zones) = self.db.get_managed_zones() {
            let normalized_qname = crate::db::normalize_name(&qname);
            for zone in &zones {
                if normalized_qname.ends_with(zone) || normalized_qname == *zone {
                    // Name is under a managed zone but not found - check if the zone
                    // itself has records. If so, this is authoritative NXDOMAIN.
                    let zone_records = self.db.lookup(zone, None);
                    if let Ok(records) = zone_records {
                        if !records.is_empty() {
                            debug!(
                                "Authoritative NXDOMAIN for {} (zone {} exists)",
                                qname, zone
                            );
                            return Ok(build_response(
                                &message,
                                ResponseCode::NXDomain,
                                vec![],
                            ));
                        }
                    }
                }
            }
        }

        // Forward to upstream resolvers
        self.forward_query(query_data).await
    }

    /// Forwards a DNS query to the configured upstream resolvers.
    async fn forward_query(&self, query_data: &[u8]) -> Result<Vec<u8>> {
        let forwarders = self.forwarders.read().await;
        if forwarders.is_empty() {
            return Ok(make_error_response(query_data, ResponseCode::ServFail));
        }

        // Try each forwarder in order
        for forwarder in forwarders.iter() {
            match self.forward_udp(query_data, forwarder).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    warn!("Forward to {} failed: {}", forwarder, e);
                    continue;
                }
            }
        }

        Ok(make_error_response(query_data, ResponseCode::ServFail))
    }

    async fn forward_udp(&self, query_data: &[u8], target: &SocketAddr) -> Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(query_data, target).await?;

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let timeout =
            tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv(&mut buf));
        let len = timeout
            .await
            .context("forwarder timeout")?
            .context("forwarder recv error")?;
        buf.truncate(len);
        Ok(buf)
    }
}

/// Extracts an IP address from a DNS name for RBL checking.
/// This handles reverse DNS names (in-addr.arpa / ip6.arpa) by reconstructing the IP.
fn extract_ip_from_name(name: &str) -> Option<IpAddr> {
    let name = name.trim_end_matches('.');

    // Check for IPv4 reverse DNS (x.x.x.x.in-addr.arpa)
    if let Some(stripped) = name.strip_suffix(".in-addr.arpa") {
        let parts: Vec<&str> = stripped.split('.').collect();
        if parts.len() == 4 {
            let octets: Vec<u8> = parts.iter().rev().filter_map(|p| p.parse().ok()).collect();
            if octets.len() == 4 {
                return Some(IpAddr::V4(Ipv4Addr::new(
                    octets[0], octets[1], octets[2], octets[3],
                )));
            }
        }
    }

    // Check for IPv6 reverse DNS (nibbles.ip6.arpa)
    if let Some(stripped) = name.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = stripped.split('.').collect();
        if nibbles.len() == 32 {
            let mut bytes = [0u8; 16];
            for i in 0..16 {
                let high = u8::from_str_radix(nibbles[31 - i * 2], 16).ok()?;
                let low = u8::from_str_radix(nibbles[31 - i * 2 - 1], 16).ok()?;
                bytes[i] = (high << 4) | low;
            }
            return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
        }
    }

    None
}

/// Maps a hickory RecordType to our internal RecordKind.
fn map_query_type_to_kind(rt: RecordType) -> Option<RecordKind> {
    match rt {
        RecordType::A => Some(RecordKind::A),
        RecordType::AAAA => Some(RecordKind::AAAA),
        RecordType::CNAME => Some(RecordKind::CNAME),
        RecordType::MX => Some(RecordKind::MX),
        RecordType::TXT => Some(RecordKind::TXT),
        RecordType::NS => Some(RecordKind::NS),
        RecordType::SOA => Some(RecordKind::SOA),
        RecordType::SRV => Some(RecordKind::SRV),
        RecordType::PTR => Some(RecordKind::PTR),
        _ => None,
    }
}

/// Converts a database record to a hickory DNS record.
fn db_record_to_dns_record(db_rec: &crate::db::DnsRecord) -> Option<Record> {
    let name = Name::from_ascii(&db_rec.name).ok()?;
    let rdata = match db_rec.record_type {
        RecordKind::A => {
            let ip: Ipv4Addr = db_rec.value.parse().ok()?;
            RData::A(rdata::A(ip))
        }
        RecordKind::AAAA => {
            let ip: Ipv6Addr = db_rec.value.parse().ok()?;
            RData::AAAA(rdata::AAAA(ip))
        }
        RecordKind::CNAME => {
            let target = Name::from_ascii(&db_rec.value).ok()?;
            RData::CNAME(rdata::CNAME(target))
        }
        RecordKind::MX => {
            let target = Name::from_ascii(&db_rec.value).ok()?;
            RData::MX(rdata::MX::new(db_rec.priority as u16, target))
        }
        RecordKind::TXT => RData::TXT(rdata::TXT::new(vec![db_rec.value.clone()])),
        RecordKind::NS => {
            let target = Name::from_ascii(&db_rec.value).ok()?;
            RData::NS(rdata::NS(target))
        }
        RecordKind::SOA => {
            // SOA value format: "mname rname serial refresh retry expire minimum"
            let parts: Vec<&str> = db_rec.value.split_whitespace().collect();
            if parts.len() >= 7 {
                let mname = Name::from_ascii(parts[0]).ok()?;
                let rname = Name::from_ascii(parts[1]).ok()?;
                let serial: u32 = parts[2].parse().ok()?;
                let refresh: i32 = parts[3].parse().ok()?;
                let retry: i32 = parts[4].parse().ok()?;
                let expire: i32 = parts[5].parse().ok()?;
                let minimum: u32 = parts[6].parse().ok()?;
                RData::SOA(rdata::SOA::new(
                    mname, rname, serial, refresh, retry, expire, minimum,
                ))
            } else {
                return None;
            }
        }
        RecordKind::SRV => {
            // SRV value format: "weight port target"
            let parts: Vec<&str> = db_rec.value.split_whitespace().collect();
            if parts.len() >= 3 {
                let weight: u16 = parts[0].parse().ok()?;
                let port: u16 = parts[1].parse().ok()?;
                let target = Name::from_ascii(parts[2]).ok()?;
                RData::SRV(rdata::SRV::new(
                    db_rec.priority as u16,
                    weight,
                    port,
                    target,
                ))
            } else {
                return None;
            }
        }
        RecordKind::PTR => {
            let target = Name::from_ascii(&db_rec.value).ok()?;
            RData::PTR(rdata::PTR(target))
        }
    };

    let mut record = Record::from_rdata(name, db_rec.ttl, rdata);
    record.set_dns_class(DNSClass::IN);
    Some(record)
}

/// Builds a DNS response message.
fn build_response(
    query: &hickory_proto::op::Message,
    rcode: ResponseCode,
    answers: Vec<Record>,
) -> Vec<u8> {
    let mut response = hickory_proto::op::Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(rcode);
    response.set_recursion_desired(query.recursion_desired());
    response.set_recursion_available(true);

    // Copy the question section
    for q in query.queries() {
        response.add_query(q.clone());
    }

    for answer in answers {
        response.add_answer(answer);
    }

    response.to_bytes().unwrap_or_default()
}

/// Creates an error response preserving the query ID.
fn make_error_response(query_data: &[u8], rcode: ResponseCode) -> Vec<u8> {
    if query_data.len() >= 2 {
        let id = u16::from_be_bytes([query_data[0], query_data[1]]);
        let mut response = hickory_proto::op::Message::new();
        response.set_id(id);
        response.set_message_type(MessageType::Response);
        response.set_response_code(rcode);
        response.to_bytes().unwrap_or_default()
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Database, DnsRecord, RecordKind};
    use crate::rbl::{RblChecker, RblProvider, RblResolver};
    use hickory_proto::op::Message;
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use std::net::Ipv4Addr;

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

    fn make_test_server(db: Database) -> Arc<DnsServer> {
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        Arc::new(DnsServer::new(db, rbl, vec![]))
    }

    fn make_test_server_with_rbl(db: Database, listed: bool) -> Arc<DnsServer> {
        let resolver: Arc<dyn RblResolver> = if listed {
            Arc::new(AlwaysListedResolver)
        } else {
            Arc::new(NeverListedResolver)
        };
        let rbl = Arc::new(RblChecker::with_resolver(
            true,
            vec![RblProvider {
                zone: "test.rbl".to_string(),
                enabled: true,
            }],
            resolver,
        ));
        Arc::new(DnsServer::new(db, rbl, vec![]))
    }

    fn build_query(name: &str, qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(1234);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);

        let mut query = hickory_proto::op::Query::new();
        query.set_name(Name::from_ascii(name).unwrap());
        query.set_query_type(qtype);
        query.set_query_class(DNSClass::IN);
        msg.add_query(query);

        msg.to_bytes().unwrap()
    }

    #[tokio::test]
    async fn test_local_a_record_lookup() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "test.local.".to_string(),
            record_type: RecordKind::A,
            value: "192.168.1.100".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("test.local.", RecordType::A);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        if let RData::A(rdata::A(ip)) = response.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 100));
        } else {
            panic!("expected A record");
        }
    }

    #[tokio::test]
    async fn test_local_aaaa_record_lookup() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "test.local.".to_string(),
            record_type: RecordKind::AAAA,
            value: "::1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("test.local.", RecordType::AAAA);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_local_cname_record_lookup() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "alias.local.".to_string(),
            record_type: RecordKind::CNAME,
            value: "real.local.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("alias.local.", RecordType::A);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        // Should return the CNAME when querying for A record
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_local_mx_record_lookup() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "example.local.".to_string(),
            record_type: RecordKind::MX,
            value: "mail.example.local.".to_string(),
            ttl: 300,
            priority: 10,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("example.local.", RecordType::MX);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_local_txt_record_lookup() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "txt.local.".to_string(),
            record_type: RecordKind::TXT,
            value: "v=spf1 include:example.com ~all".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("txt.local.", RecordType::TXT);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_nonexistent_record_no_forwarders() {
        let db = Database::open_memory().unwrap();
        let server = make_test_server(db);
        let query = build_query("nonexistent.example.com.", RecordType::A);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        // No forwarders configured, should get SERVFAIL
        assert_eq!(response.response_code(), ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn test_malformed_query() {
        let db = Database::open_memory().unwrap();
        let server = make_test_server(db);
        let response_bytes = server.handle_query(&[0, 1]).await.unwrap();
        // Should get a response (possibly empty or error)
        assert!(!response_bytes.is_empty());
    }

    #[tokio::test]
    async fn test_multiple_records_same_name() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "multi.local.".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "multi.local.".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.2".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("multi.local.", RecordType::A);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 2);
    }

    #[tokio::test]
    async fn test_split_horizon_local_preferred() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "internal.company.com.".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.50".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("internal.company.com.", RecordType::A);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        if let RData::A(rdata::A(ip)) = response.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 50));
        }
    }

    #[tokio::test]
    async fn test_rbl_blocks_reverse_dns() {
        let db = Database::open_memory().unwrap();
        let server = make_test_server_with_rbl(db, true);
        // Query for a reverse DNS name
        let query = build_query("100.1.168.192.in-addr.arpa.", RecordType::PTR);
        let response_bytes = server.handle_query(&query).await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NXDomain);
    }

    #[test]
    fn test_extract_ip_from_name_ipv4() {
        let ip = extract_ip_from_name("100.1.168.192.in-addr.arpa.");
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
    }

    #[test]
    fn test_extract_ip_from_name_not_reverse() {
        let ip = extract_ip_from_name("example.com.");
        assert_eq!(ip, None);
    }

    #[test]
    fn test_extract_ip_from_name_ipv6() {
        let name =
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.";
        let ip = extract_ip_from_name(name);
        assert_eq!(ip, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_map_query_type_to_kind() {
        assert_eq!(map_query_type_to_kind(RecordType::A), Some(RecordKind::A));
        assert_eq!(
            map_query_type_to_kind(RecordType::AAAA),
            Some(RecordKind::AAAA)
        );
        assert_eq!(
            map_query_type_to_kind(RecordType::CNAME),
            Some(RecordKind::CNAME)
        );
        assert_eq!(map_query_type_to_kind(RecordType::MX), Some(RecordKind::MX));
        assert_eq!(
            map_query_type_to_kind(RecordType::TXT),
            Some(RecordKind::TXT)
        );
        assert_eq!(map_query_type_to_kind(RecordType::NS), Some(RecordKind::NS));
        assert_eq!(
            map_query_type_to_kind(RecordType::SOA),
            Some(RecordKind::SOA)
        );
        assert_eq!(
            map_query_type_to_kind(RecordType::SRV),
            Some(RecordKind::SRV)
        );
        assert_eq!(
            map_query_type_to_kind(RecordType::PTR),
            Some(RecordKind::PTR)
        );
    }

    #[test]
    fn test_db_record_to_dns_record_a() {
        let db_rec = DnsRecord {
            id: None,
            name: "test.local.".to_string(),
            record_type: RecordKind::A,
            value: "192.168.1.1".to_string(),
            ttl: 300,
            priority: 0,
        };
        let record = db_record_to_dns_record(&db_rec).unwrap();
        assert_eq!(record.record_type(), RecordType::A);
        assert_eq!(record.ttl(), 300);
    }

    #[test]
    fn test_db_record_to_dns_record_invalid_ip() {
        let db_rec = DnsRecord {
            id: None,
            name: "test.local.".to_string(),
            record_type: RecordKind::A,
            value: "not-an-ip".to_string(),
            ttl: 300,
            priority: 0,
        };
        assert!(db_record_to_dns_record(&db_rec).is_none());
    }

    #[tokio::test]
    async fn test_set_forwarders() {
        let db = Database::open_memory().unwrap();
        let server = make_test_server(db);
        assert!(server.get_forwarders().await.is_empty());

        server
            .set_forwarders(vec!["8.8.8.8:53".parse().unwrap()])
            .await;
        let forwarders = server.get_forwarders().await;
        assert_eq!(forwarders.len(), 1);
    }

    #[test]
    fn test_build_response() {
        let query_bytes = build_query("test.local.", RecordType::A);
        let query = Message::from_bytes(&query_bytes).unwrap();

        let response_bytes = build_response(&query, ResponseCode::NoError, vec![]);
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.id(), query.id());
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }

    #[test]
    fn test_make_error_response() {
        let query_bytes = build_query("test.local.", RecordType::A);
        let response_bytes = make_error_response(&query_bytes, ResponseCode::ServFail);
        let response = Message::from_bytes(&response_bytes).unwrap();
        assert_eq!(response.response_code(), ResponseCode::ServFail);
    }
}
