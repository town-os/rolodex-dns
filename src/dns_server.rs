use crate::db::{Database, RecordKind};
use crate::dns_cache::DnsCache;
use crate::rbl::RblChecker;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use hickory_proto::op::{MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, warn};

const FORWARD_POOL_SIZE: usize = 8;

/// Maximum UDP DNS message size.
const MAX_UDP_SIZE: usize = 4096;
/// Maximum TCP DNS message size (with 2-byte length prefix).
const MAX_TCP_SIZE: usize = 65535;

/// The DNS server handles both UDP and TCP DNS queries.
/// It performs split-horizon resolution: local database records are preferred,
/// and unmatched queries are forwarded to upstream resolvers.
///
/// When network scoping is active, DNS queries are resolved within the context
/// of the network scope associated with the source IP. Unassociated IPs receive
/// REFUSED responses. RBL checks are also scoped to the network.
pub struct DnsServer {
    db: Database,
    rbl: Arc<RblChecker>,
    forwarders: Arc<ArcSwap<Vec<SocketAddr>>>,
    /// Optional DNS response cache for privacy-first resolution.
    dns_cache: Option<Arc<DnsCache>>,
    /// Optional DNS64 prefix for synthesizing AAAA records from A records.
    dns64_prefix: Option<Ipv6Addr>,
    /// Whether to randomize QNAME case in forwarded queries (0x20 encoding).
    qname_randomization: bool,
    /// TTL drift configuration for adjusting cached record TTLs.
    ttl_drift_config: Arc<ArcSwap<crate::ttl_drift::TtlDriftConfig>>,
    /// Optional proxy configuration for upstream forwarding.
    proxy_config: Arc<ArcSwap<Option<crate::doh_proxy::ProxyConfig>>>,
    /// Pool of pre-bound UDP sockets for forwarding queries.
    forward_sockets: Vec<Arc<tokio::sync::Mutex<Option<UdpSocket>>>>,
    /// Round-robin index for the forward socket pool.
    forward_socket_idx: AtomicUsize,
}

impl DnsServer {
    pub fn new(db: Database, rbl: Arc<RblChecker>, forwarders: Vec<SocketAddr>) -> Self {
        let forward_sockets = (0..FORWARD_POOL_SIZE)
            .map(|_| Arc::new(tokio::sync::Mutex::new(None)))
            .collect();
        Self {
            db,
            rbl,
            forwarders: Arc::new(ArcSwap::from_pointee(forwarders)),
            dns_cache: None,
            dns64_prefix: None,
            qname_randomization: true,
            ttl_drift_config: Arc::new(ArcSwap::from_pointee(
                crate::ttl_drift::TtlDriftConfig::default(),
            )),
            proxy_config: Arc::new(ArcSwap::from_pointee(None)),
            forward_sockets,
            forward_socket_idx: AtomicUsize::new(0),
        }
    }

    /// Creates a DnsServer with all optional features configurable.
    pub fn new_with_options(
        db: Database,
        rbl: Arc<RblChecker>,
        forwarders: Vec<SocketAddr>,
        dns_cache: Option<Arc<DnsCache>>,
        dns64_prefix: Option<Ipv6Addr>,
        qname_randomization: bool,
    ) -> Self {
        let forward_sockets = (0..FORWARD_POOL_SIZE)
            .map(|_| Arc::new(tokio::sync::Mutex::new(None)))
            .collect();
        Self {
            db,
            rbl,
            forwarders: Arc::new(ArcSwap::from_pointee(forwarders)),
            dns_cache,
            dns64_prefix,
            qname_randomization,
            ttl_drift_config: Arc::new(ArcSwap::from_pointee(
                crate::ttl_drift::TtlDriftConfig::default(),
            )),
            proxy_config: Arc::new(ArcSwap::from_pointee(None)),
            forward_sockets,
            forward_socket_idx: AtomicUsize::new(0),
        }
    }

    /// Sets the TTL drift configuration.
    pub async fn set_ttl_drift_config(&self, config: crate::ttl_drift::TtlDriftConfig) {
        self.ttl_drift_config.store(Arc::new(config));
    }

    /// Gets the current TTL drift configuration.
    pub async fn get_ttl_drift_config(&self) -> crate::ttl_drift::TtlDriftConfig {
        self.ttl_drift_config.load().as_ref().clone()
    }

    /// Returns a reference to the database.
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Flushes the in-memory DNS cache (and its persistent backing store).
    pub fn flush_cache(&self) {
        if let Some(ref cache) = self.dns_cache {
            cache.flush();
        }
    }

    /// Updates the upstream forwarder list.
    pub async fn set_forwarders(&self, forwarders: Vec<SocketAddr>) {
        self.forwarders.store(Arc::new(forwarders));
    }

    /// Returns the current forwarder list.
    pub async fn get_forwarders(&self) -> Vec<SocketAddr> {
        self.forwarders.load().as_ref().clone()
    }

    /// Sets the proxy configuration for upstream forwarding.
    pub fn set_proxy_config(&self, config: Option<crate::doh_proxy::ProxyConfig>) {
        self.proxy_config.store(Arc::new(config));
    }

    /// Returns the current proxy configuration.
    pub fn get_proxy_config(&self) -> Option<crate::doh_proxy::ProxyConfig> {
        self.proxy_config.load().as_ref().clone()
    }

    /// Starts the UDP DNS listener.
    /// Processes queries concurrently by spawning a task per received query.
    pub async fn serve_udp(self: Arc<Self>, bind_addr: &str) -> Result<()> {
        let socket = Arc::new(
            UdpSocket::bind(bind_addr)
                .await
                .with_context(|| format!("failed to bind UDP socket to {}", bind_addr))?,
        );
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

            let mut data = Vec::with_capacity(len);
            data.extend_from_slice(&buf[..len]);
            let server = Arc::clone(&self);
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                match server.handle_query_from(&data, src.ip()).await {
                    Ok(resp) => {
                        if let Err(e) = socket.send_to(&resp, src).await {
                            error!("UDP send error to {}: {}", src, e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to handle DNS query from {}: {}", src, e);
                    }
                }
            });
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

            let response = self.handle_query_from(&msg_buf, src.ip()).await?;
            let resp_len = (response.len() as u16).to_be_bytes();
            writer.write_all(&resp_len).await?;
            writer.write_all(&response).await?;
        }
    }

    /// Handles a raw DNS query and returns the raw response bytes.
    /// This is a convenience method that does not enforce network scoping.
    /// Used for tests where source IP context is not available.
    pub async fn handle_query(&self, query_data: &[u8]) -> Result<Vec<u8>> {
        self.resolve_query(query_data, None).await
    }

    /// Handles a raw DNS query with source IP context for network scoping.
    ///
    /// When network scopes exist, the source IP must be associated with a
    /// network scope to receive DNS responses. Unassociated IPs receive
    /// REFUSED responses. When no network scopes are defined, the server
    /// operates in legacy mode without scope enforcement.
    pub async fn handle_query_from(&self, query_data: &[u8], source_ip: IpAddr) -> Result<Vec<u8>> {
        self.resolve_query(query_data, Some(source_ip)).await
    }

    /// Core DNS resolution logic with optional network scope context.
    async fn resolve_query(&self, query_data: &[u8], source_ip: Option<IpAddr>) -> Result<Vec<u8>> {
        let message = match hickory_proto::op::Message::from_bytes(query_data) {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to parse DNS query: {}", e);
                return Ok(make_error_response(query_data, ResponseCode::FormErr));
            }
        };

        // Extract EDNS context from the query
        let edns_ctx = crate::edns::EdnsContext::from_message(&message);

        // If EDNS version > 0, return BADVERS (RFC 6891 section 6.1.3)
        if let Some(ref ctx) = edns_ctx
            && ctx.is_unsupported_version()
        {
            debug!("Rejecting EDNS version {} query", ctx.version);
            return Ok(build_response_edns(
                &message,
                ResponseCode::from(0, 16), // BADVERS
                vec![],
                false,
                edns_ctx.as_ref(),
            ));
        }

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

        // Determine network scope for this query
        let scope_name = if let Some(ip) = source_ip {
            let ip_str = ip.to_string();
            if self.db.has_scopes() {
                let scope = self.db.get_scope_for_ip(&ip_str);
                if scope.is_none() {
                    // IP is not associated with any scope - refuse resolution
                    debug!("Refusing DNS query from unassociated IP {}", ip);
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::Refused,
                        vec![],
                        false,
                        edns_ctx.as_ref(),
                    ));
                }
                scope
            } else {
                None
            }
        } else {
            None
        };

        let question = &questions[0];
        let qname = question.name().to_string();
        let qtype = question.query_type();

        debug!("DNS query: {} {:?} (scope: {:?})", qname, qtype, scope_name);

        // If we have a network scope, check scoped RBL first
        if let Some(ref scope) = scope_name {
            if let Some(ip) = extract_ip_from_name(&qname)
                && (self.rbl.is_listed(&ip).await || self.db.lookup_local_rbl(&ip.to_string()))
            {
                debug!("RBL block in scope {}: {} is blacklisted", scope, qname);
                return Ok(build_response_edns(
                    &message,
                    ResponseCode::NXDomain,
                    vec![],
                    true,
                    edns_ctx.as_ref(),
                ));
            }

            // Try scoped records first
            let record_kind = map_query_type_to_kind(qtype);
            if let Some(kind) = record_kind {
                // Check cache before hitting the database
                let mut scoped_cache_name =
                    String::with_capacity(1 + scope.len() + 1 + qname.len());
                scoped_cache_name.push('@');
                scoped_cache_name.push_str(scope);
                scoped_cache_name.push('/');
                scoped_cache_name.push_str(&qname);
                if let Some(ref cache) = self.dns_cache {
                    let cached = cache.lookup(&scoped_cache_name, Some(kind));
                    if !cached.is_empty() {
                        debug!(
                            "Cache hit (scoped) for {} {:?} in scope {}: {} records",
                            qname,
                            qtype,
                            scope,
                            cached.len()
                        );
                        let dns_records =
                            cached.iter().filter_map(db_record_to_dns_record).collect();
                        return Ok(build_response_edns(
                            &message,
                            ResponseCode::NoError,
                            dns_records,
                            true,
                            edns_ctx.as_ref(),
                        ));
                    }
                }

                let records = self.db.lookup_scoped(scope, &qname, Some(kind));
                if !records.is_empty() {
                    debug!(
                        "Scoped hit for {} {:?} in scope {}: {} records",
                        qname,
                        qtype,
                        scope,
                        records.len()
                    );
                    if let Some(ref cache) = self.dns_cache {
                        cache.insert_local(&scoped_cache_name, Some(kind), records.clone());
                    }
                    let dns_records = records.iter().filter_map(db_record_to_dns_record).collect();
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NoError,
                        dns_records,
                        true,
                        edns_ctx.as_ref(),
                    ));
                }

                // ANAME resolution: if querying A/AAAA and there's an ANAME, resolve it
                if kind == RecordKind::A || kind == RecordKind::AAAA {
                    let aname_records =
                        self.db
                            .lookup_scoped(scope, &qname, Some(RecordKind::ANAME));
                    if !aname_records.is_empty() {
                        let target = &aname_records[0].value;
                        let target_records = self.db.lookup_scoped(scope, target, Some(kind));
                        if !target_records.is_empty() {
                            let dns_records: Vec<Record> = target_records
                                .iter()
                                .filter_map(|r| {
                                    let mut rec = db_record_to_dns_record(r)?;
                                    rec.set_name(Name::from_ascii(&qname).ok()?);
                                    Some(rec)
                                })
                                .collect();
                            return Ok(build_response_edns(
                                &message,
                                ResponseCode::NoError,
                                dns_records,
                                true,
                                edns_ctx.as_ref(),
                            ));
                        }
                    }
                }
            }

            // Check CNAME in scoped records
            if record_kind.is_some() {
                let cname_records = self
                    .db
                    .lookup_scoped(scope, &qname, Some(RecordKind::CNAME));
                if !cname_records.is_empty() {
                    let dns_records = cname_records
                        .iter()
                        .filter_map(db_record_to_dns_record)
                        .collect();
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NoError,
                        dns_records,
                        true,
                        edns_ctx.as_ref(),
                    ));
                }
            }

            // Check DNAME in scoped records (walk up labels)
            if let Some(dname_result) = self.check_dname_scoped(scope, &qname, qtype, &message) {
                return Ok(dname_result);
            }

            // Check if name falls under a scoped managed zone
            if let Ok(zones) = self.db.get_scoped_managed_zones(scope) {
                let normalized_qname = crate::db::normalize_name(&qname);
                for zone in &zones {
                    if normalized_qname.ends_with(zone) || normalized_qname == *zone {
                        let zone_records = self.db.lookup_scoped(scope, zone, None);
                        if !zone_records.is_empty() {
                            debug!(
                                "Scoped authoritative NXDOMAIN for {} (scope {} zone {} exists)",
                                qname, scope, zone
                            );
                            return Ok(build_response_edns(
                                &message,
                                ResponseCode::NXDomain,
                                vec![],
                                true,
                                edns_ctx.as_ref(),
                            ));
                        }
                    }
                }
            }

            // Fall through to global records and forwarding
        }

        // Check RBL for reverse DNS queries (global, non-scoped)
        if scope_name.is_none()
            && let Some(ip) = extract_ip_from_name(&qname)
            && (self.rbl.is_listed(&ip).await || self.db.lookup_local_rbl(&ip.to_string()))
        {
            debug!("RBL block: {} is blacklisted", qname);
            return Ok(build_response_edns(
                &message,
                ResponseCode::NXDomain,
                vec![],
                false,
                edns_ctx.as_ref(),
            ));
        }

        // Determine if this query is for an authoritative zone
        let is_authoritative = self.db.is_authoritative_zone(&qname);

        // Try local database first (split-horizon: local records take priority)
        // Uses a single UNION ALL query to fetch exact, wildcard, CNAME, and ANAME
        // results in one lock acquisition instead of 4+ separate queries.
        let record_kind = map_query_type_to_kind(qtype);
        if let Some(kind) = record_kind {
            // Check cache before hitting the database
            if let Some(ref cache) = self.dns_cache {
                let cached = cache.lookup(&qname, Some(kind));
                if !cached.is_empty() {
                    debug!(
                        "Cache hit (local) for {} {:?}: {} records",
                        qname,
                        qtype,
                        cached.len()
                    );
                    let dns_records = cached.iter().filter_map(db_record_to_dns_record).collect();
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NoError,
                        dns_records,
                        is_authoritative,
                        edns_ctx.as_ref(),
                    ));
                }
            }

            if let Ok(result) = self.db.lookup_with_fallbacks(&qname, kind) {
                // Priority: exact > wildcard > CNAME > ANAME
                let records = if !result.exact.is_empty() {
                    result.exact
                } else if !result.wildcard.is_empty() {
                    result.wildcard
                } else {
                    Vec::new()
                };

                if !records.is_empty() {
                    debug!(
                        "Local hit for {} {:?}: {} records",
                        qname,
                        qtype,
                        records.len()
                    );
                    if let Some(ref cache) = self.dns_cache {
                        cache.insert_local(&qname, Some(kind), records.clone());
                    }
                    let dns_records = records.iter().filter_map(db_record_to_dns_record).collect();
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NoError,
                        dns_records,
                        is_authoritative,
                        edns_ctx.as_ref(),
                    ));
                }

                // ANAME resolution: if querying A/AAAA and there's an ANAME, resolve it
                if (kind == RecordKind::A || kind == RecordKind::AAAA) && !result.aname.is_empty() {
                    let target = &result.aname[0].value;
                    if let Ok(target_records) = self.db.lookup(target, Some(kind))
                        && !target_records.is_empty()
                    {
                        let dns_records: Vec<Record> = target_records
                            .iter()
                            .filter_map(|r| {
                                let mut rec = db_record_to_dns_record(r)?;
                                rec.set_name(Name::from_ascii(&qname).ok()?);
                                Some(rec)
                            })
                            .collect();
                        return Ok(build_response_edns(
                            &message,
                            ResponseCode::NoError,
                            dns_records,
                            is_authoritative,
                            edns_ctx.as_ref(),
                        ));
                    }
                }

                // CNAME chain
                if !result.cname.is_empty() {
                    let dns_records = result
                        .cname
                        .iter()
                        .filter_map(db_record_to_dns_record)
                        .collect();
                    return Ok(build_response_edns(
                        &message,
                        ResponseCode::NoError,
                        dns_records,
                        is_authoritative,
                        edns_ctx.as_ref(),
                    ));
                }
            }
        }

        // Check DNAME (walk up labels checking for DNAME records, synthesize CNAME)
        if let Some(dname_result) = self.check_dname_global(&qname, qtype, &message) {
            return Ok(dname_result);
        }

        // Check if this name falls under a managed zone (O(labels) via DashSet lookup)
        if let Some(zone) = self.db.find_managed_zone(&qname) {
            let zone_records = self.db.lookup(&zone, None);
            if let Ok(records) = zone_records
                && !records.is_empty()
            {
                debug!(
                    "Authoritative NXDOMAIN for {} (zone {} exists)",
                    qname, zone
                );
                return Ok(build_response_edns(
                    &message,
                    ResponseCode::NXDomain,
                    vec![],
                    true,
                    edns_ctx.as_ref(),
                ));
            }
        }

        // Check explicit authoritative zones (O(labels) via DashSet lookup)
        if let Some(zone) = self.db.find_authoritative_zone(&qname) {
            debug!(
                "Authoritative NXDOMAIN for {} (authoritative zone {})",
                qname, zone
            );
            return Ok(build_response_edns(
                &message,
                ResponseCode::NXDomain,
                vec![],
                true,
                edns_ctx.as_ref(),
            ));
        }

        // Check DNS cache before forwarding upstream
        if let Some(ref cache) = self.dns_cache {
            let cached = cache.lookup(&qname, record_kind);
            if !cached.is_empty() {
                debug!(
                    "Cache hit for {} {:?}: {} records",
                    qname,
                    qtype,
                    cached.len()
                );
                let dns_records = cached.iter().filter_map(db_record_to_dns_record).collect();
                return Ok(build_response_edns(
                    &message,
                    ResponseCode::NoError,
                    dns_records,
                    false,
                    edns_ctx.as_ref(),
                ));
            }
        }

        // Forward to upstream resolvers
        let forward_result = self.forward_query(query_data).await;

        // DNS64 synthesis: if AAAA query returned no answers and dns64_prefix is set,
        // re-query for A and synthesize AAAA records by embedding IPv4 in the prefix
        if let Ok(ref response_bytes) = forward_result
            && qtype == RecordType::AAAA
            && let Some(prefix) = self.dns64_prefix
            && let Ok(fwd_msg) = hickory_proto::op::Message::from_bytes(response_bytes)
        {
            let has_aaaa = fwd_msg
                .answers()
                .iter()
                .any(|a| a.record_type() == RecordType::AAAA);
            if !has_aaaa {
                // Build an A query for the same name
                let a_query = build_query_for_type(&qname, RecordType::A, message.id());
                if let Ok(a_response_bytes) = self.forward_query(&a_query).await
                    && let Ok(a_msg) = hickory_proto::op::Message::from_bytes(&a_response_bytes)
                {
                    let synthesized: Vec<Record> = a_msg
                        .answers()
                        .iter()
                        .filter_map(|a_rec| {
                            if let RData::A(rdata::A(ipv4)) = a_rec.data() {
                                let synth_ipv6 = synthesize_dns64_address(&prefix, ipv4);
                                let name = a_rec.name().clone();
                                let mut rec = Record::from_rdata(
                                    name,
                                    a_rec.ttl(),
                                    RData::AAAA(rdata::AAAA(synth_ipv6)),
                                );
                                rec.set_dns_class(DNSClass::IN);
                                Some(rec)
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !synthesized.is_empty() {
                        debug!(
                            "DNS64 synthesized {} AAAA records for {}",
                            synthesized.len(),
                            qname
                        );
                        return Ok(build_response_edns(
                            &message,
                            ResponseCode::NoError,
                            synthesized,
                            false,
                            edns_ctx.as_ref(),
                        ));
                    }
                }
            }
        }

        forward_result
    }

    /// Checks for DNAME records in global database by walking up labels.
    /// RFC 6672: synthesize a CNAME from the DNAME.
    fn check_dname_global(
        &self,
        qname: &str,
        _qtype: RecordType,
        message: &hickory_proto::op::Message,
    ) -> Option<Vec<u8>> {
        let normalized = crate::db::normalize_name(qname);
        let parts: Vec<&str> = normalized.trim_end_matches('.').split('.').collect();
        // Walk up from qname, checking each parent for DNAME
        for i in 1..parts.len() {
            let parent = format!("{}.", parts[i..].join("."));
            if let Ok(dname_records) = self.db.lookup(&parent, Some(RecordKind::DNAME))
                && !dname_records.is_empty()
            {
                let dname_target = &dname_records[0].value;
                // Synthesize CNAME: replace parent suffix with dname target
                let prefix = parts[..i].join(".");
                let synth_target = format!("{}.{}", prefix, dname_target.trim_end_matches('.'));
                let synth_cname = crate::db::DnsRecord {
                    id: None,
                    name: normalized.clone(),
                    record_type: RecordKind::CNAME,
                    value: crate::db::normalize_name(&synth_target),
                    ttl: dname_records[0].ttl,
                    priority: 0,
                };
                let mut dns_records = Vec::new();
                // Add the DNAME record
                if let Some(dr) = db_record_to_dns_record(&dname_records[0]) {
                    dns_records.push(dr);
                }
                // Add the synthesized CNAME
                if let Some(cr) = db_record_to_dns_record(&synth_cname) {
                    dns_records.push(cr);
                }
                return Some(build_response_ex(
                    message,
                    ResponseCode::NoError,
                    dns_records,
                    true,
                ));
            }
        }
        None
    }

    /// Checks for DNAME records in scoped database by walking up labels.
    fn check_dname_scoped(
        &self,
        scope: &str,
        qname: &str,
        _qtype: RecordType,
        message: &hickory_proto::op::Message,
    ) -> Option<Vec<u8>> {
        let normalized = crate::db::normalize_name(qname);
        let parts: Vec<&str> = normalized.trim_end_matches('.').split('.').collect();
        for i in 1..parts.len() {
            let parent = format!("{}.", parts[i..].join("."));
            let dname_records = self
                .db
                .lookup_scoped(scope, &parent, Some(RecordKind::DNAME));
            if !dname_records.is_empty() {
                let dname_target = &dname_records[0].value;
                let prefix = parts[..i].join(".");
                let synth_target = format!("{}.{}", prefix, dname_target.trim_end_matches('.'));
                let synth_cname = crate::db::DnsRecord {
                    id: None,
                    name: normalized.clone(),
                    record_type: RecordKind::CNAME,
                    value: crate::db::normalize_name(&synth_target),
                    ttl: dname_records[0].ttl,
                    priority: 0,
                };
                let mut dns_records = Vec::new();
                if let Some(dr) = db_record_to_dns_record(&dname_records[0]) {
                    dns_records.push(dr);
                }
                if let Some(cr) = db_record_to_dns_record(&synth_cname) {
                    dns_records.push(cr);
                }
                return Some(build_response_ex(
                    message,
                    ResponseCode::NoError,
                    dns_records,
                    true,
                ));
            }
        }
        None
    }

    /// Forwards a DNS query to the configured upstream resolvers.
    async fn forward_query(&self, query_data: &[u8]) -> Result<Vec<u8>> {
        let forwarders = self.forwarders.load();
        if forwarders.is_empty() {
            return Ok(make_error_response(query_data, ResponseCode::ServFail));
        }

        let proxy = self.proxy_config.load();

        // Try each forwarder in order
        for forwarder in forwarders.iter() {
            let result = if let Some(ref proxy_cfg) = **proxy {
                // Forward through proxy (TCP tunneled)
                crate::doh_proxy::forward_via_proxy(query_data, forwarder, proxy_cfg).await
            } else {
                // Direct UDP forwarding
                self.forward_udp(query_data, forwarder).await
            };
            match result {
                Ok(response) => {
                    // Parse upstream response and insert into cache asynchronously
                    if let Some(ref cache) = self.dns_cache
                        && let Ok(upstream_msg) = hickory_proto::op::Message::from_bytes(&response)
                        && upstream_msg.response_code() == ResponseCode::NoError
                        && !upstream_msg.answers().is_empty()
                    {
                        let answers = upstream_msg.answers();
                        // Use the first answer's name and type as cache key
                        if let Some(first) = answers.first() {
                            let name = first.name().to_string();
                            let rtype = first.record_type();
                            let kind = map_query_type_to_kind(rtype);
                            let ttl = answers.iter().map(|a| a.ttl()).min().unwrap_or(300);
                            let cache_records: Vec<crate::db::DnsRecord> =
                                answers.iter().filter_map(dns_record_to_db_record).collect();
                            if !cache_records.is_empty() {
                                cache.insert(&name, kind, cache_records, ttl);
                            }
                        }
                    }
                    return Ok(response);
                }
                Err(e) => {
                    warn!("Forward to {} failed: {}", forwarder, e);
                    continue;
                }
            }
        }

        Ok(make_error_response(query_data, ResponseCode::ServFail))
    }

    async fn forward_udp(&self, query_data: &[u8], target: &SocketAddr) -> Result<Vec<u8>> {
        // Acquire a socket from the pool (round-robin)
        let idx = self.forward_socket_idx.fetch_add(1, Ordering::Relaxed) % FORWARD_POOL_SIZE;
        let mut socket_guard = self.forward_sockets[idx].lock().await;
        // Lazily bind the socket on first use
        if socket_guard.is_none() {
            *socket_guard = Some(UdpSocket::bind("0.0.0.0:0").await?);
        }
        let socket = socket_guard
            .as_ref()
            .context("forward socket not initialized after bind")?;

        // Apply QNAME case randomization (0x20 encoding) if enabled
        let (send_data, randomized_name) = if self.qname_randomization {
            match randomize_qname_case(query_data) {
                Some((modified, original_qname, rand_name)) => {
                    (modified, Some((original_qname, rand_name)))
                }
                None => (query_data.to_vec(), None),
            }
        } else {
            (query_data.to_vec(), None)
        };

        socket.send_to(&send_data, target).await?;

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let timeout =
            tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv(&mut buf));
        let len = timeout
            .await
            .context("forwarder timeout")?
            .context("forwarder recv error")?;
        buf.truncate(len);
        // Release the socket back to the pool
        drop(socket_guard);

        // Verify QNAME case in response matches what we sent (0x20 check)
        if let Some((ref original_qname, ref sent_randomized)) = randomized_name
            && let Ok(response_msg) = hickory_proto::op::Message::from_bytes(&buf)
            && let Some(resp_q) = response_msg.queries().first()
        {
            let resp_qname = resp_q.name().to_string();
            if resp_qname != *sent_randomized {
                warn!(
                    "QNAME case mismatch from {}: sent '{}', got '{}' (original: '{}')",
                    target, sent_randomized, resp_qname, original_qname
                );
            }
        }

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
        RecordType::TLSA => Some(RecordKind::TLSA),
        RecordType::CERT => Some(RecordKind::CERT),
        RecordType::SSHFP => Some(RecordKind::SSHFP),
        RecordType::DNSKEY => Some(RecordKind::DNSKEY),
        RecordType::RRSIG => Some(RecordKind::RRSIG),
        RecordType::NSEC => Some(RecordKind::NSEC),
        RecordType::NSEC3 => Some(RecordKind::NSEC3),
        RecordType::NSEC3PARAM => Some(RecordKind::NSEC3PARAM),
        _ => {
            // Handle types that hickory may not have direct variants for
            let code: u16 = rt.into();
            match code {
                256 => Some(RecordKind::URI),     // URI (RFC 7553)
                39 => Some(RecordKind::DNAME),    // DNAME (RFC 6672)
                43 => Some(RecordKind::DS),       // DS
                63 => Some(RecordKind::ZONEMD),   // ZONEMD (RFC 9156)
                65305 => Some(RecordKind::ANAME), // ANAME (draft)
                _ => None,
            }
        }
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
        RecordKind::DNAME => {
            // DNAME is type 39 but hickory doesn't have a native DNAME variant.
            // We use ANAME's structure since it's also a name-pointing record.
            let target = Name::from_ascii(&db_rec.value).ok()?;
            // Build as CNAME format but the record type in the wire format
            // will be set based on what the caller specifies. For DNAME synthesis
            // purposes, we primarily use this for internal lookup.
            RData::CNAME(rdata::CNAME(target))
        }
        RecordKind::SSHFP => {
            // SSHFP: "algorithm fp_type hex_fingerprint"
            let parts: Vec<&str> = db_rec.value.split_whitespace().collect();
            if parts.len() >= 3 {
                let algorithm: rdata::sshfp::Algorithm = parts[0].parse::<u8>().ok()?.into();
                let fp_type: rdata::sshfp::FingerprintType = parts[1].parse::<u8>().ok()?.into();
                let fingerprint = hex::decode(parts[2]).ok()?;
                RData::SSHFP(rdata::SSHFP::new(algorithm, fp_type, fingerprint))
            } else {
                return None;
            }
        }
        RecordKind::URI | RecordKind::ZONEMD | RecordKind::ANAME => {
            // These types are stored as TXT-like opaque data in DNS wire format.
            // We encode them as a TXT record containing the raw value.
            // The actual wire encoding differs, but for now we serve them as
            // unknown/opaque RData via the record value string.
            RData::TXT(rdata::TXT::new(vec![db_rec.value.clone()]))
        }
        RecordKind::TLSA => {
            // TLSA: "usage selector matching_type hex_data"
            let parts: Vec<&str> = db_rec.value.split_whitespace().collect();
            if parts.len() >= 4 {
                let usage: u8 = parts[0].parse().ok()?;
                let selector: u8 = parts[1].parse().ok()?;
                let matching_type: u8 = parts[2].parse().ok()?;
                let cert_data = hex::decode(parts[3]).ok()?;
                RData::TLSA(rdata::TLSA::new(
                    hickory_proto::rr::rdata::tlsa::CertUsage::from(usage),
                    hickory_proto::rr::rdata::tlsa::Selector::from(selector),
                    hickory_proto::rr::rdata::tlsa::Matching::from(matching_type),
                    cert_data,
                ))
            } else {
                return None;
            }
        }
        RecordKind::CERT => {
            // CERT (RFC 4398): "cert_type key_tag algorithm base64_cert_data"
            let parts: Vec<&str> = db_rec.value.split_whitespace().collect();
            if parts.len() >= 4 {
                let cert_type: u16 = parts[0].parse().ok()?;
                let key_tag: u16 = parts[1].parse().ok()?;
                let algorithm: u8 = parts[2].parse().ok()?;
                let cert_data =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, parts[3])
                        .ok()?;
                RData::CERT(rdata::CERT::new(
                    hickory_proto::rr::rdata::cert::CertType::from(cert_type),
                    key_tag,
                    hickory_proto::rr::rdata::cert::Algorithm::from(algorithm),
                    cert_data,
                ))
            } else {
                return None;
            }
        }
        RecordKind::DNSKEY
        | RecordKind::DS
        | RecordKind::RRSIG
        | RecordKind::NSEC
        | RecordKind::NSEC3
        | RecordKind::NSEC3PARAM => {
            // DNSSEC records: stored as opaque TXT for now, proper wire format
            // will be handled by the DNSSEC module when signing
            RData::TXT(rdata::TXT::new(vec![db_rec.value.clone()]))
        }
    };

    let mut record = Record::from_rdata(name, db_rec.ttl, rdata);
    record.set_dns_class(DNSClass::IN);
    Some(record)
}

/// Builds a DNS response message (without EDNS).
#[cfg(test)]
fn build_response(
    query: &hickory_proto::op::Message,
    rcode: ResponseCode,
    answers: Vec<Record>,
) -> Vec<u8> {
    build_response_ex(query, rcode, answers, false)
}

/// Builds a DNS response message with optional authoritative flag.
fn build_response_ex(
    query: &hickory_proto::op::Message,
    rcode: ResponseCode,
    answers: Vec<Record>,
    authoritative: bool,
) -> Vec<u8> {
    let mut response = hickory_proto::op::Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(rcode);
    response.set_recursion_desired(query.recursion_desired());
    response.set_recursion_available(true);
    response.set_authoritative(authoritative);

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

/// Builds a DNS response with EDNS OPT record if EDNS was present in the query.
fn build_response_edns(
    query: &hickory_proto::op::Message,
    rcode: ResponseCode,
    answers: Vec<Record>,
    authoritative: bool,
    edns_ctx: Option<&crate::edns::EdnsContext>,
) -> Vec<u8> {
    let mut response = hickory_proto::op::Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(rcode);
    response.set_recursion_desired(query.recursion_desired());
    response.set_recursion_available(true);
    response.set_authoritative(authoritative);

    // Copy the question section
    for q in query.queries() {
        response.add_query(q.clone());
    }

    for answer in answers {
        response.add_answer(answer);
    }

    // If the query included EDNS, add OPT record to the response
    if let Some(ctx) = edns_ctx {
        crate::edns::add_edns_to_response(&mut response, ctx.max_payload, ctx.dnssec_ok);
    }

    response.to_bytes().unwrap_or_default()
}

/// Builds a DNS query message for a specific record type (used for DNS64 A re-query).
fn build_query_for_type(name: &str, qtype: RecordType, id: u16) -> Vec<u8> {
    let mut msg = hickory_proto::op::Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);

    let mut query = hickory_proto::op::Query::new();
    if let Ok(n) = Name::from_ascii(name) {
        query.set_name(n);
    }
    query.set_query_type(qtype);
    query.set_query_class(DNSClass::IN);
    msg.add_query(query);

    msg.to_bytes().unwrap_or_default()
}

/// Synthesizes a DNS64 IPv6 address by embedding an IPv4 address in the prefix.
/// Uses the well-known prefix format (RFC 6052): prefix::/96 with IPv4 in last 32 bits.
fn synthesize_dns64_address(prefix: &Ipv6Addr, ipv4: &Ipv4Addr) -> Ipv6Addr {
    let mut octets = prefix.octets();
    let v4_octets = ipv4.octets();
    // Embed IPv4 in the last 4 bytes (bits 96-127) of the IPv6 address
    octets[12] = v4_octets[0];
    octets[13] = v4_octets[1];
    octets[14] = v4_octets[2];
    octets[15] = v4_octets[3];
    Ipv6Addr::from(octets)
}

/// Extracts a DNS QNAME from wire-format label encoding into a dotted string.
fn extract_qname(data: &[u8]) -> Option<String> {
    let mut name = String::with_capacity(64);
    let mut pos = 0;
    loop {
        if pos >= data.len() {
            return None;
        }
        let label_len = data[pos] as usize;
        if label_len == 0 {
            break;
        }
        if pos + 1 + label_len > data.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        for i in 1..=label_len {
            name.push(data[pos + i] as char);
        }
        pos += label_len + 1;
    }
    name.push('.');
    Some(name)
}

/// Randomizes the case of the QNAME in a DNS query for 0x20 encoding.
/// Returns (modified_bytes, original_qname, randomized_qname), or None if parsing fails.
///
/// Operates directly on DNS wire-format bytes for efficiency: the QNAME starts
/// at byte offset 12 (after the 12-byte DNS header) and uses label encoding
/// (length byte followed by ASCII label bytes). Case is toggled in-place by
/// flipping the 0x20 bit on ASCII alphabetic bytes.
pub fn randomize_qname_case(query_data: &[u8]) -> Option<(Vec<u8>, String, String)> {
    // DNS header is 12 bytes; need at least header + 1 byte for QNAME
    if query_data.len() < 13 {
        return None;
    }

    let original_name = extract_qname(&query_data[12..])?;
    let mut modified = Vec::with_capacity(query_data.len());
    modified.extend_from_slice(query_data);

    let mut rng = rand::rng();
    let mut pos = 12;
    loop {
        if pos >= modified.len() {
            return None;
        }
        let label_len = modified[pos] as usize;
        if label_len == 0 {
            break;
        }
        if pos + 1 + label_len > modified.len() {
            return None;
        }
        for i in 1..=label_len {
            if modified[pos + i].is_ascii_alphabetic() && rng.random_bool(0.5) {
                modified[pos + i] ^= 0x20;
            }
        }
        pos += label_len + 1;
    }

    let randomized_name = extract_qname(&modified[12..])?;
    Some((modified, original_name, randomized_name))
}

/// Converts a hickory DNS Record to a database DnsRecord (for cache insertion).
fn dns_record_to_db_record(record: &Record) -> Option<crate::db::DnsRecord> {
    let name = record.name().to_string();
    let ttl = record.ttl();
    let (record_type, value, priority) = match record.data() {
        RData::A(rdata::A(ip)) => (RecordKind::A, ip.to_string(), 0u32),
        RData::AAAA(rdata::AAAA(ip)) => (RecordKind::AAAA, ip.to_string(), 0u32),
        RData::CNAME(rdata::CNAME(target)) => (RecordKind::CNAME, target.to_string(), 0u32),
        RData::MX(mx) => (
            RecordKind::MX,
            mx.exchange().to_string(),
            mx.preference() as u32,
        ),
        RData::TXT(txt) => {
            let value = txt
                .iter()
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>()
                .join("");
            (RecordKind::TXT, value, 0u32)
        }
        RData::NS(rdata::NS(target)) => (RecordKind::NS, target.to_string(), 0u32),
        RData::PTR(rdata::PTR(target)) => (RecordKind::PTR, target.to_string(), 0u32),
        _ => return None,
    };

    Some(crate::db::DnsRecord {
        id: None,
        name,
        record_type,
        value,
        ttl,
        priority,
    })
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
        let name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.";
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
        assert_eq!(
            map_query_type_to_kind(RecordType::CERT),
            Some(RecordKind::CERT)
        );
    }

    #[test]
    fn test_db_record_to_dns_record_cert() {
        // CERT (RFC 4398): "cert_type key_tag algorithm base64_cert_data"
        let payload = b"fake der bytes";
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, payload);
        let db_rec = DnsRecord {
            id: None,
            name: "_ca.example.com.".to_string(),
            record_type: RecordKind::CERT,
            value: format!("1 0 0 {}", b64),
            ttl: 3600,
            priority: 0,
        };
        let rec = db_record_to_dns_record(&db_rec).expect("CERT record");
        assert_eq!(rec.record_type(), RecordType::CERT);
        match rec.data() {
            RData::CERT(cert) => {
                assert_eq!(u16::from(cert.cert_type()), 1); // PKIX
                assert_eq!(cert.key_tag(), 0);
                assert_eq!(u8::from(cert.algorithm()), 0);
                assert_eq!(cert.cert_data(), payload);
            }
            other => panic!("expected CERT rdata, got {:?}", other),
        }
    }

    #[test]
    fn test_db_record_to_dns_record_cert_malformed() {
        let db_rec = DnsRecord {
            id: None,
            name: "_ca.example.com.".to_string(),
            record_type: RecordKind::CERT,
            value: "1 0 0 not!base64!".to_string(),
            ttl: 3600,
            priority: 0,
        };
        assert!(db_record_to_dns_record(&db_rec).is_none());
        let too_short = DnsRecord {
            value: "1 0 0".to_string(),
            ..db_rec
        };
        assert!(db_record_to_dns_record(&too_short).is_none());
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

    // ================================================================
    // Network Scoping Tests
    // ================================================================

    use crate::db::{NetworkAssociation, NetworkScope};

    #[tokio::test]
    async fn test_scoped_record_lookup() {
        let db = Database::open_memory().unwrap();

        // Create a scope and add a scoped record
        db.create_network_scope(&NetworkScope {
            name: "testnet".to_string(),
            home_domain: "testnet.home".to_string(),
        })
        .unwrap();

        db.add_scoped_record(
            "testnet",
            &DnsRecord {
                id: None,
                name: "server.testnet.home.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        // Associate an IP with the scope
        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.50".to_string(),
            scope_name: "testnet".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("server.testnet.home.", RecordType::A);
        let response_bytes = server
            .handle_query_from(&query, "192.168.1.50".parse().unwrap())
            .await
            .unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        if let RData::A(rdata::A(ip)) = response.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 1));
        } else {
            panic!("expected A record");
        }
    }

    #[tokio::test]
    async fn test_unassociated_ip_refused_when_scopes_exist() {
        let db = Database::open_memory().unwrap();

        // Create a scope but don't associate the querying IP
        db.create_network_scope(&NetworkScope {
            name: "private".to_string(),
            home_domain: "private.home".to_string(),
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("anything.com.", RecordType::A);
        let response_bytes = server
            .handle_query_from(&query, "192.168.1.99".parse().unwrap())
            .await
            .unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::Refused);
    }

    #[tokio::test]
    async fn test_no_scopes_allows_all_queries() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "open.test.".to_string(),
            record_type: RecordKind::A,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("open.test.", RecordType::A);
        let response_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_scoped_records_isolated_between_scopes() {
        let db = Database::open_memory().unwrap();

        // Create two scopes with different views
        db.create_network_scope(&NetworkScope {
            name: "scope_a".to_string(),
            home_domain: "a.home".to_string(),
        })
        .unwrap();
        db.create_network_scope(&NetworkScope {
            name: "scope_b".to_string(),
            home_domain: "b.home".to_string(),
        })
        .unwrap();

        // Same name, different values per scope
        db.add_scoped_record(
            "scope_a",
            &DnsRecord {
                id: None,
                name: "shared.internal.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();
        db.add_scoped_record(
            "scope_b",
            &DnsRecord {
                id: None,
                name: "shared.internal.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.2".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        // Associate IPs
        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.1".to_string(),
            scope_name: "scope_a".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();
        db.join_network(&NetworkAssociation {
            ip_address: "192.168.2.1".to_string(),
            scope_name: "scope_b".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("shared.internal.", RecordType::A);

        // Query from scope_a IP
        let resp_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        if let RData::A(rdata::A(ip)) = resp.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 1));
        }

        // Query from scope_b IP
        let resp_bytes = server
            .handle_query_from(&query, "192.168.2.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        if let RData::A(rdata::A(ip)) = resp.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 2));
        }
    }

    #[tokio::test]
    async fn test_scoped_rbl_blocks_reverse_dns() {
        let db = Database::open_memory().unwrap();

        db.create_network_scope(&NetworkScope {
            name: "rblscope".to_string(),
            home_domain: "rblscope.home".to_string(),
        })
        .unwrap();
        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.1".to_string(),
            scope_name: "rblscope".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server_with_rbl(db, true);
        let query = build_query("100.1.168.192.in-addr.arpa.", RecordType::PTR);
        let resp_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn test_scoped_cname_lookup() {
        let db = Database::open_memory().unwrap();

        db.create_network_scope(&NetworkScope {
            name: "cnamescope".to_string(),
            home_domain: "cnamescope.home".to_string(),
        })
        .unwrap();

        db.add_scoped_record(
            "cnamescope",
            &DnsRecord {
                id: None,
                name: "alias.cnamescope.home.".to_string(),
                record_type: RecordKind::CNAME,
                value: "real.cnamescope.home.".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.1".to_string(),
            scope_name: "cnamescope".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("alias.cnamescope.home.", RecordType::A);
        let resp_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();

        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_scoped_managed_zone_nxdomain() {
        let db = Database::open_memory().unwrap();

        db.create_network_scope(&NetworkScope {
            name: "zonescope".to_string(),
            home_domain: "zonescope.home".to_string(),
        })
        .unwrap();

        // Add a record at the zone level to make it authoritative
        db.add_scoped_record(
            "zonescope",
            &DnsRecord {
                id: None,
                name: "zonescope.home.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        // Also add a record under the zone
        db.add_scoped_record(
            "zonescope",
            &DnsRecord {
                id: None,
                name: "existing.zonescope.home.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.2".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.1".to_string(),
            scope_name: "zonescope".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server(db);

        // Query for a known name should succeed
        let query = build_query("existing.zonescope.home.", RecordType::A);
        let resp_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);

        // Query for a non-existent name under the scoped managed zone
        let query = build_query("nonexistent.zonescope.home.", RecordType::A);
        let resp_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();

        // Should get authoritative NXDOMAIN since the zone exists but name doesn't
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn test_expired_association_refused() {
        let db = Database::open_memory().unwrap();

        db.create_network_scope(&NetworkScope {
            name: "expirenet".to_string(),
            home_domain: "expirenet.home".to_string(),
        })
        .unwrap();

        db.add_scoped_record(
            "expirenet",
            &DnsRecord {
                id: None,
                name: "host.expirenet.home.".to_string(),
                record_type: RecordKind::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            },
        )
        .unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.1".to_string(),
            scope_name: "expirenet".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server(db.clone());

        // Should resolve while association is active
        let query = build_query("host.expirenet.home.", RecordType::A);
        let resp_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);

        // Expire the association cache entry
        db.expire_association("192.168.1.1");

        // Should get REFUSED after association expires
        let resp_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::Refused);
    }

    #[tokio::test]
    async fn test_scoped_query_falls_through_to_global() {
        let db = Database::open_memory().unwrap();

        db.create_network_scope(&NetworkScope {
            name: "fallthrough".to_string(),
            home_domain: "fallthrough.home".to_string(),
        })
        .unwrap();

        // Add a global record (not scoped)
        db.add_record(&DnsRecord {
            id: None,
            name: "global.test.".to_string(),
            record_type: RecordKind::A,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        db.join_network(&NetworkAssociation {
            ip_address: "192.168.1.1".to_string(),
            scope_name: "fallthrough".to_string(),
            ttl_seconds: 3600,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("global.test.", RecordType::A);
        let resp_bytes = server
            .handle_query_from(&query, "192.168.1.1".parse().unwrap())
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();

        // Should still resolve global records even when in a scope
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
    }

    // ================================================================
    // extract_qname tests
    // ================================================================

    #[test]
    fn test_extract_qname_simple() {
        // "example.com." in wire format: \x07example\x03com\x00
        let data = b"\x07example\x03com\x00";
        assert_eq!(extract_qname(data).unwrap(), "example.com.");
    }

    #[test]
    fn test_extract_qname_subdomain() {
        // "sub.example.com." in wire format
        let data = b"\x03sub\x07example\x03com\x00";
        assert_eq!(extract_qname(data).unwrap(), "sub.example.com.");
    }

    #[test]
    fn test_extract_qname_single_label() {
        let data = b"\x03com\x00";
        assert_eq!(extract_qname(data).unwrap(), "com.");
    }

    #[test]
    fn test_extract_qname_empty() {
        // Root label only
        let data = b"\x00";
        assert_eq!(extract_qname(data).unwrap(), ".");
    }

    #[test]
    fn test_extract_qname_truncated() {
        // Label says 7 bytes but only 3 follow
        let data = b"\x07exa";
        assert!(extract_qname(data).is_none());
    }

    #[test]
    fn test_extract_qname_empty_input() {
        assert!(extract_qname(b"").is_none());
    }

    // ================================================================
    // randomize_qname_case tests
    // ================================================================

    #[test]
    fn test_randomize_qname_case_preserves_structure() {
        let query = build_query("example.com.", RecordType::A);
        let result = randomize_qname_case(&query);
        assert!(result.is_some());
        let (modified, original, _randomized) = result.unwrap();

        // Original name should be correct
        assert_eq!(original.to_lowercase(), "example.com.");

        // Modified bytes should be valid DNS and same length
        assert_eq!(modified.len(), query.len());

        // Should parse as a valid DNS message
        let msg = Message::from_bytes(&modified).unwrap();
        assert_eq!(msg.id(), 1234);
        assert_eq!(msg.queries().len(), 1);
    }

    #[test]
    fn test_randomize_qname_case_only_changes_alpha() {
        let query = build_query("test-123.example.com.", RecordType::A);
        // Run many times to exercise randomness
        for _ in 0..20 {
            if let Some((modified, _, _)) = randomize_qname_case(&query) {
                // DNS header (12 bytes) should be identical
                assert_eq!(&modified[..12], &query[..12]);

                // Non-alpha bytes in labels should be unchanged
                // Walk labels and check digits/hyphens
                let mut pos = 12;
                while pos < modified.len() {
                    let label_len = modified[pos] as usize;
                    if label_len == 0 {
                        break;
                    }
                    // Label length byte unchanged
                    assert_eq!(modified[pos], query[pos]);
                    for i in 1..=label_len {
                        let orig = query[pos + i];
                        let modif = modified[pos + i];
                        if !orig.is_ascii_alphabetic() {
                            // Non-alpha bytes must be unchanged
                            assert_eq!(modif, orig);
                        } else {
                            // Alpha bytes should differ only by case bit
                            assert_eq!(modif.to_ascii_lowercase(), orig.to_ascii_lowercase());
                        }
                    }
                    pos += label_len + 1;
                }
            }
        }
    }

    #[test]
    fn test_randomize_qname_case_too_short() {
        assert!(randomize_qname_case(b"").is_none());
        assert!(randomize_qname_case(b"short").is_none());
        assert!(randomize_qname_case(&[0u8; 12]).is_none());
    }

    #[test]
    fn test_randomize_qname_case_round_trip_names() {
        let query = build_query("My.DnS.Name.", RecordType::AAAA);
        let (_, original, randomized) = randomize_qname_case(&query).unwrap();
        // Both should normalize to the same lowercase name
        assert_eq!(original.to_lowercase(), randomized.to_lowercase());
    }

    // ================================================================
    // lookup_with_fallbacks integration tests
    // ================================================================

    #[tokio::test]
    async fn test_lookup_with_fallbacks_exact_hit() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "exact.example.com.".to_string(),
            record_type: RecordKind::A,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("exact.example.com.", RecordType::A);
        let resp_bytes = server.handle_query(&query).await.unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_lookup_with_fallbacks_cname_fallback() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "alias.example.com.".to_string(),
            record_type: RecordKind::CNAME,
            value: "target.example.com.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("alias.example.com.", RecordType::A);
        let resp_bytes = server.handle_query(&query).await.unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_lookup_with_fallbacks_aname_resolution() {
        let db = Database::open_memory().unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "aname.example.com.".to_string(),
            record_type: RecordKind::ANAME,
            value: "target.example.com.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "target.example.com.".to_string(),
            record_type: RecordKind::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("aname.example.com.", RecordType::A);
        let resp_bytes = server.handle_query(&query).await.unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        if let RData::A(rdata::A(ip)) = resp.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 1));
        } else {
            panic!("expected A record");
        }
    }

    #[tokio::test]
    async fn test_lookup_with_fallbacks_exact_over_cname() {
        let db = Database::open_memory().unwrap();
        // Both exact A and CNAME exist - exact should win
        db.add_record(&DnsRecord {
            id: None,
            name: "both.example.com.".to_string(),
            record_type: RecordKind::A,
            value: "1.1.1.1".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();
        db.add_record(&DnsRecord {
            id: None,
            name: "both.example.com.".to_string(),
            record_type: RecordKind::CNAME,
            value: "other.example.com.".to_string(),
            ttl: 300,
            priority: 0,
        })
        .unwrap();

        let server = make_test_server(db);
        let query = build_query("both.example.com.", RecordType::A);
        let resp_bytes = server.handle_query(&query).await.unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        // Should get the A record, not the CNAME
        if let RData::A(rdata::A(ip)) = resp.answers()[0].data() {
            assert_eq!(*ip, Ipv4Addr::new(1, 1, 1, 1));
        } else {
            panic!("expected A record, not CNAME");
        }
    }
}
