//! Iterative DNS resolver.
//!
//! Resolves names by walking the delegation chain starting at the root
//! name servers — querying a root, following the NS referral to the TLD
//! servers, then to the authoritative servers for the zone, until an
//! answer (or an authoritative negative response) is obtained. This is an
//! alternative to forwarding queries to a recursive upstream resolver and
//! is the default resolution mode.
//!
//! Queries are sent with the recursion-desired bit cleared (iterative
//! mode). Responses are validated by transaction id and question name to
//! resist off-path spoofing. UDP is used first, with automatic TCP
//! fallback when a response is truncated.

use anyhow::{Context, Result, bail};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rand::Rng;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

/// Maximum UDP DNS message size we are willing to receive.
const MAX_UDP_SIZE: usize = 4096;
/// Per-nameserver query timeout.
const DEFAULT_QUERY_TIMEOUT_SECS: u64 = 5;
/// Maximum number of delegation hops within a single name resolution.
const MAX_REFERRALS: usize = 30;
/// Maximum number of CNAME indirections we will follow.
const MAX_CNAME_CHAIN: usize = 16;
/// Maximum recursion depth (CNAME chasing + glue-less NS resolution).
const MAX_RESOLUTION_DEPTH: u32 = 16;
/// Maximum number of NS targets to try when resolving a glue-less delegation.
const MAX_GLUELESS_NS: usize = 4;

/// The IANA root server IPv4 addresses (the "root hints").
///
/// IPv4 only: every host that can reach the internet can reach these, and
/// using a single address family avoids stalling on IPv6 servers from a
/// host without IPv6 connectivity. Glue and glue-less resolution may still
/// yield IPv6 authoritative servers, which are tried opportunistically.
pub const ROOT_HINTS: [IpAddr; 13] = [
    IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), // a.root-servers.net
    IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)), // b.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 33, 4, 12)), // c.root-servers.net
    IpAddr::V4(Ipv4Addr::new(199, 7, 91, 13)), // d.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 203, 230, 10)), // e.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 5, 5, 241)), // f.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 112, 36, 4)), // g.root-servers.net
    IpAddr::V4(Ipv4Addr::new(198, 97, 190, 53)), // h.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 36, 148, 17)), // i.root-servers.net
    IpAddr::V4(Ipv4Addr::new(192, 58, 128, 30)), // j.root-servers.net
    IpAddr::V4(Ipv4Addr::new(193, 0, 14, 129)), // k.root-servers.net
    IpAddr::V4(Ipv4Addr::new(199, 7, 83, 42)), // l.root-servers.net
    IpAddr::V4(Ipv4Addr::new(202, 12, 27, 33)), // m.root-servers.net
];

/// The result of an iterative resolution: the final response code and the
/// accumulated answer records (including any CNAME chain that was followed).
#[derive(Debug, Clone)]
pub struct Resolution {
    pub rcode: ResponseCode,
    pub answers: Vec<Record>,
}

/// Classification of a single nameserver response relative to the query.
#[derive(Debug)]
enum Step {
    /// A usable answer (the requested type, or terminal records).
    Answer(Vec<Record>),
    /// A CNAME pointing elsewhere; resolution must continue at `target`.
    Cname { target: Name, records: Vec<Record> },
    /// A delegation to a more specific zone.
    Referral {
        zone: Name,
        glue: Vec<IpAddr>,
        ns_targets: Vec<Name>,
    },
    /// An authoritative negative response (NXDOMAIN or NODATA).
    Negative(ResponseCode),
}

/// An iterative resolver that resolves names from the root servers down.
#[derive(Debug, Clone)]
pub struct IterativeResolver {
    root_hints: Vec<IpAddr>,
    timeout: Duration,
    /// Port used to reach nameservers (always 53 in production; overridable
    /// for tests).
    port: u16,
}

impl IterativeResolver {
    /// Creates a resolver using the given root hints, falling back to the
    /// built-in [`ROOT_HINTS`] when the list is empty.
    pub fn new(root_hints: Vec<IpAddr>) -> Self {
        let root_hints = if root_hints.is_empty() {
            ROOT_HINTS.to_vec()
        } else {
            root_hints
        };
        Self {
            root_hints,
            timeout: Duration::from_secs(DEFAULT_QUERY_TIMEOUT_SECS),
            port: 53,
        }
    }

    /// Creates a resolver using the built-in root hints.
    pub fn with_defaults() -> Self {
        Self::new(Vec::new())
    }

    /// Overrides the per-nameserver query timeout (used by tests).
    #[cfg(test)]
    fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Overrides the nameserver port (used by tests).
    #[cfg(test)]
    fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Resolves `name`/`qtype` iteratively from the root servers.
    pub async fn resolve(
        &self,
        name: &Name,
        qtype: RecordType,
        qclass: DNSClass,
    ) -> Result<Resolution> {
        let mut cname_seen: Vec<Name> = Vec::new();
        self.resolve_inner(name, qtype, qclass, 0, &mut cname_seen)
            .await
    }

    async fn resolve_inner(
        &self,
        name: &Name,
        qtype: RecordType,
        qclass: DNSClass,
        depth: u32,
        cname_seen: &mut Vec<Name>,
    ) -> Result<Resolution> {
        if depth > MAX_RESOLUTION_DEPTH {
            bail!("maximum resolution depth exceeded resolving {}", name);
        }

        let mut servers = self.root_hints.clone();
        let mut visited_zones: HashSet<String> = HashSet::new();

        for _hop in 0..MAX_REFERRALS {
            let response = self.query_servers(&servers, name, qtype, qclass).await?;

            match classify(&response, qtype) {
                Step::Answer(records) => {
                    return Ok(Resolution {
                        rcode: response.response_code(),
                        answers: records,
                    });
                }
                Step::Cname { target, records } => {
                    if cname_seen.iter().any(|n| n == &target) {
                        bail!("CNAME loop detected at {}", target);
                    }
                    if cname_seen.len() >= MAX_CNAME_CHAIN {
                        bail!("CNAME chain too long resolving {}", name);
                    }
                    cname_seen.push(target.clone());
                    let mut accumulated = records;
                    let sub =
                        Box::pin(self.resolve_inner(&target, qtype, qclass, depth + 1, cname_seen))
                            .await?;
                    accumulated.extend(sub.answers);
                    return Ok(Resolution {
                        rcode: sub.rcode,
                        answers: accumulated,
                    });
                }
                Step::Negative(rcode) => {
                    return Ok(Resolution {
                        rcode,
                        answers: Vec::new(),
                    });
                }
                Step::Referral {
                    zone,
                    glue,
                    ns_targets,
                } => {
                    let zone_key = zone.to_ascii().to_lowercase();
                    if !visited_zones.insert(zone_key) {
                        bail!("delegation loop at zone {} resolving {}", zone, name);
                    }
                    servers = if !glue.is_empty() {
                        glue
                    } else {
                        self.resolve_ns_addresses(&ns_targets, qclass, depth + 1)
                            .await?
                    };
                    if servers.is_empty() {
                        bail!("no reachable nameservers for delegation of {}", zone);
                    }
                }
            }
        }

        bail!("too many referrals resolving {}", name)
    }

    /// Resolves the addresses of glue-less delegation nameservers.
    async fn resolve_ns_addresses(
        &self,
        ns_targets: &[Name],
        qclass: DNSClass,
        depth: u32,
    ) -> Result<Vec<IpAddr>> {
        let mut addrs = Vec::new();
        for ns in ns_targets.iter().take(MAX_GLUELESS_NS) {
            let mut seen = Vec::new();
            if let Ok(res) =
                Box::pin(self.resolve_inner(ns, RecordType::A, qclass, depth, &mut seen)).await
            {
                for record in &res.answers {
                    if let RData::A(rdata::A(ip)) = record.data() {
                        addrs.push(IpAddr::V4(*ip));
                    }
                }
            }
            if !addrs.is_empty() {
                break;
            }
        }
        Ok(addrs)
    }

    /// Sends the query to each server in turn, returning the first valid response.
    async fn query_servers(
        &self,
        servers: &[IpAddr],
        name: &Name,
        qtype: RecordType,
        qclass: DNSClass,
    ) -> Result<Message> {
        let (query, id) = build_query(name, qtype, qclass)?;
        for server in servers {
            match self.query_one(*server, &query, id, name).await {
                Ok(msg) => return Ok(msg),
                Err(e) => {
                    debug!("query for {} to {} failed: {}", name, server, e);
                    continue;
                }
            }
        }
        bail!("all nameservers failed for {}", name)
    }

    /// Sends a single query over UDP (falling back to TCP on truncation) and
    /// validates the response transaction id and question name.
    async fn query_one(
        &self,
        server: IpAddr,
        query: &[u8],
        id: u16,
        qname: &Name,
    ) -> Result<Message> {
        let target = SocketAddr::new(server, self.port);
        let bind = if server.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.send_to(query, target).await?;

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let len = tokio::time::timeout(self.timeout, socket.recv(&mut buf))
            .await
            .context("nameserver timeout")?
            .context("nameserver recv error")?;
        buf.truncate(len);

        let msg = Message::from_bytes(&buf)?;
        if msg.id() != id {
            bail!("response id mismatch from {}", server);
        }
        if msg.truncated() {
            return self.query_tcp(target, query, id, qname).await;
        }
        validate_question(&msg, qname)?;
        Ok(msg)
    }

    /// Sends a single query over TCP with the standard 2-byte length prefix.
    async fn query_tcp(
        &self,
        target: SocketAddr,
        query: &[u8],
        id: u16,
        qname: &Name,
    ) -> Result<Message> {
        let mut stream = tokio::time::timeout(self.timeout, TcpStream::connect(target))
            .await
            .context("nameserver TCP connect timeout")??;

        let len = u16::try_from(query.len()).context("query too large for TCP framing")?;
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(query);
        tokio::time::timeout(self.timeout, stream.write_all(&framed))
            .await
            .context("nameserver TCP write timeout")??;

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut len_buf))
            .await
            .context("nameserver TCP length read timeout")??;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut resp_buf))
            .await
            .context("nameserver TCP body read timeout")??;

        let msg = Message::from_bytes(&resp_buf)?;
        if msg.id() != id {
            bail!("TCP response id mismatch from {}", target);
        }
        validate_question(&msg, qname)?;
        Ok(msg)
    }
}

/// Builds an iterative query (recursion desired cleared) for `name`/`qtype`,
/// returning the wire bytes and the random transaction id.
fn build_query(name: &Name, qtype: RecordType, qclass: DNSClass) -> Result<(Vec<u8>, u16)> {
    let id: u16 = rand::rng().random();
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false);

    let mut query = Query::new();
    query.set_name(name.clone());
    query.set_query_type(qtype);
    query.set_query_class(qclass);
    msg.add_query(query);

    Ok((msg.to_bytes()?, id))
}

/// Verifies the response question matches the name we asked for (case-insensitive).
fn validate_question(msg: &Message, qname: &Name) -> Result<()> {
    match msg.queries().first() {
        Some(q) if names_equal(q.name(), qname) => Ok(()),
        Some(q) => bail!(
            "response question {} does not match query {}",
            q.name(),
            qname
        ),
        None => bail!("response has no question section"),
    }
}

/// Case-insensitive DNS name comparison.
fn names_equal(a: &Name, b: &Name) -> bool {
    a.to_ascii().eq_ignore_ascii_case(&b.to_ascii())
}

/// Classifies a nameserver response relative to the requested type.
fn classify(response: &Message, qtype: RecordType) -> Step {
    let answers = response.answers();

    if !answers.is_empty() {
        let has_requested = answers.iter().any(|r| r.record_type() == qtype);
        if has_requested || qtype == RecordType::CNAME || qtype == RecordType::ANY {
            return Step::Answer(answers.to_vec());
        }
        if let Some(target) = answers.iter().find_map(|r| match r.data() {
            RData::CNAME(rdata::CNAME(t)) => Some(t.clone()),
            _ => None,
        }) {
            return Step::Cname {
                target,
                records: answers.to_vec(),
            };
        }
        // Answers present but neither the requested type nor a CNAME: return as-is.
        return Step::Answer(answers.to_vec());
    }

    if response.response_code() == ResponseCode::NXDomain {
        return Step::Negative(ResponseCode::NXDomain);
    }

    // No answers, NoError: a delegation (NS in authority) or NODATA.
    let ns_records: Vec<&Record> = response
        .name_servers()
        .iter()
        .filter(|r| matches!(r.data(), RData::NS(_)))
        .collect();

    if ns_records.is_empty() {
        return Step::Negative(response.response_code());
    }

    let zone = ns_records
        .first()
        .map(|r| r.name().clone())
        .unwrap_or_else(Name::root);
    let ns_targets: Vec<Name> = ns_records
        .iter()
        .filter_map(|r| match r.data() {
            RData::NS(rdata::NS(t)) => Some(t.clone()),
            _ => None,
        })
        .collect();
    let glue = collect_glue(response, &ns_targets);

    Step::Referral {
        zone,
        glue,
        ns_targets,
    }
}

/// Extracts glue address records from the additional section for the given
/// NS targets, ordering IPv4 before IPv6 for reachability.
fn collect_glue(response: &Message, ns_targets: &[Name]) -> Vec<IpAddr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for rec in response.additionals() {
        if !ns_targets.iter().any(|t| names_equal(t, rec.name())) {
            continue;
        }
        match rec.data() {
            RData::A(rdata::A(ip)) => v4.push(IpAddr::V4(*ip)),
            RData::AAAA(rdata::AAAA(ip)) => v6.push(IpAddr::V6(*ip)),
            _ => {}
        }
    }
    v4.extend(v6);
    v4
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, SOA};
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    fn a_record(owner: &str, ip: Ipv4Addr) -> Record {
        Record::from_rdata(name(owner), 300, RData::A(A(ip)))
    }

    fn ns_record(zone: &str, target: &str) -> Record {
        Record::from_rdata(name(zone), 300, RData::NS(NS(name(target))))
    }

    fn cname_record(owner: &str, target: &str) -> Record {
        Record::from_rdata(name(owner), 300, RData::CNAME(CNAME(name(target))))
    }

    #[test]
    fn root_hints_count() {
        assert_eq!(ROOT_HINTS.len(), 13);
        assert!(ROOT_HINTS.iter().all(|h| h.is_ipv4()));
    }

    #[test]
    fn resolver_defaults_to_root_hints() {
        let r = IterativeResolver::new(Vec::new());
        assert_eq!(r.root_hints.len(), 13);
        let custom = IterativeResolver::new(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        assert_eq!(
            custom.root_hints,
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]
        );
    }

    #[test]
    fn build_query_roundtrips_with_rd_clear() {
        let (bytes, id) =
            build_query(&name("example.com."), RecordType::A, DNSClass::IN).expect("build query");
        let msg = Message::from_bytes(&bytes).expect("parse");
        assert_eq!(msg.id(), id);
        assert!(!msg.recursion_desired());
        assert_eq!(msg.message_type(), MessageType::Query);
        let q = msg.queries().first().expect("question");
        assert!(names_equal(q.name(), &name("example.com.")));
        assert_eq!(q.query_type(), RecordType::A);
    }

    #[test]
    fn names_equal_is_case_insensitive() {
        assert!(names_equal(&name("Example.COM."), &name("example.com.")));
        assert!(!names_equal(&name("example.com."), &name("example.org.")));
    }

    #[test]
    fn classify_direct_answer() {
        let mut msg = Message::new();
        msg.add_answer(a_record("example.com.", Ipv4Addr::new(93, 184, 216, 34)));
        match classify(&msg, RecordType::A) {
            Step::Answer(records) => assert_eq!(records.len(), 1),
            other => panic!("expected answer, got {:?}", other),
        }
    }

    #[test]
    fn classify_cname_indirection() {
        let mut msg = Message::new();
        msg.add_answer(cname_record("www.example.com.", "example.com."));
        match classify(&msg, RecordType::A) {
            Step::Cname { target, records } => {
                assert!(names_equal(&target, &name("example.com.")));
                assert_eq!(records.len(), 1);
            }
            other => panic!("expected cname, got {:?}", other),
        }
    }

    #[test]
    fn classify_cname_when_cname_requested_is_answer() {
        let mut msg = Message::new();
        msg.add_answer(cname_record("www.example.com.", "example.com."));
        match classify(&msg, RecordType::CNAME) {
            Step::Answer(records) => assert_eq!(records.len(), 1),
            other => panic!("expected answer, got {:?}", other),
        }
    }

    #[test]
    fn classify_referral_with_glue() {
        let mut msg = Message::new();
        msg.add_name_server(ns_record("com.", "a.gtld-servers.net."));
        msg.add_additional(a_record(
            "a.gtld-servers.net.",
            Ipv4Addr::new(192, 5, 6, 30),
        ));
        match classify(&msg, RecordType::A) {
            Step::Referral {
                zone,
                glue,
                ns_targets,
            } => {
                assert!(names_equal(&zone, &name("com.")));
                assert_eq!(glue, vec![IpAddr::V4(Ipv4Addr::new(192, 5, 6, 30))]);
                assert_eq!(ns_targets.len(), 1);
            }
            other => panic!("expected referral, got {:?}", other),
        }
    }

    #[test]
    fn classify_referral_glueless() {
        let mut msg = Message::new();
        msg.add_name_server(ns_record("example.com.", "ns1.example.net."));
        match classify(&msg, RecordType::A) {
            Step::Referral {
                glue, ns_targets, ..
            } => {
                assert!(glue.is_empty());
                assert_eq!(ns_targets.len(), 1);
            }
            other => panic!("expected glueless referral, got {:?}", other),
        }
    }

    #[test]
    fn classify_nxdomain() {
        let mut msg = Message::new();
        msg.set_response_code(ResponseCode::NXDomain);
        msg.add_name_server(Record::from_rdata(
            name("com."),
            300,
            RData::SOA(SOA::new(
                name("a.gtld-servers.net."),
                name("nstld.verisign-grs.com."),
                1,
                7200,
                3600,
                1_209_600,
                3600,
            )),
        ));
        match classify(&msg, RecordType::A) {
            Step::Negative(rcode) => assert_eq!(rcode, ResponseCode::NXDomain),
            other => panic!("expected negative, got {:?}", other),
        }
    }

    #[test]
    fn classify_nodata_soa_only() {
        let mut msg = Message::new();
        msg.add_name_server(Record::from_rdata(
            name("example.com."),
            300,
            RData::SOA(SOA::new(
                name("ns1.example.com."),
                name("hostmaster.example.com."),
                1,
                7200,
                3600,
                1_209_600,
                3600,
            )),
        ));
        match classify(&msg, RecordType::AAAA) {
            Step::Negative(rcode) => assert_eq!(rcode, ResponseCode::NoError),
            other => panic!("expected nodata negative, got {:?}", other),
        }
    }

    #[test]
    fn collect_glue_orders_v4_before_v6() {
        let mut msg = Message::new();
        msg.add_additional(Record::from_rdata(
            name("ns1.example.net."),
            300,
            RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        ));
        msg.add_additional(a_record("ns1.example.net.", Ipv4Addr::new(203, 0, 113, 1)));
        // Unrelated additional record must be ignored.
        msg.add_additional(a_record(
            "other.example.net.",
            Ipv4Addr::new(203, 0, 113, 9),
        ));
        let glue = collect_glue(&msg, &[name("ns1.example.net.")]);
        assert_eq!(glue.len(), 2);
        assert!(glue[0].is_ipv4());
        assert!(glue[1].is_ipv6());
    }

    /// Drives a full delegation chain from a single mock UDP nameserver: the
    /// first query gets a referral to `com.`, the second a referral to
    /// `example.com.`, and the third the final A answer. Each referral's glue
    /// points back at the same server (127.0.0.1), so the resolver walks the
    /// chain without any real network access.
    #[tokio::test]
    async fn iterative_resolution_follows_full_chain() {
        // Bind the mock nameserver socket.
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock ns");
        let port = server.local_addr().expect("local addr").port();
        let self_ip = Ipv4Addr::new(127, 0, 0, 1);

        // Drive three staged responses from the single socket.
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_SIZE];
            for stage in 0..3u8 {
                let (len, peer) = server.recv_from(&mut buf).await.expect("recv");
                let query = Message::from_bytes(&buf[..len]).expect("parse query");
                let mut resp = Message::new();
                resp.set_id(query.id());
                resp.set_message_type(MessageType::Response);
                resp.set_op_code(OpCode::Query);
                if let Some(q) = query.queries().first() {
                    resp.add_query(q.clone());
                }
                match stage {
                    0 => {
                        // Referral to com.
                        resp.add_name_server(Record::from_rdata(
                            Name::from_str("com.").unwrap(),
                            172_800,
                            RData::NS(NS(Name::from_str("a.gtld.").unwrap())),
                        ));
                        resp.add_additional(Record::from_rdata(
                            Name::from_str("a.gtld.").unwrap(),
                            172_800,
                            RData::A(A(self_ip)),
                        ));
                    }
                    1 => {
                        // Referral to example.com.
                        resp.add_name_server(Record::from_rdata(
                            Name::from_str("example.com.").unwrap(),
                            172_800,
                            RData::NS(NS(Name::from_str("ns1.example.com.").unwrap())),
                        ));
                        resp.add_additional(Record::from_rdata(
                            Name::from_str("ns1.example.com.").unwrap(),
                            172_800,
                            RData::A(A(self_ip)),
                        ));
                    }
                    _ => {
                        // Final authoritative answer.
                        resp.set_authoritative(true);
                        resp.add_answer(Record::from_rdata(
                            Name::from_str("example.com.").unwrap(),
                            300,
                            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                        ));
                    }
                }
                let bytes = resp.to_bytes().expect("encode response");
                server.send_to(&bytes, peer).await.expect("send");
            }
        });

        let resolver = IterativeResolver::new(vec![IpAddr::V4(self_ip)])
            .with_port(port)
            .with_timeout(Duration::from_secs(2));

        let result = resolver
            .resolve(&name("example.com."), RecordType::A, DNSClass::IN)
            .await
            .expect("resolution succeeds");

        handle.await.expect("mock ns task");

        assert_eq!(result.rcode, ResponseCode::NoError);
        assert_eq!(result.answers.len(), 1);
        match result.answers[0].data() {
            RData::A(A(ip)) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn iterative_resolution_returns_nxdomain() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock ns");
        let port = server.local_addr().expect("local addr").port();
        let self_ip = Ipv4Addr::new(127, 0, 0, 1);

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_SIZE];
            let (len, peer) = server.recv_from(&mut buf).await.expect("recv");
            let query = Message::from_bytes(&buf[..len]).expect("parse query");
            let mut resp = Message::new();
            resp.set_id(query.id());
            resp.set_message_type(MessageType::Response);
            resp.set_response_code(ResponseCode::NXDomain);
            resp.set_authoritative(true);
            if let Some(q) = query.queries().first() {
                resp.add_query(q.clone());
            }
            let bytes = resp.to_bytes().expect("encode");
            server.send_to(&bytes, peer).await.expect("send");
        });

        let resolver = IterativeResolver::new(vec![IpAddr::V4(self_ip)])
            .with_port(port)
            .with_timeout(Duration::from_secs(2));

        let result = resolver
            .resolve(&name("nope.invalid."), RecordType::A, DNSClass::IN)
            .await
            .expect("resolution returns");

        handle.await.expect("mock ns task");
        assert_eq!(result.rcode, ResponseCode::NXDomain);
        assert!(result.answers.is_empty());
    }

    #[test]
    fn validate_question_rejects_mismatch() {
        let mut msg = Message::new();
        let mut q = Query::new();
        q.set_name(name("evil.example.com."));
        q.set_query_type(RecordType::A);
        q.set_query_class(DNSClass::IN);
        msg.add_query(q);
        assert!(validate_question(&msg, &name("example.com.")).is_err());
        assert!(validate_question(&msg, &name("evil.example.com.")).is_ok());
    }
}
