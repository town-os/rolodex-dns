//! A *counting* mock DNS hierarchy: root -> TLD -> authoritative.
//!
//! The delegation-cache bug and its fix are only observable as **query counts**.
//! Latency assertions would be flaky and prove nothing; `root.hits()` is exact.
//! "Resolving ten `.com` names touches the root server once, not ten times" is
//! the whole claim, and this harness is what makes it assertable.
//!
//! Each level is a real UDP nameserver wrapping an `AtomicUsize`, and referrals
//! carry glue pointing at the next level down — so the resolver walks a genuine
//! delegation chain over real sockets, with none of its internals mocked.
//!
//! **Why the levels share one port on different loopback IPs:** the resolver
//! reaches nameservers at `SocketAddr::new(glue_ip, self.port)` — glue is an IP,
//! the port is fixed. So a multi-level hierarchy cannot put each level on its own
//! ephemeral port; instead each level binds a distinct `127.0.0.x` at one shared
//! port ([`bind_levels`] finds a port free on all of them).

#![allow(dead_code)]

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, NS, SOA};
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;

/// How a level answers a query.
#[derive(Clone, Debug)]
pub enum Behavior {
    /// Delegate `zone` to `next`, with glue.
    Refer {
        zone: String,
        next: Ipv4Addr,
        ttl: u32,
    },
    /// Delegate `zone` with **no glue**, forcing the resolver to resolve the NS
    /// name itself before it can continue.
    ReferGlueless {
        zone: String,
        ns_name: String,
        ttl: u32,
    },
    /// Delegate `zone` to a v6 nameserver *and* a v4 one, v6 listed first in the
    /// additional section. Used to prove v4 is still tried first.
    ReferMixedFamily {
        zone: String,
        v6: std::net::Ipv6Addr,
        v4: Ipv4Addr,
        ttl: u32,
    },
    /// Answer authoritatively with an A record.
    Answer { ip: Ipv4Addr, ttl: u32 },
    /// NXDOMAIN with an SOA, so a negative TTL can be derived (RFC 2308).
    NxDomain { minimum: u32, soa_ttl: u32 },
    /// NODATA (NoError, no answers) with an SOA.
    NoData { minimum: u32, soa_ttl: u32 },
}

/// One level of the mock hierarchy.
pub struct MockNs {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
    dead: Arc<AtomicBool>,
}

impl MockNs {
    /// Queries this level has received — the assertion that matters.
    pub fn hits(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }

    pub fn reset(&self) {
        self.queries.store(0, Ordering::SeqCst);
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn ip(&self) -> IpAddr {
        self.addr.ip()
    }

    pub fn ipv4(&self) -> Ipv4Addr {
        match self.addr.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => unreachable!("mock hierarchy is IPv4"),
        }
    }

    /// Stops answering, simulating a server that black-holes traffic. Queries are
    /// still *counted*, so a test can prove a dead server is being avoided rather
    /// than merely failing.
    pub fn kill(&self) {
        self.dead.store(true, Ordering::SeqCst);
    }

    pub fn revive(&self) {
        self.dead.store(false, Ordering::SeqCst);
    }
}

/// Binds one UDP socket per requested loopback IP, all on a single shared port.
///
/// Retries with a fresh candidate port until one is free on every IP, so
/// concurrently-running test binaries don't collide.
pub async fn bind_levels(ips: &[Ipv4Addr]) -> (u16, Vec<UdpSocket>) {
    for _ in 0..64 {
        // Let the OS pick a free port on the first IP, then try to claim that
        // same port on all the others.
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
    panic!("could not find a port free on all mock hierarchy IPs");
}

/// Starts serving `behavior` on an already-bound socket.
pub fn serve(socket: UdpSocket, behavior: Behavior) -> MockNs {
    serve_with_delay(socket, behavior, Duration::ZERO)
}

/// Starts serving `behavior`, waiting `delay` before each answer (for RTT-ordering
/// tests).
pub fn serve_with_delay(socket: UdpSocket, behavior: Behavior, delay: Duration) -> MockNs {
    let addr = socket.local_addr().expect("mock ns addr");
    let queries = Arc::new(AtomicUsize::new(0));
    let dead = Arc::new(AtomicBool::new(false));

    let counter = Arc::clone(&queries);
    let is_dead = Arc::clone(&dead);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);

            if is_dead.load(Ordering::SeqCst) {
                continue; // counted, then black-holed
            }
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }

            let Ok(query) = Message::from_bytes(&buf[..len]) else {
                continue;
            };
            let response = build_response(&query, &behavior);
            if let Ok(bytes) = response.to_bytes() {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    });

    MockNs {
        addr,
        queries,
        dead,
    }
}

pub fn name(s: &str) -> Name {
    Name::from_str(s).expect("valid name")
}

fn soa_record(zone: &str, minimum: u32, soa_ttl: u32) -> Record {
    let zone = if zone.ends_with('.') {
        zone.to_string()
    } else {
        format!("{zone}.")
    };
    Record::from_rdata(
        name(&zone),
        soa_ttl,
        RData::SOA(SOA::new(
            name(&format!("ns1.{zone}")),
            name(&format!("hostmaster.{zone}")),
            1,
            7200,
            3600,
            1_209_600,
            minimum,
        )),
    )
}

fn build_response(query: &Message, behavior: &Behavior) -> Message {
    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    if let Some(q) = query.queries().first() {
        resp.add_query(q.clone());
    }
    let qname = query
        .queries()
        .first()
        .map(|q| q.name().to_string())
        .unwrap_or_else(|| ".".to_string());

    match behavior {
        Behavior::Refer { zone, next, ttl } => {
            let ns_name = format!("ns1.{zone}");
            resp.add_name_server(Record::from_rdata(
                name(zone),
                *ttl,
                RData::NS(NS(name(&ns_name))),
            ));
            resp.add_additional(Record::from_rdata(name(&ns_name), *ttl, RData::A(A(*next))));
        }
        Behavior::ReferGlueless { zone, ns_name, ttl } => {
            resp.add_name_server(Record::from_rdata(
                name(zone),
                *ttl,
                RData::NS(NS(name(ns_name))),
            ));
            // No additional section: the resolver must resolve `ns_name` itself.
        }
        Behavior::ReferMixedFamily { zone, v6, v4, ttl } => {
            let ns6 = format!("ns6.{zone}");
            let ns4 = format!("ns4.{zone}");
            resp.add_name_server(Record::from_rdata(
                name(zone),
                *ttl,
                RData::NS(NS(name(&ns6))),
            ));
            resp.add_name_server(Record::from_rdata(
                name(zone),
                *ttl,
                RData::NS(NS(name(&ns4))),
            ));
            // v6 deliberately first in the wire order — collect_glue must still
            // put the v4 address ahead of it.
            resp.add_additional(Record::from_rdata(
                name(&ns6),
                *ttl,
                RData::AAAA(hickory_proto::rr::rdata::AAAA(*v6)),
            ));
            resp.add_additional(Record::from_rdata(name(&ns4), *ttl, RData::A(A(*v4))));
        }
        Behavior::Answer { ip, ttl } => {
            resp.set_authoritative(true);
            resp.add_answer(Record::from_rdata(name(&qname), *ttl, RData::A(A(*ip))));
        }
        Behavior::NxDomain { minimum, soa_ttl } => {
            resp.set_authoritative(true);
            resp.set_response_code(ResponseCode::NXDomain);
            resp.add_name_server(soa_record(&apex_of(&qname), *minimum, *soa_ttl));
        }
        Behavior::NoData { minimum, soa_ttl } => {
            resp.set_authoritative(true);
            resp.set_response_code(ResponseCode::NoError);
            resp.add_name_server(soa_record(&apex_of(&qname), *minimum, *soa_ttl));
        }
    }
    resp
}

/// Crude apex: strip the leftmost label ("nope.example.com." -> "example.com.").
fn apex_of(qname: &str) -> String {
    let n = name(qname);
    if n.num_labels() <= 2 {
        return n.to_string();
    }
    n.base_name().to_string()
}
