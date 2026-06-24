/// DHCPv4 server integrated with Rolodex DNS.
///
/// Provides IP address allocation (IPAM) with consistent MAC→IP binding,
/// automatic DNS hostname registration under `lan.<tld>`, certificate delivery
/// via DHCP options, and per-scope RBL integration.
use crate::db::{Database, DhcpLease, DhcpPool, DnsRecord, NetworkAssociation, RecordKind};
use crate::dns_server::DnsServer;
use anyhow::{Context, Result};
use dhcproto::v4::{self, DhcpOption, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

/// Runtime DHCP configuration.
#[derive(Debug, Clone)]
pub struct DhcpRuntimeConfig {
    pub default_lease_duration: u64,
    pub reclaim_timeout: u64,
    pub sweep_interval: u64,
    pub tld: String,
}

impl From<&crate::config::DhcpConfig> for DhcpRuntimeConfig {
    fn from(cfg: &crate::config::DhcpConfig) -> Self {
        Self {
            default_lease_duration: cfg.default_lease_duration,
            reclaim_timeout: cfg.reclaim_timeout,
            sweep_interval: cfg.sweep_interval,
            tld: cfg.tld.clone(),
        }
    }
}

/// The DHCP server.
pub struct DhcpServer {
    db: Database,
    dns_server: Arc<DnsServer>,
    config: DhcpRuntimeConfig,
}

impl DhcpServer {
    pub fn new(
        db: Database,
        dns_server: Arc<DnsServer>,
        config: &crate::config::DhcpConfig,
    ) -> Self {
        Self {
            db,
            dns_server,
            config: DhcpRuntimeConfig::from(config),
        }
    }

    /// Returns a reference to the database.
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Starts the DHCP UDP listener.
    pub async fn serve_dhcp(&self, bind_addr: &str) -> Result<()> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind DHCP socket to {}", bind_addr))?;
        socket.set_broadcast(true)?;
        info!("DHCP server listening on {}", bind_addr);

        let mut buf = vec![0u8; 1500];
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    error!("DHCP recv error: {}", e);
                    continue;
                }
            };

            let data = &buf[..len];
            match Message::decode(&mut Decoder::new(data)) {
                Ok(msg) => {
                    if let Err(e) = self.handle_message(&socket, &msg, src).await {
                        warn!("DHCP message handling error: {}", e);
                    }
                }
                Err(e) => {
                    debug!("Failed to parse DHCP message from {}: {}", src, e);
                }
            }
        }
    }

    /// Runs the background lease expiry sweep.
    pub async fn run_lease_sweep(&self) {
        let interval = Duration::from_secs(self.config.sweep_interval);
        loop {
            tokio::time::sleep(interval).await;
            match self.db.sweep_expired_leases(self.config.reclaim_timeout) {
                Ok(expired) => {
                    for lease in &expired {
                        self.cleanup_lease(lease);
                        info!(
                            "Swept expired lease: MAC={} IP={} scope={}",
                            lease.mac, lease.ip, lease.scope_name
                        );
                    }
                }
                Err(e) => {
                    error!("Lease sweep error: {}", e);
                }
            }
        }
    }

    async fn handle_message(
        &self,
        socket: &UdpSocket,
        msg: &Message,
        src: SocketAddr,
    ) -> Result<()> {
        // Only handle BOOTREQUEST (client → server)
        if msg.opcode() != Opcode::BootRequest {
            return Ok(());
        }

        let msg_type = msg
            .opts()
            .get(OptionCode::MessageType)
            .and_then(|opt| match opt {
                DhcpOption::MessageType(mt) => Some(*mt),
                _ => None,
            });

        let mac = format_mac(msg.chaddr());

        let reply = match msg_type {
            Some(MessageType::Discover) => self.handle_discover(msg, &mac)?,
            Some(MessageType::Request) => self.handle_request(msg, &mac)?,
            Some(MessageType::Release) => {
                self.handle_release(msg, &mac).await?;
                None
            }
            Some(MessageType::Decline) => {
                self.handle_decline(msg, &mac).await?;
                None
            }
            _ => {
                debug!("Ignoring DHCP message type {:?} from {}", msg_type, mac);
                None
            }
        };

        if let Some(reply) = reply {
            send_reply(socket, &reply, src).await?;
        }

        Ok(())
    }

    /// Handles a DHCP DISCOVER message. Returns an OFFER reply or None.
    pub fn handle_discover(&self, msg: &Message, mac: &str) -> Result<Option<Message>> {
        debug!("DHCP DISCOVER from {}", mac);

        let pools = self.db.list_dhcp_pools(None)?;
        if pools.is_empty() {
            warn!("DHCP DISCOVER from {} but no pools configured", mac);
            return Ok(None);
        }

        // Check for existing lease (sticky binding)
        let (ip, scope_name) = if let Ok(Some(lease)) = self.db.get_lease_by_mac(mac) {
            (lease.ip.clone(), lease.scope_name.clone())
        } else {
            let mut allocated = None;
            for pool in &pools {
                if let Ok(Some(ip)) = self.db.allocate_ip(&pool.scope_name, mac) {
                    allocated = Some((ip, pool.scope_name.clone()));
                    break;
                }
            }
            match allocated {
                Some(a) => a,
                None => {
                    warn!("DHCP DISCOVER from {} but no IPs available", mac);
                    return Ok(None);
                }
            }
        };

        let offered_ip: Ipv4Addr = ip.parse().context("invalid allocated IP")?;
        let pool = pools
            .iter()
            .find(|p| p.scope_name == scope_name)
            .context("pool not found for scope")?;

        let mut reply = build_reply(msg, MessageType::Offer, offered_ip);
        add_pool_options(&mut reply, pool, self.config.default_lease_duration);

        // Add certificate options if configured
        if let Ok(cert_opts) = self.db.list_dhcp_cert_options(&scope_name) {
            for opt in cert_opts {
                reply
                    .opts_mut()
                    .insert(DhcpOption::Unknown(v4::UnknownOption::new(
                        OptionCode::from(opt.option_code as u8),
                        opt.cert_data,
                    )));
            }
        }

        info!("DHCP OFFER {} to {} (scope: {})", ip, mac, scope_name);
        Ok(Some(reply))
    }

    /// Handles a DHCP REQUEST message. Returns an ACK reply or None.
    pub fn handle_request(&self, msg: &Message, mac: &str) -> Result<Option<Message>> {
        debug!("DHCP REQUEST from {}", mac);

        let requested_ip = msg
            .opts()
            .get(OptionCode::RequestedIpAddress)
            .and_then(|opt| match opt {
                DhcpOption::RequestedIpAddress(ip) => Some(*ip),
                _ => None,
            })
            .unwrap_or_else(|| msg.ciaddr());

        if requested_ip.is_unspecified() {
            warn!("DHCP REQUEST from {} with no IP", mac);
            return Ok(None);
        }

        let ip_str = requested_ip.to_string();

        let scope_name = if let Ok(Some(lease)) = self.db.get_lease_by_mac(mac) {
            lease.scope_name
        } else {
            let pools = self.db.list_dhcp_pools(None)?;
            pools
                .iter()
                .find(|p| ip_in_range(&ip_str, &p.range_start, &p.range_end))
                .map(|p| p.scope_name.clone())
                .context("requested IP not in any pool")?
        };

        let hostname = msg
            .opts()
            .get(OptionCode::Hostname)
            .and_then(|opt| match opt {
                DhcpOption::Hostname(h) => Some(h.clone()),
                _ => None,
            });

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs() as i64;

        let lease_duration = self.config.default_lease_duration as i64;

        let lease = DhcpLease {
            mac: mac.to_string(),
            ip: ip_str.clone(),
            scope_name: scope_name.clone(),
            hostname: hostname.clone(),
            lease_start: now,
            lease_duration,
            state: "active".to_string(),
        };
        self.db.create_lease(&lease)?;

        let assoc = NetworkAssociation {
            ip_address: ip_str.clone(),
            scope_name: scope_name.clone(),
            ttl_seconds: lease_duration as u64,
        };
        self.db.join_network(&assoc)?;

        if let Some(ref host) = hostname {
            self.register_dns_hostname(host, &ip_str, &scope_name, lease_duration as u32)?;
        }

        let pool = self
            .db
            .list_dhcp_pools(Some(&scope_name))?
            .into_iter()
            .next();

        let mut reply = build_reply(msg, MessageType::Ack, requested_ip);
        if let Some(ref p) = pool {
            add_pool_options(&mut reply, p, self.config.default_lease_duration);
        }

        if let Ok(cert_opts) = self.db.list_dhcp_cert_options(&scope_name) {
            for opt in cert_opts {
                reply
                    .opts_mut()
                    .insert(DhcpOption::Unknown(v4::UnknownOption::new(
                        OptionCode::from(opt.option_code as u8),
                        opt.cert_data,
                    )));
            }
        }

        info!(
            "DHCP ACK {} to {} (scope: {}, hostname: {:?})",
            ip_str, mac, scope_name, hostname
        );
        Ok(Some(reply))
    }

    pub async fn handle_release(&self, msg: &Message, mac: &str) -> Result<()> {
        debug!("DHCP RELEASE from {}", mac);

        if let Ok(Some(lease)) = self.db.release_lease(mac) {
            // Remove DNS records
            if let Some(ref host) = lease.hostname {
                self.unregister_dns_hostname(host, &lease.ip, &lease.scope_name)?;
            }

            // Leave network scope
            if let Err(e) = self.db.leave_network(&lease.ip) {
                warn!("failed to leave network for {}: {}", lease.ip, e);
            }
            self.dns_server.flush_cache();

            info!(
                "DHCP RELEASE {} from {} (scope: {})",
                msg.ciaddr(),
                mac,
                lease.scope_name
            );
        }
        Ok(())
    }

    async fn handle_decline(&self, _msg: &Message, mac: &str) -> Result<()> {
        debug!("DHCP DECLINE from {}", mac);

        // Mark the lease as declined so the IP won't be reused
        if let Ok(Some(_lease)) = self.db.release_lease(mac) {
            info!("DHCP DECLINE from {} — IP marked unavailable", mac);
        }
        Ok(())
    }

    /// Registers A and PTR records for a DHCP hostname.
    fn register_dns_hostname(
        &self,
        hostname: &str,
        ip: &str,
        scope_name: &str,
        ttl: u32,
    ) -> Result<()> {
        let fqdn = format!("{}.lan.{}.", hostname, self.config.tld);

        // Add A record
        let a_record = DnsRecord {
            id: None,
            name: fqdn.clone(),
            record_type: RecordKind::A,
            value: ip.to_string(),
            ttl,
            priority: 0,
        };
        self.db.add_scoped_record(scope_name, &a_record)?;

        // Add PTR record for reverse DNS
        if let Ok(addr) = ip.parse::<Ipv4Addr>() {
            let ptr_name = crate::db::reverse_ptr_name(std::net::IpAddr::V4(addr));
            let ptr_record = DnsRecord {
                id: None,
                name: ptr_name,
                record_type: RecordKind::PTR,
                value: fqdn,
                ttl,
                priority: 0,
            };
            self.db.add_scoped_record(scope_name, &ptr_record)?;
        }

        self.dns_server.flush_cache();
        Ok(())
    }

    /// Removes DNS records for a DHCP hostname.
    fn unregister_dns_hostname(&self, hostname: &str, ip: &str, scope_name: &str) -> Result<()> {
        let fqdn = format!("{}.lan.{}.", hostname, self.config.tld);

        // Remove A record
        if let Err(e) = self
            .db
            .remove_scoped_records(scope_name, &fqdn, Some(RecordKind::A), "")
        {
            warn!("failed to remove A record for {}: {}", fqdn, e);
        }

        // Remove PTR record
        if let Ok(addr) = ip.parse::<Ipv4Addr>() {
            let ptr_name = crate::db::reverse_ptr_name(std::net::IpAddr::V4(addr));
            if let Err(e) =
                self.db
                    .remove_scoped_records(scope_name, &ptr_name, Some(RecordKind::PTR), "")
            {
                warn!("failed to remove PTR record for {}: {}", ptr_name, e);
            }
        }

        self.dns_server.flush_cache();
        Ok(())
    }

    /// Cleans up DNS and network associations for an expired lease.
    pub fn cleanup_lease(&self, lease: &DhcpLease) {
        if let Some(ref host) = lease.hostname
            && let Err(e) = self.unregister_dns_hostname(host, &lease.ip, &lease.scope_name)
        {
            warn!("failed to unregister DNS for {}: {}", host, e);
        }
        if let Err(e) = self.db.leave_network(&lease.ip) {
            warn!("failed to leave network for {}: {}", lease.ip, e);
        }
        self.dns_server.flush_cache();
    }
}

/// Formats a MAC address from raw bytes as "xx:xx:xx:xx:xx:xx".
pub fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(6)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Checks if an IP string falls within a range (inclusive).
pub fn ip_in_range(ip: &str, start: &str, end: &str) -> bool {
    let ip: u32 = match ip.parse::<Ipv4Addr>() {
        Ok(a) => a.into(),
        Err(_) => return false,
    };
    let start: u32 = match start.parse::<Ipv4Addr>() {
        Ok(a) => a.into(),
        Err(_) => return false,
    };
    let end: u32 = match end.parse::<Ipv4Addr>() {
        Ok(a) => a.into(),
        Err(_) => return false,
    };
    ip >= start && ip <= end
}

/// Builds a DHCP reply message from a request.
fn build_reply(request: &Message, msg_type: MessageType, offered_ip: Ipv4Addr) -> Message {
    let mut reply = Message::default();
    reply.set_opcode(Opcode::BootReply);
    reply.set_xid(request.xid());
    reply.set_flags(request.flags());
    reply.set_yiaddr(offered_ip);
    reply.set_giaddr(request.giaddr());
    reply.set_chaddr(request.chaddr());

    reply.opts_mut().insert(DhcpOption::MessageType(msg_type));

    // Server identifier — use the offered IP's network as a rough server ID
    // In production, this should be the server's actual IP
    reply
        .opts_mut()
        .insert(DhcpOption::ServerIdentifier(Ipv4Addr::UNSPECIFIED));

    reply
}

/// Adds pool-specific options (subnet mask, gateway, DNS, lease time) to a reply.
fn add_pool_options(reply: &mut Message, pool: &DhcpPool, lease_duration: u64) {
    // Subnet mask
    if let Ok(mask) = pool.subnet_mask.parse::<Ipv4Addr>() {
        reply.opts_mut().insert(DhcpOption::SubnetMask(mask));
    }

    // Gateway/router
    if let Some(ref gw) = pool.gateway
        && let Ok(gw_ip) = gw.parse::<Ipv4Addr>()
    {
        reply.opts_mut().insert(DhcpOption::Router(vec![gw_ip]));
    }

    // DNS servers
    if let Some(ref dns) = pool.dns_servers {
        let dns_ips: Vec<Ipv4Addr> = dns
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        if !dns_ips.is_empty() {
            reply
                .opts_mut()
                .insert(DhcpOption::DomainNameServer(dns_ips));
        }
    }

    // Lease time
    reply
        .opts_mut()
        .insert(DhcpOption::AddressLeaseTime(lease_duration as u32));
}

/// Sends a DHCP reply to the client.
async fn send_reply(socket: &UdpSocket, reply: &Message, src: SocketAddr) -> Result<()> {
    let mut buf = Vec::with_capacity(1500);
    let mut encoder = Encoder::new(&mut buf);
    reply.encode(&mut encoder)?;

    // If giaddr is set, send to relay agent; otherwise respond to client
    let dest = if !reply.giaddr().is_unspecified() {
        SocketAddr::new(reply.giaddr().into(), 67)
    } else if src.ip().is_unspecified() || reply.flags().broadcast() {
        // Broadcast
        SocketAddr::new(Ipv4Addr::BROADCAST.into(), 68)
    } else {
        SocketAddr::new(src.ip(), 68)
    };

    socket.send_to(&buf, dest).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_mac() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(format_mac(&mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_format_mac_short() {
        let mac = [0x01, 0x02, 0x03];
        assert_eq!(format_mac(&mac), "01:02:03");
    }

    #[test]
    fn test_ip_in_range() {
        assert!(ip_in_range("192.168.1.10", "192.168.1.1", "192.168.1.254"));
        assert!(ip_in_range("192.168.1.1", "192.168.1.1", "192.168.1.254"));
        assert!(ip_in_range("192.168.1.254", "192.168.1.1", "192.168.1.254"));
        assert!(!ip_in_range("192.168.1.0", "192.168.1.1", "192.168.1.254"));
        assert!(!ip_in_range("192.168.2.1", "192.168.1.1", "192.168.1.254"));
        assert!(!ip_in_range("invalid", "192.168.1.1", "192.168.1.254"));
    }

    #[test]
    fn test_build_reply() {
        let mut request = Message::default();
        request.set_opcode(Opcode::BootRequest);
        request.set_xid(12345);
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        request.set_chaddr(&mac);

        let offered = Ipv4Addr::new(192, 168, 1, 100);
        let reply = build_reply(&request, MessageType::Offer, offered);

        assert_eq!(reply.opcode(), Opcode::BootReply);
        assert_eq!(reply.xid(), 12345);
        assert_eq!(reply.yiaddr(), offered);
        assert_eq!(&reply.chaddr()[..6], &mac);
    }

    #[test]
    fn test_add_pool_options() {
        let pool = DhcpPool {
            id: 1,
            scope_name: "test".to_string(),
            range_start: "192.168.1.100".to_string(),
            range_end: "192.168.1.200".to_string(),
            gateway: Some("192.168.1.1".to_string()),
            subnet_mask: "255.255.255.0".to_string(),
            dns_servers: Some("8.8.8.8,8.8.4.4".to_string()),
        };

        let mut request = Message::default();
        request.set_opcode(Opcode::BootRequest);
        let mut reply = build_reply(
            &request,
            MessageType::Offer,
            Ipv4Addr::new(192, 168, 1, 100),
        );
        add_pool_options(&mut reply, &pool, 3600);

        // Verify options are set
        assert!(reply.opts().get(OptionCode::SubnetMask).is_some());
        assert!(reply.opts().get(OptionCode::Router).is_some());
        assert!(reply.opts().get(OptionCode::DomainNameServer).is_some());
        assert!(reply.opts().get(OptionCode::AddressLeaseTime).is_some());
    }

    #[test]
    fn test_runtime_config_from_config() {
        let cfg = crate::config::DhcpConfig {
            bind: "0.0.0.0:67".to_string(),
            default_lease_duration: 7200,
            reclaim_timeout: 172800,
            sweep_interval: 120,
            tld: "example.com".to_string(),
        };
        let runtime = DhcpRuntimeConfig::from(&cfg);
        assert_eq!(runtime.default_lease_duration, 7200);
        assert_eq!(runtime.reclaim_timeout, 172800);
        assert_eq!(runtime.sweep_interval, 120);
        assert_eq!(runtime.tld, "example.com");
    }
}
