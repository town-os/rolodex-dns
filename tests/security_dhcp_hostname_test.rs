//! Security regression tests for DHCP-supplied hostnames.
//!
//! These assert behaviour the DHCP server *should* have and are expected to FAIL
//! against the current implementation. Do not weaken an assertion to make one
//! pass.
//!
//! `register_dns_hostname` (`src/dhcp.rs`) builds the record name with
//! `format!("{}.lan.{}.", hostname, self.config.tld)`. `hostname` is DHCP option
//! 12 — supplied verbatim by the client, and validated nowhere. A DHCP client is
//! an unauthenticated device on the LAN, which is precisely the population this
//! server exists to serve and precisely the one that cannot be trusted to name
//! itself honestly.
//!
//! The sharp edge is `*`. A client that calls itself `*` gets `*.lan.<tld>.`
//! written as a scoped A record, and `make_wildcard_name` (`src/db.rs`) makes
//! that a **real wildcard**: `lookup_scoped` falls back to it for every
//! unregistered name under `lan.<tld>`, so one laptop answers for the whole
//! namespace of its scope. The matching PTR is planted the same way.
//!
//! Dots are the other half. A hostname is a single label; one containing dots
//! silently creates names at other depths, so a client can occupy
//! `a.b.lan.<tld>` — or collide with a name some other convention owns — rather
//! than the one slot it was allocated.
//!
//! There is also no length check, so labels over the 63-byte DNS limit and names
//! over 255 bytes reach the database and are only discovered later, at
//! serialization time, one query at a time.
//!
//! Each test drives the real DISCOVER/REQUEST handlers and then reads the
//! database directly: what matters is what was *stored*, since that is what
//! every later query resolves against. The tests are deliberately loose about
//! how a bad hostname is handled — sanitized, or the registration skipped
//! entirely — and assert only that the dangerous name is not what lands.
//!
//! Everything is in-memory; the host is untouched and no packet leaves the
//! process.

use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
use rolodex_dns::config::DhcpConfig;
use rolodex_dns::db::{Database, DhcpPool, NetworkScope, RecordKind};
use rolodex_dns::dhcp::DhcpServer;
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::rbl::{RblChecker, RblResolver};
use std::sync::Arc;

const SCOPE: &str = "testnet";
const TLD: &str = "example.com";

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

fn make_server() -> (Database, DhcpServer) {
    let db = Database::open_memory().unwrap();
    let rbl = Arc::new(RblChecker::with_resolver(
        false,
        vec![],
        Arc::new(NeverListedResolver),
    ));
    let dns_server = Arc::new(DnsServer::new(db.clone(), rbl, vec![]));
    let config = DhcpConfig {
        bind: "127.0.0.1:0".to_string(),
        default_lease_duration: 3600,
        reclaim_timeout: 86400,
        sweep_interval: 60,
        tld: TLD.to_string(),
    };
    let dhcp = DhcpServer::new(db.clone(), dns_server, &config);

    db.create_network_scope(&NetworkScope {
        name: SCOPE.to_string(),
        home_domain: "testnet.home.".to_string(),
    })
    .unwrap();
    db.add_dhcp_pool(&DhcpPool {
        id: 0,
        scope_name: SCOPE.to_string(),
        range_start: "192.168.1.100".to_string(),
        range_end: "192.168.1.110".to_string(),
        gateway: Some("192.168.1.1".to_string()),
        subnet_mask: "255.255.255.0".to_string(),
        dns_servers: Some("192.168.1.1".to_string()),
    })
    .unwrap();

    (db, dhcp)
}

/// Runs a full DISCOVER/REQUEST for `mac` claiming `hostname`, and returns every
/// scoped record the exchange created.
fn lease_with_hostname(
    db: &Database,
    dhcp: &DhcpServer,
    mac: &[u8; 6],
    mac_str: &str,
    hostname: &str,
) -> Vec<rolodex_dns::db::DnsRecord> {
    let mut discover = Message::default();
    discover.set_opcode(Opcode::BootRequest);
    discover.set_xid(0x515c);
    discover.set_chaddr(mac);
    discover
        .opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Discover));

    let offer = dhcp
        .handle_discover(&discover, mac_str)
        .expect("discover")
        .expect("an OFFER");
    let offered = offer.yiaddr();

    let mut request = Message::default();
    request.set_opcode(Opcode::BootRequest);
    request.set_xid(0x515c);
    request.set_chaddr(mac);
    request
        .opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Request));
    request
        .opts_mut()
        .insert(DhcpOption::RequestedIpAddress(offered));
    request
        .opts_mut()
        .insert(DhcpOption::Hostname(hostname.to_string()));

    dhcp.handle_request(&request, mac_str)
        .expect("request")
        .expect("an ACK");

    db.list_scoped_records(SCOPE, "", None)
        .expect("list scoped records")
}

// ============================================================================
// Wildcard injection
// ============================================================================

/// A client calling itself `*` must not end up owning the scope's namespace.
///
/// `*.lan.<tld>.` is not a decorative name: `lookup_scoped` falls back to the
/// wildcard whenever an exact match misses, so this one record answers for every
/// unregistered host in the scope — every service a package plants later,
/// every name a peer expects to be NXDOMAIN.
#[test]
fn a_wildcard_hostname_does_not_capture_the_scope() {
    let (db, dhcp) = make_server();
    let records = lease_with_hostname(
        &db,
        &dhcp,
        &[0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01],
        "aa:bb:cc:00:00:01",
        "*",
    );

    let wildcard = format!("*.lan.{}.", TLD);
    assert!(
        !records.iter().any(|r| r.name == wildcard),
        "a DHCP client named itself `*` and got {} registered: one client now \
         answers for every name in the scope. Records: {:?}",
        wildcard,
        records.iter().map(|r| &r.name).collect::<Vec<_>>()
    );

    // And the wildcard must not be reachable through the resolution path either,
    // whichever name it was ultimately stored under.
    let resolved = db.lookup_scoped(
        SCOPE,
        &format!("unclaimed-service.lan.{}.", TLD),
        Some(RecordKind::A),
    );
    assert!(
        resolved.is_empty(),
        "an unregistered name under lan.{} resolved to {:?} because a DHCP \
         client planted a wildcard",
        TLD,
        resolved.iter().map(|r| &r.value).collect::<Vec<_>>()
    );
}

// ============================================================================
// Label escape
// ============================================================================

/// A DHCP hostname is a single label. One containing dots lets a client place
/// itself at a depth it was never given — occupying `a.b.lan.<tld>` rather than
/// the one name its lease entitles it to.
#[test]
fn a_dotted_hostname_does_not_create_a_deeper_name() {
    let (db, dhcp) = make_server();
    let records = lease_with_hostname(
        &db,
        &dhcp,
        &[0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02],
        "aa:bb:cc:00:00:02",
        "www.internal",
    );

    let escaped = format!("www.internal.lan.{}.", TLD);
    assert!(
        !records.iter().any(|r| r.name == escaped),
        "a DHCP client supplied a dotted hostname and got {} registered; a \
         hostname is one label. Records: {:?}",
        escaped,
        records.iter().map(|r| &r.name).collect::<Vec<_>>()
    );
}

// ============================================================================
// Malformed labels
// ============================================================================

/// A label longer than 63 bytes cannot be encoded in the DNS wire format, and a
/// name longer than 255 bytes cannot either. Storing one defers the failure to
/// serialization time, where it recurs on every query for the zone instead of
/// being rejected once at the point it arrived.
#[test]
fn an_oversized_hostname_is_not_stored() {
    let (db, dhcp) = make_server();
    let long = "a".repeat(120);
    let records = lease_with_hostname(
        &db,
        &dhcp,
        &[0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x03],
        "aa:bb:cc:00:00:03",
        &long,
    );

    assert!(
        !records.iter().any(|r| r.name.starts_with(&long)),
        "a 120-byte DHCP hostname was stored as a DNS label; the wire format \
         caps a label at 63 bytes"
    );
}

/// Characters outside the LDH set are not hostname characters. A hostname
/// carrying spaces or control bytes reaches the database, the PTR value, and
/// eventually a wire-format encoder.
#[test]
fn a_non_ldh_hostname_is_not_stored_verbatim() {
    let (db, dhcp) = make_server();
    let hostile = "bad host\u{0}name";
    let records = lease_with_hostname(
        &db,
        &dhcp,
        &[0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x04],
        "aa:bb:cc:00:00:04",
        hostile,
    );

    assert!(
        !records
            .iter()
            .any(|r| r.name.contains(' ') || r.name.contains('\u{0}')),
        "a DHCP hostname containing a space and a NUL was stored verbatim as a \
         DNS name. Records: {:?}",
        records.iter().map(|r| &r.name).collect::<Vec<_>>()
    );
}

// ============================================================================
// Control: ordinary hostnames must still register
// ============================================================================

/// The mirror invariant, and the reason this cannot be "drop every hostname":
/// registering a client's name in DNS is the feature. A fix that rejects a
/// perfectly ordinary hostname has broken it.
#[test]
fn an_ordinary_hostname_still_registers_forward_and_reverse() {
    let (db, dhcp) = make_server();
    let records = lease_with_hostname(
        &db,
        &dhcp,
        &[0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x05],
        "aa:bb:cc:00:00:05",
        "my-laptop",
    );

    let fqdn = format!("my-laptop.lan.{}.", TLD);
    assert!(
        records
            .iter()
            .any(|r| r.name == fqdn && r.record_type == RecordKind::A),
        "an ordinary hostname must still get its A record. Records: {:?}",
        records.iter().map(|r| &r.name).collect::<Vec<_>>()
    );
    assert!(
        records
            .iter()
            .any(|r| r.record_type == RecordKind::PTR && r.value == fqdn),
        "an ordinary hostname must still get its PTR record. Records: {:?}",
        records
            .iter()
            .map(|r| (&r.name, &r.value))
            .collect::<Vec<_>>()
    );
}
