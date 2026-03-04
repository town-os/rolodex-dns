use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rolodex::grpc_service::proto::rolodex_service_client::RolodexServiceClient;
#[allow(unused_imports)]
use rolodex::grpc_service::proto::*;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

/// CLI client for managing a Rolodex DNS server via its gRPC management interface.
///
/// Supports connecting over TCP or Unix socket. All record management,
/// forwarder configuration, and RBL settings can be controlled through
/// subcommands.
#[derive(Parser)]
#[command(name = "rolodex-cli")]
#[command(version)]
#[command(about = "CLI client for managing a Rolodex DNS server via gRPC")]
#[command(long_about = "CLI client for managing a Rolodex split-horizon DNS server.\n\n\
    Connects to the Rolodex gRPC management interface over TCP or Unix socket \
    to manage DNS records, upstream forwarders, and RBL configuration.\n\n\
    TCP connections require authentication via --auth-token when the server \
    has a shared secret configured. Unix socket connections bypass authentication.")]
struct Cli {
    /// gRPC server address for TCP connections (host:port format).
    /// Ignored when --unix-socket is specified.
    /// Calls: http://<address> via gRPC TCP transport
    #[arg(
        short = 'a',
        long,
        default_value = "127.0.0.1:50051",
        global = true
    )]
    address: String,

    /// Path to Unix domain socket for gRPC connections.
    /// When specified, overrides --address and connects via Unix socket.
    /// Unix socket connections bypass authentication (auth-token is ignored).
    #[arg(short = 'u', long, global = true)]
    unix_socket: Option<String>,

    /// Authentication token for TCP gRPC connections.
    /// Required when the server has a shared secret configured.
    /// Ignored for Unix socket connections.
    #[arg(short = 't', long, default_value = "", global = true)]
    auth_token: String,

    #[command(subcommand)]
    command: Commands,
}

/// DNS record type. Determines how the record value is interpreted.
///
/// Default: A (IPv4 address mapping)
#[derive(Clone, Copy, ValueEnum, Debug)]
enum RecordTypeArg {
    /// IPv4 address mapping. Value: IPv4 address (e.g. "192.168.1.1")
    A,
    /// IPv6 address mapping. Value: IPv6 address (e.g. "::1")
    Aaaa,
    /// Canonical name alias. Value: target FQDN (e.g. "target.example.com.")
    Cname,
    /// Mail exchange. Value: mail server FQDN. Uses --priority field
    Mx,
    /// Text record. Value: arbitrary text content
    Txt,
    /// Name server. Value: nameserver FQDN
    Ns,
    /// Start of authority. Value: "mname rname serial refresh retry expire minimum" (space-separated)
    Soa,
    /// Service locator. Value: "weight port target" (space-separated). Uses --priority field
    Srv,
    /// Pointer for reverse DNS. Value: target FQDN
    Ptr,
    /// URI record (RFC 7553). Value: "priority weight target_uri"
    Uri,
    /// SSHFP record (RFC 4255). Value: "algorithm fp_type hex_fingerprint"
    Sshfp,
    /// DNAME delegation (RFC 6672). Value: target FQDN
    Dname,
    /// ANAME alias. Value: target FQDN (resolved at query time for A/AAAA)
    Aname,
    /// ZONEMD digest (RFC 9156). Value: "serial scheme hash_algorithm hex_digest"
    Zonemd,
    /// TLSA certificate (RFC 6698). Value: "usage selector matching_type hex_data"
    Tlsa,
    /// DNSKEY public key (DNSSEC)
    Dnskey,
    /// DS delegation signer (DNSSEC)
    Ds,
    /// RRSIG signature (DNSSEC)
    Rrsig,
    /// NSEC next secure (DNSSEC)
    Nsec,
    /// NSEC3 next secure v3 (DNSSEC)
    Nsec3,
    /// NSEC3PARAM parameters (DNSSEC)
    Nsec3param,
}

impl RecordTypeArg {
    fn to_proto_i32(self) -> i32 {
        match self {
            RecordTypeArg::A => 0,
            RecordTypeArg::Aaaa => 1,
            RecordTypeArg::Cname => 2,
            RecordTypeArg::Mx => 3,
            RecordTypeArg::Txt => 4,
            RecordTypeArg::Ns => 5,
            RecordTypeArg::Soa => 6,
            RecordTypeArg::Srv => 7,
            RecordTypeArg::Ptr => 8,
            RecordTypeArg::Uri => 9,
            RecordTypeArg::Sshfp => 10,
            RecordTypeArg::Dname => 11,
            RecordTypeArg::Aname => 12,
            RecordTypeArg::Zonemd => 13,
            RecordTypeArg::Tlsa => 14,
            RecordTypeArg::Dnskey => 15,
            RecordTypeArg::Ds => 16,
            RecordTypeArg::Rrsig => 17,
            RecordTypeArg::Nsec => 18,
            RecordTypeArg::Nsec3 => 19,
            RecordTypeArg::Nsec3param => 20,
        }
    }

    fn from_proto_i32(v: i32) -> &'static str {
        match v {
            0 => "A",
            1 => "AAAA",
            2 => "CNAME",
            3 => "MX",
            4 => "TXT",
            5 => "NS",
            6 => "SOA",
            7 => "SRV",
            8 => "PTR",
            9 => "URI",
            10 => "SSHFP",
            11 => "DNAME",
            12 => "ANAME",
            13 => "ZONEMD",
            14 => "TLSA",
            15 => "DNSKEY",
            16 => "DS",
            17 => "RRSIG",
            18 => "NSEC",
            19 => "NSEC3",
            20 => "NSEC3PARAM",
            _ => "UNKNOWN",
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Add a DNS record to the local database.
    /// gRPC path: /rolodex.RolodexService/AddRecord
    #[command(name = "add-record")]
    AddRecord {
        /// Fully qualified domain name (e.g. "example.com." — trailing dot recommended)
        #[arg(short, long)]
        name: String,

        /// DNS record type. Determines how the value field is interpreted.
        /// Default: A
        #[arg(short = 'r', long, value_enum, default_value = "a")]
        record_type: RecordTypeArg,

        /// Record data. Format depends on record type:
        ///   A: IPv4 address (e.g. "192.168.1.1")
        ///   AAAA: IPv6 address (e.g. "::1")
        ///   CNAME: target FQDN (e.g. "target.example.com.")
        ///   MX: mail server FQDN (use --priority for MX priority)
        ///   TXT: arbitrary text
        ///   NS: nameserver FQDN
        ///   SOA: "mname rname serial refresh retry expire minimum"
        ///   SRV: "weight port target" (use --priority for SRV priority)
        ///   PTR: target FQDN
        #[arg(short, long)]
        value: String,

        /// Time-to-live in seconds. If set to 0, defaults to 300.
        /// Default: 300
        #[arg(long, default_value = "300")]
        ttl: u32,

        /// Priority for MX and SRV records. Ignored for other record types.
        /// Lower values indicate higher priority.
        /// Default: 0
        #[arg(short, long, default_value = "0")]
        priority: u32,
    },

    /// Remove DNS record(s) from the local database.
    /// Removes by name, with optional type and value filters.
    /// gRPC path: /rolodex.RolodexService/RemoveRecord
    #[command(name = "remove-record")]
    RemoveRecord {
        /// Fully qualified domain name of records to remove
        #[arg(short, long)]
        name: String,

        /// If specified, only remove records of this type.
        /// If omitted, removes all record types for the given name.
        #[arg(short = 'r', long, value_enum)]
        record_type: Option<RecordTypeArg>,

        /// If specified, only remove the record with this exact value.
        /// If omitted, removes all records matching name (and type, if given).
        #[arg(short, long)]
        value: Option<String>,
    },

    /// List DNS records from the local database with optional filters.
    /// gRPC path: /rolodex.RolodexService/ListRecords
    #[command(name = "list-records")]
    ListRecords {
        /// Filter by domain name. Supports wildcard prefix "*." to match
        /// all subdomains (e.g. "*.example.com." matches "foo.example.com."
        /// and "bar.example.com." but not "example.com." itself).
        /// If omitted, returns all records.
        #[arg(short, long)]
        name: Option<String>,

        /// Filter by record type. If omitted, returns all record types.
        #[arg(short = 'r', long, value_enum)]
        record_type: Option<RecordTypeArg>,
    },

    /// Set upstream DNS forwarders at runtime.
    /// Replaces the entire forwarder list. The DNS server will use these
    /// forwarders for queries not resolved by the local database.
    /// gRPC path: /rolodex.RolodexService/SetForwarders
    #[command(name = "set-forwarders")]
    SetForwarders {
        /// Upstream DNS server addresses in "host:port" format.
        /// Provide multiple addresses separated by spaces.
        /// Example: --forwarders 8.8.8.8:53 1.1.1.1:53
        #[arg(short, long, num_args = 1..)]
        forwarders: Vec<String>,
    },

    /// Configure RBL (Realtime Blackhole List) settings at runtime.
    /// Replaces the entire RBL configuration including the global enable
    /// flag and all providers.
    /// gRPC path: /rolodex.RolodexService/SetRblConfig
    #[command(name = "set-rbl-config")]
    SetRblConfig {
        /// Enable or disable RBL checking globally.
        /// When disabled, no reverse DNS queries are checked against RBL providers.
        /// Default: false
        #[arg(short, long)]
        enabled: bool,

        /// RBL provider specifications in "zone:enabled" format.
        /// The "enabled" part is a boolean (true/false) controlling whether
        /// this specific provider is active.
        /// Example: --providers "zen.spamhaus.org:true" "bl.spamcop.net:false"
        #[arg(short, long, num_args = 0..)]
        providers: Vec<String>,
    },

    /// Retrieve the current RBL configuration.
    /// Shows the global enabled state and all configured providers.
    /// gRPC path: /rolodex.RolodexService/GetRblConfig
    #[command(name = "get-rbl-config")]
    GetRblConfig,

    /// Flush the RBL result cache.
    /// Clears all cached RBL lookup results, forcing fresh lookups
    /// for subsequent reverse DNS queries.
    /// gRPC path: /rolodex.RolodexService/FlushCache
    #[command(name = "flush-cache")]
    FlushCache,

    /// Create a new network scope with a reserved .home domain.
    /// Each scope defines a DNS view that associates IPs with scoped records.
    /// gRPC path: /rolodex.RolodexService/CreateNetworkScope
    #[command(name = "create-scope")]
    CreateScope {
        /// Unique name for the network scope (e.g. "office", "lab")
        #[arg(short, long)]
        name: String,

        /// Reserved .home domain for this scope.
        /// If omitted, defaults to "<name>.home" (e.g. "office.home").
        /// Used as the default search domain for DHCP clients in this network.
        #[arg(short = 'd', long)]
        home_domain: Option<String>,
    },

    /// Delete a network scope and all its records and associations.
    /// gRPC path: /rolodex.RolodexService/DeleteNetworkScope
    #[command(name = "delete-scope")]
    DeleteScope {
        /// Name of the scope to delete
        #[arg(short, long)]
        name: String,
    },

    /// List all configured network scopes.
    /// gRPC path: /rolodex.RolodexService/ListNetworkScopes
    #[command(name = "list-scopes")]
    ListScopes,

    /// Associate an IP address with a network scope ("join the network").
    /// The association has a TTL that must be refreshed to maintain DNS
    /// resolution. If the TTL expires, the DNS server stops resolving
    /// queries from this IP.
    /// gRPC path: /rolodex.RolodexService/JoinNetwork
    #[command(name = "join-network")]
    JoinNetwork {
        /// The client IP address to associate (e.g. "192.168.1.100")
        #[arg(short, long)]
        ip: String,

        /// The network scope name to join
        #[arg(short, long)]
        scope: String,

        /// TTL in seconds for this association. Must be refreshed before expiry.
        /// Default: 300 seconds
        #[arg(long, default_value = "300")]
        ttl: u64,
    },

    /// Remove an IP address's association with its network scope ("leave the network").
    /// gRPC path: /rolodex.RolodexService/LeaveNetwork
    #[command(name = "leave-network")]
    LeaveNetwork {
        /// The client IP address to disassociate
        #[arg(short, long)]
        ip: String,
    },

    /// List IP-to-scope associations.
    /// gRPC path: /rolodex.RolodexService/GetNetworkAssociations
    #[command(name = "list-associations")]
    ListAssociations {
        /// Filter by scope name. If omitted, lists all associations.
        #[arg(short, long)]
        scope: Option<String>,
    },

    /// Add a DNS record within a specific network scope.
    /// Scoped records are only visible to IPs associated with the scope.
    /// gRPC path: /rolodex.RolodexService/AddScopedRecord
    #[command(name = "add-scoped-record")]
    AddScopedRecord {
        /// The network scope name to add the record to
        #[arg(short, long)]
        scope: String,

        /// Fully qualified domain name
        #[arg(short, long)]
        name: String,

        /// DNS record type
        #[arg(short = 'r', long, value_enum, default_value = "a")]
        record_type: RecordTypeArg,

        /// Record data (format depends on record type)
        #[arg(short, long)]
        value: String,

        /// Time-to-live in seconds. Default: 300
        #[arg(long, default_value = "300")]
        ttl: u32,

        /// Priority for MX and SRV records. Default: 0
        #[arg(short, long, default_value = "0")]
        priority: u32,
    },

    /// Remove DNS record(s) from a specific network scope.
    /// gRPC path: /rolodex.RolodexService/RemoveScopedRecord
    #[command(name = "remove-scoped-record")]
    RemoveScopedRecord {
        /// The network scope name
        #[arg(short, long)]
        scope: String,

        /// Fully qualified domain name to remove records for
        #[arg(short, long)]
        name: String,

        /// If specified, only remove records of this type
        #[arg(short = 'r', long, value_enum)]
        record_type: Option<RecordTypeArg>,

        /// If specified, only remove the record with this exact value
        #[arg(short, long)]
        value: Option<String>,
    },

    /// List DNS records within a network scope.
    /// gRPC path: /rolodex.RolodexService/ListScopedRecords
    #[command(name = "list-scoped-records")]
    ListScopedRecords {
        /// The network scope name
        #[arg(short, long)]
        scope: String,

        /// Filter by domain name (supports wildcard prefix "*.")
        #[arg(short, long)]
        name: Option<String>,

        /// Filter by record type
        #[arg(short = 'r', long, value_enum)]
        record_type: Option<RecordTypeArg>,
    },

    /// Get the search domains for a client IP address.
    /// Returns the .home domain of the scope the IP is associated with.
    /// gRPC path: /rolodex.RolodexService/GetSearchDomains
    #[command(name = "get-search-domains")]
    GetSearchDomains {
        /// The IP address to look up search domains for
        #[arg(short, long)]
        ip: String,
    },

    /// Add an authoritative zone declaration.
    /// gRPC path: /rolodex.RolodexService/AddAuthoritativeZone
    #[command(name = "add-auth-zone")]
    AddAuthZone {
        /// The zone name (e.g. "example.com.")
        #[arg(short, long)]
        zone: String,
    },

    /// Remove an authoritative zone declaration.
    /// gRPC path: /rolodex.RolodexService/RemoveAuthoritativeZone
    #[command(name = "remove-auth-zone")]
    RemoveAuthZone {
        /// The zone name to remove
        #[arg(short, long)]
        zone: String,
    },

    /// List all authoritative zone declarations.
    /// gRPC path: /rolodex.RolodexService/ListAuthoritativeZones
    #[command(name = "list-auth-zones")]
    ListAuthZones,

    /// Flush the DNS response cache.
    /// gRPC path: /rolodex.RolodexService/FlushDnsCache
    #[command(name = "flush-dns-cache")]
    FlushDnsCache,

    /// Get DNS cache statistics.
    /// gRPC path: /rolodex.RolodexService/GetCacheStats
    #[command(name = "cache-stats")]
    CacheStats,

    /// Add a local RBL entry.
    /// gRPC path: /rolodex.RolodexService/AddLocalRblEntry
    #[command(name = "add-local-rbl")]
    AddLocalRbl {
        /// The name or IP to block
        #[arg(short, long)]
        name: String,

        /// Reason for blocking
        #[arg(short, long, default_value = "")]
        reason: String,
    },

    /// Remove a local RBL entry.
    /// gRPC path: /rolodex.RolodexService/RemoveLocalRblEntry
    #[command(name = "remove-local-rbl")]
    RemoveLocalRbl {
        /// The name to unblock
        #[arg(short, long)]
        name: String,
    },

    /// List all local RBL entries.
    /// gRPC path: /rolodex.RolodexService/ListLocalRblEntries
    #[command(name = "list-local-rbl")]
    ListLocalRbl,

    /// Set TTL drift configuration.
    /// gRPC path: /rolodex.RolodexService/SetTtlDriftConfig
    #[command(name = "set-ttl-drift")]
    SetTtlDrift {
        /// Drift mode: "disabled", "fixed", or "logarithmic"
        #[arg(short, long)]
        mode: String,
        /// Fixed adjustment (e.g. "+5m", "-30s"). Only used in "fixed" mode.
        #[arg(short, long, default_value = "0s")]
        adjustment: String,
        /// Logarithmic multiplier. Only used in "logarithmic" mode.
        #[arg(short, long, default_value_t = 0.1)]
        log_multiplier: f64,
    },

    /// Get current TTL drift configuration.
    /// gRPC path: /rolodex.RolodexService/GetTtlDriftConfig
    #[command(name = "get-ttl-drift")]
    GetTtlDrift,

    /// Get query latency statistics for upstream servers.
    /// gRPC path: /rolodex.RolodexService/GetQueryLatencyStats
    #[command(name = "latency-stats")]
    LatencyStats,

    /// Set DNS64 configuration.
    /// gRPC path: /rolodex.RolodexService/SetDns64Config
    #[command(name = "set-dns64")]
    SetDns64 {
        /// Enable or disable DNS64 synthesis.
        #[arg(short, long)]
        enabled: bool,
        /// IPv6 prefix for AAAA synthesis (e.g. "64:ff9b::").
        #[arg(short, long, default_value = "64:ff9b::")]
        prefix: String,
    },

    /// Get current DNS64 configuration.
    /// gRPC path: /rolodex.RolodexService/GetDns64Config
    #[command(name = "get-dns64")]
    GetDns64,

    /// Generate a DNSSEC key pair for a zone.
    /// gRPC path: /rolodex.RolodexService/GenerateDnssecKey
    #[command(name = "generate-dnssec-key")]
    GenerateDnssecKey {
        /// The DNS zone to generate a key for (e.g. "example.com.")
        #[arg(short, long)]
        zone: String,
        /// Algorithm: "ed25519", "ecdsa-p256", "ecdsa-p384", "rsa-sha256"
        #[arg(short, long, default_value = "ed25519")]
        algorithm: String,
        /// Key type: "ZSK" or "KSK"
        #[arg(short, long, default_value = "ZSK")]
        key_type: String,
    },

    /// List DNSSEC keys for a zone.
    /// gRPC path: /rolodex.RolodexService/ListDnssecKeys
    #[command(name = "list-dnssec-keys")]
    ListDnssecKeys {
        /// The DNS zone to list keys for
        #[arg(short, long)]
        zone: String,
    },

    /// Sign a zone with DNSSEC.
    /// gRPC path: /rolodex.RolodexService/SignZone
    #[command(name = "sign-zone")]
    SignZone {
        /// The DNS zone to sign
        #[arg(short, long)]
        zone: String,
    },

    /// Generate a DANE TLSA record from a certificate.
    /// gRPC path: /rolodex.RolodexService/GenerateTlsaRecord
    #[command(name = "generate-tlsa")]
    GenerateTlsa {
        /// Domain name for the TLSA record
        #[arg(short, long)]
        domain: String,
        /// Port number
        #[arg(short, long)]
        port: u32,
        /// Protocol (e.g. "tcp")
        #[arg(long, default_value = "tcp")]
        protocol: String,
        /// Path to certificate PEM file
        #[arg(short, long)]
        cert_path: String,
        /// TLSA usage: 0-3 (default: 3 for domain-issued)
        #[arg(long, default_value_t = 3)]
        usage: u32,
        /// TLSA selector: 0 (full cert) or 1 (SPKI)
        #[arg(long, default_value_t = 0)]
        selector: u32,
        /// TLSA matching type: 0 (exact), 1 (SHA-256), 2 (SHA-512)
        #[arg(long, default_value_t = 1)]
        matching_type: u32,
    },

    /// Request an ACME certificate via DNS-01 challenge.
    /// gRPC path: /rolodex.RolodexService/RequestAcmeCert
    #[command(name = "request-acme-cert")]
    RequestAcmeCert {
        /// Domain to request a certificate for
        #[arg(short, long)]
        domain: String,
        /// ACME provider URL (e.g. Let's Encrypt)
        #[arg(short, long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
        provider_url: String,
    },

    /// Get ACME certificate status for a domain.
    /// gRPC path: /rolodex.RolodexService/GetAcmeStatus
    #[command(name = "acme-status")]
    AcmeStatus {
        /// Domain to check status for
        #[arg(short, long)]
        domain: String,
    },
}

async fn connect(cli: &Cli) -> Result<RolodexServiceClient<Channel>> {
    if let Some(ref socket_path) = cli.unix_socket {
        let socket_path = socket_path.clone();
        let channel = Endpoint::try_from("http://[::]:50051")
            .context("failed to create endpoint")?
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = socket_path.clone();
                async move {
                    let stream = tokio::net::UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await
            .context("failed to connect to Unix socket")?;
        Ok(RolodexServiceClient::new(channel))
    } else {
        let addr = format!("http://{}", cli.address);
        let channel = Channel::from_shared(addr.clone())
            .context("invalid address")?
            .connect()
            .await
            .context(format!("failed to connect to {}", addr))?;
        Ok(RolodexServiceClient::new(channel))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut client = connect(&cli).await?;

    match cli.command {
        Commands::AddRecord {
            name,
            record_type,
            value,
            ttl,
            priority,
        } => {
            let response = client
                .add_record(AddRecordRequest {
                    record: Some(DnsRecord {
                        name: name.clone(),
                        record_type: record_type.to_proto_i32(),
                        value: value.clone(),
                        ttl,
                        priority,
                    }),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("add-record RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!(
                    "Added record: {} {} {} (TTL: {}, Priority: {})",
                    name,
                    RecordTypeArg::from_proto_i32(record_type.to_proto_i32()),
                    value,
                    ttl,
                    priority
                );
            } else {
                anyhow::bail!("Failed to add record: {}", resp.message);
            }
        }

        Commands::RemoveRecord {
            name,
            record_type,
            value,
        } => {
            let response = client
                .remove_record(RemoveRecordRequest {
                    name: name.clone(),
                    record_type: record_type.map(|r| r.to_proto_i32()).unwrap_or(0),
                    value: value.clone().unwrap_or_default(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("remove-record RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!(
                    "Removed {} record(s) for {}",
                    resp.removed_count, name
                );
            } else {
                anyhow::bail!("Failed to remove records: {}", resp.message);
            }
        }

        Commands::ListRecords { name, record_type } => {
            let response = client
                .list_records(ListRecordsRequest {
                    name_filter: name.unwrap_or_default(),
                    record_type_filter: record_type.map(|r| r.to_proto_i32()).unwrap_or(0),
                    filter_by_type: record_type.is_some(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("list-records RPC failed")?;
            let records = response.into_inner().records;
            if records.is_empty() {
                println!("No records found.");
            } else {
                println!(
                    "{:<40} {:<8} {:<40} {:<6} {}",
                    "NAME", "TYPE", "VALUE", "TTL", "PRIORITY"
                );
                println!("{}", "-".repeat(100));
                for r in &records {
                    println!(
                        "{:<40} {:<8} {:<40} {:<6} {}",
                        r.name,
                        RecordTypeArg::from_proto_i32(r.record_type),
                        r.value,
                        r.ttl,
                        r.priority
                    );
                }
                println!("\n{} record(s) found.", records.len());
            }
        }

        Commands::SetForwarders { forwarders } => {
            let response = client
                .set_forwarders(SetForwarderRequest {
                    forwarders: forwarders.clone(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("set-forwarders RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("Forwarders updated: {}", forwarders.join(", "));
            } else {
                anyhow::bail!("Failed to set forwarders: {}", resp.message);
            }
        }

        Commands::SetRblConfig { enabled, providers } => {
            let mut rbl_providers = Vec::new();
            for p in &providers {
                let parts: Vec<&str> = p.rsplitn(2, ':').collect();
                if parts.len() != 2 {
                    anyhow::bail!(
                        "Invalid provider format '{}'. Expected 'zone:enabled' (e.g. 'zen.spamhaus.org:true')",
                        p
                    );
                }
                let enabled_flag: bool = parts[0].parse().context(format!(
                    "Invalid enabled value '{}' in provider '{}'. Expected 'true' or 'false'",
                    parts[0], p
                ))?;
                rbl_providers.push(RblConfig {
                    zone: parts[1].to_string(),
                    enabled: enabled_flag,
                });
            }
            let response = client
                .set_rbl_config(SetRblConfigRequest {
                    enabled,
                    providers: rbl_providers,
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("set-rbl-config RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("RBL config updated (enabled: {})", enabled);
            } else {
                anyhow::bail!("Failed to set RBL config: {}", resp.message);
            }
        }

        Commands::GetRblConfig => {
            let response = client
                .get_rbl_config(GetRblConfigRequest {
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("get-rbl-config RPC failed")?;
            let config = response.into_inner();
            println!("RBL enabled: {}", config.enabled);
            if config.providers.is_empty() {
                println!("No RBL providers configured.");
            } else {
                println!("\nProviders:");
                println!("{:<40} {}", "ZONE", "ENABLED");
                println!("{}", "-".repeat(50));
                for p in &config.providers {
                    println!("{:<40} {}", p.zone, p.enabled);
                }
            }
        }

        Commands::FlushCache => {
            let response = client
                .flush_cache(FlushCacheRequest {
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("flush-cache RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("Cache flushed successfully.");
            } else {
                anyhow::bail!("Failed to flush cache: {}", resp.message);
            }
        }

        Commands::CreateScope { name, home_domain } => {
            let response = client
                .create_network_scope(CreateNetworkScopeRequest {
                    scope: Some(rolodex::grpc_service::proto::NetworkScope {
                        name: name.clone(),
                        home_domain: home_domain.unwrap_or_default(),
                    }),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("create-scope RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("Created network scope: {}", name);
            } else {
                anyhow::bail!("Failed to create scope: {}", resp.message);
            }
        }

        Commands::DeleteScope { name } => {
            let response = client
                .delete_network_scope(DeleteNetworkScopeRequest {
                    name: name.clone(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("delete-scope RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("Deleted network scope: {}", name);
            } else {
                anyhow::bail!("Failed to delete scope: {}", resp.message);
            }
        }

        Commands::ListScopes => {
            let response = client
                .list_network_scopes(ListNetworkScopesRequest {
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("list-scopes RPC failed")?;
            let scopes = response.into_inner().scopes;
            if scopes.is_empty() {
                println!("No network scopes configured.");
            } else {
                println!("{:<30} {}", "NAME", "HOME DOMAIN");
                println!("{}", "-".repeat(60));
                for s in &scopes {
                    println!("{:<30} {}", s.name, s.home_domain);
                }
                println!("\n{} scope(s) found.", scopes.len());
            }
        }

        Commands::JoinNetwork { ip, scope, ttl } => {
            let response = client
                .join_network(JoinNetworkRequest {
                    ip_address: ip.clone(),
                    scope_name: scope.clone(),
                    ttl_seconds: ttl,
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("join-network RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("IP {} joined scope '{}' (TTL: {}s)", ip, scope, ttl);
            } else {
                anyhow::bail!("Failed to join network: {}", resp.message);
            }
        }

        Commands::LeaveNetwork { ip } => {
            let response = client
                .leave_network(LeaveNetworkRequest {
                    ip_address: ip.clone(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("leave-network RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("IP {} left network", ip);
            } else {
                anyhow::bail!("Failed to leave network: {}", resp.message);
            }
        }

        Commands::ListAssociations { scope } => {
            let response = client
                .get_network_associations(GetNetworkAssociationsRequest {
                    scope_name: scope.unwrap_or_default(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("list-associations RPC failed")?;
            let assocs = response.into_inner().associations;
            if assocs.is_empty() {
                println!("No network associations found.");
            } else {
                println!("{:<20} {:<20} {}", "IP ADDRESS", "SCOPE", "TTL");
                println!("{}", "-".repeat(50));
                for a in &assocs {
                    println!("{:<20} {:<20} {}", a.ip_address, a.scope_name, a.ttl_seconds);
                }
                println!("\n{} association(s) found.", assocs.len());
            }
        }

        Commands::AddScopedRecord {
            scope,
            name,
            record_type,
            value,
            ttl,
            priority,
        } => {
            let response = client
                .add_scoped_record(AddScopedRecordRequest {
                    scope_name: scope.clone(),
                    record: Some(DnsRecord {
                        name: name.clone(),
                        record_type: record_type.to_proto_i32(),
                        value: value.clone(),
                        ttl,
                        priority,
                    }),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("add-scoped-record RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!(
                    "Added scoped record in '{}': {} {} {} (TTL: {}, Priority: {})",
                    scope,
                    name,
                    RecordTypeArg::from_proto_i32(record_type.to_proto_i32()),
                    value,
                    ttl,
                    priority
                );
            } else {
                anyhow::bail!("Failed to add scoped record: {}", resp.message);
            }
        }

        Commands::RemoveScopedRecord {
            scope,
            name,
            record_type,
            value,
        } => {
            let response = client
                .remove_scoped_record(RemoveScopedRecordRequest {
                    scope_name: scope.clone(),
                    name: name.clone(),
                    record_type: record_type.map(|r| r.to_proto_i32()).unwrap_or(0),
                    value: value.unwrap_or_default(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("remove-scoped-record RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!(
                    "Removed {} scoped record(s) from '{}' for {}",
                    resp.removed_count, scope, name
                );
            } else {
                anyhow::bail!("Failed to remove scoped records: {}", resp.message);
            }
        }

        Commands::ListScopedRecords {
            scope,
            name,
            record_type,
        } => {
            let response = client
                .list_scoped_records(ListScopedRecordsRequest {
                    scope_name: scope.clone(),
                    name_filter: name.unwrap_or_default(),
                    record_type_filter: record_type.map(|r| r.to_proto_i32()).unwrap_or(0),
                    filter_by_type: record_type.is_some(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("list-scoped-records RPC failed")?;
            let records = response.into_inner().records;
            if records.is_empty() {
                println!("No scoped records found in '{}'.", scope);
            } else {
                println!(
                    "{:<40} {:<8} {:<40} {:<6} {}",
                    "NAME", "TYPE", "VALUE", "TTL", "PRIORITY"
                );
                println!("{}", "-".repeat(100));
                for r in &records {
                    println!(
                        "{:<40} {:<8} {:<40} {:<6} {}",
                        r.name,
                        RecordTypeArg::from_proto_i32(r.record_type),
                        r.value,
                        r.ttl,
                        r.priority
                    );
                }
                println!("\n{} record(s) found in scope '{}'.", records.len(), scope);
            }
        }

        Commands::GetSearchDomains { ip } => {
            let response = client
                .get_search_domains(GetSearchDomainsRequest {
                    ip_address: ip.clone(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("get-search-domains RPC failed")?;
            let domains = response.into_inner().search_domains;
            if domains.is_empty() {
                println!("No search domains for IP {}.", ip);
            } else {
                println!("Search domains for {}:", ip);
                for d in &domains {
                    println!("  {}", d);
                }
            }
        }

        Commands::AddAuthZone { zone } => {
            let response = client
                .add_authoritative_zone(AddAuthoritativeZoneRequest {
                    zone: zone.clone(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("add-auth-zone RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("Added authoritative zone: {}", zone);
            } else {
                anyhow::bail!("Failed to add authoritative zone: {}", resp.message);
            }
        }

        Commands::RemoveAuthZone { zone } => {
            let response = client
                .remove_authoritative_zone(RemoveAuthoritativeZoneRequest {
                    zone: zone.clone(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("remove-auth-zone RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("Removed authoritative zone: {}", zone);
            } else {
                anyhow::bail!("Failed to remove authoritative zone: {}", resp.message);
            }
        }

        Commands::ListAuthZones => {
            let response = client
                .list_authoritative_zones(ListAuthoritativeZonesRequest {
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("list-auth-zones RPC failed")?;
            let zones = response.into_inner().zones;
            if zones.is_empty() {
                println!("No authoritative zones configured.");
            } else {
                println!("Authoritative zones:");
                for z in &zones {
                    println!("  {}", z);
                }
                println!("\n{} zone(s) found.", zones.len());
            }
        }

        Commands::FlushDnsCache => {
            let response = client
                .flush_dns_cache(FlushDnsCacheRequest {
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("flush-dns-cache RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("DNS cache flushed successfully.");
            } else {
                anyhow::bail!("Failed to flush DNS cache: {}", resp.message);
            }
        }

        Commands::CacheStats => {
            let response = client
                .get_cache_stats(GetCacheStatsRequest {
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("cache-stats RPC failed")?;
            let stats = response.into_inner();
            println!("DNS Cache Statistics:");
            println!("  Total entries: {}", stats.total_entries);
            println!("  Hit count:     {}", stats.hit_count);
            println!("  Miss count:    {}", stats.miss_count);
        }

        Commands::AddLocalRbl { name, reason } => {
            let response = client
                .add_local_rbl_entry(AddLocalRblEntryRequest {
                    entry: Some(LocalRblEntry {
                        name: name.clone(),
                        reason: reason.clone(),
                    }),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("add-local-rbl RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("Added local RBL entry: {}", name);
            } else {
                anyhow::bail!("Failed to add local RBL entry: {}", resp.message);
            }
        }

        Commands::RemoveLocalRbl { name } => {
            let response = client
                .remove_local_rbl_entry(RemoveLocalRblEntryRequest {
                    name: name.clone(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("remove-local-rbl RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("Removed local RBL entry: {}", name);
            } else {
                anyhow::bail!("Failed to remove local RBL entry: {}", resp.message);
            }
        }

        Commands::ListLocalRbl => {
            let response = client
                .list_local_rbl_entries(ListLocalRblEntriesRequest {
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("list-local-rbl RPC failed")?;
            let entries = response.into_inner().entries;
            if entries.is_empty() {
                println!("No local RBL entries configured.");
            } else {
                println!("{:<40} {}", "NAME", "REASON");
                println!("{}", "-".repeat(60));
                for e in &entries {
                    println!("{:<40} {}", e.name, e.reason);
                }
                println!("\n{} entry(ies) found.", entries.len());
            }
        }

        Commands::SetTtlDrift { mode, adjustment, log_multiplier } => {
            let response = client
                .set_ttl_drift_config(SetTtlDriftConfigRequest {
                    config: Some(TtlDriftConfig {
                        mode: mode.clone(),
                        fixed_adjustment: adjustment.clone(),
                        log_multiplier,
                    }),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("set-ttl-drift RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("TTL drift config updated: mode={}", mode);
            } else {
                anyhow::bail!("Failed to set TTL drift config: {}", resp.message);
            }
        }

        Commands::GetTtlDrift => {
            let response = client
                .get_ttl_drift_config(GetTtlDriftConfigRequest {
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("get-ttl-drift RPC failed")?;
            let resp = response.into_inner();
            if let Some(config) = resp.config {
                println!("TTL Drift Configuration:");
                println!("  Mode:             {}", config.mode);
                println!("  Fixed adjustment: {}", config.fixed_adjustment);
                println!("  Log multiplier:   {}", config.log_multiplier);
            } else {
                println!("TTL drift not configured.");
            }
        }

        Commands::LatencyStats => {
            let response = client
                .get_query_latency_stats(GetQueryLatencyStatsRequest {
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("latency-stats RPC failed")?;
            let stats = response.into_inner().stats;
            if stats.is_empty() {
                println!("No latency statistics available.");
            } else {
                println!("{:<30} {:<15} {}", "SERVER", "AVG LATENCY MS", "QUERY COUNT");
                println!("{}", "-".repeat(60));
                for s in &stats {
                    println!("{:<30} {:<15.2} {}", s.server, s.avg_latency_ms, s.query_count);
                }
            }
        }

        Commands::SetDns64 { enabled, prefix } => {
            let response = client
                .set_dns64_config(SetDns64ConfigRequest {
                    config: Some(Dns64Config {
                        enabled,
                        prefix: prefix.clone(),
                    }),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("set-dns64 RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("DNS64 config updated: enabled={}, prefix={}", enabled, prefix);
            } else {
                anyhow::bail!("Failed to set DNS64 config: {}", resp.message);
            }
        }

        Commands::GetDns64 => {
            let response = client
                .get_dns64_config(GetDns64ConfigRequest {
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("get-dns64 RPC failed")?;
            let resp = response.into_inner();
            if let Some(config) = resp.config {
                println!("DNS64 Configuration:");
                println!("  Enabled: {}", config.enabled);
                println!("  Prefix:  {}", config.prefix);
            } else {
                println!("DNS64 not configured.");
            }
        }

        Commands::GenerateDnssecKey { zone, algorithm, key_type } => {
            let response = client
                .generate_dnssec_key(GenerateDnssecKeyRequest {
                    zone: zone.clone(),
                    algorithm: algorithm.clone(),
                    key_type: key_type.clone(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("generate-dnssec-key RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                if let Some(key) = resp.key {
                    println!("Generated DNSSEC key for {}:", zone);
                    println!("  Algorithm: {}", key.algorithm);
                    println!("  Key type:  {}", key.key_type);
                    println!("  Key tag:   {}", key.key_tag);
                    println!("  ID:        {}", key.id);
                }
            } else {
                anyhow::bail!("Failed to generate DNSSEC key: {}", resp.message);
            }
        }

        Commands::ListDnssecKeys { zone } => {
            let response = client
                .list_dnssec_keys(ListDnssecKeysRequest {
                    zone: zone.clone(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("list-dnssec-keys RPC failed")?;
            let keys = response.into_inner().keys;
            if keys.is_empty() {
                println!("No DNSSEC keys found for {}.", zone);
            } else {
                println!("{:<10} {:<15} {:<6} {:<10}", "ID", "ALGORITHM", "TYPE", "KEY TAG");
                println!("{}", "-".repeat(50));
                for k in &keys {
                    println!("{:<10} {:<15} {:<6} {:<10}", k.id, k.algorithm, k.key_type, k.key_tag);
                }
                println!("\n{} key(s) found.", keys.len());
            }
        }

        Commands::SignZone { zone } => {
            let response = client
                .sign_zone(SignZoneRequest {
                    zone: zone.clone(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("sign-zone RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("Zone {} signed successfully.", zone);
            } else {
                anyhow::bail!("Failed to sign zone: {}", resp.message);
            }
        }

        Commands::GenerateTlsa { domain, port, protocol, cert_path, usage, selector, matching_type } => {
            let cert_pem = std::fs::read_to_string(&cert_path)
                .context(format!("failed to read certificate file: {}", cert_path))?;
            let response = client
                .generate_tlsa_record(GenerateTlsaRecordRequest {
                    domain: domain.clone(),
                    port,
                    protocol: protocol.clone(),
                    cert_pem,
                    usage,
                    selector,
                    matching_type,
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("generate-tlsa RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("TLSA record generated:");
                println!("  {}", resp.tlsa_record);
            } else {
                anyhow::bail!("Failed to generate TLSA record: {}", resp.message);
            }
        }

        Commands::RequestAcmeCert { domain, provider_url } => {
            let response = client
                .request_acme_cert(RequestAcmeCertRequest {
                    domain: domain.clone(),
                    provider_url: provider_url.clone(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("request-acme-cert RPC failed")?;
            let resp = response.into_inner();
            if resp.success {
                println!("ACME certificate requested for {}.", domain);
            } else {
                anyhow::bail!("Failed to request ACME certificate: {}", resp.message);
            }
        }

        Commands::AcmeStatus { domain } => {
            let response = client
                .get_acme_status(GetAcmeStatusRequest {
                    domain: domain.clone(),
                    auth_token: cli.auth_token.clone(),
                })
                .await
                .context("acme-status RPC failed")?;
            let resp = response.into_inner();
            println!("ACME Status for {}:", domain);
            println!("  Status:  {}", resp.status);
            println!("  Domain:  {}", resp.domain);
            if resp.expires_at > 0 {
                println!("  Expires: {}", resp.expires_at);
            }
        }
    }

    Ok(())
}
