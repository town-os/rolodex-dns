use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rolodex::grpc_service::proto::rolodex_service_client::RolodexServiceClient;
use rolodex::grpc_service::proto::{
    AddRecordRequest, DnsRecord, FlushCacheRequest, GetRblConfigRequest, ListRecordsRequest,
    RblConfig, RemoveRecordRequest, SetForwarderRequest, SetRblConfigRequest,
};
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
    }

    Ok(())
}
