use anyhow::{Context, Result};
use clap::Parser;
use rolodex::config::Config;
use rolodex::db::Database;
use rolodex::dns_server::DnsServer;
use rolodex::grpc_service::proto::rolodex_service_server::RolodexServiceServer;
use rolodex::grpc_service::RolodexGrpcService;
use rolodex::rbl::{RblChecker, RblProvider};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UnixListener;
use tonic::transport::Server;
use tracing::{error, info};

/// Rolodex - Split-horizon DNS server with gRPC management
#[derive(Parser)]
#[command(name = "rolodex")]
#[command(about = "A split-horizon DNS server and forwarding resolver")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "rolodex.yml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rolodex=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    let config = if std::path::Path::new(&cli.config).exists() {
        let content =
            std::fs::read_to_string(&cli.config).context("failed to read config file")?;
        serde_yaml_ng::from_str(&content).context("failed to parse config file")?
    } else {
        info!("No config file found, using defaults");
        Config::default()
    };

    let db = Database::open(&config.database_path).context("failed to open database")?;

    let rbl_providers: Vec<RblProvider> = config
        .rbl
        .providers
        .iter()
        .map(|p| RblProvider {
            zone: p.zone.clone(),
            enabled: p.enabled,
        })
        .collect();
    let rbl = Arc::new(RblChecker::new(config.rbl.enabled, rbl_providers));

    let forwarders: Vec<SocketAddr> = config
        .forwarders
        .iter()
        .filter_map(|f| f.parse().ok())
        .collect();
    let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), forwarders));

    // Spawn DNS UDP server
    let udp_server = Arc::clone(&dns_server);
    let udp_bind = config.dns.udp_bind.clone();
    tokio::spawn(async move {
        if let Err(e) = udp_server.serve_udp(&udp_bind).await {
            error!("DNS UDP server error: {}", e);
        }
    });

    // Spawn DNS TCP server
    let tcp_server = Arc::clone(&dns_server);
    let tcp_bind = config.dns.tcp_bind.clone();
    tokio::spawn(async move {
        if let Err(e) = tcp_server.serve_tcp(&tcp_bind).await {
            error!("DNS TCP server error: {}", e);
        }
    });

    // Spawn gRPC TCP server
    if !config.grpc.tcp_bind.is_empty() {
        let grpc_service = RolodexGrpcService::new(
            db.clone(),
            Arc::clone(&dns_server),
            rbl.clone(),
            config.grpc.shared_secret.clone(),
            false,
        );
        let addr: SocketAddr = config.grpc.tcp_bind.parse().context("invalid gRPC TCP bind address")?;
        info!("gRPC TCP server listening on {}", addr);
        tokio::spawn(async move {
            if let Err(e) = Server::builder()
                .add_service(RolodexServiceServer::new(grpc_service))
                .serve(addr)
                .await
            {
                error!("gRPC TCP server error: {}", e);
            }
        });
    }

    // Spawn gRPC Unix socket server
    if !config.grpc.unix_socket.is_empty() {
        let socket_path = config.grpc.unix_socket.clone();
        // Remove stale socket file if it exists
        let _ = std::fs::remove_file(&socket_path);

        let uds = UnixListener::bind(&socket_path).context("failed to bind Unix socket")?;
        let uds_stream = tokio_stream::wrappers::UnixListenerStream::new(uds);

        let grpc_service = RolodexGrpcService::new(
            db.clone(),
            Arc::clone(&dns_server),
            rbl.clone(),
            config.grpc.shared_secret.clone(),
            true,
        );
        info!("gRPC Unix socket server listening on {}", socket_path);
        tokio::spawn(async move {
            if let Err(e) = Server::builder()
                .add_service(RolodexServiceServer::new(grpc_service))
                .serve_with_incoming(uds_stream)
                .await
            {
                error!("gRPC Unix socket server error: {}", e);
            }
        });
    }

    info!("Rolodex DNS server started");

    // Wait forever
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;
    info!("Shutting down");

    Ok(())
}
