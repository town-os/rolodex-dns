#![deny(dead_code)]
#![deny(unsafe_code)]

use anyhow::{Context, Result};
use clap::Parser;
use rolodex_dns::config::Config;
use rolodex_dns::db::Database;
use rolodex_dns::dns_cache::DnsCache;
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::grpc_service::RolodexDnsGrpcService;
use rolodex_dns::grpc_service::proto::rolodex_dns_service_server::RolodexDnsServiceServer;
use rolodex_dns::rbl::{RblChecker, RblProvider};
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UnixListener;
use tonic::transport::Server;
use tracing::{error, info};

/// Rolodex DNS - Split-horizon DNS server with gRPC management
#[derive(Parser)]
#[command(name = "rolodex-dns")]
#[command(about = "A split-horizon DNS server and forwarding resolver")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "rolodex-dns.yml")]
    config: String,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let directive = "rolodex_dns=info"
        .parse()
        .context("failed to parse tracing directive")?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive(directive))
        .init();

    let cli = Cli::parse();

    let config = if std::path::Path::new(&cli.config).exists() {
        let content = std::fs::read_to_string(&cli.config).context("failed to read config file")?;
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

    // Initialize DNS cache (load_from_disk happens automatically in new())
    let dns_cache = Arc::new(DnsCache::new(db.clone()));
    info!(
        "DNS cache loaded ({} entries)",
        dns_cache.stats().total_entries
    );

    // Parse DNS64 prefix if enabled
    let dns64_prefix = if config.dns64.enabled {
        match config.dns64.prefix.parse::<Ipv6Addr>() {
            Ok(prefix) => {
                info!("DNS64 enabled with prefix {}", prefix);
                Some(prefix)
            }
            Err(e) => {
                error!("Invalid DNS64 prefix '{}': {}", config.dns64.prefix, e);
                None
            }
        }
    } else {
        None
    };

    let dns_server = Arc::new(DnsServer::new_with_options(
        db.clone(),
        rbl.clone(),
        forwarders,
        Some(dns_cache),
        dns64_prefix,
        config.security.qname_case_randomization,
    ));

    // Apply proxy configuration if set
    if let Some(ref proxy_cfg) = config.proxy
        && !proxy_cfg.url.is_empty()
    {
        let runtime_proxy = rolodex_dns::doh_proxy::ProxyConfig::from(proxy_cfg);
        info!(
            "Proxy configured: {} (mode: {})",
            proxy_cfg.url,
            runtime_proxy.mode.as_str()
        );
        dns_server.set_proxy_config(Some(runtime_proxy));
    }

    // Spawn DNS UDP servers
    for udp_bind in config.dns.udp_bind.clone() {
        let udp_server = Arc::clone(&dns_server);
        tokio::spawn(async move {
            if let Err(e) = udp_server.serve_udp(&udp_bind).await {
                error!("DNS UDP server error on {}: {}", udp_bind, e);
            }
        });
    }

    // Spawn DNS TCP servers
    for tcp_bind in config.dns.tcp_bind.clone() {
        let tcp_server = Arc::clone(&dns_server);
        tokio::spawn(async move {
            if let Err(e) = tcp_server.serve_tcp(&tcp_bind).await {
                error!("DNS TCP server error on {}: {}", tcp_bind, e);
            }
        });
    }

    // Spawn DNS-over-TLS (DoT) server if configured
    if let Some(ref dot_config) = config.dot {
        let tls_cfg = rolodex_dns::tls::TlsConfig {
            cert_path: dot_config.tls.cert_path.clone(),
            key_path: dot_config.tls.key_path.clone(),
            auto_self_signed: dot_config.tls.auto_self_signed,
        };
        match rolodex_dns::tls::TlsManager::new(tls_cfg, vec![]) {
            Ok(tls_mgr) => {
                let dot_bind = dot_config.bind.clone();
                let dot_dns = Arc::clone(&dns_server);
                let acceptor = tokio_rustls::TlsAcceptor::from(tls_mgr.server_config());
                tokio::spawn(async move {
                    if let Err(e) =
                        rolodex_dns::dot_server::serve_dot(&dot_bind, dot_dns, acceptor).await
                    {
                        error!("DoT server error: {}", e);
                    }
                });
            }
            Err(e) => error!("Failed to initialize DoT TLS: {}", e),
        }
    }

    // Spawn DNS-over-HTTPS (DoH) server if configured
    if let Some(ref doh_config) = config.doh {
        let tls_cfg = rolodex_dns::tls::TlsConfig {
            cert_path: doh_config.tls.cert_path.clone(),
            key_path: doh_config.tls.key_path.clone(),
            auto_self_signed: doh_config.tls.auto_self_signed,
        };
        match rolodex_dns::tls::TlsManager::new(tls_cfg, vec![b"h2".to_vec(), b"http/1.1".to_vec()])
        {
            Ok(tls_mgr) => {
                let doh_bind = doh_config.bind.clone();
                let doh_dns = Arc::clone(&dns_server);
                let server_config = tls_mgr.server_config();
                tokio::spawn(async move {
                    if let Err(e) =
                        rolodex_dns::doh_server::serve_doh(&doh_bind, doh_dns, server_config).await
                    {
                        error!("DoH server error: {}", e);
                    }
                });
            }
            Err(e) => error!("Failed to initialize DoH TLS: {}", e),
        }
    }

    // Spawn DNS-over-QUIC (DoQ) server if configured
    if let Some(ref doq_config) = config.doq {
        let tls_cfg = rolodex_dns::tls::TlsConfig {
            cert_path: doq_config.tls.cert_path.clone(),
            key_path: doq_config.tls.key_path.clone(),
            auto_self_signed: doq_config.tls.auto_self_signed,
        };
        match rolodex_dns::tls::TlsManager::new(tls_cfg, vec![b"doq".to_vec()]) {
            Ok(tls_mgr) => {
                let doq_bind = doq_config.bind.clone();
                let doq_dns = Arc::clone(&dns_server);
                let server_config = tls_mgr.server_config();
                tokio::spawn(async move {
                    if let Err(e) =
                        rolodex_dns::doq_server::serve_doq(&doq_bind, doq_dns, server_config).await
                    {
                        error!("DoQ server error: {}", e);
                    }
                });
            }
            Err(e) => error!("Failed to initialize DoQ TLS: {}", e),
        }
    }

    // Spawn gRPC TCP server
    if !config.grpc.tcp_bind.is_empty() {
        let grpc_service = RolodexDnsGrpcService::new(
            db.clone(),
            Arc::clone(&dns_server),
            rbl.clone(),
            config.grpc.shared_secret.clone(),
            false,
        );
        let addr: SocketAddr = config
            .grpc
            .tcp_bind
            .parse()
            .context("invalid gRPC TCP bind address")?;
        info!("gRPC TCP server listening on {}", addr);
        tokio::spawn(async move {
            if let Err(e) = Server::builder()
                .add_service(RolodexDnsServiceServer::new(grpc_service))
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
        if let Err(e) = std::fs::remove_file(&socket_path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            error!("failed to remove stale socket {}: {}", socket_path, e);
        }

        let uds = UnixListener::bind(&socket_path).context("failed to bind Unix socket")?;
        let uds_stream = tokio_stream::wrappers::UnixListenerStream::new(uds);

        let grpc_service = RolodexDnsGrpcService::new(
            db.clone(),
            Arc::clone(&dns_server),
            rbl.clone(),
            config.grpc.shared_secret.clone(),
            true,
        );
        info!("gRPC Unix socket server listening on {}", socket_path);
        tokio::spawn(async move {
            if let Err(e) = Server::builder()
                .add_service(RolodexDnsServiceServer::new(grpc_service))
                .serve_with_incoming(uds_stream)
                .await
            {
                error!("gRPC Unix socket server error: {}", e);
            }
        });
    }

    // Spawn DHCP server if configured
    if let Some(ref dhcp_config) = config.dhcp {
        let dhcp_server = Arc::new(rolodex_dns::dhcp::DhcpServer::new(
            db.clone(),
            Arc::clone(&dns_server),
            dhcp_config,
        ));
        let dhcp_bind = dhcp_config.bind.clone();
        let sweep_server = Arc::clone(&dhcp_server);
        tokio::spawn(async move {
            if let Err(e) = dhcp_server.serve_dhcp(&dhcp_bind).await {
                error!("DHCP server error: {}", e);
            }
        });
        tokio::spawn(async move {
            sweep_server.run_lease_sweep().await;
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
