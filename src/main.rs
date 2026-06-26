#![deny(dead_code)]
#![deny(unsafe_code)]

use anyhow::{Context, Result};
use clap::Parser;
use rolodex_dns::config::Config;
use rolodex_dns::db::Database;
use rolodex_dns::dns_cache::DnsCache;
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::dns_server::ResolutionMode;
use rolodex_dns::grpc_service::RolodexDnsGrpcService;
use rolodex_dns::grpc_service::proto::rolodex_dns_service_server::RolodexDnsServiceServer;
use rolodex_dns::rbl::{RblChecker, RblProvider};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UnixListener;
use tonic::transport::Server;
use tracing::{error, info, warn};

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

    // Configure upstream resolution mode (recursive-from-roots by default).
    let resolution_mode = match config.resolution.mode.to_ascii_lowercase().as_str() {
        "forward" => ResolutionMode::Forward,
        "recursive" | "" => ResolutionMode::Recursive,
        other => {
            warn!("Unknown resolution mode '{}', using recursive", other);
            ResolutionMode::Recursive
        }
    };
    dns_server.set_resolution_mode(resolution_mode);
    info!("Upstream resolution mode: {:?}", resolution_mode);

    // Apply custom root hints if provided.
    if !config.resolution.root_hints.is_empty() {
        let hints: Vec<IpAddr> = config
            .resolution
            .root_hints
            .iter()
            .filter_map(|h| h.parse().ok())
            .collect();
        if hints.is_empty() {
            warn!("No valid root hints parsed from config; using built-in root hints");
        } else {
            info!("Using {} custom root hint(s)", hints.len());
            dns_server.set_root_hints(hints);
        }
    }

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
    for addr in config.dns.udp_addrs() {
        let resolved = rolodex_dns::config::resolve_bind_addrs(addr)
            .with_context(|| format!("resolving UDP bind address '{}'", addr))?;
        for udp_bind in resolved {
            let udp_server = Arc::clone(&dns_server);
            tokio::spawn(async move {
                if let Err(e) = udp_server.serve_udp(&udp_bind).await {
                    error!("DNS UDP server error on {}: {}", udp_bind, e);
                }
            });
        }
    }

    // Spawn DNS TCP servers
    for addr in config.dns.tcp_addrs() {
        let resolved = rolodex_dns::config::resolve_bind_addrs(addr)
            .with_context(|| format!("resolving TCP bind address '{}'", addr))?;
        for tcp_bind in resolved {
            let tcp_server = Arc::clone(&dns_server);
            tokio::spawn(async move {
                if let Err(e) = tcp_server.serve_tcp(&tcp_bind).await {
                    error!("DNS TCP server error on {}: {}", tcp_bind, e);
                }
            });
        }
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
                let dot_binds = rolodex_dns::config::resolve_bind_addrs(&dot_config.bind)
                    .context("resolving DoT bind address")?;
                let acceptor = tokio_rustls::TlsAcceptor::from(tls_mgr.server_config());
                for dot_bind in dot_binds {
                    let dot_dns = Arc::clone(&dns_server);
                    let dot_acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            rolodex_dns::dot_server::serve_dot(&dot_bind, dot_dns, dot_acceptor)
                                .await
                        {
                            error!("DoT server error on {}: {}", dot_bind, e);
                        }
                    });
                }
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
                let doh_binds = rolodex_dns::config::resolve_bind_addrs(&doh_config.bind)
                    .context("resolving DoH bind address")?;
                let server_config = tls_mgr.server_config();
                for doh_bind in doh_binds {
                    let doh_dns = Arc::clone(&dns_server);
                    let doh_config = server_config.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            rolodex_dns::doh_server::serve_doh(&doh_bind, doh_dns, doh_config).await
                        {
                            error!("DoH server error on {}: {}", doh_bind, e);
                        }
                    });
                }
            }
            Err(e) => error!("Failed to initialize DoH TLS: {}", e),
        }
    }

    // Spawn the ACME issuer (CA) + enrollment portal if configured
    if let Some(ref acme_config) = config.acme {
        // Ensure the Rolodex root CA exists before serving.
        rolodex_dns::ca::ensure_root_ca(&db, &acme_config.root_ca_cn)
            .context("failed to initialize Rolodex root CA")?;

        let tls_cfg = rolodex_dns::tls::TlsConfig {
            cert_path: acme_config.tls.cert_path.clone(),
            key_path: acme_config.tls.key_path.clone(),
            auto_self_signed: acme_config.tls.auto_self_signed,
        };
        match rolodex_dns::tls::TlsManager::new(tls_cfg, vec![b"h2".to_vec(), b"http/1.1".to_vec()])
        {
            Ok(tls_mgr) => {
                let server_config = tls_mgr.server_config();
                let acme_state = rolodex_dns::acme_server::AcmeState {
                    db: db.clone(),
                    dns_server: Some(Arc::clone(&dns_server)),
                    directory_url: acme_config.directory_url.clone(),
                    require_eab: acme_config.require_eab,
                    issuance_any: acme_config.issuance_any(),
                    leaf_validity_days: acme_config.leaf_validity_days,
                    tlsa_port: acme_config.tlsa_port,
                    tlsa_proto: acme_config.tlsa_proto.clone(),
                };

                // Client-facing ACME HTTPS listener(s).
                match rolodex_dns::config::resolve_bind_addrs(&acme_config.bind) {
                    Ok(acme_binds) => {
                        for acme_bind in acme_binds {
                            let state = acme_state.clone();
                            let cfg = server_config.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    rolodex_dns::acme_server::serve_acme(&acme_bind, state, cfg)
                                        .await
                                {
                                    error!("ACME server error on {}: {}", acme_bind, e);
                                }
                            });
                        }
                    }
                    Err(e) => error!("resolving ACME bind address: {}", e),
                }

                // Trusted-network enrollment portal listener(s).
                let portal_state = rolodex_dns::portal::PortalState {
                    db: db.clone(),
                    acme: acme_state.clone(),
                };
                match rolodex_dns::config::resolve_bind_addrs(&acme_config.portal_bind) {
                    Ok(portal_binds) => {
                        for portal_bind in portal_binds {
                            let state = portal_state.clone();
                            let cfg = server_config.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    rolodex_dns::portal::serve_portal(&portal_bind, state, cfg)
                                        .await
                                {
                                    error!("ACME portal error on {}: {}", portal_bind, e);
                                }
                            });
                        }
                    }
                    Err(e) => error!("resolving ACME portal bind address: {}", e),
                }
            }
            Err(e) => error!("Failed to initialize ACME TLS: {}", e),
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
                let doq_binds = rolodex_dns::config::resolve_bind_addrs(&doq_config.bind)
                    .context("resolving DoQ bind address")?;
                let server_config = tls_mgr.server_config();
                for doq_bind in doq_binds {
                    let doq_dns = Arc::clone(&dns_server);
                    let doq_config = server_config.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            rolodex_dns::doq_server::serve_doq(&doq_bind, doq_dns, doq_config).await
                        {
                            error!("DoQ server error on {}: {}", doq_bind, e);
                        }
                    });
                }
            }
            Err(e) => error!("Failed to initialize DoQ TLS: {}", e),
        }
    }

    // ACME issuer parameters threaded into the gRPC admin RPCs.
    let (acme_directory_url, acme_root_cn) = match &config.acme {
        Some(a) => (a.directory_url.clone(), a.root_ca_cn.clone()),
        None => (String::new(), String::new()),
    };

    // Spawn gRPC TCP server
    if !config.grpc.tcp_bind.is_empty() {
        let grpc_binds = rolodex_dns::config::resolve_bind_addrs(&config.grpc.tcp_bind)
            .context("resolving gRPC TCP bind address")?;
        for grpc_bind in grpc_binds {
            let grpc_service = RolodexDnsGrpcService::new(
                db.clone(),
                Arc::clone(&dns_server),
                rbl.clone(),
                config.grpc.shared_secret.clone(),
                false,
            )
            .with_acme(acme_directory_url.clone(), acme_root_cn.clone())
            .with_auto_ptr(config.dns.auto_ptr);
            let addr: SocketAddr = grpc_bind
                .parse()
                .with_context(|| format!("invalid gRPC TCP bind address: {}", grpc_bind))?;
            info!("gRPC TCP server listening on {}", addr);
            tokio::spawn(async move {
                if let Err(e) = Server::builder()
                    .add_service(RolodexDnsServiceServer::new(grpc_service))
                    .serve(addr)
                    .await
                {
                    error!("gRPC TCP server error on {}: {}", addr, e);
                }
            });
        }
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
        )
        .with_acme(acme_directory_url.clone(), acme_root_cn.clone())
        .with_auto_ptr(config.dns.auto_ptr);
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
        let dhcp_binds = rolodex_dns::config::resolve_bind_addrs(&dhcp_config.bind)
            .context("resolving DHCP bind address")?;
        let sweep_server = Arc::clone(&dhcp_server);
        for dhcp_bind in dhcp_binds {
            let dhcp = Arc::clone(&dhcp_server);
            tokio::spawn(async move {
                if let Err(e) = dhcp.serve_dhcp(&dhcp_bind).await {
                    error!("DHCP server error on {}: {}", dhcp_bind, e);
                }
            });
        }
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
