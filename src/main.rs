#![deny(dead_code)]
#![deny(unsafe_code)]

use anyhow::{Context, Result};
use clap::Parser;
use rolodex_dns::config::Config;
use rolodex_dns::db::Database;
use rolodex_dns::dns_cache::DnsCache;
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::dns_server::ResolutionMode;
use rolodex_dns::dnsbl::{DnsblChecker, DnsblProvider, RecursiveDnsblResolver};
use rolodex_dns::grpc_service::RolodexDnsGrpcService;
use rolodex_dns::grpc_service::proto::rolodex_dns_service_server::RolodexDnsServiceServer;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
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

/// Builds a listener's TLS manager, starts the task that keeps its certificate
/// current, and returns the channel the listener follows.
///
/// The manager is pushed onto `managers` rather than returned because it has to
/// outlive this call by the life of the process: it owns the watch sender, and a
/// dropped sender is a listener that can never be handed a renewed certificate.
///
/// The reloader is only started for a file-backed listener. Generated material
/// has no file to renew, and re-generating on a timer would hand every client a
/// different self-signed certificate every half-minute.
fn start_tls(
    label: &'static str,
    configured: &rolodex_dns::config::TlsConfig,
    binds: &[String],
    alpn_protocols: Vec<Vec<u8>>,
    managers: &mut Vec<Arc<rolodex_dns::tls::TlsManager>>,
) -> Result<tokio::sync::watch::Receiver<Arc<rustls::ServerConfig>>> {
    let tls_cfg = rolodex_dns::tls::TlsConfig::for_listener(configured, binds);
    let manager = Arc::new(rolodex_dns::tls::TlsManager::new(tls_cfg, alpn_protocols)?);
    let watch = manager.watch();
    if manager
        .spawn_reloader(label, rolodex_dns::tls::CERT_RELOAD_INTERVAL)
        .is_some()
    {
        info!(
            "{} certificate will be reloaded from disk within {:?} of a change",
            label,
            rolodex_dns::tls::CERT_RELOAD_INTERVAL
        );
    }
    managers.push(manager);
    Ok(watch)
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

    // Read and parsed inside `#[tokio::main]`, so it is a blocking region like
    // any other and is measured like one. It runs once, before any listener
    // exists, and the series is here so the claim "config loading is free" stays
    // a measurement rather than an assumption — a config on a slow or remote
    // filesystem is the case that stops being free.
    let config = rolodex_dns::metrics::time_blocking(
        rolodex_dns::metrics::BLOCK_SITE_CONFIG_LOAD,
        || -> Result<Config> {
            if std::path::Path::new(&cli.config).exists() {
                let content =
                    std::fs::read_to_string(&cli.config).context("failed to read config file")?;
                serde_yaml_ng::from_str(&content).context("failed to parse config file")
            } else {
                info!("No config file found, using defaults");
                Ok(Config::default())
            }
        },
    )?;

    let db = Database::open(&config.database_path).context("failed to open database")?;

    // Upstreams for both the main resolver and the RBL/DNSBL resolver. Parsed
    // here (before the RBL checker) so blocklist lookups can resolve the same way
    // rolodex does — from the roots, then the forwarder — instead of via the
    // local stub (which points back at rolodex and loops; see RecursiveDnsblResolver).
    let forwarders: Vec<SocketAddr> = config
        .forwarders
        .iter()
        .filter_map(|f| f.parse().ok())
        .collect();
    let root_hint_ips: Vec<IpAddr> = config
        .resolution
        .root_hints
        .iter()
        .filter_map(|h| h.parse().ok())
        .collect();

    // A malformed refusal code fails startup rather than being dropped: a code
    // that silently does not apply means the provider's "stop querying me"
    // answer reads as a listing and NXDOMAINs every name checked against it.
    let dnsbl = Arc::new(DnsblChecker::with_resolver(Arc::new(
        RecursiveDnsblResolver::new(root_hint_ips.clone(), forwarders.clone()),
    )));
    dnsbl.set_refusal_cooldown(config.dnsbl.refusal_cooldown_secs);

    let dnsbl_providers: Vec<DnsblProvider> =
        rolodex_dns::config::to_providers(&config.dnsbl.providers).map_err(anyhow::Error::msg)?;
    dnsbl
        .set_config(config.dnsbl.enabled, dnsbl_providers)
        .await;

    // Provider lookups go out over plaintext :53. On a network that filters :53
    // they only time out and add latency, so gate them on a live :53 probe:
    // disable the resolver-backed blocklist (with a logged flag) when :53 is
    // down, re-enable when it recovers.
    //
    // Spawned unconditionally, and gated inside on the checker's *runtime*
    // enabled flag rather than on `config.dnsbl.enabled` here — a blocklist
    // turned on later over gRPC has to get a probe too. Same shape as
    // `recovery_probe_loop` below, which is also always spawned and no-ops when
    // it has nothing to do. See `DnsblChecker::resolver_availability_loop`.
    tokio::spawn(dnsbl.clone().resolver_availability_loop());

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
        dnsbl.clone(),
        forwarders,
        Some(Arc::clone(&dns_cache)),
        dns64_prefix,
        config.security.qname_case_randomization,
    ));

    // Configure upstream resolution mode (auto fallback chain by default).
    let resolution_mode = match config.resolution.mode.to_ascii_lowercase().as_str() {
        "forward" => ResolutionMode::Forward,
        "recursive" => ResolutionMode::Recursive,
        "auto" | "" => ResolutionMode::Auto,
        other => {
            warn!("Unknown resolution mode '{}', using auto", other);
            ResolutionMode::Auto
        }
    };
    dns_server.set_resolution_mode(resolution_mode);
    info!("Upstream resolution mode: {:?}", resolution_mode);

    // Network-overlay ranges: only these (WireGuard) source IPs are scope-
    // enforced; every other source is a trusted local client. Bad entries are
    // warned about and skipped so a typo can't accidentally trust the overlay.
    let overlay_cidrs: Vec<_> = config
        .security
        .overlay_cidrs
        .iter()
        .filter_map(|c| match rolodex_dns::cidr::IpCidr::parse(c) {
            Ok(cidr) => Some(cidr),
            Err(e) => {
                warn!("Skipping overlay CIDR '{}': {}", c, e);
                None
            }
        })
        .collect();
    info!("Scope-enforced overlay ranges: {}", overlay_cidrs.len());
    dns_server.set_overlay_cidrs(overlay_cidrs);

    // Who may drive upstream resolution. A source outside these ranges still
    // gets this server's authoritative data but is REFUSED rather than recursed
    // for, so a routable `dns.bind` is not an open resolver. Bad entries are
    // warned about and skipped — the failure mode of a typo is a source range
    // that loses recursion, not one that silently gains it.
    let recursion_cidrs: Vec<_> = config
        .security
        .recursion_cidrs
        .iter()
        .filter_map(|c| match rolodex_dns::cidr::IpCidr::parse(c) {
            Ok(cidr) => Some(cidr),
            Err(e) => {
                warn!("Skipping recursion CIDR '{}': {}", c, e);
                None
            }
        })
        .collect();
    info!(
        "Recursion offered to {} source range(s); all other sources are served local data only",
        recursion_cidrs.len()
    );
    dns_server.set_recursion_cidrs(recursion_cidrs);

    // Auto mode: build the secure (DoT) tier, the public :53 last-resort tier,
    // and the switch tuning. Bad entries are warned about and skipped so a typo
    // can't take resolution down.
    let secure_upstreams: Vec<_> = config
        .resolution
        .secure_upstreams
        .iter()
        .filter_map(
            |c| match rolodex_dns::secure_client::SecureUpstream::from_config(c) {
                Ok(u) => Some(u),
                Err(e) => {
                    warn!("Skipping secure upstream: {}", e);
                    None
                }
            },
        )
        .collect();
    let public_fallback: Vec<SocketAddr> = config
        .resolution
        .public_fallback
        .iter()
        .filter_map(|f| match f.parse() {
            Ok(a) => Some(a),
            Err(e) => {
                warn!("Skipping public fallback '{}': {}", f, e);
                None
            }
        })
        .collect();
    if resolution_mode == ResolutionMode::Auto {
        info!(
            "Auto resolution: {} secure (DoH/DoT) upstream(s), {} public fallback(s), grace={} failures, async recovery probe every {}s (roots require a DNSSEC-validated answer)",
            secure_upstreams.len(),
            public_fallback.len(),
            config.resolution.switch_grace_failures,
            config.resolution.recovery_probe_secs,
        );
    }
    dns_server.set_secure_upstreams(secure_upstreams);
    dns_server.set_public_fallback(public_fallback);
    dns_server.set_auto_params(
        config.resolution.switch_grace_failures,
        config.resolution.recovery_probe_secs,
    );

    // Address-family answer preference: apply the configured mode and, in auto,
    // spawn the routability probe so rolodex stops handing clients addresses in a
    // family the host can't route (which otherwise stalls the connection).
    rolodex_dns::probe::start(Arc::clone(&dns_server), &config.address_family).await;

    // Back the iterative resolver with a persistent delegation cache, so cold
    // names do not re-walk root -> TLD every time and a restart comes back warm.
    let delegations = Arc::new(
        rolodex_dns::delegation_cache::DelegationCache::with_db(
            db.clone(),
            config.resolution.delegation_persist_min_ttl,
        )
        .with_default_ttl(config.resolution.default_ttl),
    );
    info!(
        "Delegation cache: {} zone(s) restored, persisting delegations with TTL > {}s; \
         fallback TTL {}s where none is supplied",
        delegations.len(),
        config.resolution.delegation_persist_min_ttl,
        config.resolution.default_ttl
    );
    dns_server.set_delegation_cache(delegations, config.resolution.default_ttl);

    // Apply custom root hints if provided (parsed once, above). This preserves
    // the delegation cache installed above.
    if !root_hint_ips.is_empty() {
        info!("Using {} custom root hint(s)", root_hint_ips.len());
        dns_server.set_root_hints(root_hint_ips);
    } else if !config.resolution.root_hints.is_empty() {
        warn!("No valid root hints parsed from config; using built-in root hints");
    }

    // DNSSEC validation. Applied after the delegation cache and the root hints,
    // both of which rebuild the resolver, so that turning validation on is the
    // last word rather than something a later builder call quietly drops.
    if config.dnssec.validate {
        let anchors = if config.dnssec.trust_anchors.is_empty() {
            rolodex_dns::dnssec_validate::Anchors::iana_defaults()
        } else {
            // A bad anchor is a hard startup failure, not a warning that
            // degrades to the IANA keys: an operator who configured a private
            // root and got the real one instead would have a resolver that
            // validates, reports success, and is anchored to the wrong thing.
            rolodex_dns::dnssec_validate::Anchors::from_dnskey_strings(&config.dnssec.trust_anchors)
                .map_err(|e| anyhow::anyhow!("invalid dnssec.trust_anchors: {e}"))?
        };
        info!(
            "DNSSEC validation enabled with {} trust anchor(s); bogus answers become SERVFAIL",
            anchors.len()
        );
        dns_server.set_dnssec_anchors(Some(anchors));
    } else {
        info!("DNSSEC validation disabled (dnssec.validate: false)");
        dns_server.set_dnssec_anchors(None);
    }

    // Prime the root zone in the background: ask the roots who the roots are and
    // cache the live NS set with its TTL, so the compiled-in hints are a bootstrap
    // rather than the only root servers we ever know about. Backgrounded because a
    // prime must never delay (or fail) a lookup — on failure we just keep the hints.
    {
        let resolver = dns_server.resolver();
        tokio::spawn(async move {
            resolver.prime_roots(hickory_proto::rr::DNSClass::IN).await;
        });
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

    // Pre-warm the auto-resolution chain so the first *client* query doesn't pay
    // the cold-tier discovery cost: on a :53-filtered network this drives the
    // sticky tier past the dead roots to DoH and completes the TLS handshake
    // before traffic arrives. Fire-and-forget so it never delays startup; a
    // no-op in non-auto modes and on networks where the roots answer.
    if resolution_mode == ResolutionMode::Auto {
        let warm_server = Arc::clone(&dns_server);
        tokio::spawn(async move {
            warm_server.prewarm_auto().await;
        });
    }

    // Recovery runs here, on its own canary, rather than on the query path: a
    // client's lookup must never be spent probing a tier the box has already
    // stopped trusting. Reclaiming the roots additionally requires a
    // DNSSEC-validated answer, so a network that merely intercepts :53 cannot
    // promote itself back to the most-trusted tier.
    //
    // Spawned unconditionally, NOT under the auto branch above, because the
    // mode is no longer fixed for the life of the process — SetResolutionMode
    // can switch into auto at runtime, and a box that reached auto that way
    // would otherwise degrade past a dead tier and never climb back, with no
    // symptom beyond permanently slower and less private resolution. Each pass
    // re-checks the current mode and returns immediately outside auto, so this
    // costs one sleeping task in the modes that do not use it. The prewarm
    // above stays gated: it is a one-shot, and the RPC fires its own on the
    // transition into auto.
    let probe_server = Arc::clone(&dns_server);
    tokio::spawn(async move {
        probe_server.recovery_probe_loop().await;
    });

    // Shard every UDP listener across SO_REUSEPORT sockets so receive and send
    // scale across cores instead of funnelling through one socket. Must be set
    // before any listener starts, including the ingress listeners below.
    dns_server.set_udp_shards(config.dns.udp_shards);

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

    // Per-TLD ingress listeners: bind a DNS listener on each TLD's ingress IP so
    // programmed names under that TLD resolve to the network's ingress
    // controller. The IPs are registered via gRPC (`AddScopeTld` with a
    // listen_ip) and persisted, so re-create them here at boot.
    dns_server.set_ingress_port(config.dns.ingress_listen_port);
    dns_server.sync_ingress_listeners();

    // Every TLS listener's certificate manager, kept alive for the life of the
    // process.
    //
    // This is load-bearing, not bookkeeping: the manager owns the watch sender
    // the listeners follow and the task that re-reads the certificate files.
    // Dropping one at the end of the block that built it — which is what used to
    // happen — leaves its listeners holding receivers nobody will ever send on,
    // and no amount of renewing the files reaches them.
    let mut tls_managers: Vec<Arc<rolodex_dns::tls::TlsManager>> = Vec::new();

    // The encrypted transports' supervisor. It owns their listeners and their
    // certificate managers for the life of the process, which is why the
    // `tls_managers` vector above no longer needs to hold theirs — only the ACME
    // pair, whose listeners are still spawned directly.
    let transports = Arc::new(rolodex_dns::transports::TransportSupervisor::new(
        Arc::clone(&dns_server),
    ));

    // The encrypted transports (DoT, DoH, DoQ) all go up through the SUPERVISOR
    // rather than being spawned here directly, so the startup path and the
    // `Set<Transport>Config` RPCs are one code path. That is what makes the RPC
    // trustworthy: a configuration that works at boot is applied by exactly the
    // same code that applies one arriving at runtime, and neither can drift into
    // doing something the other does not.
    //
    // A failure is logged and the box keeps going. Encrypted DNS not starting is
    // bad; `:53` not starting because of it would be worse, and the transports
    // can be brought up over gRPC once whatever was wrong is fixed — without a
    // restart, which is the whole point.
    for (kind, settings) in [
        config.dot.as_ref().map(|c| {
            (
                rolodex_dns::transports::TransportKind::Dot,
                rolodex_dns::transports::TransportSettings::new(c.bind.clone(), c.tls.clone()),
            )
        }),
        config.doh.as_ref().map(|c| {
            if c.enable_h3 {
                warn!(
                    "doh.enable_h3 is set but HTTP/3 is not implemented; serving h2 and http/1.1"
                );
            }
            (
                rolodex_dns::transports::TransportKind::Doh,
                rolodex_dns::transports::TransportSettings::new(c.bind.clone(), c.tls.clone()),
            )
        }),
        config.doq.as_ref().map(|c| {
            (
                rolodex_dns::transports::TransportKind::Doq,
                rolodex_dns::transports::TransportSettings::new(c.bind.clone(), c.tls.clone()),
            )
        }),
    ]
    .into_iter()
    .flatten()
    {
        if let Err(e) = transports.apply(kind, settings).await {
            error!("{} not started: {:#}", kind.label(), e);
        }
    }

    // Spawn the ACME issuer (CA) + enrollment portal if configured
    if let Some(ref acme_config) = config.acme {
        // Ensure the Rolodex root CA exists before serving.
        rolodex_dns::ca::ensure_root_ca(&db, &acme_config.root_ca_cn)
            .context("failed to initialize Rolodex root CA")?;

        // Both listeners share one certificate, so it has to name both sets of
        // bind addresses. Resolved here purely for the SAN list — the listeners
        // below resolve again and report their own failures, which is what keeps
        // a bad `portal_bind` from taking the ACME listener down with it.
        let acme_sans: Vec<String> = rolodex_dns::config::resolve_bind_addrs(&acme_config.bind)
            .into_iter()
            .chain(rolodex_dns::config::resolve_bind_addrs(
                &acme_config.portal_bind,
            ))
            .flatten()
            .collect();
        // Resolved before any listener starts: a malformed endpoint must stop the
        // server rather than surface later as an issuance that quietly published
        // fewer TLSA records than the operator asked for.
        let tlsa_endpoints = match acme_config.tlsa_endpoints() {
            Ok(endpoints) => endpoints,
            Err(e) => {
                error!("{}", e);
                std::process::exit(1);
            }
        };
        match start_tls(
            "ACME",
            &acme_config.tls,
            &acme_sans,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            &mut tls_managers,
        ) {
            Ok(tls) => {
                let acme_state = rolodex_dns::acme_server::AcmeState {
                    db: db.clone(),
                    dns_server: Some(Arc::clone(&dns_server)),
                    directory_url: acme_config.directory_url.clone(),
                    require_eab: acme_config.require_eab,
                    issuance_any: acme_config.issuance_any(),
                    leaf_validity_days: acme_config.leaf_validity_days,
                    tlsa_endpoints: tlsa_endpoints.clone(),
                };

                // Client-facing ACME HTTPS listener(s).
                match rolodex_dns::config::resolve_bind_addrs(&acme_config.bind) {
                    Ok(acme_binds) => {
                        for acme_bind in acme_binds {
                            let state = acme_state.clone();
                            let cfg = tls.clone();
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
                            let cfg = tls.clone();
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
            Err(e) => error!("Failed to initialize ACME TLS: {:#}", e),
        }
    }

    // Spawn the Prometheus metrics endpoint if configured
    if let Some(ref metrics_config) = config.metrics {
        // Install the tracked-TLD set before the first query is served, so the
        // per-TLD attribution is right from the first sample rather than from
        // the first scrape. The config list is pinned here; the effective set
        // unions it with the stored list and every owned TLD.
        rolodex_dns::metrics::set_config_tracked_tlds(metrics_config.tracked_tlds.clone());
        rolodex_dns::metrics::refresh_tracked_tlds(&db);

        let metrics_binds = rolodex_dns::config::resolve_bind_addrs(&metrics_config.bind)
            .context("resolving metrics bind address")?;
        for metrics_bind in metrics_binds {
            let state = rolodex_dns::metrics::MetricsState {
                db: db.clone(),
                dns_server: Arc::clone(&dns_server),
                dns_cache: Some(Arc::clone(&dns_cache)),
                dnsbl: dnsbl.clone(),
            };
            tokio::spawn(async move {
                if let Err(e) = rolodex_dns::metrics::serve_metrics(&metrics_bind, state).await {
                    error!("metrics server error on {}: {}", metrics_bind, e);
                }
            });
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

        rolodex_dns::config::check_grpc_exposure(
            &config.grpc.tcp_bind,
            &grpc_binds,
            &config.grpc.shared_secret,
        )?;

        for grpc_bind in grpc_binds {
            let grpc_service = RolodexDnsGrpcService::new(
                db.clone(),
                Arc::clone(&dns_server),
                dnsbl.clone(),
                config.grpc.shared_secret.clone(),
                false,
            )
            .with_acme(acme_directory_url.clone(), acme_root_cn.clone())
            .with_auto_ptr(config.dns.auto_ptr)
            .with_transports(Arc::clone(&transports));
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

        // A connection over the Unix socket bypasses authentication entirely, so
        // the socket's file mode *is* the access control for the management
        // plane. A bare `bind` creates it under the umask — typically 0755 —
        // which hands every local user unauthenticated administrative control.
        //
        // Bind to a temporary name, restrict it, and rename into place: chmod
        // after binding at the published path would leave a window in which the
        // socket exists and is world-connectable. Rename is atomic and keeps the
        // same inode, so the listener is unaffected and the published path never
        // exists in a permissive mode. 0660 rather than 0600 so a deployment can
        // grant a dedicated admin group access by chgrp'ing the socket.
        let staging_path = format!("{}.{}.tmp", socket_path, std::process::id());
        if let Err(e) = std::fs::remove_file(&staging_path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            error!("failed to remove stale socket {}: {}", staging_path, e);
        }
        let uds = UnixListener::bind(&staging_path).context("failed to bind Unix socket")?;
        std::fs::set_permissions(&staging_path, std::fs::Permissions::from_mode(0o660))
            .context("failed to restrict Unix socket permissions")?;
        std::fs::rename(&staging_path, &socket_path)
            .context("failed to move Unix socket into place")?;
        let uds_stream = tokio_stream::wrappers::UnixListenerStream::new(uds);

        let grpc_service = RolodexDnsGrpcService::new(
            db.clone(),
            Arc::clone(&dns_server),
            dnsbl.clone(),
            config.grpc.shared_secret.clone(),
            true,
        )
        .with_acme(acme_directory_url.clone(), acme_root_cn.clone())
        .with_auto_ptr(config.dns.auto_ptr)
        .with_transports(Arc::clone(&transports));
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
