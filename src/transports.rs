//! Runtime supervision of the encrypted DNS listeners (DoT, DoH, DoQ).
//!
//! # Why this exists
//!
//! `dot`, `doh` and `doq` used to be startup-only: the listeners were opened
//! once from the config file and `SetDotConfig`/`SetDohConfig`/`SetDoqConfig`
//! logged their request and returned `success: true` having stored nothing. An
//! orchestrator could not tell that apart from working, so the only way to
//! configure encrypted DNS was to write the config file and restart the
//! process — and on a box where rolodex is the only resolver, a restart is a
//! DNS outage for everything on it.
//!
//! That is the same argument the resolution mode and the forwarder list already
//! won. This supervisor is what lets the encrypted transports win it too: each
//! one can be opened, moved, re-keyed or shut down while the server runs, and
//! **`:53` is never touched** — these are independent listeners, so
//! reconfiguring one costs nothing outside itself.
//!
//! # The ordering problem, and what is done about it
//!
//! A listener cannot be started before the old one on that port is stopped, so
//! there is no way to prove the new configuration binds before giving up the
//! old one. What can be done, and is:
//!
//!   1. Everything that can be validated *without* the port is validated first
//!      — the bind list resolves, and the TLS material loads or generates. A
//!      typo'd address or an unreadable certificate is rejected with the old
//!      listener still running and serving.
//!   2. Only then are the old listeners stopped, and **awaited**, so their
//!      sockets are closed before the new ones are opened. Aborting without
//!      awaiting races the new bind against the old socket's close and fails
//!      with `EADDRINUSE` perhaps one time in ten.
//!   3. If the new bind fails anyway — something else took the port in between —
//!      the previous configuration is put back and the caller is told the
//!      transport is down. Reporting success there would leave a box that
//!      believes it is serving DoT and is not.
//!
//! An empty bind list is a shutdown, not an error: it is how a transport is
//! turned off, and it is what an omitted config section already means.

use crate::config::BindList;
use crate::dns_server::DnsServer;
use crate::tls::TlsManager;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// Which encrypted transport a configuration applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    Dot,
    Doh,
    Doq,
}

impl TransportKind {
    /// The label used in logs and in TLS-manager diagnostics.
    pub fn label(self) -> &'static str {
        match self {
            TransportKind::Dot => "DoT",
            TransportKind::Doh => "DoH",
            TransportKind::Doq => "DoQ",
        }
    }

    /// The ALPN tokens the listener offers.
    ///
    /// DoT and DoQ each offer exactly the one IANA assigns them, and offering
    /// *only* it is deliberate: a client asking for the right protocol
    /// negotiates, a client offering some other protocol is refused rather than
    /// quietly served, and a client sending no ALPN at all (Android's Private
    /// DNS, systemd-resolved in opportunistic mode) is unaffected, because TLS
    /// fails a handshake only when the client offers protocols and none match.
    fn alpn(self) -> Vec<Vec<u8>> {
        match self {
            TransportKind::Dot => crate::dot_server::alpn_protocols(),
            TransportKind::Doh => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            TransportKind::Doq => vec![b"doq".to_vec()],
        }
    }
}

/// One encrypted transport's configuration, as a caller supplies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportSettings {
    /// Where to listen. Empty (or all-empty) shuts the transport down.
    pub binds: BindList,
    /// Certificate material, exactly as the config file's `tls:` section.
    pub tls: crate::config::TlsConfig,
    /// Whether DoH also serves HTTP/3 on the same address over UDP.
    ///
    /// Meaningful only for [`TransportKind::Doh`]; the other transports carry it
    /// as `false` and ignore it. It is part of the settings rather than a
    /// separate switch because the supervisor decides whether to restart a
    /// transport by comparing these values, and a flag kept outside them is one
    /// that can be changed with nothing noticing.
    pub enable_h3: bool,
}

impl TransportSettings {
    pub fn new(binds: BindList, tls: crate::config::TlsConfig) -> Self {
        Self {
            binds,
            tls,
            enable_h3: false,
        }
    }

    /// Turns HTTP/3 on or off for a DoH transport. See [`Self::enable_h3`].
    pub fn with_h3(mut self, enable_h3: bool) -> Self {
        self.enable_h3 = enable_h3;
        self
    }
}

/// A transport that is currently listening.
struct Running {
    settings: TransportSettings,
    /// The addresses actually bound, which is what a reader wants to see —
    /// `primary:853` and `eth0:853` do not name their addresses.
    bound: Vec<String>,
    tasks: Vec<JoinHandle<()>>,
    /// Kept alive for the life of the listeners: the manager owns the watch
    /// sender they follow, and a dropped sender is a listener that can never be
    /// handed a renewed certificate.
    _manager: Arc<TlsManager>,
}

impl Running {
    /// Stops every listener and waits for it to actually finish, so the sockets
    /// are closed before anything tries to take the ports.
    async fn stop(self) {
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            // A cancelled task is the expected outcome; anything else already
            // logged for itself on the way out.
            let _ = task.await;
        }
    }
}

/// Supervises the encrypted DNS listeners.
pub struct TransportSupervisor {
    dns_server: Arc<DnsServer>,
    /// One entry per transport that is up. A transport that is down has no
    /// entry, which is the same state it is in before it is ever configured.
    running: Mutex<HashMap<TransportKind, Running>>,
}

impl TransportSupervisor {
    pub fn new(dns_server: Arc<DnsServer>) -> Self {
        Self {
            dns_server,
            running: Mutex::new(HashMap::new()),
        }
    }

    /// The settings a transport is currently running with, or `None` when it is
    /// down.
    pub async fn current(&self, kind: TransportKind) -> Option<TransportSettings> {
        self.running
            .lock()
            .await
            .get(&kind)
            .map(|r| r.settings.clone())
    }

    /// The addresses a transport is actually listening on. Empty when it is down.
    pub async fn bound_addrs(&self, kind: TransportKind) -> Vec<String> {
        self.running
            .lock()
            .await
            .get(&kind)
            .map(|r| r.bound.clone())
            .unwrap_or_default()
    }

    /// Applies a configuration, replacing whatever that transport was doing.
    ///
    /// See the module comment for the ordering this follows and why. On failure
    /// the previous configuration is restored where it can be, and the error
    /// describes what the transport is doing *now* rather than only what went
    /// wrong.
    pub async fn apply(&self, kind: TransportKind, settings: TransportSettings) -> Result<()> {
        // (1) Validate everything that does not need the port.
        let binds = settings
            .binds
            .resolve()
            .with_context(|| format!("{} bind address", kind.label()))?;

        let mut guard = self.running.lock().await;

        if binds.is_empty() {
            if let Some(old) = guard.remove(&kind) {
                old.stop().await;
                info!(
                    "{} listener stopped (no bind addresses configured)",
                    kind.label()
                );
            }
            return Ok(());
        }

        // Building the manager loads the certificate files, or generates
        // material — either way a bad configuration fails here, with the
        // existing listener still up and serving.
        let manager = Self::build_manager(kind, &settings, &binds)?;

        // (2) Stop the old listeners and wait for their sockets to close.
        let previous = guard.remove(&kind);
        let had_previous = previous.as_ref().map(|p| p.settings.clone());
        if let Some(old) = previous {
            old.stop().await;
        }

        // (3) Bind. On failure, put the old configuration back.
        match self.start(kind, &settings, &binds, manager).await {
            Ok(running) => {
                info!("{} listening on {}", kind.label(), binds.join(", "));
                guard.insert(kind, running);
                Ok(())
            }
            Err(err) => {
                let restored = match had_previous {
                    Some(prev) => match self.restart_previous(kind, &prev).await {
                        Some(running) => {
                            guard.insert(kind, running);
                            " — the previous configuration was restored"
                        }
                        None => {
                            " — and the previous configuration could not be restored either, so the transport is DOWN"
                        }
                    },
                    None => "",
                };
                Err(err.context(format!("{} listener not started{}", kind.label(), restored)))
            }
        }
    }

    /// Rebuilds a transport from settings that were known to work. Returns
    /// `None` when even that fails, which the caller reports rather than hides.
    async fn restart_previous(
        &self,
        kind: TransportKind,
        prev: &TransportSettings,
    ) -> Option<Running> {
        let binds = prev.binds.resolve().ok()?;
        let manager = Self::build_manager(kind, prev, &binds).ok()?;
        match self.start(kind, prev, &binds, manager).await {
            Ok(running) => Some(running),
            Err(e) => {
                warn!("{} could not be restored: {:#}", kind.label(), e);
                None
            }
        }
    }

    fn build_manager(
        kind: TransportKind,
        settings: &TransportSettings,
        binds: &[String],
    ) -> Result<Arc<TlsManager>> {
        let tls_cfg = crate::tls::TlsConfig::for_listener(&settings.tls, binds);
        let manager = Arc::new(
            TlsManager::new(tls_cfg, kind.alpn())
                .with_context(|| format!("{} TLS configuration", kind.label()))?,
        );
        // A file-backed listener gets the renewal poller; generated material has
        // no file to renew, and regenerating on a timer would hand every client
        // a different self-signed certificate every half-minute.
        manager.spawn_reloader(kind.label(), crate::tls::CERT_RELOAD_INTERVAL);
        Ok(manager)
    }

    /// Binds every address and spawns a listener on each. A failure on any one
    /// address stops the ones already started, so a partial apply never leaves
    /// half a transport up wearing the new configuration's name.
    async fn start(
        &self,
        kind: TransportKind,
        settings: &TransportSettings,
        binds: &[String],
        manager: Arc<TlsManager>,
    ) -> Result<Running> {
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();
        let mut bound: Vec<String> = Vec::new();

        for addr in binds {
            let watch = manager.watch();
            let dns = Arc::clone(&self.dns_server);
            let label = kind.label();
            let addr_owned = addr.clone();
            // Each arm yields every task it started, because one of them starts
            // two: DoH with HTTP/3 is a TCP listener and a QUIC endpoint on the
            // same address, and a supervisor holding only one handle would stop
            // half a transport and report it down.

            // Each arm reports the address the socket ACTUALLY took, not the one
            // that was asked for. They differ whenever the request named port 0
            // — "give me any free port" — and a `Get<Transport>Config` that
            // echoed `127.0.0.1:0` back would be telling the caller nothing it
            // did not already know, on the one occasion it most needs an answer.
            let spawn_result = match kind {
                TransportKind::Dot => {
                    crate::dot_server::bind_dot(addr)
                        .await
                        .and_then(|listener| {
                            let actual = listener.local_addr()?.to_string();
                            Ok((
                                actual,
                                vec![tokio::spawn(async move {
                                    if let Err(e) =
                                        crate::dot_server::serve_dot_on(listener, dns, watch).await
                                    {
                                        warn!(
                                            "{} listener on {} exited: {:#}",
                                            label, addr_owned, e
                                        );
                                    }
                                })],
                            ))
                        })
                }
                TransportKind::Doh => crate::doh_server::bind_doh(addr).and_then(|listener| {
                    let bound_addr = listener.local_addr()?;
                    let actual = bound_addr.to_string();

                    // HTTP/3 is bound BEFORE the router is built, and on the
                    // address the TCP listener actually took rather than the one
                    // that was asked for. Both matter when the request named
                    // port 0: the QUIC endpoint has to land on the same port for
                    // the `Alt-Svc` advertisement to name anything real, and the
                    // router cannot advertise a port that has not been chosen.
                    let h3 = if settings.enable_h3 {
                        let endpoint =
                            crate::doh_h3_server::bind_doh_h3(&actual, manager.server_config())?;
                        let h3_addr = endpoint.local_addr()?;
                        let h3_dns = Arc::clone(&self.dns_server);
                        let h3_watch = manager.watch();
                        Some((
                            h3_addr.port(),
                            tokio::spawn(async move {
                                if let Err(e) = crate::doh_h3_server::serve_doh_h3_on(
                                    endpoint, h3_dns, h3_watch,
                                )
                                .await
                                {
                                    warn!(
                                        "{} HTTP/3 listener on {} exited: {:#}",
                                        label, h3_addr, e
                                    );
                                }
                            }),
                        ))
                    } else {
                        None
                    };

                    let (h3_port, h3_task) = match h3 {
                        Some((port, task)) => (Some(port), Some(task)),
                        None => (None, None),
                    };
                    let app = crate::doh_server::build_router(dns, h3_port);
                    let mut started = vec![tokio::spawn(async move {
                        if let Err(e) = crate::doh_server::serve_doh_on(listener, app, watch).await
                        {
                            warn!("{} listener on {} exited: {:#}", label, addr_owned, e);
                        }
                    })];
                    started.extend(h3_task);
                    Ok((actual, started))
                }),
                TransportKind::Doq => crate::doq_server::bind_doq(addr, manager.server_config())
                    .and_then(|endpoint| {
                        let actual = endpoint.local_addr()?.to_string();
                        Ok((
                            actual,
                            vec![tokio::spawn(async move {
                                if let Err(e) =
                                    crate::doq_server::serve_doq_on(endpoint, dns, watch).await
                                {
                                    warn!("{} listener on {} exited: {:#}", label, addr_owned, e);
                                }
                            })],
                        ))
                    }),
            };

            match spawn_result {
                Ok((actual, started)) => {
                    tasks.extend(started);
                    bound.push(actual);
                }
                Err(e) => {
                    // Unwind the ones already up rather than leaving a partial
                    // listener set behind.
                    for t in &tasks {
                        t.abort();
                    }
                    for t in tasks {
                        let _ = t.await;
                    }
                    return Err(e);
                }
            }
        }

        Ok(Running {
            settings: settings.clone(),
            bound,
            tasks,
            _manager: manager,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::dnsbl::DnsblChecker;

    fn server() -> Arc<DnsServer> {
        let db = Database::open_memory().expect("in-memory database");
        Arc::new(DnsServer::new(
            db,
            Arc::new(DnsblChecker::new()),
            Vec::new(),
        ))
    }

    fn generated_tls() -> crate::config::TlsConfig {
        crate::config::TlsConfig {
            cert_path: None,
            key_path: None,
            auto_self_signed: true,
            self_signed_sans: Vec::new(),
        }
    }

    /// Binds on an ephemeral port so nothing collides with a real listener or
    /// with another test running beside it.
    fn ephemeral(kind: &str) -> String {
        let _ = kind;
        "127.0.0.1:0".to_string()
    }

    #[tokio::test]
    async fn a_transport_starts_and_reports_what_it_bound() {
        let sup = TransportSupervisor::new(server());
        sup.apply(
            TransportKind::Dot,
            TransportSettings::new(BindList::one(ephemeral("dot")), generated_tls()),
        )
        .await
        .expect("DoT should start");

        // `127.0.0.1:0` is a request for any port, so what it actually bound is
        // the only useful answer — and the caller cannot know it otherwise.
        let bound = sup.bound_addrs(TransportKind::Dot).await;
        assert_eq!(bound.len(), 1);
        assert!(bound[0].starts_with("127.0.0.1:"));
        assert!(sup.current(TransportKind::Dot).await.is_some());
    }

    #[tokio::test]
    async fn an_empty_bind_list_shuts_the_transport_down() {
        let sup = TransportSupervisor::new(server());
        sup.apply(
            TransportKind::Dot,
            TransportSettings::new(BindList::one(ephemeral("dot")), generated_tls()),
        )
        .await
        .expect("DoT should start");
        assert!(sup.current(TransportKind::Dot).await.is_some());

        // Turning a transport off is a configuration, not an error — it is what
        // an omitted config section already means.
        sup.apply(
            TransportKind::Dot,
            TransportSettings::new(BindList::one(""), generated_tls()),
        )
        .await
        .expect("an empty bind list is a shutdown, not a failure");
        assert!(sup.current(TransportKind::Dot).await.is_none());
        assert!(sup.bound_addrs(TransportKind::Dot).await.is_empty());
    }

    #[tokio::test]
    async fn a_bad_bind_address_is_refused_before_the_running_listener_is_touched() {
        // The whole point of validating first: a typo must not cost the
        // listener that is currently serving.
        let sup = TransportSupervisor::new(server());
        sup.apply(
            TransportKind::Dot,
            TransportSettings::new(BindList::one(ephemeral("dot")), generated_tls()),
        )
        .await
        .expect("DoT should start");
        let before = sup.bound_addrs(TransportKind::Dot).await;

        let err = sup
            .apply(
                TransportKind::Dot,
                TransportSettings::new(BindList::one("no-port-here"), generated_tls()),
            )
            .await
            .expect_err("a bind address with no port must be refused");
        assert!(
            format!("{:#}", err).contains("no-port-here"),
            "the error must name the offending entry, got: {:#}",
            err
        );

        // Still up, still on the same address.
        assert_eq!(sup.bound_addrs(TransportKind::Dot).await, before);
    }

    #[tokio::test]
    async fn an_unreadable_certificate_is_refused_before_the_listener_is_touched() {
        let sup = TransportSupervisor::new(server());
        sup.apply(
            TransportKind::Dot,
            TransportSettings::new(BindList::one(ephemeral("dot")), generated_tls()),
        )
        .await
        .expect("DoT should start");
        let before = sup.bound_addrs(TransportKind::Dot).await;

        let broken = crate::config::TlsConfig {
            cert_path: Some("/nonexistent/cert.pem".to_string()),
            key_path: Some("/nonexistent/key.pem".to_string()),
            auto_self_signed: false,
            self_signed_sans: Vec::new(),
        };
        sup.apply(
            TransportKind::Dot,
            TransportSettings::new(BindList::one(ephemeral("dot")), broken),
        )
        .await
        .expect_err("a certificate that cannot be loaded must be refused");

        assert_eq!(
            sup.bound_addrs(TransportKind::Dot).await,
            before,
            "the previously-serving listener must be untouched"
        );
    }

    #[tokio::test]
    async fn rebinding_the_same_port_succeeds() {
        // The regression this whole ordering exists for: stopping the old
        // listener without awaiting it races the new bind against the old
        // socket's close, and fails with EADDRINUSE intermittently. Bind a real
        // port, then re-apply the SAME address.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
        let addr = probe.local_addr().expect("probe addr").to_string();
        drop(probe);

        let sup = TransportSupervisor::new(server());
        for attempt in 0..5 {
            sup.apply(
                TransportKind::Dot,
                TransportSettings::new(BindList::one(addr.clone()), generated_tls()),
            )
            .await
            .unwrap_or_else(|e| panic!("re-apply {} on {} failed: {:#}", attempt, addr, e));
            assert_eq!(
                sup.bound_addrs(TransportKind::Dot).await,
                vec![addr.clone()]
            );
        }
    }

    #[tokio::test]
    async fn each_transport_is_independent() {
        let sup = TransportSupervisor::new(server());
        sup.apply(
            TransportKind::Dot,
            TransportSettings::new(BindList::one(ephemeral("dot")), generated_tls()),
        )
        .await
        .expect("DoT should start");
        sup.apply(
            TransportKind::Doq,
            TransportSettings::new(BindList::one(ephemeral("doq")), generated_tls()),
        )
        .await
        .expect("DoQ should start");

        // Shutting one down must not disturb the other — they are separate
        // listeners and reconfiguring one is supposed to cost nothing elsewhere.
        sup.apply(
            TransportKind::Dot,
            TransportSettings::new(BindList::one(""), generated_tls()),
        )
        .await
        .expect("DoT shutdown");

        assert!(sup.current(TransportKind::Dot).await.is_none());
        assert!(sup.current(TransportKind::Doq).await.is_some());
    }
}
