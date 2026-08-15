/// TLS certificate management for encrypted DNS transports.
///
/// Supports loading certificates from PEM files and generating self-signed
/// certificates using rcgen. Used by DoT, DoH, and DoQ servers.
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tracing::{info, warn};

/// How often a file-backed listener's certificate is checked for a change.
///
/// This is a poll rather than an inotify watch on purpose: the interesting write
/// is not always to the file itself. An ACME client that renews by writing a new
/// file and renaming it over the old one, or by replacing a symlink to a
/// versioned directory (certbot's `live/` layout), changes the *directory* entry
/// and leaves an inotify watch on the old inode watching a file nobody will ever
/// write to again. Re-reading the path by name catches every one of those
/// shapes, and thirty seconds of an expiring-but-still-valid certificate costs
/// nothing next to a renewal that silently never takes effect.
pub const CERT_RELOAD_INTERVAL: Duration = Duration::from_secs(30);

/// TLS configuration.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub auto_self_signed: bool,
    /// Extra subject alternative names to bake into an auto-generated
    /// certificate, on top of the built-in loopback set.
    ///
    /// A generated certificate naming only `localhost` is unusable to any client
    /// that checks the name it dialled — which is every DoT client configured
    /// with an authentication name, and the only way a self-signed certificate
    /// can be verified at all beyond raw public-key pinning. The listener's own
    /// bind addresses land here so a LAN client dialling the box by address gets
    /// a certificate that matches; operators add hostnames via
    /// `<transport>.tls.self_signed_sans`.
    ///
    /// Ignored entirely when `cert_path`/`key_path` are set — that certificate
    /// carries whatever names it was issued for.
    pub self_signed_sans: Vec<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            auto_self_signed: true,
            self_signed_sans: Vec::new(),
        }
    }
}

impl TlsConfig {
    /// Builds a listener's runtime TLS config from its configured `tls` section
    /// and the addresses that listener will actually bind.
    ///
    /// The bind addresses are folded into `self_signed_sans` because they are
    /// the identities clients dial *by construction* — a listener on
    /// `192.168.1.5:853` is reached as `192.168.1.5`, and an operator should not
    /// have to restate that in the config for a name-checking client to work.
    /// Operator-supplied names come first so the list reads as configured, with
    /// the derived addresses appended; duplicates and the wildcard binds are
    /// dropped downstream by [`generate_self_signed_with`].
    ///
    /// `binds` are socket-address strings as [`crate::config::resolve_bind_addrs`]
    /// returns them (`1.2.3.4:853`, `[fd00::5]:853`). One that does not parse is
    /// skipped rather than fatal: it will fail at `bind()` with a far better
    /// message than a certificate error would give.
    pub fn for_listener(configured: &crate::config::TlsConfig, binds: &[String]) -> Self {
        let mut sans = configured.self_signed_sans.clone();
        for bind in binds {
            if let Ok(addr) = bind.parse::<std::net::SocketAddr>() {
                sans.push(addr.ip().to_string());
            }
        }
        Self {
            cert_path: configured.cert_path.clone(),
            key_path: configured.key_path.clone(),
            auto_self_signed: configured.auto_self_signed,
            self_signed_sans: sans,
        }
    }
}

/// Manages TLS certificates with hot-reload support.
///
/// Holds the TLS configuration and ALPN protocols so certificates can be
/// reloaded at runtime (e.g. after ACME renewal). Callers obtain the current
/// config via `server_config()`, or subscribe to changes via `watch()`.
pub struct TlsManager {
    config: TlsConfig,
    alpn_protocols: Vec<Vec<u8>>,
    sender: Arc<watch::Sender<Arc<rustls::ServerConfig>>>,
    receiver: watch::Receiver<Arc<rustls::ServerConfig>>,
    /// Fingerprint of the file contents behind the config currently being
    /// served, or `None` when the material was generated rather than read.
    ///
    /// Recorded only after a *successful* load, which is what makes the poller
    /// self-correcting: a renewal caught mid-write leaves the fingerprint at the
    /// last good pair, so the next tick sees a difference again and retries
    /// rather than accepting the torn state as the new normal.
    loaded: Mutex<Option<[u8; 32]>>,
}

impl TlsManager {
    /// Creates a new TLS manager from configuration.
    pub fn new(config: TlsConfig, alpn_protocols: Vec<Vec<u8>>) -> Result<Self> {
        let material = load_material(&config)?;
        let fingerprint = material.fingerprint;
        let server_config = build_server_config(material, &alpn_protocols)?;
        let (tx, rx) = watch::channel(Arc::new(server_config));
        Ok(Self {
            config,
            alpn_protocols,
            sender: Arc::new(tx),
            receiver: rx,
            loaded: Mutex::new(fingerprint),
        })
    }

    /// Returns the current server config for use with TLS acceptors.
    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        self.receiver.borrow().clone()
    }

    /// Returns a watch receiver for config changes (hot-reload).
    pub fn watch(&self) -> watch::Receiver<Arc<rustls::ServerConfig>> {
        self.receiver.clone()
    }

    /// Reloads the TLS certificate from the current configuration.
    ///
    /// Rebuilds the `rustls::ServerConfig` and pushes it to all watchers,
    /// unconditionally — see [`reload_if_changed`](Self::reload_if_changed) for
    /// the poll that only acts on a real change. A failure leaves the previous
    /// certificate serving: a renewal that writes a truncated file must not take
    /// the listener down with it.
    pub fn reload(&self) -> Result<()> {
        let material = load_material(&self.config)?;
        let fingerprint = material.fingerprint;
        let new_config = build_server_config(material, &self.alpn_protocols)?;
        self.sender
            .send(Arc::new(new_config))
            .map_err(|_| anyhow::anyhow!("all TLS config receivers have been dropped"))?;
        self.record_loaded(fingerprint);
        Ok(())
    }

    /// Reloads only if the certificate files have changed since the last
    /// successful load. Returns whether a reload happened.
    ///
    /// Always `Ok(false)` for a manager serving generated material: there is no
    /// file behind it, so nothing on disk can change, and re-generating would
    /// hand every client a different self-signed certificate every poll.
    pub fn reload_if_changed(&self) -> Result<bool> {
        let material = load_material(&self.config)?;
        let Some(fingerprint) = material.fingerprint else {
            return Ok(false);
        };
        if self.loaded_fingerprint() == Some(fingerprint) {
            return Ok(false);
        }
        let new_config = build_server_config(material, &self.alpn_protocols)?;
        self.sender
            .send(Arc::new(new_config))
            .map_err(|_| anyhow::anyhow!("all TLS config receivers have been dropped"))?;
        self.record_loaded(Some(fingerprint));
        Ok(true)
    }

    /// Whether this manager has certificate files to watch at all.
    pub fn is_file_backed(&self) -> bool {
        self.config.cert_path.is_some() && self.config.key_path.is_some()
    }

    /// Spawns the task that keeps this manager's certificate current, polling
    /// every `interval`. Returns `None` when there is nothing to watch.
    ///
    /// `label` names the listener in the log lines, since a box can run four of
    /// these and "certificate reloaded" on its own says nothing about which.
    pub fn spawn_reloader(
        self: &Arc<Self>,
        label: &'static str,
        interval: Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if !self.is_file_backed() {
            return None;
        }
        let manager = Arc::clone(self);
        Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // The first tick fires immediately and would re-read files that were
            // just read by `new()`; skipping it costs nothing and keeps the log
            // quiet at boot.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                // On a blocking pool, not a runtime worker. The read is two small
                // files, but this box's data directory can be removable media —
                // a stalled read on a runtime thread would stall whatever DNS
                // queries that thread was serving, and the certificate poll is
                // the least urgent thing running.
                let polled = Arc::clone(&manager);
                let outcome = tokio::task::spawn_blocking(move || polled.reload_if_changed()).await;
                match outcome {
                    Ok(Ok(true)) => info!("{} TLS certificate reloaded from disk", label),
                    Ok(Ok(false)) => {}
                    // Logged every tick until it resolves, and deliberately so: a
                    // renewal that has been failing for an hour is worth
                    // repeating, and the previous certificate is still serving
                    // in the meantime.
                    Ok(Err(e)) => warn!("{} TLS certificate reload failed: {:#}", label, e),
                    // The poll itself panicked. Log it and keep polling: the
                    // previous certificate is still serving, and giving up would
                    // silently restore the restart-to-renew behaviour this task
                    // exists to remove.
                    Err(e) => warn!("{} TLS certificate poll did not complete: {}", label, e),
                }
            }
        }))
    }

    fn loaded_fingerprint(&self) -> Option<[u8; 32]> {
        // The guarded value is a plain fingerprint with no invariant a panic
        // could break, so a poisoned lock is recovered rather than propagated —
        // refusing to reload certificates for the life of the process because
        // some other task panicked would be the worse failure.
        *self
            .loaded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn record_loaded(&self, fingerprint: Option<[u8; 32]>) {
        *self
            .loaded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = fingerprint;
    }
}

/// The certificate and key a manager serves, with a fingerprint of the bytes
/// they were read from.
struct Material {
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    /// `None` when the material was generated rather than read from disk.
    fingerprint: Option<[u8; 32]>,
}

/// Reads (or generates) the certificate material a `TlsConfig` describes.
///
/// The fingerprint is taken over the bytes actually parsed, in the same pass —
/// not by stat-ing the files afterwards. Fingerprinting separately would leave a
/// window where a file changed between the load and the stat, and the manager
/// would record the *new* fingerprint against the *old* certificate and never
/// notice the renewal at all.
///
/// The two files are hashed together with a length prefix on the certificate, so
/// moving a byte across the boundary between them cannot produce the same
/// fingerprint as leaving it where it was.
fn load_material(config: &TlsConfig) -> Result<Material> {
    if let (Some(cert_path), Some(key_path)) = (&config.cert_path, &config.key_path) {
        let cert_data = std::fs::read(cert_path)
            .with_context(|| format!("failed to read certificate file: {}", cert_path))?;
        let key_data = std::fs::read(key_path)
            .with_context(|| format!("failed to read key file: {}", key_path))?;

        let mut hasher = Sha256::new();
        hasher.update((cert_data.len() as u64).to_be_bytes());
        hasher.update(&cert_data);
        hasher.update(&key_data);
        let fingerprint: [u8; 32] = hasher.finalize().into();

        let (certs, key) = parse_pem_pair(&cert_data, &key_data)?;
        Ok(Material {
            certs,
            key,
            fingerprint: Some(fingerprint),
        })
    } else if config.auto_self_signed {
        let (certs, key) = generate_self_signed_with(&config.self_signed_sans)?;
        Ok(Material {
            certs,
            key,
            fingerprint: None,
        })
    } else {
        anyhow::bail!("no TLS certificate configured and auto_self_signed is disabled");
    }
}

/// Builds a `rustls::ServerConfig` from loaded material.
///
/// `with_single_cert` cross-checks the private key's `SubjectPublicKeyInfo`
/// against the certificate's, which is what makes polling a renewal safe without
/// any coordination with whoever writes the files: a poll that catches an ACME
/// client between writing the new certificate and the new key sees a pair that
/// does not match and fails here, and the caller keeps serving the old one and
/// tries again.
fn build_server_config(
    material: Material,
    alpn_protocols: &[Vec<u8>],
) -> Result<rustls::ServerConfig> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(material.certs, material.key)
        .context("failed to build TLS server config")?;

    server_config.alpn_protocols = alpn_protocols.to_vec();

    Ok(server_config)
}

/// Keeps an `axum-server` TLS config in step with a manager's watch channel.
///
/// The HTTPS listeners (DoH, ACME, the enrollment portal) hold their certificate
/// inside an `axum_server::RustlsConfig` rather than reading it per connection,
/// so swapping one means storing into that config rather than handing the
/// listener a new value. Never returns; callers run it alongside the server and
/// drop it when the server does.
pub async fn drive_axum_tls(
    tls_config: axum_server::tls_rustls::RustlsConfig,
    mut updates: watch::Receiver<Arc<rustls::ServerConfig>>,
) {
    while updates.changed().await.is_ok() {
        tls_config.reload_from_config(updates.borrow_and_update().clone());
    }
}

/// Loads certificates and private key from PEM files.
pub fn load_certs_from_pem(
    cert_path: &str,
    key_path: &str,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let cert_data = std::fs::read(cert_path)
        .with_context(|| format!("failed to read certificate file: {}", cert_path))?;
    let key_data = std::fs::read(key_path)
        .with_context(|| format!("failed to read key file: {}", key_path))?;
    parse_pem_pair(&cert_data, &key_data)
}

/// Parses a PEM certificate chain and private key out of bytes already read.
///
/// Separate from [`load_certs_from_pem`] so the reload path can hash the exact
/// bytes it parses rather than reading each file twice.
fn parse_pem_pair(
    cert_data: &[u8],
    key_data: &[u8],
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_data[..])
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse certificate PEM")?;

    let key = rustls_pemfile::private_key(&mut &key_data[..])
        .context("failed to parse private key PEM")?
        .context("no private key found in PEM file")?;

    Ok((certs, key))
}

/// The subject alternative names every generated certificate carries, whatever
/// else is added: the loopback identities the box's own clients dial.
const BASE_SANS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// Normalizes one SAN entry so two spellings of the same identity dedupe against
/// each other.
///
/// A bind address reaches here as it was written in the config, and `[::1]`,
/// `::1` and `::0:1` are one address while `DNS.Home.` and `dns.home` are one
/// name. Without this the certificate would carry the same identity two or three
/// times over — harmless on the wire, but it makes the SAN list impossible to
/// assert against and hides a genuine duplicate behind a formatting difference.
///
/// Returns `None` for an entry with nothing in it.
fn normalize_san(entry: &str) -> Option<String> {
    let entry = entry.trim();
    // A bracketed IPv6 literal is how a bind address spells one; the brackets
    // are socket-address syntax, not part of the address.
    let entry = entry
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(entry);
    if entry.is_empty() {
        return None;
    }
    match entry.parse::<std::net::IpAddr>() {
        // `to_canonical` folds `::ffff:192.0.2.1` onto `192.0.2.1`, which is the
        // form a v4 peer's certificate check uses.
        Ok(ip) => Some(ip.to_canonical().to_string()),
        Err(_) => {
            let name = entry.trim_end_matches('.').to_ascii_lowercase();
            (!name.is_empty()).then_some(name)
        }
    }
}

/// Builds the SAN list for a generated certificate: the loopback set, then
/// `extra` in the order given, with duplicates dropped.
///
/// Order is preserved rather than sorted so the list reads the way it was
/// configured, and the loopback names come first because they are the ones the
/// box's own resolver path depends on.
fn self_signed_sans(extra: &[String]) -> Vec<String> {
    let mut sans: Vec<String> = BASE_SANS.iter().map(|s| s.to_string()).collect();
    for entry in extra {
        let Some(normalized) = normalize_san(entry) else {
            continue;
        };
        // An unspecified address is not an identity — `0.0.0.0:853` is "every
        // address", and no client ever dials it by that name. Binding the
        // wildcard is the common LAN case, so this is reached on most boxes.
        if normalized == "0.0.0.0" || normalized == "::" {
            continue;
        }
        if !sans.contains(&normalized) {
            sans.push(normalized);
        }
    }
    sans
}

/// Generates a self-signed certificate covering the loopback identities only.
pub fn generate_self_signed() -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    generate_self_signed_with(&[])
}

/// Generates a self-signed certificate using rcgen, covering the loopback
/// identities plus `extra_sans`.
///
/// `rcgen::CertificateParams::new` classifies each entry itself — an entry that
/// parses as an IP address becomes an `iPAddress` SAN and everything else a
/// `dNSName` — which is the same split a TLS client applies when it decides
/// whether it dialled a name or an address, so the two agree by construction.
pub fn generate_self_signed_with(
    extra_sans: &[String],
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let sans = self_signed_sans(extra_sans);
    let params = rcgen::CertificateParams::new(sans.clone())
        .with_context(|| format!("failed to create cert params for SANs {:?}", sans))?;

    let key_pair = rcgen::KeyPair::generate().context("failed to generate key pair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("failed to generate self-signed certificate")?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    );

    Ok((vec![cert_der], key_der))
}

/// Checks if cert/key files exist at the given paths.
pub fn certs_exist(cert_path: &str, key_path: &str) -> bool {
    Path::new(cert_path).exists() && Path::new(key_path).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed() {
        let (certs, key) = generate_self_signed().unwrap();
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].is_empty());
        match &key {
            rustls::pki_types::PrivateKeyDer::Pkcs8(k) => assert!(!k.secret_pkcs8_der().is_empty()),
            _ => panic!("expected PKCS8 key"),
        }
    }

    #[test]
    fn test_tls_manager_self_signed() {
        let config = TlsConfig {
            cert_path: None,
            key_path: None,
            auto_self_signed: true,
            self_signed_sans: Vec::new(),
        };
        let manager = TlsManager::new(config, vec![b"h2".to_vec()]).unwrap();
        let sc = manager.server_config();
        assert_eq!(sc.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn test_certs_exist_false() {
        assert!(!certs_exist(
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem"
        ));
    }

    #[test]
    fn test_normalize_san_strips_ipv6_brackets() {
        // `[fd00::1]` is how a bind address spells the same identity `fd00::1`
        // does; a certificate SAN with brackets in it matches nothing.
        assert_eq!(normalize_san("[fd00::1]").as_deref(), Some("fd00::1"));
        assert_eq!(normalize_san("fd00::1").as_deref(), Some("fd00::1"));
    }

    #[test]
    fn test_normalize_san_canonicalizes_addresses() {
        // Two spellings of one IPv6 address, and the v4-mapped form of a v4 one.
        assert_eq!(normalize_san("::0:1").as_deref(), Some("::1"));
        assert_eq!(
            normalize_san("::ffff:192.0.2.1").as_deref(),
            Some("192.0.2.1")
        );
    }

    #[test]
    fn test_normalize_san_folds_name_case_and_root_dot() {
        // DNS names are case-insensitive and the trailing root dot is optional,
        // so `DNS.Home.` and `dns.home` are one identity.
        assert_eq!(normalize_san("DNS.Home.").as_deref(), Some("dns.home"));
    }

    #[test]
    fn test_normalize_san_rejects_empty() {
        assert_eq!(normalize_san(""), None);
        assert_eq!(normalize_san("   "), None);
        assert_eq!(normalize_san("[]"), None);
        // A bare root dot normalizes to nothing, not to an empty DNS name.
        assert_eq!(normalize_san("."), None);
    }

    #[test]
    fn test_self_signed_sans_always_carries_loopback() {
        // The control for every case below: the loopback identities are present
        // whether or not anything was added, because the box's own resolver path
        // dials them.
        let bare = self_signed_sans(&[]);
        assert_eq!(bare, vec!["localhost", "127.0.0.1", "::1"]);

        let with_extra = self_signed_sans(&["192.168.1.5".to_string()]);
        for base in ["localhost", "127.0.0.1", "::1"] {
            assert!(
                with_extra.iter().any(|s| s == base),
                "adding a LAN address dropped the base SAN {base}: {with_extra:?}"
            );
        }
    }

    #[test]
    fn test_self_signed_sans_appends_extras_in_order() {
        let sans = self_signed_sans(&[
            "192.168.1.5".to_string(),
            "dns.home".to_string(),
            "[fd00::5]".to_string(),
        ]);
        assert_eq!(
            sans,
            vec![
                "localhost",
                "127.0.0.1",
                "::1",
                "192.168.1.5",
                "dns.home",
                "fd00::5",
            ]
        );
    }

    #[test]
    fn test_self_signed_sans_dedupes_against_the_base_set() {
        // A loopback bind address is the ordinary case for DoH, which the
        // install fronts with an ingress: it must not produce `127.0.0.1` twice.
        let sans = self_signed_sans(&["127.0.0.1".to_string(), "[::1]".to_string()]);
        assert_eq!(sans, vec!["localhost", "127.0.0.1", "::1"]);
    }

    #[test]
    fn test_self_signed_sans_drops_the_wildcard_addresses() {
        // `0.0.0.0:853` is the documented DoT default and means "every address";
        // it is not an identity any client dials, and a certificate asserting it
        // is asserting nonsense.
        let sans = self_signed_sans(&[
            "0.0.0.0".to_string(),
            "::".to_string(),
            "192.0.2.9".to_string(),
        ]);
        assert_eq!(sans, vec!["localhost", "127.0.0.1", "::1", "192.0.2.9"]);
    }

    #[test]
    fn test_for_listener_derives_sans_from_bind_addresses() {
        // The whole point: an operator who wrote nothing but a bind address
        // still gets a certificate naming the address clients dial.
        let configured = crate::config::TlsConfig::default();
        let built = TlsConfig::for_listener(
            &configured,
            &["192.168.1.5:853".to_string(), "[fd00::5]:853".to_string()],
        );
        assert_eq!(
            built.self_signed_sans,
            vec!["192.168.1.5".to_string(), "fd00::5".to_string()]
        );
        assert_eq!(
            self_signed_sans(&built.self_signed_sans),
            vec!["localhost", "127.0.0.1", "::1", "192.168.1.5", "fd00::5"]
        );
    }

    #[test]
    fn test_for_listener_keeps_configured_names_ahead_of_binds() {
        let configured = crate::config::TlsConfig {
            cert_path: None,
            key_path: None,
            auto_self_signed: true,
            self_signed_sans: vec!["dns.home".to_string()],
        };
        let built = TlsConfig::for_listener(&configured, &["192.168.1.5:853".to_string()]);
        assert_eq!(
            built.self_signed_sans,
            vec!["dns.home".to_string(), "192.168.1.5".to_string()]
        );
    }

    #[test]
    fn test_for_listener_skips_an_unparseable_bind() {
        // `resolve_bind_addrs` returns socket-address strings, but a listener
        // whose bind is malformed must still get a certificate — it fails at
        // `bind()` with a message about the address, not a TLS error.
        let configured = crate::config::TlsConfig::default();
        let built = TlsConfig::for_listener(
            &configured,
            &["not-an-address".to_string(), "192.168.1.5:853".to_string()],
        );
        assert_eq!(built.self_signed_sans, vec!["192.168.1.5".to_string()]);
    }

    #[test]
    fn test_for_listener_carries_the_pem_paths_through() {
        // The control for the SAN cases: a configured certificate is used as-is,
        // and `for_listener` must not quietly turn a listener into a self-signed
        // one by dropping the paths.
        let configured = crate::config::TlsConfig {
            cert_path: Some("/etc/certs/dot.pem".to_string()),
            key_path: Some("/etc/certs/dot.key".to_string()),
            auto_self_signed: false,
            self_signed_sans: Vec::new(),
        };
        let built = TlsConfig::for_listener(&configured, &["192.168.1.5:853".to_string()]);
        assert_eq!(built.cert_path.as_deref(), Some("/etc/certs/dot.pem"));
        assert_eq!(built.key_path.as_deref(), Some("/etc/certs/dot.key"));
        assert!(!built.auto_self_signed);
    }

    #[test]
    fn test_generate_self_signed_with_extra_sans_succeeds() {
        // The paired negative is `test_generate_self_signed_rejects_a_bad_san`:
        // a generator that accepted anything would pass this on its own.
        let (certs, _key) = generate_self_signed_with(&[
            "192.168.1.5".to_string(),
            "dns.home".to_string(),
            "[fd00::5]".to_string(),
        ])
        .unwrap();
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].is_empty());
    }

    #[test]
    fn test_generate_self_signed_rejects_a_bad_san() {
        // A non-ASCII name is neither an IP address nor an IA5String, so it
        // cannot be encoded as a dNSName. Failing loudly beats generating a
        // certificate that silently omits the name the operator asked for.
        let err = generate_self_signed_with(&["dns.hõme".to_string()])
            .expect_err("a non-IA5 DNS name is not encodable as a dNSName SAN");
        assert!(
            format!("{err:#}").contains("cert params"),
            "unexpected error: {err:#}"
        );
    }
}
