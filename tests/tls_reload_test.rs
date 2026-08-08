//! TLS certificate hot-reload (`rolodex_dns::tls::TlsManager`).
//!
//! `TlsManager::reload()` had no test at all: the three unit tests in
//! `src/tls.rs` cover self-signed generation and a missing-file check, and
//! nothing called `reload()` or `watch()`. The claim being made — a certificate
//! can be replaced at runtime, e.g. after an ACME renewal — is precisely the one
//! that was unverified.
//!
//! Every assertion here is made through a **real TLS handshake** against an
//! acceptor built from the manager's current config, and the client records the
//! certificate the server actually presented. Reaching into
//! `rustls::ServerConfig` to compare `cert_resolver` pointers would pin the
//! implementation rather than the behaviour, and would not notice a config that
//! was rebuilt correctly but never reached the acceptor. What a peer sees on the
//! wire is the property that matters.
//!
//! The cases:
//!
//! - a rotated PEM pair on disk is picked up by `reload()`, and *only* by
//!   `reload()` — a manager that re-read the files on every `server_config()`
//!   call would make the reload a no-op and hide a broken one;
//! - a reload that cannot build a config (missing or corrupt PEM) fails **and
//!   leaves the previous certificate serving**, because the alternative is an
//!   ACME renewal that writes a truncated file taking the listener down;
//! - watchers subscribed before the reload observe it, which is the mechanism a
//!   listener would use to swap acceptors;
//! - ALPN survives the rebuild, since it is re-applied from the manager's stored
//!   protocols rather than carried over from the old config.
//!
//! ## Scope
//!
//! These test the manager. As of this writing `src/main.rs` takes a one-time
//! `server_config()` snapshot for each listener and never subscribes to
//! `watch()`, so no running listener swaps its certificate yet; that is a wiring
//! gap above this layer, not a defect in what is tested here.
//!
//! Everything binds ephemeral loopback ports and writes only into a temporary
//! directory; the host is untouched.

use rolodex_dns::tls::{TlsConfig, TlsManager};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// ALPN token used throughout, so the handshakes here look like DoT.
const ALPN: &[u8] = b"dot";

/// A handshake that works should be immediate; this only stops a hang from
/// becoming a stuck test binary.
const PATIENCE: Duration = Duration::from_secs(10);

/// A verifier that accepts any certificate and records the one it was shown.
///
/// Accepting anything is correct *here* and nowhere else: the assertion under
/// test is which certificate the server presented, so the verifier must not
/// reject it before the test can look. Signature verification is still delegated
/// to the real provider, so a server that could not prove possession of the key
/// still fails the handshake.
#[derive(Debug)]
struct RecordingVerifier {
    seen: Arc<Mutex<Option<CertificateDer<'static>>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock().expect("seen") = Some(end_entity.clone().into_owned());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A generated certificate: its PEM pair, and the DER a peer would see.
struct GeneratedCert {
    cert_pem: String,
    key_pem: String,
    der: Vec<u8>,
}

/// Generates a self-signed certificate carrying `name` as its subject alt name,
/// so two certificates in the same test are distinguishable by more than their
/// bytes when a failure has to be read.
fn generate_cert(name: &str) -> GeneratedCert {
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).expect("cert params");
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    let key_pair = rcgen::KeyPair::generate().expect("key pair");
    let cert = params.self_signed(&key_pair).expect("self-signed");

    GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        der: cert.der().to_vec(),
    }
}

/// Writes a PEM pair to `cert_path`/`key_path`, replacing whatever was there.
fn write_pem(cert_path: &std::path::Path, key_path: &std::path::Path, cert: &GeneratedCert) {
    std::fs::write(cert_path, &cert.cert_pem).expect("write certificate");
    std::fs::write(key_path, &cert.key_pem).expect("write key");
}

/// Completes one TLS handshake against an acceptor built from `config` and
/// returns the certificate DER the server presented.
///
/// A fresh listener per call, because the point is what a *new* connection sees:
/// a hot reload cannot retroactively change a session already in progress, and
/// testing it that way would be asserting something no implementation provides.
async fn presented_certificate(config: Arc<rustls::ServerConfig>) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let acceptor = TlsAcceptor::from(config);

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _unused = acceptor.accept(stream).await;
        }
    });

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let seen = Arc::new(Mutex::new(None));
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RecordingVerifier {
            seen: Arc::clone(&seen),
            provider,
        }))
        .with_no_client_auth();
    client_config.alpn_protocols = vec![ALPN.to_vec()];

    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let name = ServerName::try_from("localhost").expect("server name");
    tokio::time::timeout(PATIENCE, connector.connect(name, tcp))
        .await
        .expect("the handshake did not complete")
        .expect("TLS handshake");

    let der = seen.lock().expect("seen").clone();
    der.expect("the handshake completed without the client seeing a certificate")
        .as_ref()
        .to_vec()
}

/// A manager backed by a PEM pair in a temporary directory.
fn file_backed_manager() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    TlsManager,
) {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let dir = tempfile::tempdir().expect("temp dir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    write_pem(&cert_path, &key_path, &generate_cert("first.example.com"));

    let manager = TlsManager::new(
        TlsConfig {
            cert_path: Some(cert_path.to_string_lossy().to_string()),
            key_path: Some(key_path.to_string_lossy().to_string()),
            auto_self_signed: false,
        },
        vec![ALPN.to_vec()],
    )
    .expect("manager from PEM files");

    (dir, cert_path, key_path, manager)
}

// ============================================================================
// Rotation
// ============================================================================

/// The headline case: replace the PEM pair on disk, call `reload()`, and the
/// next connection is served the new certificate.
///
/// The pre-reload handshake is asserted too. Without it, a manager that served
/// the *second* certificate all along — because it read the files lazily at
/// handshake time — would pass on the post-reload assertion alone, and the
/// reload would be doing nothing.
#[tokio::test]
async fn reload_serves_a_rotated_certificate_from_disk() {
    let (_dir, cert_path, key_path, manager) = file_backed_manager();

    let renewed = generate_cert("renewed.example.com");

    let before = presented_certificate(manager.server_config()).await;
    assert_ne!(
        before, renewed.der,
        "the manager served the renewed certificate before it was written, so \
         this test cannot distinguish a reload from a lazy read"
    );

    write_pem(&cert_path, &key_path, &renewed);

    // Written but not yet reloaded: the manager must still be serving the old
    // certificate. This is what makes `reload()` the thing under test rather
    // than the filesystem.
    let after_write = presented_certificate(manager.server_config()).await;
    assert_eq!(
        after_write, before,
        "the certificate changed without `reload()` being called"
    );

    manager.reload().expect("reload after rotation");

    let after_reload = presented_certificate(manager.server_config()).await;
    assert_eq!(
        after_reload, renewed.der,
        "after `reload()` the manager is still serving the old certificate"
    );
}

/// `reload()` on an auto-self-signed manager must mint a *fresh* certificate
/// rather than republishing the one it already had. A reload that returned `Ok`
/// without rebuilding would be indistinguishable from a working one on the
/// file-backed path if the files happened not to change; here there are no files
/// and the only evidence is that the certificate is new.
#[tokio::test]
async fn reload_of_a_self_signed_manager_mints_a_new_certificate() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let manager = TlsManager::new(
        TlsConfig {
            cert_path: None,
            key_path: None,
            auto_self_signed: true,
        },
        vec![ALPN.to_vec()],
    )
    .expect("self-signed manager");

    let before = presented_certificate(manager.server_config()).await;
    manager.reload().expect("reload");
    let after = presented_certificate(manager.server_config()).await;

    assert_ne!(
        before, after,
        "`reload()` republished the same self-signed certificate instead of \
         generating a new one"
    );
}

/// The ALPN protocols are not part of the certificate, and `build_server_config`
/// re-applies them from the manager's stored list on every rebuild. If that were
/// dropped, a reload would silently produce a config that negotiates no ALPN —
/// and for DoT and DoQ, which mandate it, that turns a certificate renewal into
/// an outage.
#[tokio::test]
async fn alpn_protocols_survive_a_reload() {
    let (_dir, cert_path, key_path, manager) = file_backed_manager();

    assert_eq!(
        manager.server_config().alpn_protocols,
        vec![ALPN.to_vec()],
        "the manager did not apply its ALPN protocols in the first place"
    );

    write_pem(&cert_path, &key_path, &generate_cert("renewed.example.com"));
    manager.reload().expect("reload");

    assert_eq!(
        manager.server_config().alpn_protocols,
        vec![ALPN.to_vec()],
        "the reloaded config lost its ALPN protocols"
    );
}

// ============================================================================
// Failure
// ============================================================================

/// A reload that cannot build a config must fail *and change nothing*.
///
/// This is the renewal-gone-wrong case: an ACME client that truncates the
/// certificate file, or removes it between writes, and a reload that fires on
/// the half-written result. Replacing a working certificate with nothing would
/// take the listener down over a transient; keeping the old one degrades to
/// "serving a certificate that is merely getting older".
#[tokio::test]
async fn a_failed_reload_leaves_the_previous_certificate_serving() {
    let (_dir, cert_path, key_path, manager) = file_backed_manager();
    let before = presented_certificate(manager.server_config()).await;

    // A half-written PEM: the header is there, the body is not.
    std::fs::write(&cert_path, "-----BEGIN CERTIFICATE-----\n").expect("truncate certificate");

    assert!(
        manager.reload().is_err(),
        "reloading an unparseable certificate reported success"
    );

    let after = presented_certificate(manager.server_config()).await;
    assert_eq!(
        after, before,
        "a failed reload replaced the working certificate"
    );

    // And the recovery path: once the file is whole again, a reload takes.
    let renewed = generate_cert("recovered.example.com");
    write_pem(&cert_path, &key_path, &renewed);
    manager
        .reload()
        .expect("reload after the file was repaired");
    assert_eq!(
        presented_certificate(manager.server_config()).await,
        renewed.der,
        "the manager did not recover once the certificate file was valid again"
    );
}

/// A missing file is the other half of the same failure: the certificate is
/// deleted rather than corrupted. Both must be errors, and neither may disturb
/// what is currently being served.
#[tokio::test]
async fn a_reload_with_a_missing_file_fails_without_disturbing_the_current_config() {
    let (_dir, cert_path, _key_path, manager) = file_backed_manager();
    let before = presented_certificate(manager.server_config()).await;

    std::fs::remove_file(&cert_path).expect("remove certificate");

    assert!(
        manager.reload().is_err(),
        "reloading a missing certificate reported success"
    );
    assert_eq!(
        presented_certificate(manager.server_config()).await,
        before,
        "a reload against a missing file disturbed the served certificate"
    );
}

// ============================================================================
// Watchers
// ============================================================================

/// `watch()` is the mechanism a listener would use to pick up a rotation. A
/// receiver taken *before* the reload must observe the change, and the value it
/// then reads must be the new config — not merely a change notification with the
/// old bytes behind it.
#[tokio::test]
async fn a_watcher_subscribed_before_the_reload_observes_it() {
    let (_dir, cert_path, key_path, manager) = file_backed_manager();

    let mut watcher = manager.watch();
    assert!(
        !watcher.has_changed().expect("watch channel is open"),
        "a fresh watcher reports a change before anything has been reloaded"
    );

    let renewed = generate_cert("watched.example.com");
    write_pem(&cert_path, &key_path, &renewed);
    manager.reload().expect("reload");

    assert!(
        watcher.has_changed().expect("watch channel is open"),
        "the watcher did not observe the reload"
    );

    let observed = watcher.borrow_and_update().clone();
    assert_eq!(
        presented_certificate(observed).await,
        renewed.der,
        "the config the watcher received is not the reloaded one"
    );
}

/// A watcher created *after* a reload starts from the current value, so a
/// listener that subscribes late is not left serving a stale certificate until
/// the next rotation happens to come along.
#[tokio::test]
async fn a_watcher_subscribed_after_a_reload_starts_from_the_current_config() {
    let (_dir, cert_path, key_path, manager) = file_backed_manager();

    let renewed = generate_cert("late.example.com");
    write_pem(&cert_path, &key_path, &renewed);
    manager.reload().expect("reload");

    let watcher = manager.watch();
    let current = watcher.borrow().clone();
    assert_eq!(
        presented_certificate(current).await,
        renewed.der,
        "a watcher subscribing after a reload started from the pre-reload config"
    );
}

/// Several watchers all receive the same reload. A `watch` channel broadcasts,
/// but the manager holds its own receiver as well; this pins that additional
/// subscribers are served rather than the notification going to whichever one
/// asked first.
#[tokio::test]
async fn every_watcher_receives_the_same_reload() {
    let (_dir, cert_path, key_path, manager) = file_backed_manager();

    let mut watchers: Vec<_> = (0..3).map(|_| manager.watch()).collect();

    let renewed = generate_cert("broadcast.example.com");
    write_pem(&cert_path, &key_path, &renewed);
    manager.reload().expect("reload");

    for (i, watcher) in watchers.iter_mut().enumerate() {
        assert!(
            watcher.has_changed().expect("watch channel is open"),
            "watcher {i} did not observe the reload"
        );
        let observed = watcher.borrow_and_update().clone();
        assert_eq!(
            presented_certificate(observed).await,
            renewed.der,
            "watcher {i} received a config other than the reloaded one"
        );
    }
}

// ============================================================================
// Construction
// ============================================================================

/// A manager with neither certificate paths nor `auto_self_signed` has nothing
/// to serve and must fail at construction rather than producing a config that
/// fails every handshake later.
#[tokio::test]
async fn a_manager_with_no_certificate_source_is_refused() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let outcome = TlsManager::new(
        TlsConfig {
            cert_path: None,
            key_path: None,
            auto_self_signed: false,
        },
        vec![ALPN.to_vec()],
    );

    assert!(
        outcome.is_err(),
        "a manager with no certificate and no self-signed fallback was accepted"
    );
}
