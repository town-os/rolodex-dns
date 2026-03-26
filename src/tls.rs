/// TLS certificate management for encrypted DNS transports.
///
/// Supports loading certificates from PEM files and generating self-signed
/// certificates using rcgen. Used by DoT, DoH, and DoQ servers.
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::watch;

/// TLS configuration.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub auto_self_signed: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            auto_self_signed: true,
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
}

impl TlsManager {
    /// Creates a new TLS manager from configuration.
    pub fn new(config: TlsConfig, alpn_protocols: Vec<Vec<u8>>) -> Result<Self> {
        let server_config = Self::build_server_config(&config, &alpn_protocols)?;
        let (tx, rx) = watch::channel(Arc::new(server_config));
        Ok(Self {
            config,
            alpn_protocols,
            sender: Arc::new(tx),
            receiver: rx,
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
    /// Rebuilds the `rustls::ServerConfig` and pushes it to all watchers.
    pub fn reload(&self) -> Result<()> {
        let new_config = Self::build_server_config(&self.config, &self.alpn_protocols)?;
        self.sender
            .send(Arc::new(new_config))
            .map_err(|_| anyhow::anyhow!("all TLS config receivers have been dropped"))
    }

    fn build_server_config(
        config: &TlsConfig,
        alpn_protocols: &[Vec<u8>],
    ) -> Result<rustls::ServerConfig> {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let (certs, key) =
            if let (Some(cert_path), Some(key_path)) = (&config.cert_path, &config.key_path) {
                load_certs_from_pem(cert_path, key_path)?
            } else if config.auto_self_signed {
                generate_self_signed()?
            } else {
                anyhow::bail!("no TLS certificate configured and auto_self_signed is disabled");
            };

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("failed to build TLS server config")?;

        server_config.alpn_protocols = alpn_protocols.to_vec();

        Ok(server_config)
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
        .context(format!("failed to read certificate file: {}", cert_path))?;
    let key_data =
        std::fs::read(key_path).context(format!("failed to read key file: {}", key_path))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_data[..])
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse certificate PEM")?;

    let key = rustls_pemfile::private_key(&mut &key_data[..])
        .context("failed to parse private key PEM")?
        .context("no private key found in PEM file")?;

    Ok((certs, key))
}

/// Generates a self-signed certificate using rcgen.
pub fn generate_self_signed() -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .context("failed to create cert params")?;
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        )));
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V6(
            std::net::Ipv6Addr::LOCALHOST,
        )));

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
}
