//! Encrypted DNS upstream clients: DNS-over-HTTPS (DoH, :443) and
//! DNS-over-TLS (DoT, :853).
//!
//! Used by the `auto` resolution fallback chain (see [`crate::dns_server`]) to
//! reach public resolvers over an encrypted transport when plaintext DNS (:53)
//! is filtered. **DoH is preferred**: :443 looks like ordinary HTTPS and
//! survives deep-packet-inspection filtering that blocks DoT's :853 (observed on
//! real networks that let the TCP connect through but drop the DoT TLS session).
//!
//! Both transports send the caller's exact wire query and return the raw wire
//! response, preserving EDNS/flags/rcode like the UDP/TCP forward paths.

use anyhow::{Context, Result, anyhow, bail};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// Encrypted transport for a secure upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// DNS-over-HTTPS (RFC 8484), HTTP POST of `application/dns-message` on :443.
    Doh,
    /// DNS-over-TLS (RFC 7858), length-prefixed wire messages on :853.
    Dot,
}

/// A resolved encrypted upstream: an address dialed directly by IP (so it needs
/// no prior DNS) plus the TLS server name its certificate is validated against.
#[derive(Debug, Clone)]
pub struct SecureUpstream {
    pub transport: Transport,
    pub addr: SocketAddr,
    pub server_name: ServerName<'static>,
    /// SNI / Host hostname string (e.g. `cloudflare-dns.com`).
    pub hostname: String,
    /// DoH request path (e.g. `/dns-query`); unused for DoT.
    pub path: String,
    /// Human-readable label for logging, e.g. `https://cloudflare-dns.com`.
    pub label: String,
}

impl SecureUpstream {
    /// Builds a secure upstream from a config entry. Returns an error for an
    /// unsupported transport or an unparseable address/hostname so the caller
    /// can warn and skip it rather than fail startup.
    pub fn from_config(cfg: &crate::config::SecureUpstreamConfig) -> Result<Self> {
        let transport = match cfg.transport.to_ascii_lowercase().as_str() {
            "https" | "doh" => Transport::Doh,
            "tls" | "dot" => Transport::Dot,
            other => {
                return Err(anyhow!(
                    "unsupported secure upstream transport '{}' (use 'https'/DoH or 'tls'/DoT)",
                    other
                ));
            }
        };
        let addr: SocketAddr = cfg
            .addr
            .parse()
            .with_context(|| format!("invalid secure upstream address '{}'", cfg.addr))?;
        let server_name = ServerName::try_from(cfg.hostname.clone())
            .with_context(|| format!("invalid secure upstream hostname '{}'", cfg.hostname))?;
        let scheme = match transport {
            Transport::Doh => "https",
            Transport::Dot => "tls",
        };
        Ok(Self {
            transport,
            addr,
            server_name,
            hostname: cfg.hostname.clone(),
            path: cfg.path.clone(),
            label: format!("{scheme}://{}", cfg.hostname),
        })
    }
}

/// Builds a rustls client config with the given ALPN protocols, Mozilla webpki
/// roots, and no client auth. Pins the ring provider (like `src/tls.rs`) so
/// `ClientConfig::builder()` has an unambiguous default even with aws-lc-rs also
/// compiled in.
fn build_client_config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// Client config for DoT (ALPN `dot`), built once.
fn dot_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| build_client_config(&[b"dot"]))
        .clone()
}

/// Client config for DoH (ALPN `http/1.1` — we speak HTTP/1.1 explicitly), built
/// once. Offering only `http/1.1` prevents the server from negotiating h2, which
/// our hand-written request does not speak.
fn doh_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| build_client_config(&[b"http/1.1"]))
        .clone()
}

/// Sends a wire DNS query to a secure upstream and returns the wire response,
/// dispatching on the upstream's transport. Bounded by `timeout`.
pub async fn query(
    query_data: &[u8],
    upstream: &SecureUpstream,
    timeout: Duration,
) -> Result<Vec<u8>> {
    match upstream.transport {
        Transport::Doh => query_doh(query_data, upstream, timeout).await,
        Transport::Dot => query_dot(query_data, upstream, timeout).await,
    }
}

/// DNS-over-HTTPS: HTTP/1.1 POST of the wire query as `application/dns-message`.
pub async fn query_doh(
    query_data: &[u8],
    upstream: &SecureUpstream,
    timeout: Duration,
) -> Result<Vec<u8>> {
    tokio::time::timeout(timeout, async move {
        let tcp = TcpStream::connect(upstream.addr)
            .await
            .with_context(|| format!("DoH TCP connect to {} failed", upstream.label))?;
        tcp.set_nodelay(true).ok();

        let connector = TlsConnector::from(doh_config());
        let mut tls = connector
            .connect(upstream.server_name.clone(), tcp)
            .await
            .with_context(|| format!("DoH TLS handshake with {} failed", upstream.label))?;

        // `Connection: close` lets us read the body to EOF, which also sidesteps
        // keep-alive framing ambiguity.
        let mut req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            upstream.path,
            upstream.hostname,
            query_data.len(),
        )
        .into_bytes();
        req.extend_from_slice(query_data);
        tls.write_all(&req).await.context("DoH request write failed")?;
        tls.flush().await.context("DoH flush failed")?;

        // Read headers up to the blank line.
        let mut headers = Vec::with_capacity(512);
        let mut byte = [0u8; 1];
        loop {
            let n = tls.read(&mut byte).await.context("DoH header read failed")?;
            if n == 0 {
                bail!("DoH {}: connection closed before headers complete", upstream.label);
            }
            headers.push(byte[0]);
            if headers.ends_with(b"\r\n\r\n") {
                break;
            }
            if headers.len() > 16384 {
                bail!("DoH {}: response headers too large", upstream.label);
            }
        }

        let header_str = String::from_utf8_lossy(&headers);
        let status = header_str.lines().next().unwrap_or_default();
        if !status.contains(" 200") {
            bail!("DoH {} returned HTTP status: {}", upstream.label, status.trim());
        }
        let content_length = header_str.lines().find_map(|l| {
            let low = l.to_ascii_lowercase();
            low.strip_prefix("content-length:")
                .and_then(|v| v.trim().parse::<usize>().ok())
        });
        let chunked = header_str.lines().any(|l| {
            let low = l.to_ascii_lowercase();
            low.starts_with("transfer-encoding:") && low.contains("chunked")
        });

        // With `Connection: close` the server sends the whole body then closes,
        // so reading to EOF is safe regardless of framing.
        let mut rest = Vec::new();
        tls.read_to_end(&mut rest)
            .await
            .context("DoH body read failed")?;

        let body = if chunked {
            dechunk(&rest).context("DoH chunked decode failed")?
        } else if let Some(len) = content_length {
            if rest.len() < len {
                bail!("DoH {}: body shorter than Content-Length", upstream.label);
            }
            rest.truncate(len);
            rest
        } else {
            rest
        };
        if body.is_empty() {
            bail!("DoH {} returned empty body", upstream.label);
        }
        Ok(body)
    })
    .await
    .with_context(|| format!("DoH query to {} timed out", upstream.label))?
}

/// DNS-over-TLS: length-prefixed wire message over TLS (RFC 7858).
pub async fn query_dot(
    query_data: &[u8],
    upstream: &SecureUpstream,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let len =
        u16::try_from(query_data.len()).context("DNS query too large for DoT 2-byte framing")?;

    tokio::time::timeout(timeout, async move {
        let tcp = TcpStream::connect(upstream.addr)
            .await
            .with_context(|| format!("DoT TCP connect to {} failed", upstream.label))?;
        tcp.set_nodelay(true).ok();

        let connector = TlsConnector::from(dot_config());
        let mut tls = connector
            .connect(upstream.server_name.clone(), tcp)
            .await
            .with_context(|| format!("DoT TLS handshake with {} failed", upstream.label))?;

        let mut framed = Vec::with_capacity(2 + query_data.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(query_data);
        tls.write_all(&framed).await.context("DoT write failed")?;
        tls.flush().await.context("DoT flush failed")?;

        let mut len_buf = [0u8; 2];
        tls.read_exact(&mut len_buf)
            .await
            .context("DoT response length read failed")?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 {
            bail!("DoT upstream {} returned empty response", upstream.label);
        }
        let mut resp = vec![0u8; resp_len];
        tls.read_exact(&mut resp)
            .await
            .context("DoT response body read failed")?;
        Ok(resp)
    })
    .await
    .with_context(|| format!("DoT query to {} timed out", upstream.label))?
}

/// Decodes an HTTP/1.1 chunked-transfer body held entirely in memory.
fn dechunk(mut data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let crlf = find_crlf(data).context("missing chunk-size line")?;
        let size_line = std::str::from_utf8(&data[..crlf]).context("non-utf8 chunk size")?;
        // A chunk size may carry `;ext` extensions — take the hex prefix only.
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16).context("invalid chunk size")?;
        data = &data[crlf + 2..];
        if size == 0 {
            break;
        }
        if data.len() < size {
            bail!("truncated chunk body");
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        // Skip the CRLF that terminates the chunk data.
        if data.starts_with(b"\r\n") {
            data = &data[2..];
        }
    }
    Ok(out)
}

/// Returns the index of the first `\r\n` in `data`, if any.
fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecureUpstreamConfig;

    fn cfg(transport: &str, addr: &str, hostname: &str) -> SecureUpstreamConfig {
        SecureUpstreamConfig {
            transport: transport.to_string(),
            addr: addr.to_string(),
            hostname: hostname.to_string(),
            path: "/dns-query".to_string(),
        }
    }

    #[test]
    fn from_config_parses_doh() {
        let up = SecureUpstream::from_config(&cfg("https", "1.1.1.1:443", "cloudflare-dns.com"))
            .unwrap();
        assert_eq!(up.transport, Transport::Doh);
        assert_eq!(up.addr, "1.1.1.1:443".parse().unwrap());
        assert_eq!(up.label, "https://cloudflare-dns.com");
        assert_eq!(up.path, "/dns-query");
    }

    #[test]
    fn from_config_parses_dot() {
        let up = SecureUpstream::from_config(&cfg("tls", "8.8.8.8:853", "dns.google")).unwrap();
        assert_eq!(up.transport, Transport::Dot);
        assert_eq!(up.label, "tls://dns.google");
    }

    #[test]
    fn from_config_transport_is_case_insensitive() {
        assert!(
            SecureUpstream::from_config(&cfg("HTTPS", "1.1.1.1:443", "cloudflare-dns.com")).is_ok()
        );
        assert!(SecureUpstream::from_config(&cfg("DoT", "8.8.8.8:853", "dns.google")).is_ok());
    }

    #[test]
    fn from_config_rejects_unknown_transport() {
        assert!(SecureUpstream::from_config(&cfg("quic", "1.1.1.1:853", "dns.q")).is_err());
    }

    #[test]
    fn from_config_rejects_bad_address() {
        assert!(SecureUpstream::from_config(&cfg("https", "nope", "cloudflare-dns.com")).is_err());
    }

    #[test]
    fn dechunk_decodes_simple_body() {
        // "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n" => "Wikipedia"
        let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk(raw).unwrap(), b"Wikipedia");
    }
}
