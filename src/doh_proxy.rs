/// DNS forwarding through HTTP proxies.
///
/// Two modes:
/// - **CONNECT proxy**: TCP tunnel to upstream DNS server through HTTP CONNECT
/// - **DoH proxy**: Forward DoH requests through an HTTP proxy
use anyhow::{Context, Result};
use std::net::SocketAddr;
use tracing::{debug, warn};

/// Proxy configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Proxy URL (e.g. "http://proxy:8080")
    pub url: String,
    /// Optional proxy authentication ("user:pass")
    pub auth: Option<String>,
    /// Proxy mode: "connect" or "doh"
    pub mode: ProxyMode,
}

/// Proxy operating mode.
#[derive(Debug, Clone)]
pub enum ProxyMode {
    /// TCP tunnel via HTTP CONNECT
    Connect,
    /// Forward DoH requests through HTTP proxy
    Doh,
}

impl ProxyMode {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "doh" => ProxyMode::Doh,
            _ => ProxyMode::Connect,
        }
    }
}

/// Forwards a DNS query through an HTTP CONNECT proxy to an upstream DNS server.
pub async fn forward_via_connect_proxy(
    query_data: &[u8],
    upstream: &SocketAddr,
    proxy_url: &str,
    proxy_auth: Option<&str>,
) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // Parse proxy URL
    let proxy_addr = parse_proxy_addr(proxy_url)?;

    // Connect to proxy
    let mut stream = TcpStream::connect(&proxy_addr)
        .await
        .context("failed to connect to proxy")?;

    // Send CONNECT request
    let mut connect_req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
        upstream, upstream
    );
    if let Some(auth) = proxy_auth {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            auth.as_bytes(),
        );
        connect_req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
    }
    connect_req.push_str("\r\n");

    stream.write_all(connect_req.as_bytes()).await?;

    // Read CONNECT response
    let mut response_buf = vec![0u8; 1024];
    let n = stream.read(&mut response_buf).await?;
    let response_str = String::from_utf8_lossy(&response_buf[..n]);

    if !response_str.contains("200") {
        anyhow::bail!("proxy CONNECT failed: {}", response_str.trim());
    }

    // Now tunnel DNS query (TCP framing: 2-byte length prefix)
    let len_bytes = (query_data.len() as u16).to_be_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(query_data).await?;

    // Read response
    let mut resp_len_buf = [0u8; 2];
    stream.read_exact(&mut resp_len_buf).await?;
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await?;

    Ok(resp_buf)
}

/// Parses a proxy URL into a host:port string.
fn parse_proxy_addr(url: &str) -> Result<String> {
    let url = url.trim_start_matches("http://").trim_start_matches("https://");
    if url.contains(':') {
        Ok(url.to_string())
    } else {
        Ok(format!("{}:8080", url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proxy_addr() {
        assert_eq!(
            parse_proxy_addr("http://proxy:8080").unwrap(),
            "proxy:8080"
        );
        assert_eq!(
            parse_proxy_addr("https://proxy:3128").unwrap(),
            "proxy:3128"
        );
        assert_eq!(
            parse_proxy_addr("proxy.local").unwrap(),
            "proxy.local:8080"
        );
    }

    #[test]
    fn test_proxy_mode_from_str() {
        assert!(matches!(ProxyMode::from_str("connect"), ProxyMode::Connect));
        assert!(matches!(ProxyMode::from_str("doh"), ProxyMode::Doh));
        assert!(matches!(ProxyMode::from_str("unknown"), ProxyMode::Connect));
    }
}
