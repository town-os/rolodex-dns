/// DNS forwarding through proxies.
///
/// Three modes:
/// - **CONNECT proxy**: TCP tunnel to upstream DNS server through HTTP CONNECT
/// - **SOCKS5 proxy**: TCP tunnel to upstream DNS server through SOCKS5 (RFC 1928)
/// - **DoH proxy**: Forward DoH requests through an HTTP proxy
use anyhow::{Context, Result};
use std::net::SocketAddr;

/// Proxy configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Proxy URL (e.g. "http://proxy:8080" or "socks5://127.0.0.1:1080")
    pub url: String,
    /// Optional proxy authentication ("user:pass")
    pub auth: Option<String>,
    /// Proxy mode: "connect", "socks5", or "doh"
    pub mode: ProxyMode,
}

/// Proxy operating mode.
#[derive(Debug, Clone, PartialEq)]
pub enum ProxyMode {
    /// TCP tunnel via HTTP CONNECT
    Connect,
    /// TCP tunnel via SOCKS5 (RFC 1928)
    Socks5,
    /// Forward DoH requests through HTTP proxy
    Doh,
}

impl ProxyMode {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "socks5" => ProxyMode::Socks5,
            "doh" => ProxyMode::Doh,
            _ => ProxyMode::Connect,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ProxyMode::Connect => "connect",
            ProxyMode::Socks5 => "socks5",
            ProxyMode::Doh => "doh",
        }
    }
}

impl From<&crate::config::ProxyConfig> for ProxyConfig {
    fn from(cfg: &crate::config::ProxyConfig) -> Self {
        ProxyConfig {
            url: cfg.url.clone(),
            auth: cfg.auth.clone(),
            mode: ProxyMode::parse(&cfg.mode),
        }
    }
}

/// Dispatches a DNS query through the configured proxy mode.
pub async fn forward_via_proxy(
    query_data: &[u8],
    upstream: &SocketAddr,
    config: &ProxyConfig,
) -> Result<Vec<u8>> {
    match config.mode {
        ProxyMode::Connect => {
            forward_via_connect_proxy(query_data, upstream, &config.url, config.auth.as_deref())
                .await
        }
        ProxyMode::Socks5 => {
            forward_via_socks5_proxy(query_data, upstream, &config.url, config.auth.as_deref())
                .await
        }
        ProxyMode::Doh => {
            forward_via_doh_proxy(query_data, upstream, &config.url, config.auth.as_deref()).await
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
    let mut connect_req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", upstream, upstream);
    if let Some(auth) = proxy_auth {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, auth.as_bytes());
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
    tunnel_dns_query(&mut stream, query_data).await
}

/// Forwards a DNS query through a SOCKS5 proxy to an upstream DNS server (RFC 1928).
pub async fn forward_via_socks5_proxy(
    query_data: &[u8],
    upstream: &SocketAddr,
    proxy_url: &str,
    proxy_auth: Option<&str>,
) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let proxy_addr = parse_proxy_addr(proxy_url)?;

    let mut stream = TcpStream::connect(&proxy_addr)
        .await
        .context("failed to connect to SOCKS5 proxy")?;

    // SOCKS5 greeting: version 5
    if proxy_auth.is_some() {
        // Offer no-auth (0x00) and username/password (0x02)
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        // Offer no-auth only
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }

    // Read server's chosen method
    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp).await?;

    if method_resp[0] != 0x05 {
        anyhow::bail!(
            "SOCKS5: invalid version in greeting response: {}",
            method_resp[0]
        );
    }

    match method_resp[1] {
        0x00 => {
            // No authentication required
        }
        0x02 => {
            // Username/password authentication (RFC 1929)
            let auth = proxy_auth.context("SOCKS5 proxy requires authentication")?;
            let (user, pass) = auth.split_once(':').unwrap_or((auth, ""));

            let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
            auth_req.push(0x01); // auth version
            auth_req.push(user.len() as u8);
            auth_req.extend_from_slice(user.as_bytes());
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != 0x00 {
                anyhow::bail!("SOCKS5: authentication failed (status {})", auth_resp[1]);
            }
        }
        0xFF => {
            anyhow::bail!("SOCKS5: no acceptable authentication method");
        }
        other => {
            anyhow::bail!("SOCKS5: unsupported authentication method: {}", other);
        }
    }

    // SOCKS5 CONNECT request
    let mut connect_req = vec![
        0x05, // version
        0x01, // command: CONNECT
        0x00, // reserved
    ];

    match upstream {
        SocketAddr::V4(addr) => {
            connect_req.push(0x01); // IPv4
            connect_req.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            connect_req.push(0x04); // IPv6
            connect_req.extend_from_slice(&addr.ip().octets());
        }
    }
    connect_req.extend_from_slice(&upstream.port().to_be_bytes());

    stream.write_all(&connect_req).await?;

    // Read SOCKS5 CONNECT response
    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await?;

    if resp_header[0] != 0x05 {
        anyhow::bail!("SOCKS5: invalid version in connect response");
    }
    if resp_header[1] != 0x00 {
        let err = match resp_header[1] {
            0x01 => "general SOCKS server failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        anyhow::bail!("SOCKS5 CONNECT failed: {} (code {})", err, resp_header[1]);
    }

    // Skip the bound address in the response
    match resp_header[3] {
        0x01 => {
            // IPv4: 4 bytes + 2 port bytes
            let mut skip = [0u8; 6];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            // IPv6: 16 bytes + 2 port bytes
            let mut skip = [0u8; 18];
            stream.read_exact(&mut skip).await?;
        }
        0x03 => {
            // Domain: 1 length byte + domain + 2 port bytes
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let mut skip = vec![0u8; len_buf[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        _ => {
            anyhow::bail!(
                "SOCKS5: unknown address type in response: {}",
                resp_header[3]
            );
        }
    }

    // Tunnel is established, forward DNS query with TCP framing
    tunnel_dns_query(&mut stream, query_data).await
}

/// Forwards a DNS query as a DoH request through an HTTP proxy.
pub async fn forward_via_doh_proxy(
    query_data: &[u8],
    upstream: &SocketAddr,
    proxy_url: &str,
    proxy_auth: Option<&str>,
) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let proxy_addr = parse_proxy_addr(proxy_url)?;

    let mut stream = TcpStream::connect(&proxy_addr)
        .await
        .context("failed to connect to DoH proxy")?;

    let doh_url = format!("https://{}/dns-query", upstream);
    let body = query_data;

    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nAccept: application/dns-message\r\n",
        doh_url,
        upstream,
        body.len()
    );
    if let Some(auth) = proxy_auth {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, auth.as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
    }
    request.push_str("Connection: close\r\n\r\n");

    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;

    // Read full HTTP response
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    // Parse HTTP response: find the body after \r\n\r\n
    let response_str = String::from_utf8_lossy(&response);
    let header_end = response_str
        .find("\r\n\r\n")
        .context("DoH proxy: malformed HTTP response")?;

    let status_line = response_str
        .lines()
        .next()
        .context("DoH proxy: empty response")?;
    if !status_line.contains("200") {
        anyhow::bail!("DoH proxy request failed: {}", status_line);
    }

    let body_start = header_end + 4;
    if body_start >= response.len() {
        anyhow::bail!("DoH proxy: empty response body");
    }

    Ok(response[body_start..].to_vec())
}

/// Sends a DNS query over an established TCP tunnel using 2-byte length prefix framing
/// and reads back the response.
async fn tunnel_dns_query(
    stream: &mut tokio::net::TcpStream,
    query_data: &[u8],
) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let len_bytes = (query_data.len() as u16).to_be_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(query_data).await?;

    let mut resp_len_buf = [0u8; 2];
    stream.read_exact(&mut resp_len_buf).await?;
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await?;

    Ok(resp_buf)
}

/// Parses a proxy URL into a host:port string.
fn parse_proxy_addr(url: &str) -> Result<String> {
    let url = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_start_matches("socks5://");
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
        assert_eq!(parse_proxy_addr("http://proxy:8080").unwrap(), "proxy:8080");
        assert_eq!(
            parse_proxy_addr("https://proxy:3128").unwrap(),
            "proxy:3128"
        );
        assert_eq!(
            parse_proxy_addr("socks5://127.0.0.1:1080").unwrap(),
            "127.0.0.1:1080"
        );
        assert_eq!(parse_proxy_addr("proxy.local").unwrap(), "proxy.local:8080");
    }

    #[test]
    fn test_proxy_mode_from_str() {
        assert!(matches!(ProxyMode::parse("connect"), ProxyMode::Connect));
        assert!(matches!(ProxyMode::parse("socks5"), ProxyMode::Socks5));
        assert!(matches!(ProxyMode::parse("doh"), ProxyMode::Doh));
        assert!(matches!(ProxyMode::parse("SOCKS5"), ProxyMode::Socks5));
        assert!(matches!(ProxyMode::parse("unknown"), ProxyMode::Connect));
    }

    #[test]
    fn test_proxy_mode_as_str() {
        assert_eq!(ProxyMode::Connect.as_str(), "connect");
        assert_eq!(ProxyMode::Socks5.as_str(), "socks5");
        assert_eq!(ProxyMode::Doh.as_str(), "doh");
    }

    #[test]
    fn test_proxy_config_from_config() {
        let cfg = crate::config::ProxyConfig {
            url: "socks5://127.0.0.1:1080".to_string(),
            auth: Some("user:pass".to_string()),
            mode: "socks5".to_string(),
        };
        let runtime: ProxyConfig = ProxyConfig::from(&cfg);
        assert_eq!(runtime.url, "socks5://127.0.0.1:1080");
        assert_eq!(runtime.auth.as_deref(), Some("user:pass"));
        assert_eq!(runtime.mode, ProxyMode::Socks5);
    }
}
