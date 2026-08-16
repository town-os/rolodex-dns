//! Encrypted DNS upstream clients: DNS-over-HTTPS (DoH, :443), DNS-over-TLS
//! (DoT, :853) and DNS-over-QUIC (DoQ, :853/UDP).
//!
//! Used by the `auto` resolution fallback chain (see [`crate::dns_server`]) to
//! reach resolvers over an encrypted transport when plaintext DNS (:53) is
//! filtered. **DoH is preferred**: :443 looks like ordinary HTTPS and survives
//! deep-packet-inspection filtering that blocks DoT's :853 (observed on real
//! networks that let the TCP connect through but drop the DoT TLS session).
//!
//! Every transport sends the caller's exact wire query and returns the raw wire
//! response, preserving EDNS/flags/rcode like the UDP/TCP forward paths — with
//! one documented exception, the DoQ message ID, described on [`query_doq`].
//!
//! The upstream itself is a [`Forwarder`]; this module is only the transports.

use crate::forwarder::{Forwarder, Transport};
use anyhow::{Context, Result, bail};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// The TLS name and SNI string an encrypted forwarder validates against.
///
/// Every encrypted forwarder carries both — `Forwarder::parse` fills them in,
/// defaulting to the dialed IP — so a missing one is a forwarder built by
/// something other than the parser, and is a bug rather than a configuration
/// error. It is reported rather than assumed away, because the alternative is
/// skipping certificate validation.
fn tls_identity(upstream: &Forwarder) -> Result<(ServerName<'static>, &str)> {
    let name = upstream
        .server_name
        .clone()
        .with_context(|| format!("{} has no TLS server name", upstream.label))?;
    let hostname = upstream
        .hostname
        .as_deref()
        .with_context(|| format!("{} has no TLS hostname", upstream.label))?;
    Ok((name, hostname))
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

/// Client config for DoQ (ALPN `doq`, RFC 9250 §4.1), built once.
fn doq_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| build_client_config(&[b"doq"]))
        .clone()
}

/// Sends a wire DNS query to an encrypted upstream and returns the wire
/// response, dispatching on the upstream's transport. Bounded by `timeout`.
///
/// Plaintext transports are not handled here and are an error rather than a
/// silent downgrade: they are forwarded by [`crate::dns_server`], which owns the
/// UDP socket pool and the 0x20 query randomisation that go with them. Sending
/// a query the caller believed was encrypted over plaintext would be the worst
/// possible way to be helpful.
pub async fn query(query_data: &[u8], upstream: &Forwarder, timeout: Duration) -> Result<Vec<u8>> {
    match upstream.transport {
        Transport::Doh => query_doh(query_data, upstream, timeout).await,
        Transport::Dot => query_dot(query_data, upstream, timeout).await,
        Transport::Doq => query_doq(query_data, upstream, timeout).await,
        Transport::Do53Udp | Transport::Do53Tcp => {
            bail!(
                "{} is a plaintext forwarder, not an encrypted upstream",
                upstream.label
            )
        }
    }
}

/// DNS-over-HTTPS: HTTP/1.1 POST of the wire query as `application/dns-message`.
pub async fn query_doh(
    query_data: &[u8],
    upstream: &Forwarder,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let (server_name, hostname) = tls_identity(upstream)?;
    let path = upstream
        .path
        .as_deref()
        .unwrap_or(crate::forwarder::DEFAULT_DOH_PATH);

    tokio::time::timeout(timeout, async move {
        let tcp = TcpStream::connect(upstream.addr)
            .await
            .with_context(|| format!("DoH TCP connect to {} failed", upstream.label))?;
        tcp.set_nodelay(true).ok();

        let connector = TlsConnector::from(doh_config());
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .with_context(|| format!("DoH TLS handshake with {} failed", upstream.label))?;

        // `Connection: close` lets us read the body to EOF, which also sidesteps
        // keep-alive framing ambiguity.
        let mut req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            path,
            hostname,
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
    upstream: &Forwarder,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let len =
        u16::try_from(query_data.len()).context("DNS query too large for DoT 2-byte framing")?;
    let (server_name, _) = tls_identity(upstream)?;

    tokio::time::timeout(timeout, async move {
        let tcp = TcpStream::connect(upstream.addr)
            .await
            .with_context(|| format!("DoT TCP connect to {} failed", upstream.label))?;
        tcp.set_nodelay(true).ok();

        let connector = TlsConnector::from(dot_config());
        let mut tls = connector
            .connect(server_name, tcp)
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

/// The largest DoQ response accepted off a stream.
///
/// A DNS message is length-prefixed with two bytes, so 65535 is the most that
/// can be described; the bound exists because `read_to_end` on a QUIC stream
/// will otherwise buffer whatever a peer decides to send.
const MAX_DOQ_RESPONSE: usize = 65535;

/// A shared QUIC client endpoint per address family.
///
/// One endpoint owns one UDP socket and multiplexes every connection made
/// through it, so building one per query would allocate a socket and a fresh
/// congestion-control context each time. They are split by family because an
/// endpoint bound to `0.0.0.0` cannot reach an IPv6 peer.
fn doq_endpoint(ipv6: bool) -> Result<quinn::Endpoint> {
    static V4: OnceLock<Result<quinn::Endpoint, String>> = OnceLock::new();
    static V6: OnceLock<Result<quinn::Endpoint, String>> = OnceLock::new();

    let slot = if ipv6 { &V6 } else { &V4 };
    let bind: SocketAddr = if ipv6 {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0u8; 4], 0))
    };
    slot.get_or_init(|| quinn::Endpoint::client(bind).map_err(|e| e.to_string()))
        .clone()
        .map_err(|e| anyhow::anyhow!("DoQ client endpoint bind failed: {e}"))
}

/// DNS-over-QUIC (RFC 9250): one query per bidirectional stream, length-prefixed
/// like DoT.
///
/// **The message ID is zeroed on the wire and restored on the way back.** RFC
/// 9250 §4.2.1 requires a DoQ query to carry ID 0 — QUIC streams already
/// correlate the response, so the ID would be a second, redundant identifier
/// whose only remaining effect is to leak a cross-transport fingerprint. Servers
/// are entitled to reject a non-zero ID, so sending the caller's ID would make
/// this transport fail against conforming resolvers. The caller's ID is put back
/// before the response is returned, because everything above this function
/// matches responses to queries by ID and would otherwise drop every answer.
///
/// Sending the stream FIN after the query is likewise required rather than
/// polite: a DoQ server is entitled to wait for it before answering, so omitting
/// it deadlocks against a conforming implementation until the timeout.
pub async fn query_doq(
    query_data: &[u8],
    upstream: &Forwarder,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let len =
        u16::try_from(query_data.len()).context("DNS query too large for DoQ 2-byte framing")?;
    if query_data.len() < 2 {
        bail!("DNS query too short to carry a message ID");
    }
    let (_, hostname) = tls_identity(upstream)?;

    let mut framed = Vec::with_capacity(2 + query_data.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query_data);
    // The two ID bytes sit at the start of the message, which is now offset by
    // the two length bytes.
    let original_id = [framed[2], framed[3]];
    framed[2] = 0;
    framed[3] = 0;

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(doq_config())
        .context("DoQ client crypto config is not QUIC-compatible")?;
    let client_config = quinn::ClientConfig::new(Arc::new(crypto));
    let endpoint = doq_endpoint(upstream.addr.is_ipv6())?;

    tokio::time::timeout(timeout, async move {
        let connection = endpoint
            .connect_with(client_config, upstream.addr, hostname)
            .with_context(|| format!("DoQ connect to {} failed", upstream.label))?
            .await
            .with_context(|| format!("DoQ handshake with {} failed", upstream.label))?;

        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .with_context(|| format!("DoQ stream to {} failed", upstream.label))?;
        send.write_all(&framed)
            .await
            .context("DoQ query write failed")?;
        send.finish().context("DoQ stream finish failed")?;

        let response = recv
            .read_to_end(MAX_DOQ_RESPONSE)
            .await
            .context("DoQ response read failed")?;

        // Two length bytes plus a header that has to be long enough to hold the
        // ID that is about to be written back into it.
        if response.len() < 4 {
            bail!(
                "DoQ upstream {} returned a truncated response",
                upstream.label
            );
        }
        let declared = usize::from(u16::from_be_bytes([response[0], response[1]]));
        let mut message = response[2..].to_vec();
        if message.len() < declared {
            bail!(
                "DoQ upstream {} response shorter than its length prefix",
                upstream.label
            );
        }
        message.truncate(declared);
        if message.len() < 2 {
            bail!("DoQ upstream {} returned no DNS header", upstream.label);
        }
        message[0] = original_id[0];
        message[1] = original_id[1];
        Ok(message)
    })
    .await
    .with_context(|| format!("DoQ query to {} timed out", upstream.label))?
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

    fn forwarder(spec: &str) -> Forwarder {
        Forwarder::parse(spec).unwrap_or_else(|e| panic!("parse {spec}: {e}"))
    }

    // Routing a plaintext forwarder into this module must fail loudly. Falling
    // through to a plaintext send would be a silent downgrade of a query the
    // caller asked to have encrypted.
    #[tokio::test]
    async fn query_refuses_a_plaintext_forwarder() {
        let plaintext = forwarder("8.8.8.8:53");
        let err = query(&[0u8; 12], &plaintext, Duration::from_millis(1))
            .await
            .expect_err("plaintext must not be sent by the encrypted client");
        assert!(
            err.to_string().contains("plaintext"),
            "unhelpful error: {err}"
        );
    }

    // The DoQ framing is built before any socket is touched, so the parts that
    // RFC 9250 constrains can be checked without a server: the length prefix,
    // the zeroed message ID, and the fact that the caller's ID is what comes
    // back. This mirrors what query_doq does to the buffer.
    #[test]
    fn doq_framing_zeroes_the_message_id_and_restores_it() {
        let query_data = {
            let mut q = vec![0u8; 12];
            q[0] = 0xAB;
            q[1] = 0xCD;
            q
        };

        let len = u16::try_from(query_data.len()).expect("length");
        let mut framed = Vec::with_capacity(2 + query_data.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&query_data);
        let original_id = [framed[2], framed[3]];
        framed[2] = 0;
        framed[3] = 0;

        assert_eq!(&framed[..2], &[0x00, 0x0C], "two-byte length prefix");
        assert_eq!(&framed[2..4], &[0x00, 0x00], "RFC 9250 requires ID 0");
        assert_eq!(original_id, [0xAB, 0xCD], "caller's ID must be recoverable");

        // What the response path then does with it.
        let mut message = [0u8; 12];
        message[0] = original_id[0];
        message[1] = original_id[1];
        assert_eq!(&message[..2], &[0xAB, 0xCD], "caller's ID must be restored");
    }

    #[test]
    fn doq_rejects_a_query_too_short_to_hold_an_id() {
        let short = [0u8];
        let up = forwarder("quic://dns.adguard.com@94.140.14.14:853");
        let result = futures_lite_block_on(query_doq(&short, &up, Duration::from_millis(1)));
        assert!(result.is_err(), "a 1-byte query has no message ID to zero");
    }

    /// Minimal blocking driver so a test can assert on the pre-flight
    /// validation of an async function without standing up a runtime that would
    /// then try to open a socket.
    fn futures_lite_block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    #[test]
    fn dechunk_decodes_simple_body() {
        // "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n" => "Wikipedia"
        let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk(raw).expect("dechunk"), b"Wikipedia");
    }
}
