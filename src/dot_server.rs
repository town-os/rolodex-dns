/// DNS-over-TLS (DoT) server (RFC 7858).
///
/// Listens on a configurable port (default 853) with TLS,
/// handling DNS queries using the same TCP framing as plain DNS TCP
/// (2-byte length prefix).
use crate::dns_server::{DnsServer, MAX_TCP_CONNECTIONS, TCP_IDLE_TIMEOUT, TCP_MESSAGE_TIMEOUT};
use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// How long a client has to complete the TLS handshake.
///
/// This bound is the one plain TCP does not need. `acceptor.accept()` waits for a
/// ClientHello, so without it a bare `connect()` — no TLS implementation
/// required, not one byte sent — parks a task before any DNS is exchanged, and a
/// timeout on the DNS read loop never applies because the connection never
/// reaches it.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The ALPN protocol identifier for DNS-over-TLS, registered by RFC 7858.
///
/// A DoT listener that negotiates no ALPN at all is not merely untidy: a client
/// offering `dot` and nothing else gets `no_application_protocol` back from a
/// server that offers a *different* protocol, and gets silence on the question
/// from one that offers none — leaving it to guess whether it reached a DoT
/// listener or some other TLS service that happens to sit on the port. Offering
/// the token is what makes the answer explicit.
pub const ALPN: &[u8] = b"dot";

/// The ALPN list a DoT listener advertises.
///
/// This exists so `main.rs` and the tests cannot disagree about it: a constant
/// one of them read and the other retyped is a constant that drifts. Advertising
/// `dot` does not shut out a client that offers no ALPN — rustls only rejects a
/// handshake when the client offers protocols and none of them match, so the
/// clients that never send the extension (Android's Private DNS, systemd-resolved
/// in opportunistic mode) are unaffected.
pub fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![ALPN.to_vec()]
}

/// Serves DNS-over-TLS on the specified bind address.
///
/// `tls` is a live view of the certificate rather than a snapshot of it: the
/// acceptor is built per connection from whatever the channel currently holds,
/// so a renewed certificate is served by the next connection to arrive with no
/// restart and nothing to coordinate. Building it there is free — a
/// `TlsAcceptor` is an `Arc` around the config — and a connection already in
/// progress finishes under the certificate it handshook with, which is the only
/// thing TLS allows anyway.
pub async fn serve_dot(
    bind: &str,
    dns_server: Arc<DnsServer>,
    tls: watch::Receiver<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let listener = bind_dot(bind).await?;
    serve_dot_on(listener, dns_server, tls).await
}

/// Binds a DoT listener without starting it.
///
/// Split from [`serve_dot`] so a caller that must report a bind failure to
/// somebody — the transport supervisor, answering a `SetDotConfig` RPC — can
/// take the error synchronously instead of discovering it inside a spawned task,
/// where the only place it could go is the log.
pub async fn bind_dot(bind: &str) -> Result<TcpListener> {
    TcpListener::bind(bind)
        .await
        .context(format!("failed to bind DoT listener on {}", bind))
}

/// Serves DNS-over-TLS on an already-bound listener. See [`serve_dot`].
pub async fn serve_dot_on(
    listener: TcpListener,
    dns_server: Arc<DnsServer>,
    tls: watch::Receiver<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let bind = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    info!("DoT server listening on {}", bind);
    // Bounds concurrent connections, exactly as the plain-TCP listener does. A
    // DoT connection costs more than a TCP one — it carries TLS session state —
    // so the cap matters at least as much here.
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_TCP_CONNECTIONS));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("DoT accept error: {}", e);
                continue;
            }
        };

        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            debug!(
                "dropping DoT connection from {}: {} concurrent connections in use",
                peer, MAX_TCP_CONNECTIONS
            );
            drop(stream);
            continue;
        };

        let acceptor = TlsAcceptor::from(tls.borrow().clone());
        let dns = Arc::clone(&dns_server);

        tokio::spawn(async move {
            let handshake = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream));
            let accepted = match handshake.await {
                Ok(result) => result,
                Err(_) => {
                    debug!("DoT TLS handshake from {} timed out", peer);
                    drop(permit);
                    return;
                }
            };
            match accepted {
                Ok(tls_stream) => {
                    debug!("DoT connection from {}", peer);
                    if let Err(e) = handle_dot_connection(tls_stream, dns, peer).await {
                        debug!("DoT connection error from {}: {}", peer, e);
                    }
                }
                Err(e) => {
                    debug!("DoT TLS handshake failed from {}: {}", peer, e);
                }
            }
            drop(permit);
        });
    }
}

async fn handle_dot_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    dns_server: Arc<DnsServer>,
    peer: std::net::SocketAddr,
) -> Result<()> {
    loop {
        // Read 2-byte length prefix, timed from the last activity so a client
        // reusing the session across queries is not disconnected mid-conversation
        // — which matters more here than on plain TCP, since reconnecting costs a
        // fresh TLS handshake.
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!("closing idle DoT session from {}", peer);
                break;
            }
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 65535 {
            break;
        }

        let mut msg_buf = vec![0u8; msg_len];
        tokio::time::timeout(TCP_MESSAGE_TIMEOUT, stream.read_exact(&mut msg_buf))
            .await
            .map_err(|_| {
                anyhow::anyhow!("{} announced {} bytes and did not send them", peer, msg_len)
            })??;

        let response = dns_server
            .handle_query_proto(&msg_buf, Some(peer.ip()), None, crate::metrics::Proto::Dot)
            .await?;

        let resp_len = (response.len() as u16).to_be_bytes();
        stream.write_all(&resp_len).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpn_token_is_rfc7858_dot() {
        // The exact three octets that go on the wire, written out longhand
        // rather than compared against another expression derived from the same
        // constant: `ALPN == ALPN` proves nothing, and the ALPN extension
        // carries bytes, not a Rust identifier.
        assert_eq!(ALPN, &[0x64u8, 0x6f, 0x74]);
        assert_eq!(ALPN.len(), 3);
    }

    #[test]
    fn test_alpn_protocols_advertises_exactly_dot() {
        // Exactly one protocol, not merely "contains dot": a listener that also
        // offered `h2` or `doq` would let a confused client negotiate a protocol
        // this server does not speak on the port.
        assert_eq!(alpn_protocols(), vec![b"dot".to_vec()]);
    }
}
