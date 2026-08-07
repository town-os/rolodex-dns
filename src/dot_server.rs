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

/// Serves DNS-over-TLS on the specified bind address.
pub async fn serve_dot(
    bind: &str,
    dns_server: Arc<DnsServer>,
    acceptor: TlsAcceptor,
) -> Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .context(format!("failed to bind DoT listener on {}", bind))?;
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

        let acceptor = acceptor.clone();
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
    #[test]
    fn test_dot_module_exists() {
        // Compilation smoke test: this module builds and links.
    }
}
