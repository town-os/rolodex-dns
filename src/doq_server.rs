/// DNS-over-QUIC (DoQ) server (RFC 9250).
///
/// Listens on a configurable UDP port using QUIC protocol.
/// ALPN: "doq". Each query on a new bidirectional stream with
/// 2-byte length prefix framing (same as TCP).
use crate::dns_server::DnsServer;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Builds the QUIC server config a DoQ listener runs with.
///
/// Factored out because it is built twice: once at startup, and again each time
/// the certificate is renewed underneath a running endpoint.
fn quinn_config(server_config: Arc<rustls::ServerConfig>) -> Result<quinn::ServerConfig> {
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
        .context("failed to create QUIC server crypto config")?;
    let mut quinn_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let idle_timeout = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30))
        .context("DoQ idle timeout out of range")?;
    quinn_config.transport_config(Arc::new({
        let mut tc = quinn::TransportConfig::default();
        tc.max_idle_timeout(Some(idle_timeout));
        tc
    }));
    Ok(quinn_config)
}

/// Serves DNS-over-QUIC on the specified bind address.
///
/// `tls` is a live view of the certificate rather than a snapshot. QUIC keeps
/// its crypto config on the endpoint rather than reading it per connection, so a
/// renewal is applied with `set_server_config` in the accept loop; connections
/// already established keep the certificate they handshook with, and the next
/// one to arrive gets the new one. No restart, and no window where the listener
/// is not accepting.
pub async fn serve_doq(
    bind: &str,
    dns_server: Arc<DnsServer>,
    mut tls: watch::Receiver<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let endpoint = bind_doq(bind, tls.borrow_and_update().clone())?;
    serve_doq_on(endpoint, dns_server, tls).await
}

/// Binds a DoQ endpoint without starting its accept loop.
///
/// Split from [`serve_doq`] so a caller that must report a bind failure to
/// somebody — the transport supervisor, answering a `SetDoqConfig` RPC — can
/// take the error synchronously instead of discovering it inside a spawned task,
/// where the only place it could go is the log.
pub fn bind_doq(bind: &str, server_config: Arc<rustls::ServerConfig>) -> Result<quinn::Endpoint> {
    let initial = quinn_config(server_config)?;
    let addr: std::net::SocketAddr = bind
        .parse()
        .context(format!("invalid DoQ bind address: {}", bind))?;
    quinn::Endpoint::server(initial, addr).context("failed to create QUIC endpoint")
}

/// Serves DNS-over-QUIC on an already-bound endpoint. See [`serve_doq`].
pub async fn serve_doq_on(
    endpoint: quinn::Endpoint,
    dns_server: Arc<DnsServer>,
    mut tls: watch::Receiver<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let addr = endpoint
        .local_addr()
        .context("DoQ endpoint has no local address")?;

    info!("DoQ server listening on {}", addr);

    // Once every sender is gone the certificate can never change again, and
    // `changed()` returns immediately and forever. The branch is disabled rather
    // than looped on, which is the difference between a listener that stops
    // watching and one that spins a core.
    let mut renewals_possible = true;

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let dns = Arc::clone(&dns_server);
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(connection) => {
                            debug!("DoQ connection from {}", connection.remote_address());
                            handle_doq_connection(connection, dns).await;
                        }
                        Err(e) => {
                            debug!("DoQ connection failed: {}", e);
                        }
                    }
                });
            }
            // A renewal. A rebuild that fails leaves the endpoint on the
            // certificate it already has rather than tearing the listener down —
            // the same bargain the manager makes when a reload fails.
            changed = tls.changed(), if renewals_possible => {
                if changed.is_err() {
                    // The manager is gone; the certificate can no longer change,
                    // but the listener has no reason to stop serving.
                    renewals_possible = false;
                    continue;
                }
                match quinn_config(tls.borrow_and_update().clone()) {
                    Ok(updated) => {
                        endpoint.set_server_config(Some(updated));
                        info!("DoQ listener on {} picked up a renewed certificate", addr);
                    }
                    Err(e) => warn!("DoQ certificate renewal on {} not applied: {:#}", addr, e),
                }
            }
        }
    }

    Ok(())
}

async fn handle_doq_connection(connection: quinn::Connection, dns_server: Arc<DnsServer>) {
    loop {
        match connection.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let dns = Arc::clone(&dns_server);
                let peer = connection.remote_address();
                tokio::spawn(async move {
                    if let Err(e) = handle_doq_stream(&mut send, &mut recv, dns, peer).await {
                        debug!("DoQ stream error: {}", e);
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
            Err(e) => {
                debug!("DoQ accept_bi error: {}", e);
                break;
            }
        }
    }
}

async fn handle_doq_stream(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    dns_server: Arc<DnsServer>,
    peer: std::net::SocketAddr,
) -> Result<()> {
    // Read 2-byte length prefix
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf).await?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;

    if msg_len == 0 || msg_len > 65535 {
        anyhow::bail!("invalid message length: {}", msg_len);
    }

    let mut msg_buf = vec![0u8; msg_len];
    recv.read_exact(&mut msg_buf).await?;

    let response = dns_server
        .handle_query_proto(&msg_buf, Some(peer.ip()), None, crate::metrics::Proto::Doq)
        .await?;

    let resp_len = (response.len() as u16).to_be_bytes();
    send.write_all(&resp_len).await?;
    send.write_all(&response).await?;
    send.finish()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_doq_module_exists() {
        // Compilation smoke test: this module builds and links.
    }
}
