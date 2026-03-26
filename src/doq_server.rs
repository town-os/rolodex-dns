/// DNS-over-QUIC (DoQ) server (RFC 9250).
///
/// Listens on a configurable UDP port using QUIC protocol.
/// ALPN: "doq". Each query on a new bidirectional stream with
/// 2-byte length prefix framing (same as TCP).
use crate::dns_server::DnsServer;
use anyhow::{Context, Result};
use std::sync::Arc;
use tracing::{debug, info};

/// Serves DNS-over-QUIC on the specified bind address.
pub async fn serve_doq(
    bind: &str,
    dns_server: Arc<DnsServer>,
    server_config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
        .context("failed to create QUIC server crypto config")?;
    let mut quinn_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    quinn_config.transport_config(Arc::new({
        let mut tc = quinn::TransportConfig::default();
        tc.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).unwrap(),
        ));
        tc
    }));

    let addr: std::net::SocketAddr = bind
        .parse()
        .context(format!("invalid DoQ bind address: {}", bind))?;

    let endpoint =
        quinn::Endpoint::server(quinn_config, addr).context("failed to create QUIC endpoint")?;

    info!("DoQ server listening on {}", addr);

    while let Some(incoming) = endpoint.accept().await {
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

    let response = dns_server.handle_query_from(&msg_buf, peer.ip()).await?;

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
        assert!(true);
    }
}
