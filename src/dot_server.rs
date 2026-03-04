/// DNS-over-TLS (DoT) server (RFC 7858).
///
/// Listens on a configurable port (default 853) with TLS,
/// handling DNS queries using the same TCP framing as plain DNS TCP
/// (2-byte length prefix).
use crate::dns_server::DnsServer;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

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

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("DoT accept error: {}", e);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let dns = Arc::clone(&dns_server);

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
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
        });
    }
}

async fn handle_dot_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    dns_server: Arc<DnsServer>,
    peer: std::net::SocketAddr,
) -> Result<()> {
    loop {
        // Read 2-byte length prefix
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 65535 {
            break;
        }

        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).await?;

        let response = dns_server.handle_query_from(&msg_buf, peer.ip()).await?;

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
        // Basic compilation test
        assert!(true);
    }
}
