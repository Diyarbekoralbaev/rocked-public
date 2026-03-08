//! Local connection handling — bridges QUIC tunnel streams to local services.

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

const READ_BUF_SIZE: usize = 65_536;

/// Relay between a QUIC bi-stream and a local TCP service.
pub async fn relay_tcp(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    local_port: u16,
) {
    let local = match TcpStream::connect(format!("127.0.0.1:{local_port}")).await {
        Ok(s) => s,
        Err(e) => {
            debug!("connect to localhost:{local_port} failed: {e}");
            let _ = quic_send.reset(0u32.into());
            return;
        }
    };
    let _ = local.set_nodelay(true);
    let (mut local_read, mut local_write) = local.into_split();

    // QUIC → local
    let q2l = tokio::spawn(async move {
        let mut buf = vec![0u8; READ_BUF_SIZE];
        loop {
            match quic_recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    if local_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        let _ = local_write.shutdown().await;
    });

    // local → QUIC
    let l2q = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(READ_BUF_SIZE);
        loop {
            buf.clear();
            match local_read.read_buf(&mut buf).await {
                Ok(0) => break,
                Ok(_) => {
                    if quic_send.write_all(&buf).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = quic_send.finish();
    });

    let _ = tokio::join!(q2l, l2q);
}

/// Relay between a QUIC bi-stream and a local UDP service (length-prefixed datagrams).
pub async fn relay_udp(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    local_port: u16,
) {
    let local_target = format!("127.0.0.1:{local_port}");
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            debug!("failed to bind local UDP socket: {e}");
            let _ = quic_send.reset(0u32.into());
            return;
        }
    };

    let socket2 = std::sync::Arc::new(socket);
    let sock_recv = socket2.clone();

    // QUIC → local UDP (length-prefixed datagrams)
    let q2l = tokio::spawn(async move {
        let mut len_buf = [0u8; 4];
        loop {
            if quic_recv.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > 65535 {
                break;
            }
            let mut buf = vec![0u8; len];
            if quic_recv.read_exact(&mut buf).await.is_err() {
                break;
            }
            let _ = socket2.send_to(&buf, &local_target).await;
        }
    });

    // local UDP → QUIC (length-prefixed datagrams)
    let l2q = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match sock_recv.recv_from(&mut buf).await {
                Ok((n, _)) => {
                    let len = (n as u32).to_be_bytes();
                    if quic_send.write_all(&len).await.is_err() {
                        break;
                    }
                    if quic_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    debug!("local UDP recv error: {e}");
                    break;
                }
            }
        }
        let _ = quic_send.finish();
    });

    let _ = tokio::join!(q2l, l2q);
}
