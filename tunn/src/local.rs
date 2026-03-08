//! Local connection handling — bridges QUIC tunnel streams to local services.

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::broadcast;
use tracing::debug;

use crate::inspect::RequestEvent;

const READ_BUF_SIZE: usize = 65_536;

/// Relay between a QUIC bi-stream and a local TCP service.
/// If `inspect_tx` is provided, HTTP request/response metadata is tapped (zero latency).
pub async fn relay_tcp(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    local_port: u16,
    inspect_tx: Option<broadcast::Sender<RequestEvent>>,
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

    // Channel to pass request metadata from q2l task to l2q task
    let (meta_tx, meta_rx) = tokio::sync::oneshot::channel::<(u64, std::time::Instant)>();

    let inspect_tx2 = inspect_tx.clone();

    // QUIC → local (carries the HTTP request from server)
    let q2l = tokio::spawn(async move {
        let mut buf = vec![0u8; READ_BUF_SIZE];
        let mut parsed = false;
        let mut request_bytes: u64 = 0;
        let mut meta_tx = Some(meta_tx);
        loop {
            match quic_recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    request_bytes += n as u64;

                    // Parse first chunk to extract HTTP request metadata
                    if !parsed {
                        parsed = true;
                        if let Some(ref tx) = inspect_tx {
                            let start = std::time::Instant::now();
                            let id = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_nanos() as u64;
                            if let Some(parsed) = parse_http_request(&buf[..n]) {
                                let event = RequestEvent {
                                    id,
                                    method: parsed.method,
                                    path: parsed.path,
                                    host: parsed.host,
                                    status: None,
                                    duration_ms: None,
                                    request_size: request_bytes,
                                    response_size: 0,
                                    request_headers: parsed.headers,
                                    response_headers: Vec::new(),
                                    request_body: parsed.body,
                                    response_body: None,
                                    timestamp: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis()
                                        as u64,
                                };
                                let _ = tx.send(event);
                                if let Some(sender) = meta_tx.take() {
                                    let _ = sender.send((id, start));
                                }
                            }
                        }
                    }

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

    // local → QUIC (carries the HTTP response from local server)
    let l2q = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(READ_BUF_SIZE);
        let mut parsed = false;
        let mut response_bytes: u64 = 0;
        let meta = meta_rx.await.ok();
        loop {
            buf.clear();
            match local_read.read_buf(&mut buf).await {
                Ok(0) => break,
                Ok(_) => {
                    response_bytes += buf.len() as u64;

                    // Parse first chunk to extract HTTP response status
                    if !parsed {
                        parsed = true;
                        if let (Some(ref tx), Some((id, start))) = (&inspect_tx2, &meta) {
                            if let Some(parsed) = parse_http_response(&buf) {
                                let event = RequestEvent {
                                    id: *id,
                                    method: String::new(),
                                    path: String::new(),
                                    host: String::new(),
                                    status: Some(parsed.status),
                                    duration_ms: Some(start.elapsed().as_millis() as u64),
                                    request_size: 0,
                                    response_size: response_bytes,
                                    request_headers: Vec::new(),
                                    response_headers: parsed.headers,
                                    request_body: None,
                                    response_body: parsed.body,
                                    timestamp: 0,
                                };
                                let _ = tx.send(event);
                            }
                        }
                    }

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

/// Parsed HTTP request metadata.
struct ParsedRequest {
    method: String,
    path: String,
    host: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

/// Parsed HTTP response metadata.
struct ParsedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

/// Check if content type is text-like (should be captured as string).
fn is_text_content(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type")
            && (value.contains("json")
                || value.contains("text")
                || value.contains("xml")
                || value.contains("html")
                || value.contains("javascript")
                || value.contains("css")
                || value.contains("form-urlencoded"))
    })
}

/// Extract body from raw HTTP bytes after headers end.
fn extract_body(buf: &[u8], header_end: usize, headers: &[(String, String)]) -> Option<String> {
    if header_end >= buf.len() {
        return None;
    }
    let body_bytes = &buf[header_end..];
    if body_bytes.is_empty() {
        return None;
    }
    let limit = body_bytes.len().min(crate::inspect::MAX_BODY_CAPTURE);
    if is_text_content(headers) || std::str::from_utf8(&body_bytes[..limit]).is_ok() {
        let s = String::from_utf8_lossy(&body_bytes[..limit]).to_string();
        if limit < body_bytes.len() {
            Some(format!(
                "{s}\n\n... truncated ({} bytes total)",
                body_bytes.len()
            ))
        } else {
            Some(s)
        }
    } else {
        Some(format!("[binary data, {} bytes]", body_bytes.len()))
    }
}

/// Parse HTTP request from raw bytes.
fn parse_http_request(buf: &[u8]) -> Option<ParsedRequest> {
    let mut headers_buf = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers_buf);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(header_end)) => {
            let method = req.method?.to_string();
            let path = req.path?.to_string();
            let mut host = String::new();
            let mut headers = Vec::new();
            for h in req.headers.iter() {
                let name = h.name.to_string();
                let value = String::from_utf8_lossy(h.value).to_string();
                if name.eq_ignore_ascii_case("host") {
                    host = value.clone();
                }
                headers.push((name, value));
            }
            let body = extract_body(buf, header_end, &headers);
            Some(ParsedRequest {
                method,
                path,
                host,
                headers,
                body,
            })
        }
        Ok(httparse::Status::Partial) => {
            let method = req.method?.to_string();
            let path = req.path?.to_string();
            let mut host = String::new();
            let mut headers = Vec::new();
            for h in req.headers.iter() {
                let name = h.name.to_string();
                let value = String::from_utf8_lossy(h.value).to_string();
                if name.eq_ignore_ascii_case("host") {
                    host = value.clone();
                }
                headers.push((name, value));
            }
            Some(ParsedRequest {
                method,
                path,
                host,
                headers,
                body: None,
            })
        }
        Err(_) => None,
    }
}

/// Parse HTTP response from raw bytes.
fn parse_http_response(buf: &[u8]) -> Option<ParsedResponse> {
    let mut headers_buf = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers_buf);
    match resp.parse(buf) {
        Ok(httparse::Status::Complete(header_end)) => {
            let status = resp.code?;
            let headers: Vec<(String, String)> = resp
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).to_string(),
                    )
                })
                .collect();
            let body = extract_body(buf, header_end, &headers);
            Some(ParsedResponse {
                status,
                headers,
                body,
            })
        }
        Ok(httparse::Status::Partial) => {
            let status = resp.code?;
            let headers: Vec<(String, String)> = resp
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).to_string(),
                    )
                })
                .collect();
            Some(ParsedResponse {
                status,
                headers,
                body: None,
            })
        }
        Err(_) => None,
    }
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
