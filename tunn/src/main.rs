//! tunn: CLI binary for tunneling local services.

mod bench;
mod config;
mod error;
mod inspect;
mod local;
mod update;

use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tracing::{debug, info, warn};

use tunn_proto::{ClientHello, DomainAction, ServerHello, TunnelType, PROTOCOL_VERSION};

use config::{Cli, Command, DomainCommand};
use error::ClientError;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tunn=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Command::Update => {
            match update::run_update().await {
                Ok(()) => {}
                Err(update::UpdateError::AlreadyUpToDate(v)) => {
                    info!("tunn v{v} is already the latest version");
                }
                Err(e) => {
                    warn!("update failed: {e}");
                    std::process::exit(1);
                }
            }
            return;
        }
        Command::Activate { key } => {
            save_key(key);
            info!("license key saved. Pro features will be active on next tunnel.");
            return;
        }
        Command::Domain { action } => {
            let key = cli.key.clone().or_else(load_saved_key);
            if key.is_none() {
                eprintln!("License key required for domain management.");
                eprintln!("Activate:  tunn activate <YOUR_KEY>");
                std::process::exit(1);
            }
            match run_domain_command(&cli.server, key, action).await {
                Ok(()) => {}
                Err(e) => {
                    warn!("{e}");
                    std::process::exit(1);
                }
            }
            return;
        }
        _ => {}
    }

    let key = cli.key.clone().or_else(load_saved_key);

    // Require license key before connecting
    if key.is_none() {
        eprintln!("License key required.\n");
        eprintln!("Get a free key:  https://buy.polar.sh/polar_cl_z7iF79O39Sd0ODHPaDGCGPzEQJ7u5JAPbN0gu1cbOzF");
        eprintln!("Then activate:   tunn activate <YOUR_KEY>");
        eprintln!("Or pass inline:  tunn -k <YOUR_KEY> http <PORT>");
        std::process::exit(1);
    }

    // Bench command: open tunnel, benchmark, exit
    if let Command::Bench {
        port,
        requests,
        concurrency,
    } = &cli.command
    {
        let port = *port;
        let requests = *requests;
        let concurrency = *concurrency;

        info!("connecting to {}", cli.server);
        match run_bench_tunnel(&cli.server, port, key, requests, concurrency).await {
            Ok(()) => {}
            Err(e) => {
                warn!("bench failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    let (tunnel_type, local_port, local_host, subdomain, custom_domain, no_qr, no_inspect, inspect_port) =
        match &cli.command {
            Command::Http {
                port,
                host,
                subdomain,
                domain,
                no_qr,
                no_inspect,
                inspect_port,
            } => (
                TunnelType::Http,
                *port,
                host.clone(),
                subdomain.clone(),
                domain.clone(),
                *no_qr,
                *no_inspect,
                *inspect_port,
            ),
            Command::Tcp { port, host } => (TunnelType::Tcp, *port, host.clone(), None, None, true, true, 0),
            Command::Udp { port, host } => (TunnelType::Udp, *port, host.clone(), None, None, true, true, 0),
            Command::Update
            | Command::Activate { .. }
            | Command::Bench { .. }
            | Command::Domain { .. } => unreachable!(),
        };

    update::spawn_version_check();

    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);

    // Create endpoint once so TLS session cache persists across reconnects (enables 0-RTT)
    let endpoint = match make_quic_client() {
        Ok(e) => e,
        Err(e) => {
            warn!("failed to create QUIC client: {e}");
            std::process::exit(1);
        }
    };

    let opts = TunnelOpts {
        no_qr,
        no_inspect,
        inspect_port,
    };

    loop {
        info!("connecting to {}", cli.server);
        match run_tunnel(
            &endpoint,
            &cli.server,
            tunnel_type,
            local_port,
            &local_host,
            key.clone(),
            subdomain.clone(),
            custom_domain.clone(),
            &opts,
        )
        .await
        {
            Ok(()) => {
                info!("tunnel closed gracefully");
                break;
            }
            Err(ClientError::Server(ref msg)) => {
                warn!("{msg}");
                std::process::exit(1);
            }
            Err(ClientError::SubdomainInUse) => {
                warn!("subdomain already in use");
                std::process::exit(1);
            }
            Err(e) => {
                warn!("tunnel error: {e}, reconnecting in {:?}", backoff);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

/// Resolve "host:port" to a SocketAddr.
fn resolve_server(server: &str) -> Result<(std::net::SocketAddr, String), ClientError> {
    let addr = server
        .to_socket_addrs()
        .map_err(|e| ClientError::Server(format!("cannot resolve {server}: {e}")))?
        .next()
        .ok_or_else(|| ClientError::Server(format!("no address found for {server}")))?;

    // Extract hostname for TLS SNI (strip :port)
    let server_name = server
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(server)
        .to_string();

    Ok((addr, server_name))
}

/// Build a QUIC client endpoint that skips certificate verification (self-signed server).
fn make_quic_client() -> Result<quinn::Endpoint, ClientError> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    // Enable 0-RTT for faster reconnections
    crypto.enable_early_data = true;

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| ClientError::Server(e.to_string()))?,
    ));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Perform QUIC handshake: open control stream, send ClientHello, read ServerHello.
async fn quic_handshake(
    conn: &quinn::Connection,
    tunnel_type: TunnelType,
    key: Option<String>,
    subdomain: Option<String>,
    custom_domain: Option<String>,
    domain_action: Option<DomainAction>,
) -> Result<(ServerHello, quinn::SendStream, quinn::RecvStream), ClientError> {
    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?;

    let hello = ClientHello {
        tunnel_type,
        subdomain,
        key,
        version: PROTOCOL_VERSION,
        machine_id: Some(get_machine_id()),
        custom_domain,
        domain_action,
    };
    tunn_proto::write_control_msg(&mut ctrl_send, &hello).await?;

    let server_hello: ServerHello = tunn_proto::read_control_msg(&mut ctrl_recv).await?;

    Ok((server_hello, ctrl_send, ctrl_recv))
}

/// Extract hostname from "host:port" string.
fn extract_server_host(server: &str) -> &str {
    server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server)
}

struct TunnelOpts {
    no_qr: bool,
    no_inspect: bool,
    inspect_port: u16,
}

/// Run a single tunnel session over QUIC.
#[allow(clippy::too_many_arguments)]
async fn run_tunnel(
    endpoint: &quinn::Endpoint,
    server: &str,
    tunnel_type: TunnelType,
    local_port: u16,
    local_host: &str,
    key: Option<String>,
    subdomain: Option<String>,
    custom_domain: Option<String>,
    opts: &TunnelOpts,
) -> Result<(), ClientError> {
    let (addr, server_name) = resolve_server(server)?;

    // Try 0-RTT on reconnect (session ticket cached from previous connection)
    let connecting = endpoint.connect(addr, &server_name)?;
    let conn = match connecting.into_0rtt() {
        Ok((conn, zero_rtt_accepted)) => {
            debug!("0-RTT connection attempt");
            tokio::spawn(async move {
                if zero_rtt_accepted.await {
                    debug!("0-RTT accepted by server");
                }
            });
            conn
        }
        Err(connecting) => {
            debug!("full handshake (no cached session)");
            connecting.await?
        }
    };

    let (server_hello, _ctrl_send, _ctrl_recv) =
        quic_handshake(&conn, tunnel_type, key, subdomain, custom_domain, None).await?;

    let mut inspect_state: Option<inspect::InspectorState> = None;

    match &server_hello {
        ServerHello::Success {
            hostname,
            assigned_port,
            client_id,
            tier,
            ..
        } => {
            let tier_badge = if tier == "pro" { " [PRO]" } else { "" };
            match tunnel_type {
                TunnelType::Http => {
                    info!("tunnel opened: https://{hostname}{tier_badge}");
                }
                TunnelType::Tcp => {
                    let host = extract_server_host(server);
                    info!(
                        "tunnel opened: {host}:{}{tier_badge}",
                        assigned_port.unwrap_or(0)
                    );
                }
                TunnelType::Udp => {
                    let host = extract_server_host(server);
                    info!(
                        "tunnel opened: {host}:{} (udp){tier_badge}",
                        assigned_port.unwrap_or(0)
                    );
                }
            }
            debug!("client_id: {client_id}");

            // Print QR code
            if !opts.no_qr {
                let qr_url = match tunnel_type {
                    TunnelType::Http => format!("https://{hostname}"),
                    TunnelType::Tcp => format!(
                        "{}:{}",
                        extract_server_host(server),
                        assigned_port.unwrap_or(0)
                    ),
                    TunnelType::Udp => format!(
                        "{}:{}",
                        extract_server_host(server),
                        assigned_port.unwrap_or(0)
                    ),
                };
                if let Ok(code) = qrcode::QrCode::new(qr_url.as_bytes()) {
                    let qr_string = code
                        .render::<char>()
                        .quiet_zone(true)
                        .module_dimensions(2, 1)
                        .build();
                    eprintln!("\n{qr_string}");
                }
            }

            // Start web inspector for HTTP tunnels
            if tunnel_type == TunnelType::Http && !opts.no_inspect {
                let inspector_state = inspect::InspectorState::new();
                inspect_state = Some(inspector_state.clone());
                tokio::spawn(inspect::start_inspector(opts.inspect_port, inspector_state));
                info!("inspector: http://127.0.0.1:{}", opts.inspect_port);
            }
        }
        ServerHello::SubdomainInUse => {
            return Err(ClientError::SubdomainInUse);
        }
        ServerHello::DomainToken { .. } | ServerHello::DomainVerified { .. } => {
            return Err(ClientError::Server(
                "unexpected domain response during tunnel setup".into(),
            ));
        }
        ServerHello::Error { message } => {
            return Err(ClientError::Server(message.clone()));
        }
    }

    // Accept bi-streams from server (each = new tunnel connection)
    loop {
        let (send, mut recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
            Err(quinn::ConnectionError::LocallyClosed) => break,
            Err(e) => return Err(e.into()),
        };

        // Read stream type tag (first byte)
        let mut type_buf = [0u8; 1];
        match recv.read_exact(&mut type_buf).await {
            Ok(()) => {}
            Err(_) => continue,
        }

        match type_buf[0] {
            tunn_proto::STREAM_TYPE_RELAY => {
                let tx = inspect_state.as_ref().map(|s| s.tx.clone());
                let host = local_host.to_string();
                tokio::spawn(local::relay_tcp(send, recv, local_port, host, tx));
            }
            tunn_proto::STREAM_TYPE_UDP => {
                let host = local_host.to_string();
                tokio::spawn(local::relay_udp(send, recv, local_port, host));
            }
            other => {
                debug!("unknown stream type: {other}");
            }
        }
    }

    Ok(())
}

/// Open a tunnel, run benchmark, then exit.
async fn run_bench_tunnel(
    server: &str,
    local_port: u16,
    key: Option<String>,
    requests: usize,
    concurrency: usize,
) -> Result<(), ClientError> {
    let (addr, server_name) = resolve_server(server)?;
    let endpoint = make_quic_client()?;

    let conn = endpoint.connect(addr, &server_name)?.await?;

    let (server_hello, _ctrl_send, _ctrl_recv) =
        quic_handshake(&conn, TunnelType::Http, key, None, None, None).await?;

    let tunnel_url = match &server_hello {
        ServerHello::Success { hostname, .. } => {
            let url = format!("https://{hostname}");
            info!("tunnel: {url}");
            url
        }
        ServerHello::Error { message } => return Err(ClientError::Server(message.clone())),
        ServerHello::SubdomainInUse => return Err(ClientError::SubdomainInUse),
        _ => return Err(ClientError::Server("unexpected response".into())),
    };

    // Spawn relay in background — accept streams from server
    let conn_clone = conn.clone();
    let relay = tokio::spawn(async move {
        loop {
            let (send, mut recv) = match conn_clone.accept_bi().await {
                Ok(s) => s,
                Err(_) => break,
            };

            let mut type_buf = [0u8; 1];
            if recv.read_exact(&mut type_buf).await.is_err() {
                continue;
            }

            if type_buf[0] == tunn_proto::STREAM_TYPE_RELAY {
                tokio::spawn(local::relay_tcp(send, recv, local_port, "127.0.0.1".to_string(), None));
            }
        }
    });

    // Give tunnel a moment to stabilize
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Run benchmark
    match bench::run(&tunnel_url, local_port, requests, concurrency).await {
        Ok(result) => result.print(),
        Err(e) => warn!("benchmark error: {e}"),
    }

    // Cleanup
    relay.abort();
    conn.close(0u32.into(), b"bench done");

    Ok(())
}

/// Run a domain management command (add/verify) over QUIC.
async fn run_domain_command(
    server: &str,
    key: Option<String>,
    action: &DomainCommand,
) -> Result<(), ClientError> {
    let endpoint = make_quic_client()?;
    let (addr, server_name) = resolve_server(server)?;
    let conn = endpoint.connect(addr, &server_name)?.await?;

    let domain_action = match action {
        DomainCommand::Add { domain } => DomainAction::Add {
            domain: domain.clone(),
        },
        DomainCommand::Verify { domain } => DomainAction::Verify {
            domain: domain.clone(),
        },
    };

    let (server_hello, _ctrl_send, _ctrl_recv) = quic_handshake(
        &conn,
        TunnelType::Http, // dummy, domain_action takes priority
        key,
        None,
        None,
        Some(domain_action),
    )
    .await?;

    match server_hello {
        ServerHello::DomainToken { domain, token } => {
            eprintln!("Domain registered: {domain}\n");
            eprintln!("Add this DNS TXT record to verify ownership:\n");
            eprintln!("  Name:  _tunn-verify.{domain}");
            eprintln!("  Type:  TXT");
            eprintln!("  Value: {token}\n");
            eprintln!("Then run:  tunn domain verify {domain}");
        }
        ServerHello::DomainVerified { domain } => {
            info!("domain verified and certificate issued: {domain}");
            eprintln!("\nYour domain is ready! Use it with:\n");
            eprintln!("  tunn http 8080 --domain {domain}");
        }
        ServerHello::Error { message } => {
            return Err(ClientError::Server(message));
        }
        _ => {
            return Err(ClientError::Server("unexpected server response".into()));
        }
    }

    conn.close(0u32.into(), b"done");
    Ok(())
}

fn key_file_path() -> std::path::PathBuf {
    let dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("tunn");
    std::fs::create_dir_all(&dir).ok();
    dir.join("key")
}

fn load_saved_key() -> Option<String> {
    std::fs::read_to_string(key_file_path())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn save_key(key: &str) {
    if let Err(e) = std::fs::write(key_file_path(), key) {
        warn!("failed to save key: {e}");
    }
}

/// Get a stable machine identifier, hashed with SHA256.
fn get_machine_id() -> String {
    use sha2::{Digest, Sha256};
    let raw = read_raw_machine_id();
    let hash = Sha256::digest(raw.as_bytes());
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(target_os = "linux")]
fn read_raw_machine_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| fallback_machine_id())
}

#[cfg(target_os = "macos")]
fn read_raw_machine_id() -> String {
    std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines()
                .find(|l| l.contains("IOPlatformUUID"))
                .and_then(|l| l.split('"').nth(3))
                .map(|s| s.to_string())
        })
        .unwrap_or_else(fallback_machine_id)
}

#[cfg(target_os = "windows")]
fn read_raw_machine_id() -> String {
    std::process::Command::new("wmic")
        .args(["csproduct", "get", "uuid"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().nth(1).map(|l| l.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(fallback_machine_id)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn read_raw_machine_id() -> String {
    fallback_machine_id()
}

fn fallback_machine_id() -> String {
    let path = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("tunn")
        .join("machine_id");
    if let Ok(id) = std::fs::read_to_string(&path) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }
    let id = format!(
        "{:016x}{:016x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        std::process::id() as u128
    );
    std::fs::create_dir_all(path.parent().unwrap()).ok();
    std::fs::write(&path, &id).ok();
    id
}

/// TLS certificate verifier that accepts any certificate (for self-signed server).
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
