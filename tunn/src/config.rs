//! CLI argument parsing.

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "tunn", about = "Expose local servers to the internet", version)]
pub struct Cli {
    /// Server address (host:port for QUIC)
    #[arg(short, long, default_value = "tunn.uz:443")]
    pub server: String,

    /// License key for Pro features
    #[arg(short, long, env = "TUNN_KEY")]
    pub key: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum DomainCommand {
    /// Add a custom domain for verification
    Add {
        /// Domain name (e.g., diyarbek.uz)
        domain: String,
    },
    /// Verify domain ownership via DNS TXT record
    Verify {
        /// Domain name to verify
        domain: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Expose a local HTTP server
    Http {
        /// Local port to expose
        port: u16,
        /// Local host to forward to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Custom subdomain (Pro only)
        #[arg(short, long)]
        subdomain: Option<String>,
        /// Use a verified custom domain (Pro only)
        #[arg(long)]
        domain: Option<String>,
        /// Disable QR code display
        #[arg(long)]
        no_qr: bool,
        /// Disable web inspector
        #[arg(long)]
        no_inspect: bool,
        /// Web inspector port
        #[arg(long, default_value = "4040")]
        inspect_port: u16,
    },
    /// Expose a local TCP server
    Tcp {
        /// Local port to expose
        port: u16,
        /// Local host to forward to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
    },
    /// Expose a local UDP server
    Udp {
        /// Local port to expose
        port: u16,
        /// Local host to forward to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
    },
    /// Update tunn to the latest version
    Update,
    /// Activate a license key
    Activate {
        /// License key from Polar.sh
        key: String,
    },
    /// Manage custom domains (Pro only)
    Domain {
        #[command(subcommand)]
        action: DomainCommand,
    },
    /// Benchmark tunnel latency and throughput
    Bench {
        /// Local port to benchmark
        port: u16,
        /// Number of requests to send
        #[arg(short, long, default_value = "1000")]
        requests: usize,
        /// Concurrent connections
        #[arg(short, long, default_value = "10")]
        concurrency: usize,
    },
}
