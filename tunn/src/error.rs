//! Client error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("QUIC connection error: {0}")]
    Quic(#[from] quinn::ConnectionError),

    #[error("QUIC connect error: {0}")]
    QuicConnect(#[from] quinn::ConnectError),

    #[error("protocol error: {0}")]
    Proto(#[from] tunn_proto::ProtoError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("server error: {0}")]
    Server(String),

    #[error("subdomain already in use")]
    SubdomainInUse,
}
