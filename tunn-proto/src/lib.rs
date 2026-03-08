//! Shared protocol types for the tunn tunneling tool.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// StreamId
// ---------------------------------------------------------------------------

/// A 4-byte stream identifier.
/// Even IDs are server-initiated, odd IDs are client-initiated (HTTP/2 convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub u32);

impl StreamId {
    pub const CONTROL: Self = Self(0);

    pub fn is_server_initiated(self) -> bool {
        self.0 != 0 && self.0.is_multiple_of(2)
    }

    pub fn is_client_initiated(self) -> bool {
        self.0 % 2 == 1
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stream#{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// TunnelType
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelType {
    Http,
    Tcp,
    Udp,
}

impl fmt::Display for TunnelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunnelType::Http => write!(f, "http"),
            TunnelType::Tcp => write!(f, "tcp"),
            TunnelType::Udp => write!(f, "udp"),
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake messages (JSON text frames)
// ---------------------------------------------------------------------------

/// Current protocol version (2 = QUIC native streams).
pub const PROTOCOL_VERSION: u8 = 2;

fn default_version() -> u8 {
    2
}

/// Stream type tags (first byte on each QUIC data bi-stream).
pub const STREAM_TYPE_RELAY: u8 = 0x01; // TCP/HTTP raw byte relay
pub const STREAM_TYPE_UDP: u8 = 0x02; // UDP length-prefixed datagrams

// ---------------------------------------------------------------------------
// Control stream framing (length-prefixed JSON over QUIC bi-stream)
// ---------------------------------------------------------------------------

/// Write a length-prefixed JSON message to an async writer.
/// Format: [len:4B big-endian][json:len bytes]
pub async fn write_control_msg<W: AsyncWriteExt + Unpin, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> Result<(), ProtoError> {
    let json = serde_json::to_vec(msg)?;
    let len = (json.len() as u32).to_be_bytes();
    writer
        .write_all(&len)
        .await
        .map_err(|e| ProtoError::Io(e.to_string()))?;
    writer
        .write_all(&json)
        .await
        .map_err(|e| ProtoError::Io(e.to_string()))?;
    Ok(())
}

/// Read a length-prefixed JSON message from an async reader.
/// Max 1MB message size.
pub async fn read_control_msg<R: AsyncReadExt + Unpin, T: serde::de::DeserializeOwned>(
    reader: &mut R,
) -> Result<T, ProtoError> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| ProtoError::Io(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1_048_576 {
        return Err(ProtoError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|e| ProtoError::Io(e.to_string()))?;
    Ok(serde_json::from_slice(&buf)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub tunnel_type: TunnelType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subdomain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default = "default_version")]
    pub version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    /// Use a verified custom domain instead of a subdomain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_domain: Option<String>,
    /// Domain management command (add/verify). When set, no tunnel is created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_action: Option<DomainAction>,
}

/// Domain management actions (sent instead of creating a tunnel).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum DomainAction {
    Add { domain: String },
    Verify { domain: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum ServerHello {
    #[serde(rename = "success")]
    Success {
        hostname: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        assigned_port: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        relay_port: Option<u16>,
        client_id: String,
        #[serde(default)]
        tier: String,
    },
    #[serde(rename = "subdomain_in_use")]
    SubdomainInUse,
    /// Server returns a verification token after `DomainAction::Add`.
    #[serde(rename = "domain_token")]
    DomainToken { domain: String, token: String },
    /// Server confirms domain is verified after `DomainAction::Verify`.
    #[serde(rename = "domain_verified")]
    DomainVerified { domain: String },
    #[serde(rename = "error")]
    Error { message: String },
}

// ---------------------------------------------------------------------------
// Control packets (binary frames)
// ---------------------------------------------------------------------------

/// Wire format: [type: 1B][stream_id: 4B][payload: variable]
#[derive(Debug, Clone)]
pub enum ControlPacket {
    /// Server → client: open a new stream for an incoming connection.
    Init(StreamId),
    /// Bidirectional: tunnel payload data.
    Data(StreamId, Bytes),
    /// Client → server: local connection refused.
    Refused(StreamId),
    /// Bidirectional: stream EOF / graceful close.
    End(StreamId),
    /// Keepalive ping (stream_id = 0).
    Ping,
    /// Keepalive pong reply (stream_id = 0).
    Pong,
}

const TYPE_INIT: u8 = 0x01;
const TYPE_DATA: u8 = 0x02;
const TYPE_REFUSED: u8 = 0x03;
const TYPE_END: u8 = 0x04;
const TYPE_PING: u8 = 0x05;
const TYPE_PONG: u8 = 0x06;

impl ControlPacket {
    /// Serialize into bytes (legacy, used in tests only).
    pub fn serialize(&self) -> Bytes {
        match self {
            ControlPacket::Init(sid) => {
                let mut buf = BytesMut::with_capacity(5);
                buf.put_u8(TYPE_INIT);
                buf.put_u32_le(sid.0);
                buf.freeze()
            }
            ControlPacket::Data(sid, payload) => {
                let mut buf = BytesMut::with_capacity(5 + payload.len());
                buf.put_u8(TYPE_DATA);
                buf.put_u32_le(sid.0);
                buf.extend_from_slice(payload);
                buf.freeze()
            }
            ControlPacket::Refused(sid) => {
                let mut buf = BytesMut::with_capacity(5);
                buf.put_u8(TYPE_REFUSED);
                buf.put_u32_le(sid.0);
                buf.freeze()
            }
            ControlPacket::End(sid) => {
                let mut buf = BytesMut::with_capacity(5);
                buf.put_u8(TYPE_END);
                buf.put_u32_le(sid.0);
                buf.freeze()
            }
            ControlPacket::Ping => {
                let mut buf = BytesMut::with_capacity(5);
                buf.put_u8(TYPE_PING);
                buf.put_u32_le(0);
                buf.freeze()
            }
            ControlPacket::Pong => {
                let mut buf = BytesMut::with_capacity(5);
                buf.put_u8(TYPE_PONG);
                buf.put_u32_le(0);
                buf.freeze()
            }
        }
    }

    /// Deserialize from a binary frame payload.
    pub fn deserialize(mut data: Bytes) -> Result<Self, ProtoError> {
        if data.len() < 5 {
            return Err(ProtoError::FrameTooShort(data.len()));
        }
        let ptype = data.get_u8();
        let sid = StreamId(data.get_u32_le());

        match ptype {
            TYPE_INIT => Ok(ControlPacket::Init(sid)),
            TYPE_DATA => Ok(ControlPacket::Data(sid, data)),
            TYPE_REFUSED => Ok(ControlPacket::Refused(sid)),
            TYPE_END => Ok(ControlPacket::End(sid)),
            TYPE_PING => Ok(ControlPacket::Ping),
            TYPE_PONG => Ok(ControlPacket::Pong),
            other => Err(ProtoError::UnknownPacketType(other)),
        }
    }

    pub fn stream_id(&self) -> StreamId {
        match self {
            ControlPacket::Init(s)
            | ControlPacket::Data(s, _)
            | ControlPacket::Refused(s)
            | ControlPacket::End(s) => *s,
            ControlPacket::Ping | ControlPacket::Pong => StreamId::CONTROL,
        }
    }
}

// ---------------------------------------------------------------------------
// UDP encapsulation
// ---------------------------------------------------------------------------

/// Magic bytes for UDP relay packets.
pub const UDP_MAGIC: u16 = 0xBEEF;

/// Encode a UDP relay packet: [magic: 2B][tunnel_port: 4B][payload].
pub fn encode_udp_relay(tunnel_port: u32, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(6 + payload.len());
    buf.put_u16_le(UDP_MAGIC);
    buf.put_u32_le(tunnel_port);
    buf.extend_from_slice(payload);
    buf.freeze()
}

/// Decode a UDP relay packet. Returns `(tunnel_port, payload)`.
pub fn decode_udp_relay(mut data: Bytes) -> Result<(u32, Bytes), ProtoError> {
    if data.len() < 6 {
        return Err(ProtoError::FrameTooShort(data.len()));
    }
    let magic = data.get_u16_le();
    if magic != UDP_MAGIC {
        return Err(ProtoError::InvalidUdpMagic(magic));
    }
    let port = data.get_u32_le();
    Ok((port, data))
}

// ---------------------------------------------------------------------------
// Subdomain validation
// ---------------------------------------------------------------------------

/// Validate a subdomain: 3-63 chars, lowercase alphanumeric + hyphens,
/// cannot start/end with hyphen.
pub fn validate_subdomain(s: &str) -> Result<(), ProtoError> {
    if s.len() < 3 || s.len() > 63 {
        return Err(ProtoError::InvalidSubdomain(format!(
            "length must be 3-63, got {}",
            s.len()
        )));
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err(ProtoError::InvalidSubdomain(
            "cannot start or end with hyphen".into(),
        ));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ProtoError::InvalidSubdomain(
            "only lowercase alphanumeric and hyphens allowed".into(),
        ));
    }
    Ok(())
}

/// Sanitize a string into a valid subdomain: lowercase, replace invalid chars
/// with hyphens, trim leading/trailing hyphens, truncate to 63 chars.
pub fn sanitize_subdomain(s: &str) -> String {
    let sanitized: String = s
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches('-');
    if trimmed.len() > 63 {
        trimmed[..63].trim_end_matches('-').to_string()
    } else {
        trimmed.to_string()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("frame too short: {0} bytes")]
    FrameTooShort(usize),

    #[error("unknown packet type: 0x{0:02x}")]
    UnknownPacketType(u8),

    #[error("invalid subdomain: {0}")]
    InvalidSubdomain(String),

    #[error("invalid UDP magic: 0x{0:04x}")]
    InvalidUdpMagic(u16),

    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),

    #[error("io error: {0}")]
    Io(String),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_id_parity() {
        assert!(StreamId(2).is_server_initiated());
        assert!(StreamId(4).is_server_initiated());
        assert!(StreamId(1).is_client_initiated());
        assert!(StreamId(3).is_client_initiated());
        assert!(!StreamId(0).is_server_initiated());
        assert!(!StreamId(0).is_client_initiated());
    }

    #[test]
    fn control_packet_roundtrip_init() {
        let pkt = ControlPacket::Init(StreamId(42));
        let data = pkt.serialize();
        let decoded = ControlPacket::deserialize(data).unwrap();
        assert!(matches!(decoded, ControlPacket::Init(StreamId(42))));
    }

    #[test]
    fn control_packet_roundtrip_data() {
        let payload = Bytes::from_static(b"hello world");
        let pkt = ControlPacket::Data(StreamId(7), payload.clone());
        let data = pkt.serialize();
        let decoded = ControlPacket::deserialize(data).unwrap();
        match decoded {
            ControlPacket::Data(sid, p) => {
                assert_eq!(sid, StreamId(7));
                assert_eq!(p, payload);
            }
            _ => panic!("expected Data"),
        }
    }

    #[test]
    fn control_packet_roundtrip_all_types() {
        let packets = vec![
            ControlPacket::Init(StreamId(2)),
            ControlPacket::Data(StreamId(4), Bytes::from_static(b"test")),
            ControlPacket::Refused(StreamId(6)),
            ControlPacket::End(StreamId(8)),
            ControlPacket::Ping,
            ControlPacket::Pong,
        ];
        for pkt in packets {
            let data = pkt.serialize();
            let decoded = ControlPacket::deserialize(data).unwrap();
            assert_eq!(pkt.stream_id(), decoded.stream_id());
        }
    }

    #[test]
    fn control_packet_too_short() {
        let data = Bytes::from_static(&[0x01, 0x00]);
        assert!(ControlPacket::deserialize(data).is_err());
    }

    #[test]
    fn control_packet_unknown_type() {
        let data = Bytes::from_static(&[0xFF, 0x00, 0x00, 0x00, 0x00]);
        assert!(ControlPacket::deserialize(data).is_err());
    }

    #[test]
    fn handshake_json_roundtrip() {
        let hello = ClientHello {
            tunnel_type: TunnelType::Http,
            subdomain: Some("test".into()),
            key: None,
            version: PROTOCOL_VERSION,
            machine_id: None,
            custom_domain: None,
            domain_action: None,
        };
        let json = serde_json::to_string(&hello).unwrap();
        let decoded: ClientHello = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.tunnel_type, TunnelType::Http);
        assert_eq!(decoded.subdomain.as_deref(), Some("test"));
        assert_eq!(decoded.version, 2);
    }

    #[test]
    fn client_hello_without_version_defaults_to_2() {
        let json = r#"{"tunnel_type":"http"}"#;
        let hello: ClientHello = serde_json::from_str(json).unwrap();
        assert_eq!(hello.version, 2);
        assert_eq!(hello.subdomain, None);
    }

    #[test]
    fn server_hello_success_json() {
        let resp = ServerHello::Success {
            hostname: "test.example.com".into(),
            assigned_port: Some(12345),
            relay_port: None,
            client_id: "abc123".into(),
            tier: "free".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("success"));
        let decoded: ServerHello = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, ServerHello::Success { .. }));
    }

    #[test]
    fn validate_subdomain_ok() {
        assert!(validate_subdomain("abc").is_ok());
        assert!(validate_subdomain("my-tunnel").is_ok());
        assert!(validate_subdomain("test123").is_ok());
    }

    #[test]
    fn validate_subdomain_errors() {
        assert!(validate_subdomain("ab").is_err()); // too short
        assert!(validate_subdomain("-abc").is_err()); // starts with hyphen
        assert!(validate_subdomain("abc-").is_err()); // ends with hyphen
        assert!(validate_subdomain("ABC").is_err()); // uppercase
        assert!(validate_subdomain("a b").is_err()); // space
        let long = "a".repeat(64);
        assert!(validate_subdomain(&long).is_err()); // too long
    }

    #[test]
    fn sanitize_subdomain_works() {
        assert_eq!(sanitize_subdomain("My_App"), "my-app");
        assert_eq!(sanitize_subdomain("--test--"), "test");
        assert_eq!(sanitize_subdomain("Hello World!"), "hello-world");
    }

    #[test]
    fn udp_relay_roundtrip() {
        let payload = b"game data";
        let encoded = encode_udp_relay(25565, payload);
        let (port, data) = decode_udp_relay(encoded).unwrap();
        assert_eq!(port, 25565);
        assert_eq!(&data[..], payload);
    }

    #[tokio::test]
    async fn control_msg_roundtrip() {
        let hello = ClientHello {
            tunnel_type: TunnelType::Http,
            subdomain: Some("test".into()),
            key: None,
            version: PROTOCOL_VERSION,
            machine_id: None,
            custom_domain: None,
            domain_action: None,
        };
        let (client, server) = tokio::io::duplex(1024);
        let (mut w, mut r) = (client, server);
        write_control_msg(&mut w, &hello).await.unwrap();
        drop(w);
        let decoded: ClientHello = read_control_msg(&mut r).await.unwrap();
        assert_eq!(decoded.tunnel_type, TunnelType::Http);
        assert_eq!(decoded.subdomain.as_deref(), Some("test"));
    }

    #[test]
    fn udp_relay_bad_magic() {
        let mut buf = BytesMut::with_capacity(6);
        buf.put_u16_le(0xDEAD);
        buf.put_u32_le(0);
        assert!(decode_udp_relay(buf.freeze()).is_err());
    }
}
