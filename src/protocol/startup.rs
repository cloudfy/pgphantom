use crate::errors::ProtocolError;
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt};

// ============================================================
//  Wire constants
// ============================================================

pub const SSL_REQUEST_CODE: u32 = 80877103; // 1234 << 16 | 5679
pub const CANCEL_REQUEST_CODE: u32 = 80877102; // 1234 << 16 | 5678
pub const GSSENC_REQUEST_CODE: u32 = 80877104; // 1234 << 16 | 5680
pub const PROTOCOL_30: u32 = 196608; // 3 << 16 | 0

// ============================================================
//  Initial message (before startup)
// ============================================================

#[derive(Debug)]
pub enum InitialMessage {
    SslRequest,
    GssEncRequest,
    Startup(StartupMessage),
    CancelRequest { process_id: u32, secret_key: u32 },
}

#[derive(Debug, Clone)]
pub struct StartupMessage {
    pub protocol_version: u32,
    /// Startup parameters sent by the client (e.g. user, database, application_name).
    pub parameters: HashMap<String, String>,
}

impl StartupMessage {
    /// Serialise back to the PostgreSQL wire format (no type byte).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.protocol_version.to_be_bytes());
        for (k, v) in &self.parameters {
            payload.extend_from_slice(k.as_bytes());
            payload.push(0);
            payload.extend_from_slice(v.as_bytes());
            payload.push(0);
        }
        payload.push(0); // parameter list terminator

        let total_len = (payload.len() + 4) as u32;
        let mut msg = Vec::with_capacity(4 + payload.len());
        msg.extend_from_slice(&total_len.to_be_bytes());
        msg.extend_from_slice(&payload);
        msg
    }
}

/// Read the first (pre-startup) message from a client stream.
///
/// The PostgreSQL startup protocol does not have a type byte before the length:
///   [int32 total_len][int32 code_or_version][...parameters...]
pub async fn read_initial_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<InitialMessage, ProtocolError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let total_len = u32::from_be_bytes(len_buf);

    if total_len < 8 {
        return Err(ProtocolError::InvalidMessageLength(total_len));
    }

    let payload_len = (total_len - 4) as usize;
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;

    if payload.len() < 4 {
        return Err(ProtocolError::Violation("startup payload too short".into()));
    }

    let code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let rest = &payload[4..];

    match code {
        SSL_REQUEST_CODE => Ok(InitialMessage::SslRequest),
        GSSENC_REQUEST_CODE => Ok(InitialMessage::GssEncRequest),
        CANCEL_REQUEST_CODE => {
            if rest.len() < 8 {
                return Err(ProtocolError::Violation("cancel request too short".into()));
            }
            let process_id = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
            let secret_key = u32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]]);
            Ok(InitialMessage::CancelRequest {
                process_id,
                secret_key,
            })
        }
        PROTOCOL_30 => {
            let mut parameters = HashMap::new();
            let mut buf = rest;
            loop {
                let key = read_cstring(&mut buf)?;
                if key.is_empty() {
                    break;
                }
                let value = read_cstring(&mut buf)?;
                parameters.insert(key, value);
            }
            Ok(InitialMessage::Startup(StartupMessage {
                protocol_version: PROTOCOL_30,
                parameters,
            }))
        }
        other => Err(ProtocolError::Unsupported(format!(
            "unknown startup message code {:#010x}",
            other
        ))),
    }
}

fn read_cstring<'a>(buf: &mut &'a [u8]) -> Result<String, ProtocolError> {
    let end = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or(ProtocolError::UnterminatedCString)?;
    let s = String::from_utf8(buf[..end].to_vec())?;
    *buf = &buf[end + 1..];
    Ok(s)
}
