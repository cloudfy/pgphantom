pub mod messages;
pub mod startup;

use crate::errors::ProtocolError;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Low-level frame I/O helpers
// ---------------------------------------------------------------------------

/// Read a single PostgreSQL *regular* message (post-startup) from a stream.
///
/// Format: `[type:u8][length:u32][payload:(length-4) bytes]`
///
/// Returns `(type_byte, payload)`.
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(u8, Vec<u8>), ProtocolError> {
    let mut header = [0u8; 5];
    reader.read_exact(&mut header).await?;
    let type_byte = header[0];
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);

    if length < 4 {
        return Err(ProtocolError::InvalidMessageLength(length));
    }

    let payload_len = (length - 4) as usize;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Ok((type_byte, payload))
}

/// Write a single PostgreSQL *regular* message to a stream.
///
/// The caller provides the raw `type_byte` and `payload`; this function
/// prepends the length field.
pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    type_byte: u8,
    payload: &[u8],
) -> Result<(), ProtocolError> {
    let length = (4 + payload.len()) as u32;
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(type_byte);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    writer.write_all(&frame).await.map_err(ProtocolError::Io)?;
    Ok(())
}

/// Write an already-framed message (type + 4-byte length + payload as a single buffer).
pub async fn write_raw_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &[u8],
) -> io::Result<()> {
    writer.write_all(frame).await
}

/// Send a single-byte response with no length framing (used for SSLRequest responses).
pub async fn write_single_byte<W: AsyncWrite + Unpin>(
    writer: &mut W,
    byte: u8,
) -> io::Result<()> {
    writer.write_all(&[byte]).await
}

/// Parse the `SASLInitialResponse` payload.
///
/// Format: `mechanism_name\0 [int32 data_len] [data_len bytes]`
///
/// Returns `(mechanism_name, sasl_data)`.
pub fn parse_sasl_initial_response(payload: &[u8]) -> Result<(String, Vec<u8>), ProtocolError> {
    let nul = payload
        .iter()
        .position(|&b| b == 0)
        .ok_or(ProtocolError::UnterminatedCString)?;
    let mechanism = String::from_utf8(payload[..nul].to_vec())?;
    let rest = &payload[nul + 1..];

    if rest.len() < 4 {
        return Err(ProtocolError::Violation(
            "SASLInitialResponse data length field missing".into(),
        ));
    }
    let data_len = i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
    if data_len < 0 {
        return Ok((mechanism, Vec::new())); // no data
    }
    let data_len = data_len as usize;
    if rest.len() < 4 + data_len {
        return Err(ProtocolError::Violation(
            "SASLInitialResponse data truncated".into(),
        ));
    }
    Ok((mechanism, rest[4..4 + data_len].to_vec()))
}
