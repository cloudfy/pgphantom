use crate::errors::ProtocolError;

// ============================================================
//  Authentication request subtypes (type byte 'R', 4-byte code)
// ============================================================

#[derive(Debug, Clone)]
pub enum AuthRequest {
    Ok,
    KerberosV5,
    CleartextPassword,
    Md5Password { salt: [u8; 4] },
    ScmCredential,
    Gss,
    GssContinue { data: Vec<u8> },
    Sspi,
    /// SASL negotiation — list of mechanism names the server will accept.
    Sasl { mechanisms: Vec<String> },
    /// SASL server-first or server-challenge message.
    SaslContinue { data: Vec<u8> },
    /// SASL server-final (additional-data) message.
    SaslFinal { data: Vec<u8> },
}

impl AuthRequest {
    /// Parse from the payload of an 'R' backend message (the payload includes the 4-byte subcode).
    pub fn parse(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < 4 {
            return Err(ProtocolError::Violation(
                "auth request payload too short".into(),
            ));
        }
        let code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let rest = &payload[4..];

        match code {
            0 => Ok(AuthRequest::Ok),
            2 => Ok(AuthRequest::KerberosV5),
            3 => Ok(AuthRequest::CleartextPassword),
            5 => {
                if rest.len() < 4 {
                    return Err(ProtocolError::Violation("MD5 salt too short".into()));
                }
                Ok(AuthRequest::Md5Password {
                    salt: [rest[0], rest[1], rest[2], rest[3]],
                })
            }
            6 => Ok(AuthRequest::ScmCredential),
            7 => Ok(AuthRequest::Gss),
            8 => Ok(AuthRequest::GssContinue {
                data: rest.to_vec(),
            }),
            9 => Ok(AuthRequest::Sspi),
            10 => {
                let mut mechanisms = Vec::new();
                let mut buf = rest;
                loop {
                    let end = buf
                        .iter()
                        .position(|&b| b == 0)
                        .ok_or_else(|| ProtocolError::Violation("unterminated mechanism string".into()))?;
                    if end == 0 {
                        break; // empty string = list terminator
                    }
                    mechanisms.push(String::from_utf8(buf[..end].to_vec())?);
                    buf = &buf[end + 1..];
                }
                Ok(AuthRequest::Sasl { mechanisms })
            }
            11 => Ok(AuthRequest::SaslContinue {
                data: rest.to_vec(),
            }),
            12 => Ok(AuthRequest::SaslFinal {
                data: rest.to_vec(),
            }),
            other => Err(ProtocolError::Violation(format!(
                "unknown authentication subtype {}",
                other
            ))),
        }
    }

    /// Returns true if, after forwarding this request to the client, the client
    /// must send a response back to the backend.
    pub fn expects_client_response(&self) -> bool {
        matches!(
            self,
            AuthRequest::CleartextPassword
                | AuthRequest::Md5Password { .. }
                | AuthRequest::Gss
                | AuthRequest::GssContinue { .. }
                | AuthRequest::Sspi
                | AuthRequest::Sasl { .. }
                | AuthRequest::SaslContinue { .. }
        )
    }
}

// ============================================================
//  Error / Notice fields
// ============================================================

/// Parsed fields from a PostgreSQL ErrorResponse or NoticeResponse message.
#[derive(Debug, Default)]
pub struct ErrorFields {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
}

impl ErrorFields {
    pub fn parse(payload: &[u8]) -> Self {
        let mut fields = ErrorFields::default();
        let mut pos = 0;
        while pos < payload.len() {
            let field_type = payload[pos];
            pos += 1;
            if field_type == 0 {
                break;
            }
            let end = payload[pos..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(payload.len() - pos);
            let value = String::from_utf8_lossy(&payload[pos..pos + end]).into_owned();
            pos += end + 1;
            match field_type {
                b'S' => fields.severity = value,
                b'V' => {} // non-localised copy of severity — ignore
                b'C' => fields.code = value,
                b'M' => fields.message = value,
                b'D' => fields.detail = Some(value),
                b'H' => fields.hint = Some(value),
                _ => {} // other fields not needed for proxy operation
            }
        }
        fields
    }

    /// Serialise as an ErrorResponse payload suitable for forwarding to a client.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut push = |code: u8, v: &str| {
            buf.push(code);
            buf.extend_from_slice(v.as_bytes());
            buf.push(0);
        };
        push(b'S', &self.severity);
        push(b'V', &self.severity);
        push(b'C', &self.code);
        push(b'M', &self.message);
        if let Some(d) = &self.detail {
            push(b'D', d);
        }
        if let Some(h) = &self.hint {
            push(b'H', h);
        }
        buf.push(0); // terminator
        buf
    }
}

// ============================================================
//  Message builders
// ============================================================

/// Build a complete PostgreSQL message frame: `type_byte` + big-endian int32 length + payload.
///
/// The length field counts itself (4 bytes) plus the payload, but NOT the type byte.
pub fn build_message(type_byte: u8, payload: &[u8]) -> Vec<u8> {
    let length = (4 + payload.len()) as u32;
    let mut msg = Vec::with_capacity(5 + payload.len());
    msg.push(type_byte);
    msg.extend_from_slice(&length.to_be_bytes());
    msg.extend_from_slice(payload);
    msg
}

pub fn build_auth_ok() -> Vec<u8> {
    build_message(b'R', &0u32.to_be_bytes())
}

pub fn build_auth_cleartext() -> Vec<u8> {
    build_message(b'R', &3u32.to_be_bytes())
}

pub fn build_auth_md5(salt: &[u8; 4]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&5u32.to_be_bytes());
    payload.extend_from_slice(salt);
    build_message(b'R', &payload)
}

/// Build AuthenticationSASL offering the given mechanism list.
pub fn build_auth_sasl(mechanisms: &[&str]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&10u32.to_be_bytes());
    for mech in mechanisms {
        payload.extend_from_slice(mech.as_bytes());
        payload.push(0);
    }
    payload.push(0); // list terminator
    build_message(b'R', &payload)
}

pub fn build_auth_sasl_continue(data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + data.len());
    payload.extend_from_slice(&11u32.to_be_bytes());
    payload.extend_from_slice(data);
    build_message(b'R', &payload)
}

pub fn build_auth_sasl_final(data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + data.len());
    payload.extend_from_slice(&12u32.to_be_bytes());
    payload.extend_from_slice(data);
    build_message(b'R', &payload)
}

/// Build an ErrorResponse sending a FATAL with the given SQLSTATE code and message.
pub fn build_error_response(code: &str, message: &str) -> Vec<u8> {
    let fields = ErrorFields {
        severity: "FATAL".to_string(),
        code: code.to_string(),
        message: message.to_string(),
        ..Default::default()
    };
    build_message(b'E', &fields.to_bytes())
}

/// Rebuild an AuthenticationSASL message, filtering out channel-binding variants.
/// Used in relay mode where PgPhantom terminates TLS and channel binding would fail.
pub fn filter_sasl_mechanisms(mechanisms: &[String]) -> Vec<u8> {
    let filtered: Vec<&str> = mechanisms
        .iter()
        .filter(|m| *m != "SCRAM-SHA-256-PLUS")
        .map(String::as_str)
        .collect();
    build_auth_sasl(&filtered)
}
