use crate::errors::AuthError;

/// Parse an OAUTHBEARER SASL initial response (RFC 7628 §3.1).
///
/// The GS2-formatted initial client message is:
///   `n,,\x01auth=Bearer <token>\x01[\x01key=value]*\x01`
///
/// Returns the Bearer token.
pub fn extract_bearer_token(sasl_data: &[u8]) -> Result<String, AuthError> {
    // Expect the GS2 header to start with "n,,"
    let text = std::str::from_utf8(sasl_data)
        .map_err(|_| AuthError::OauthBearer("SASL data is not valid UTF-8".into()))?;

    // Split on the GS2 header separator (the third comma terminates the header).
    // The header is "n,," (no channel binding, no authzid).
    let rest = text
        .strip_prefix("n,,")
        .ok_or_else(|| AuthError::OauthBearer("missing GS2 header n,,".into()))?;

    // The rest is \x01-separated key=value fields, starting and ending with \x01.
    // First field is: auth=Bearer <token>
    for field in rest.split('\x01') {
        if let Some(bearer) = field.strip_prefix("auth=Bearer ") {
            let token = bearer.trim().to_string();
            if token.is_empty() {
                return Err(AuthError::OauthBearer("empty Bearer token".into()));
            }
            return Ok(token);
        }
    }

    Err(AuthError::OauthBearer(
        "no auth=Bearer field found in OAUTHBEARER response".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token_valid() {
        let data = b"n,,\x01auth=Bearer eyJhbGciOiJSUzI1NiJ9.token.sig\x01\x01";
        let token = extract_bearer_token(data).unwrap();
        assert_eq!(token, "eyJhbGciOiJSUzI1NiJ9.token.sig");
    }

    #[test]
    fn test_extract_bearer_token_missing_header() {
        let data = b"\x01auth=Bearer token\x01";
        assert!(extract_bearer_token(data).is_err());
    }
}
