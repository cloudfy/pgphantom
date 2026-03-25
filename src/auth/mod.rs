pub mod jwt;
pub mod oauthbearer;
pub mod relay;
pub mod sts;

use crate::config::{AuthConfig, AuthMode, BackendConfig};
use crate::errors::AuthError;
use crate::protocol::{
    messages::{
        build_auth_ok, build_auth_sasl, build_auth_sasl_final, build_error_response,
    },
    read_message, write_raw_message,
    startup::StartupMessage,
};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub use jwt::JwkValidator;

// ---------------------------------------------------------------------------
// JWT-mode client authentication
// ---------------------------------------------------------------------------

/// Handle SASL OAUTHBEARER authentication when the proxy is in JWT mode.
///
/// Flow:
///  1. Send `AuthenticationSASL([OAUTHBEARER])` to the client.
///  2. Read `SASLInitialResponse` from the client.
///  3. Extract the Bearer token.
///  4. Validate the JWT against the JWKS.
///  5. On success: calls `on_success` which should complete backend auth,
///     then sends `AuthenticationSASLFinal` + `AuthenticationOk` to the client.
///  6. On failure: sends `ErrorResponse` to the client.
///
/// Returns the validated JWT claims so the caller can use them for backend auth.
pub async fn jwt_authenticate_client<C>(
    client: &mut C,
    validator: &JwkValidator,
) -> Result<jwt::Claims, AuthError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    // Step 1 — offer OAUTHBEARER.
    let offer = build_auth_sasl(&["OAUTHBEARER"]);
    write_raw_message(client, &offer).await?;

    // Step 2 — read SASLInitialResponse (type byte 'p').
    let (type_byte, payload) = read_message(client).await?;
    if type_byte != b'p' {
        return Err(AuthError::Protocol(
            crate::errors::ProtocolError::UnexpectedMessageType { type_byte },
        ));
    }

    // Parse the SASLInitialResponse payload.
    let (mechanism, sasl_data) = crate::protocol::parse_sasl_initial_response(&payload)?;
    if mechanism != "OAUTHBEARER" {
        let err = build_error_response("28000", "expected OAUTHBEARER SASL mechanism");
        write_raw_message(client, &err).await?;
        return Err(AuthError::MethodNotPermitted);
    }

    // Step 3 — extract token.
    let token = oauthbearer::extract_bearer_token(&sasl_data).map_err(|e| {
        let _ = futures_send_error_sync(client, "28000", &e.to_string());
        e
    })?;

    // Step 4 — validate JWT.
    match validator.validate(&token).await {
        Ok(claims) => {
            // Step 5 — send AuthSASLFinal (empty server-final) + AuthOk.
            let final_msg = build_auth_sasl_final(&[]);
            write_raw_message(client, &final_msg).await?;
            let ok = build_auth_ok();
            write_raw_message(client, &ok).await?;
            Ok(claims)
        }
        Err(e) => {
            let err = build_error_response("28000", &format!("JWT validation failed: {e}"));
            write_raw_message(client, &err).await?;
            Err(e)
        }
    }
}

/// Fire-and-forget error send.  Used inside map_err closures where async isn't available.
fn futures_send_error_sync<W: AsyncWrite + Unpin>(_writer: &mut W, _code: &str, _msg: &str) {}
