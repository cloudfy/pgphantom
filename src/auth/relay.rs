use crate::config::AuthMethods;
use crate::errors::AuthError;
use crate::protocol::{
    messages::{build_error_response, filter_sasl_mechanisms, AuthRequest},
    read_message, write_message, write_raw_message,
};
use tokio::io::{AsyncRead, AsyncWrite};

/// Relay authentication messages between a client and a backend.
///
/// Precondition: the backend has already received the `StartupMessage`.
/// This function drives the message loop until:
///  - The backend sends `AuthenticationOk`   → both sides authenticated, returns Ok.
///  - The backend sends `ErrorResponse`      → forwards the error to the client, returns Err.
///
/// In relay mode PgPhantom never sees the user's credentials.
///
/// When TLS is terminated on the edge (`tls_terminated = true`), we strip
/// `SCRAM-SHA-256-PLUS` from any `AuthenticationSASL` mechanism list because
/// channel binding is incompatible with TLS termination.
pub async fn relay_auth<C, B>(
    client: &mut C,
    backend: &mut B,
    methods: &AuthMethods,
    tls_terminated: bool,
) -> Result<(), AuthError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let (type_byte, payload) = read_message(backend).await?;

        match type_byte {
            b'R' => {
                let auth_req = AuthRequest::parse(&payload)?;

                match auth_req {
                    AuthRequest::Ok => {
                        // Forward AuthOk to client and we're done.
                        write_message(client, b'R', &payload).await?;
                        return Ok(());
                    }

                    AuthRequest::Sasl { ref mechanisms } => {
                        // Validate that at least one mechanism is permitted.
                        if !is_sasl_permitted(mechanisms, methods) {
                            let err = build_error_response(
                                "28000",
                                "authentication method not permitted by server configuration",
                            );
                            write_raw_message(client, &err).await?;
                            return Err(AuthError::MethodNotPermitted);
                        }
                        // Strip SCRAM-SHA-256-PLUS when TLS is terminated.
                        if tls_terminated {
                            let filtered = filter_sasl_mechanisms(mechanisms);
                            write_raw_message(client, &filtered).await?;
                        } else {
                            write_message(client, b'R', &payload).await?;
                        }
                        // Read and relay client's SASLInitialResponse.
                        relay_client_to_backend(client, backend).await?;
                    }

                    AuthRequest::SaslContinue { .. } => {
                        write_message(client, b'R', &payload).await?;
                        relay_client_to_backend(client, backend).await?;
                    }

                    AuthRequest::SaslFinal { .. } => {
                        // Forward server-final to client. Client sends no reply here.
                        write_message(client, b'R', &payload).await?;
                        // The next message from backend will be AuthOk or ErrorResponse.
                    }

                    AuthRequest::Md5Password { .. } => {
                        if !methods.md5 {
                            let err = build_error_response(
                                "28000",
                                "MD5 authentication is disabled",
                            );
                            write_raw_message(client, &err).await?;
                            return Err(AuthError::MethodNotPermitted);
                        }
                        write_message(client, b'R', &payload).await?;
                        relay_client_to_backend(client, backend).await?;
                    }

                    AuthRequest::CleartextPassword => {
                        if !methods.cleartext {
                            let err = build_error_response(
                                "28000",
                                "cleartext password authentication is disabled",
                            );
                            write_raw_message(client, &err).await?;
                            return Err(AuthError::MethodNotPermitted);
                        }
                        write_message(client, b'R', &payload).await?;
                        relay_client_to_backend(client, backend).await?;
                    }

                    AuthRequest::Gss | AuthRequest::GssContinue { .. } | AuthRequest::Sspi => {
                        // Not supported in proxy mode — inform the client.
                        let err = build_error_response(
                            "28000",
                            "GSSAPI/SSPI authentication is not supported by this proxy",
                        );
                        write_raw_message(client, &err).await?;
                        return Err(AuthError::MethodNotPermitted);
                    }

                    AuthRequest::KerberosV5 | AuthRequest::ScmCredential => {
                        let err = build_error_response(
                            "28000",
                            "unsupported authentication method requested by backend",
                        );
                        write_raw_message(client, &err).await?;
                        return Err(AuthError::MethodNotPermitted);
                    }
                }
            }

            b'E' => {
                // Backend rejected authentication — forward the error and stop.
                write_message(client, b'E', &payload).await?;
                return Err(AuthError::BackendAuthFailed);
            }

            other => {
                // Unexpected message during auth phase.
                return Err(AuthError::Protocol(
                    crate::errors::ProtocolError::UnexpectedMessageType { type_byte: other },
                ));
            }
        }
    }
}

/// Forward one message from client to backend.
async fn relay_client_to_backend<C, B>(
    client: &mut C,
    backend: &mut B,
) -> Result<(), AuthError>
where
    C: AsyncRead + Unpin,
    B: AsyncWrite + Unpin,
{
    let (type_byte, payload) = read_message(client).await?;
    write_message(backend, type_byte, &payload).await?;
    Ok(())
}

/// Check whether at least one offered SASL mechanism is permitted by the policy.
fn is_sasl_permitted(mechanisms: &[String], methods: &AuthMethods) -> bool {
    for mech in mechanisms {
        match mech.as_str() {
            "SCRAM-SHA-256" | "SCRAM-SHA-256-PLUS" if methods.scram_sha_256 => return true,
            "OAUTHBEARER" if methods.oauthbearer => return true,
            _ => {}
        }
    }
    false
}
