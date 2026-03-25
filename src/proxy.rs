use crate::auth::jwt::JwkValidator;
use crate::auth::relay::relay_auth;
use crate::backend::{authenticate, connect, send_startup};
use crate::config::Config;
use crate::errors::PgPhantomError;
use crate::protocol::{
    messages::{build_auth_ok, build_auth_sasl, build_auth_sasl_final, build_error_response},
    parse_sasl_initial_response, read_message, write_raw_message, write_single_byte,
    startup::{CANCEL_REQUEST_CODE, GSSENC_REQUEST_CODE, PROTOCOL_30, SSL_REQUEST_CODE},
};
use crate::routing::RouteResolver;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Client-side stream (plain or server-TLS)
// ---------------------------------------------------------------------------

pub enum ClientStream {
    Plain(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
}

impl tokio::io::AsyncRead for ClientStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ClientStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            ClientStream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for ClientStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ClientStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            ClientStream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ClientStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            ClientStream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ClientStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            ClientStream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

/// Shared state passed to every connection task.
pub struct ProxyContext {
    pub config: Arc<Config>,
    pub resolver: Arc<RouteResolver>,
    pub tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    pub jwt_validator: Option<Arc<JwkValidator>>,
}

/// Handle a single inbound client connection end-to-end.
pub async fn handle_connection(tcp_stream: TcpStream, ctx: Arc<ProxyContext>) {
    let peer = tcp_stream.peer_addr().ok();
    if let Err(e) = handle_inner(tcp_stream, ctx).await {
        match &e {
            PgPhantomError::Io(io_err)
                if io_err.kind() == std::io::ErrorKind::UnexpectedEof
                    || io_err.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                tracing::debug!(peer = ?peer, "client disconnected early");
            }
            _ => {
                tracing::warn!(peer = ?peer, error = %e, "connection terminated with error");
            }
        }
    }
}

async fn handle_inner(
    tcp_stream: TcpStream,
    ctx: Arc<ProxyContext>,
) -> Result<(), PgPhantomError> {
    let peer = tcp_stream.peer_addr().ok();
    tracing::debug!(peer = ?peer, "accepted connection");

    // ---- step 1+2: TLS negotiation + StartupMessage (single pass) ----
    let (mut client, startup, tls_terminated) =
        negotiate_and_startup(tcp_stream, &ctx).await?;

    let user = startup.parameters.get("user").cloned().unwrap_or_default();
    let database = startup
        .parameters
        .get("database")
        .cloned()
        .unwrap_or_else(|| user.clone());

    tracing::info!(peer = ?peer, user = %user, database = %database, "startup received");

    // ---- step 3: route resolution ----
    let route = match ctx.resolver.resolve(&database, &user) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(peer = ?peer, user = %user, database = %database,
                error = %e, "no matching backend");
            let err = build_error_response(
                "3D000",
                &format!("no backend configured for database {:?}", database),
            );
            let _ = write_raw_message(&mut client, &err).await;
            return Err(PgPhantomError::Routing(e));
        }
    };

    tracing::debug!(
        peer = ?peer,
        backend = %format!("{}:{}", route.host, route.port),
        resolved_database = %route.database,
        "route resolved"
    );

    // ---- step 4+5+6: auth + proxy ----
    match ctx.config.auth.mode {
        crate::config::AuthMode::Relay => {
            relay_mode(&mut client, &route, &ctx, tls_terminated, peer).await
        }
        crate::config::AuthMode::Jwt => jwt_mode(&mut client, &route, &ctx, peer).await,
    }
}

// ---------------------------------------------------------------------------
// Relay mode
// ---------------------------------------------------------------------------

async fn relay_mode(
    client: &mut ClientStream,
    route: &crate::routing::ResolvedRoute,
    ctx: &ProxyContext,
    tls_terminated: bool,
    peer: Option<std::net::SocketAddr>,
) -> Result<(), PgPhantomError> {
    let mut backend = connect(route, &route.user).await?;
    send_startup(&mut backend, &route.user, &route.database).await?;

    relay_auth(client, &mut backend, &ctx.config.auth.methods, tls_terminated)
        .await
        .map_err(|e| {
            tracing::warn!(peer = ?peer, error = %e, "relay auth failed");
            PgPhantomError::Auth(e)
        })?;

    tracing::info!(
        peer = ?peer,
        backend = %format!("{}:{}", route.host, route.port),
        "relay auth complete — starting proxy"
    );

    tokio::io::copy_bidirectional(client, &mut backend)
        .await
        .map_err(PgPhantomError::Io)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// JWT mode
// ---------------------------------------------------------------------------

async fn jwt_mode(
    client: &mut ClientStream,
    route: &crate::routing::ResolvedRoute,
    ctx: &ProxyContext,
    peer: Option<std::net::SocketAddr>,
) -> Result<(), PgPhantomError> {
    let validator = ctx
        .jwt_validator
        .as_ref()
        .expect("JWT mode requires a JwkValidator");

    // ---- authenticate client via SASL OAUTHBEARER (returns raw token + claims) ----
    let (raw_token, claims) = authenticate_client_oauthbearer(client, validator)
        .await
        .map_err(|e| {
            tracing::warn!(peer = ?peer, error = %e, "client JWT auth failed");
            PgPhantomError::Auth(e)
        })?;

    let jwt_cfg = ctx.config.auth.jwt.as_ref().unwrap();
    let username_from_jwt = claims
        .get_claim_str(&jwt_cfg.username_claim)
        .unwrap_or_else(|| "unknown".to_string());

    // ---- resolve backend credentials ----
    let (backend_user, backend_password) = if let Some(svc_user) = &route.service_user {
        let pwd = route
            .service_password_env
            .as_ref()
            .map(|e| std::env::var(e).unwrap_or_default())
            .unwrap_or_default();
        (svc_user.clone(), pwd)
    } else if let Some(sts_cfg) = &ctx.config.auth.sts {
        let minted = crate::auth::sts::exchange_token(sts_cfg, &raw_token)
            .await
            .map_err(|e| {
                tracing::warn!(peer = ?peer, error = %e, "STS token exchange failed");
                PgPhantomError::Auth(e)
            })?;
        (username_from_jwt, minted)
    } else {
        let err = build_error_response(
            "28000",
            "no backend credentials configured for JWT mode (set service_user or sts)",
        );
        let _ = write_raw_message(client, &err).await;
        return Err(PgPhantomError::Auth(
            crate::errors::AuthError::BackendAuthFailed,
        ));
    };

    // ---- connect and authenticate to backend ----
    let mut backend = connect(route, &backend_user).await?;
    send_startup(&mut backend, &backend_user, &route.database).await?;
    authenticate(&mut backend, &backend_user, &backend_password)
        .await
        .map_err(|e| {
            tracing::warn!(peer = ?peer, error = %e, "backend auth in JWT mode failed");
            PgPhantomError::Auth(e)
        })?;

    tracing::info!(
        peer = ?peer,
        backend = %format!("{}:{}", route.host, route.port),
        backend_user = %backend_user,
        "JWT auth complete — starting proxy"
    );

    tokio::io::copy_bidirectional(client, &mut backend)
        .await
        .map_err(PgPhantomError::Io)?;
    Ok(())
}

/// Perform SASL OAUTHBEARER with the client and return (raw_token_string, validated_claims).
async fn authenticate_client_oauthbearer<C: AsyncRead + AsyncWrite + Unpin>(
    client: &mut C,
    validator: &JwkValidator,
) -> Result<(String, crate::auth::jwt::Claims), crate::errors::AuthError> {
    // Offer OAUTHBEARER.
    write_raw_message(client, &build_auth_sasl(&["OAUTHBEARER"])).await?;

    // Read SASLInitialResponse.
    let (type_byte, payload) = read_message(client).await?;
    if type_byte != b'p' {
        return Err(crate::errors::AuthError::Protocol(
            crate::errors::ProtocolError::UnexpectedMessageType { type_byte },
        ));
    }
    let (mechanism, sasl_data) = parse_sasl_initial_response(&payload)?;
    if mechanism != "OAUTHBEARER" {
        let err = build_error_response("28000", "expected OAUTHBEARER SASL mechanism");
        let _ = write_raw_message(client, &err).await;
        return Err(crate::errors::AuthError::MethodNotPermitted);
    }

    let token = crate::auth::oauthbearer::extract_bearer_token(&sasl_data)?;

    match validator.validate(&token).await {
        Ok(claims) => {
            write_raw_message(client, &build_auth_sasl_final(&[])).await?;
            write_raw_message(client, &build_auth_ok()).await?;
            Ok((token, claims))
        }
        Err(e) => {
            let err = build_error_response("28000", &format!("JWT validation failed: {e}"));
            let _ = write_raw_message(client, &err).await;
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// TLS negotiation + StartupMessage parsing (single pass)
// ---------------------------------------------------------------------------
//
// PostgreSQL pre-startup wire protocol:
//   Client sends one of:
//     SSLRequest       (8 bytes: len=8, code=80877103)
//     GSSENCRequest    (8 bytes: len=8, code=80877104)
//     CancelRequest    (16 bytes)
//     StartupMessage   (variable, code=196608 = protocol 3.0)
//
// After responding to SSLRequest with 'S', the client upgrades TLS and then
// sends StartupMessage on the TLS stream.  After 'N' the client sends
// StartupMessage on plain TCP.

/// Read the first 8 bytes, detect the pre-startup code, dispatch accordingly,
/// and return `(stream, StartupMessage, tls_was_terminated)`.
async fn negotiate_and_startup(
    tcp: TcpStream,
    ctx: &ProxyContext,
) -> Result<(ClientStream, crate::protocol::startup::StartupMessage, bool), PgPhantomError> {
    let mut tls_terminated = false;
    let mut stream = ClientStream::Plain(tcp);

    loop {
        // Read length (4 bytes).
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(PgPhantomError::Io)?;
        let total_len = u32::from_be_bytes(len_buf);
        if total_len < 8 {
            return Err(PgPhantomError::Protocol(
                crate::errors::ProtocolError::InvalidMessageLength(total_len),
            ));
        }
        // Read payload (total_len - 4 bytes).
        let rest_len = (total_len - 4) as usize;
        let mut rest = vec![0u8; rest_len];
        stream
            .read_exact(&mut rest)
            .await
            .map_err(PgPhantomError::Io)?;

        let code =
            u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);

        match code {
            SSL_REQUEST_CODE => {
                if let Some(acceptor) = ctx.tls_acceptor.clone() {
                    write_single_byte(&mut stream, b'S').await?;
                    let inner = match stream {
                        ClientStream::Plain(s) => s,
                        ClientStream::Tls(_) => unreachable!("SSLRequest on TLS stream"),
                    };
                    let tls = acceptor
                        .accept(inner)
                        .await
                        .map_err(|e| PgPhantomError::Tls(e.to_string()))?;
                    stream = ClientStream::Tls(tls);
                    tls_terminated = true;
                } else {
                    write_single_byte(&mut stream, b'N').await?;
                }
            }

            GSSENC_REQUEST_CODE => {
                write_single_byte(&mut stream, b'N').await?;
            }

            CANCEL_REQUEST_CODE => {
                // Silently drop cancel requests (no cancellation registry yet).
                return Err(PgPhantomError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "cancel request — connection closed",
                )));
            }

            PROTOCOL_30 => {
                // StartupMessage — parse key=value\0 parameter list.
                let mut parameters = HashMap::new();
                let mut buf: &[u8] = &rest[4..]; // skip 4-byte protocol version
                loop {
                    let key = read_cstring(&mut buf)?;
                    if key.is_empty() {
                        break;
                    }
                    let value = read_cstring(&mut buf)?;
                    parameters.insert(key, value);
                }
                let startup = crate::protocol::startup::StartupMessage {
                    protocol_version: PROTOCOL_30,
                    parameters,
                };
                return Ok((stream, startup, tls_terminated));
            }

            other => {
                return Err(PgPhantomError::Protocol(
                    crate::errors::ProtocolError::Unsupported(format!(
                        "unknown startup code {other:#010x}"
                    )),
                ));
            }
        }
    }
}

fn read_cstring<'a>(buf: &mut &'a [u8]) -> Result<String, PgPhantomError> {
    match buf.iter().position(|&b| b == 0) {
        Some(end) => {
            let s = String::from_utf8(buf[..end].to_vec()).map_err(|e| {
                PgPhantomError::Protocol(crate::errors::ProtocolError::InvalidUtf8(e))
            })?;
            *buf = &buf[end + 1..];
            Ok(s)
        }
        None => Err(PgPhantomError::Protocol(
            crate::errors::ProtocolError::UnterminatedCString,
        )),
    }
}
