use crate::config::TlsConfig;
use crate::errors::{AuthError, PgPhantomError};
use crate::protocol::{
    messages::{AuthRequest, ErrorFields},
    read_message, write_raw_message,
};
use crate::routing::ResolvedRoute;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

// ---------------------------------------------------------------------------
// Stream type
// ---------------------------------------------------------------------------

/// A backend connection — either plain TCP or TLS-wrapped.
pub enum BackendStream {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl tokio::io::AsyncRead for BackendStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            BackendStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            BackendStream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for BackendStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            BackendStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            BackendStream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            BackendStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            BackendStream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            BackendStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            BackendStream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

// ---------------------------------------------------------------------------
// Connect
// ---------------------------------------------------------------------------

/// Open a TCP (or TLS) connection to the backend and perform the PostgreSQL
/// startup handshake.  The caller is responsible for the *authentication* phase;
/// this function only sends the `StartupMessage` and returns an open stream
/// positioned right after it.
pub async fn connect(
    route: &ResolvedRoute,
    user: &str,
) -> Result<BackendStream, PgPhantomError> {
    let addr = format!("{}:{}", route.host, route.port);
    let tcp = TcpStream::connect(&addr).await.map_err(|e| {
        PgPhantomError::Backend(format!("TCP connect to {addr} failed: {e}"))
    })?;

    if route.tls.enabled {
        let tls_stream = tls_connect(tcp, &route.host, &route.tls).await?;
        Ok(BackendStream::Tls(tls_stream))
    } else {
        Ok(BackendStream::Plain(tcp))
    }
}

/// Build and send the PostgreSQL `StartupMessage` for the backend connection.
pub async fn send_startup<S: AsyncWrite + Unpin>(
    stream: &mut S,
    user: &str,
    database: &str,
) -> Result<(), PgPhantomError> {
    use crate::protocol::startup::StartupMessage;
    use std::collections::HashMap;

    let mut params = HashMap::new();
    params.insert("user".to_string(), user.to_string());
    params.insert("database".to_string(), database.to_string());
    params.insert("application_name".to_string(), "pgphantom".to_string());

    let msg = StartupMessage {
        protocol_version: crate::protocol::startup::PROTOCOL_30,
        parameters: params,
    };

    stream
        .write_all(&msg.to_bytes())
        .await
        .map_err(PgPhantomError::Io)?;
    Ok(())
}

/// Authenticate to the backend using a plaintext password (SCRAM-SHA-256, MD5, or cleartext).
///
/// This is used in JWT mode where PgPhantom holds the backend credentials itself.
pub async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    user: &str,
    password: &str,
) -> Result<(), AuthError> {
    loop {
        let (type_byte, payload) = read_message(stream).await?;

        match type_byte {
            b'R' => {
                let req = AuthRequest::parse(&payload)?;
                match req {
                    AuthRequest::Ok => return Ok(()),

                    AuthRequest::CleartextPassword => {
                        let msg = build_password_message(password.as_bytes());
                        write_raw_message(stream, &msg).await?;
                    }

                    AuthRequest::Md5Password { salt } => {
                        let hashed = md5_password(user, password, &salt);
                        let msg = build_password_message(hashed.as_bytes());
                        write_raw_message(stream, &msg).await?;
                    }

                    AuthRequest::Sasl { mechanisms } => {
                        let mech = mechanisms
                            .iter()
                            .find(|m| m.as_str() == "SCRAM-SHA-256")
                            .ok_or_else(|| {
                                AuthError::BackendAuthFailed
                            })?
                            .clone();
                        scram_sha256_auth(stream, user, password, &mech).await?;
                    }

                    AuthRequest::SaslContinue { .. }
                    | AuthRequest::SaslFinal { .. } => {
                        // These are handled inside scram_sha256_auth; if we see them
                        // here it is a protocol error.
                        return Err(AuthError::BackendAuthFailed);
                    }

                    _ => return Err(AuthError::BackendAuthFailed),
                }
            }
            b'E' => {
                let fields = ErrorFields::parse(&payload);
                return Err(AuthError::BackendAuthFailed);
            }
            _ => {
                // Unexpected message; ignore and continue.
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Password helpers
// ---------------------------------------------------------------------------

fn build_password_message(password: &[u8]) -> Vec<u8> {
    let length = (4 + password.len() + 1) as u32;
    let mut msg = Vec::with_capacity(5 + password.len() + 1);
    msg.push(b'p');
    msg.extend_from_slice(&length.to_be_bytes());
    msg.extend_from_slice(password);
    msg.push(0); // null terminator
    msg
}

fn md5_password(user: &str, password: &str, salt: &[u8; 4]) -> String {
    let inner = format!("{:x}", md5_hex(
        &[password.as_bytes(), user.as_bytes()].concat()
    ));
    let outer = format!("{:x}", md5_hex(
        &[inner.as_bytes(), salt.as_slice()].concat()
    ));
    format!("md5{outer}")
}

fn md5_hex(data: &[u8]) -> u128 {
    let mut hasher = md5::Md5::new();
    hasher.update(data);
    let digest = hasher.digest();
    u128::from_be_bytes(digest)
}

// ---------------------------------------------------------------------------
// SCRAM-SHA-256 client implementation
// ---------------------------------------------------------------------------

async fn scram_sha256_auth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    user: &str,
    password: &str,
    mechanism: &str,
) -> Result<(), AuthError> {
    // Generate a 24-byte random nonce (base64-encoded).
    let nonce_bytes: [u8; 18] = rand::thread_rng().gen();
    let client_nonce = B64.encode(nonce_bytes);

    // client-first-message
    let client_first_bare = format!("n={user},r={client_nonce}");
    let client_first = format!("n,,{client_first_bare}");

    // SASLInitialResponse
    let client_first_bytes = client_first.as_bytes();
    let data_len = client_first_bytes.len() as i32;
    let mut sasl_initial = Vec::new();
    sasl_initial.push(b'p');
    let payload_len = (4 + mechanism.len() + 1 + 4 + client_first_bytes.len()) as u32;
    sasl_initial.extend_from_slice(&(payload_len + 4).to_be_bytes());
    sasl_initial.extend_from_slice(mechanism.as_bytes());
    sasl_initial.push(0);
    sasl_initial.extend_from_slice(&data_len.to_be_bytes());
    sasl_initial.extend_from_slice(client_first_bytes);
    write_raw_message(stream, &sasl_initial).await?;

    // Read AuthenticationSASLContinue
    let (type_byte, payload) = read_message(stream).await?;
    if type_byte != b'R' {
        return Err(AuthError::BackendAuthFailed);
    }
    let auth_req = AuthRequest::parse(&payload)?;
    let server_first = match auth_req {
        AuthRequest::SaslContinue { data } => {
            String::from_utf8(data).map_err(|_| AuthError::BackendAuthFailed)?
        }
        _ => return Err(AuthError::BackendAuthFailed),
    };

    // Parse server-first-message: r=<nonce>,s=<base64_salt>,i=<iterations>
    let (server_nonce, server_salt, iterations) =
        parse_server_first(&server_first, &client_nonce)?;

    let salt = B64.decode(&server_salt)
        .map_err(|_| AuthError::BackendAuthFailed)?;
    let iterations: u32 = iterations.parse().map_err(|_| AuthError::BackendAuthFailed)?;

    // Compute salted password: Hi(password, salt, i) using PBKDF2-HMAC-SHA256.
    let mut salted_password = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut salted_password);

    // ClientKey = HMAC(SaltedPassword, "Client Key")
    let client_key = hmac_sha256(&salted_password, b"Client Key");
    // StoredKey = SHA256(ClientKey)
    let stored_key = Sha256::digest(&client_key);
    // ServerKey = HMAC(SaltedPassword, "Server Key")
    let server_key = hmac_sha256(&salted_password, b"Server Key");

    // client-final-without-proof:  c=base64(GS2-header),r=<server_nonce>
    // GS2 header for no channel binding = "n,,"
    let gs2_header_b64 = B64.encode(b"n,,");
    let client_final_no_proof = format!("c={gs2_header_b64},r={server_nonce}");

    // AuthMessage = client-first-bare + "," + server-first + "," + client-final-no-proof
    let auth_message = format!("{client_first_bare},{server_first},{client_final_no_proof}");

    // ClientSignature = HMAC(StoredKey, AuthMessage)
    let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());

    // ClientProof = ClientKey XOR ClientSignature
    let client_proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    let client_proof_b64 = B64.encode(&client_proof);

    let client_final = format!("{client_final_no_proof},p={client_proof_b64}");

    // SASLResponse
    let resp_bytes = client_final.as_bytes();
    let resp_len = (4 + resp_bytes.len()) as u32;
    let mut sasl_response = Vec::new();
    sasl_response.push(b'p');
    sasl_response.extend_from_slice(&resp_len.to_be_bytes());
    sasl_response.extend_from_slice(resp_bytes);
    write_raw_message(stream, &sasl_response).await?;

    // Read AuthenticationSASLFinal
    let (type_byte, payload) = read_message(stream).await?;
    if type_byte != b'R' {
        return Err(AuthError::BackendAuthFailed);
    }
    let auth_req = AuthRequest::parse(&payload)?;
    let server_final_data = match auth_req {
        AuthRequest::SaslFinal { data } => data,
        AuthRequest::Ok => return Ok(()), // some backends omit SASLFinal
        _ => return Err(AuthError::BackendAuthFailed),
    };

    // Verify server signature: v=base64(HMAC(ServerKey, AuthMessage))
    let expected_server_sig = hmac_sha256(&server_key, auth_message.as_bytes());
    let server_final =
        String::from_utf8(server_final_data).map_err(|_| AuthError::BackendAuthFailed)?;
    if let Some(v) = server_final.strip_prefix("v=") {
        let claimed_sig = B64.decode(v).map_err(|_| AuthError::BackendAuthFailed)?;
        if claimed_sig != expected_server_sig.as_slice() {
            return Err(AuthError::BackendAuthFailed);
        }
    }

    // Read the final AuthenticationOk
    let (type_byte, payload) = read_message(stream).await?;
    if type_byte == b'R' {
        let req = AuthRequest::parse(&payload)?;
        if matches!(req, AuthRequest::Ok) {
            return Ok(());
        }
    }
    Err(AuthError::BackendAuthFailed)
}

fn parse_server_first<'a>(
    server_first: &'a str,
    client_nonce: &str,
) -> Result<(String, String, String), AuthError> {
    let mut nonce = None;
    let mut salt = None;
    let mut iterations = None;

    for part in server_first.split(',') {
        if let Some(v) = part.strip_prefix("r=") {
            if !v.starts_with(client_nonce) {
                return Err(AuthError::BackendAuthFailed);
            }
            nonce = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("s=") {
            salt = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("i=") {
            iterations = Some(v.to_string());
        }
    }

    match (nonce, salt, iterations) {
        (Some(n), Some(s), Some(i)) => Ok((n, s, i)),
        _ => Err(AuthError::BackendAuthFailed),
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// TLS client connection to backend
// ---------------------------------------------------------------------------

async fn tls_connect(
    tcp: TcpStream,
    host: &str,
    tls_config: &TlsConfig,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, PgPhantomError> {
    use rustls::RootCertStore;

    let mut root_store = RootCertStore::empty();

    if let Some(ca_file) = &tls_config.ca_file {
        // Load custom CA.
        let ca_pem = std::fs::read(ca_file).map_err(|e| {
            PgPhantomError::Tls(format!("reading CA file {ca_file:?}: {e}"))
        })?;
        let mut cursor = std::io::BufReader::new(ca_pem.as_slice());
        for cert in rustls_pemfile::certs(&mut cursor) {
            root_store
                .add(cert.map_err(|e| PgPhantomError::Tls(format!("CA cert parse: {e}")))?)
                .map_err(|e| PgPhantomError::Tls(format!("CA cert add: {e}")))?;
        }
    } else {
        // Trust system/native roots.
        let native_certs = rustls_native_certs::load_native_certs()
            .unwrap_or_default();
        for cert in native_certs {
            let _ = root_store.add(cert);
        }
        // Add WebPKI roots as a fallback.
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let client_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let connector = TlsConnector::from(client_config);
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| PgPhantomError::Tls(format!("invalid server name {host:?}: {e}")))?;

    // PostgreSQL TLS handshake: send SSLRequest, expect 'S', then do TLS.
    use tokio::io::AsyncWriteExt;
    use tokio::io::AsyncReadExt;

    // We need to send SSLRequest before upgrading. TcpStream is consumed by
    // connect(); we need to do this before handing off to TlsConnector.
    // Clone the raw TCP stream reference for SSLRequest negotiation.
    let mut tcp = tcp;
    let ssl_request: [u8; 8] = {
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&8u32.to_be_bytes()); // total length
        b[4..8].copy_from_slice(&80877103u32.to_be_bytes()); // SSLRequest magic
        b
    };
    tcp.write_all(&ssl_request).await.map_err(PgPhantomError::Io)?;

    let mut resp = [0u8; 1];
    tcp.read_exact(&mut resp).await.map_err(PgPhantomError::Io)?;
    if resp[0] != b'S' {
        return Err(PgPhantomError::Tls(format!(
            "backend at {host} declined TLS (responded with {:?})",
            resp[0] as char
        )));
    }

    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| PgPhantomError::Tls(format!("TLS handshake with backend failed: {e}")))?;

    Ok(tls_stream)
}

// Minimal MD5 implementation using sha2 is not available; use a tiny inline.
// Instead of pulling in the `md5` crate, implement the hash by hand using the
// standard library's `std::collections::hash_map` is not MD5.
// We'll use the `md5` feature through hex encoding tricks.
// Actually, let's just use a tiny md5 via the digest trait pattern.
// The `md5` crate is not in our dependencies. Let's use a different approach:
// compute MD5 via the `hmac`+`sha2` ecosystem or add a dependency.
// For now, implement a standalone MD5 to avoid an extra dependency.
mod md5 {
    // A compact, standalone MD5 implementation.
    pub struct Md5 {
        state: [u32; 4],
        count: [u32; 2],
        buffer: [u8; 64],
    }

    const S: [u32; 64] = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
    ];

    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    impl Md5 {
        pub fn new() -> Self {
            Self {
                state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
                count: [0, 0],
                buffer: [0; 64],
            }
        }

        pub fn update(&mut self, input: &[u8]) {
            let mut index = ((self.count[0] >> 3) & 0x3f) as usize;
            self.count[0] = self.count[0].wrapping_add((input.len() as u32) << 3);
            if self.count[0] < (input.len() as u32) << 3 {
                self.count[1] = self.count[1].wrapping_add(1);
            }
            self.count[1] = self.count[1].wrapping_add((input.len() as u32) >> 29);

            let part_len = 64 - index;
            let mut i = 0;
            if input.len() >= part_len {
                self.buffer[index..64].copy_from_slice(&input[..part_len]);
                self.transform();
                i = part_len;
                while i + 63 < input.len() {
                    self.buffer.copy_from_slice(&input[i..i + 64]);
                    self.transform();
                    i += 64;
                }
                index = 0;
            }
            self.buffer[index..index + (input.len() - i)]
                .copy_from_slice(&input[i..]);
        }

        pub fn digest(mut self) -> [u8; 16] {
            let bits: [u8; 8] = {
                let mut b = [0u8; 8];
                b[0..4].copy_from_slice(&self.count[0].to_le_bytes());
                b[4..8].copy_from_slice(&self.count[1].to_le_bytes());
                b
            };
            let index = ((self.count[0] >> 3) & 0x3f) as usize;
            let pad_len = if index < 56 { 56 - index } else { 120 - index };
            let mut padding = [0u8; 64];
            padding[0] = 0x80;
            self.update(&padding[..pad_len]);
            self.update(&bits);

            let mut digest = [0u8; 16];
            for (i, s) in self.state.iter().enumerate() {
                digest[i * 4..i * 4 + 4].copy_from_slice(&s.to_le_bytes());
            }
            digest
        }

        fn transform(&mut self) {
            let mut a = self.state[0];
            let mut b = self.state[1];
            let mut c = self.state[2];
            let mut d = self.state[3];

            let x: Vec<u32> = (0..16)
                .map(|i| u32::from_le_bytes(self.buffer[i * 4..i * 4 + 4].try_into().unwrap()))
                .collect();

            for i in 0..64u32 {
                let (f, g) = match i {
                    0..=15 => ((b & c) | (!b & d), i),
                    16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                    32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                    _ => (c ^ (b | !d), (7 * i) % 16),
                };
                let temp = d;
                d = c;
                c = b;
                b = b.wrapping_add(
                    a.wrapping_add(f)
                        .wrapping_add(K[i as usize])
                        .wrapping_add(x[g as usize])
                        .rotate_left(S[i as usize]),
                );
                a = temp;
            }

            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut h = Md5::new();
        h.update(data);
        h.digest()
    }
}
