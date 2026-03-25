use thiserror::Error;

/// Errors in PostgreSQL wire-protocol parsing or framing.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid message length: {0}")]
    InvalidMessageLength(u32),

    #[error("Unsupported protocol feature: {0}")]
    Unsupported(String),

    #[error("Unexpected message type: {type_byte:#04x}")]
    UnexpectedMessageType { type_byte: u8 },

    #[error("Invalid UTF-8 in protocol message")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error("Unterminated C-string in startup message")]
    UnterminatedCString,

    #[error("Protocol violation: {0}")]
    Violation(String),
}

/// Errors during the authentication exchange.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("JWT validation failed: {0}")]
    JwtValidation(String),

    #[error("OAUTHBEARER parse error: {0}")]
    OauthBearer(String),

    #[error("STS token exchange failed: {0}")]
    StsExchange(String),

    #[error("Authentication method not permitted by server configuration")]
    MethodNotPermitted,

    #[error("Backend authentication failed")]
    BackendAuthFailed,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors resolving a backend route.
#[derive(Debug, Error)]
pub enum RoutingError {
    #[error("No matching backend for database={database:?}, user={user:?}")]
    NoRoute { database: String, user: String },

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),
}

/// Errors loading or validating configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error reading config file: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Unknown config file extension: {0:?}")]
    UnknownExtension(String),

    #[error("TLS configuration error: {0}")]
    Tls(String),

    #[error("Validation error: {0}")]
    Validation(String),
}

/// Top-level proxy error.
#[derive(Debug, Error)]
pub enum PgPhantomError {
    #[error("Config error: {0}")]
    Config(#[from] ConfigError),

    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("Auth error: {0}")]
    Auth(#[from] AuthError),

    #[error("Routing error: {0}")]
    Routing(#[from] RoutingError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Backend connection error: {0}")]
    Backend(String),
}

impl From<rustls::Error> for PgPhantomError {
    fn from(e: rustls::Error) -> Self {
        PgPhantomError::Tls(e.to_string())
    }
}
