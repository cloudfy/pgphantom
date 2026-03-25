use crate::errors::ConfigError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub listen: ListenConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    pub routing: RoutingConfig,
    #[serde(default)]
    pub cluster: ClusterConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListenConfig {
    #[serde(default = "defaults::host")]
    pub host: String,
    #[serde(default = "defaults::pg_port")]
    pub port: u16,
    #[serde(default)]
    pub tls: TlsConfig,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            host: defaults::host(),
            port: defaults::pg_port(),
            tls: TlsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    /// CA certificate for verifying the *other* side (used for client→backend TLS).
    pub ca_file: Option<String>,
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub methods: AuthMethods,
    #[serde(default)]
    pub mode: AuthMode,
    pub jwt: Option<JwtConfig>,
    pub sts: Option<StsConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            methods: AuthMethods::default(),
            mode: AuthMode::default(),
            jwt: None,
            sts: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthMethods {
    #[serde(default = "defaults::tru")]
    pub scram_sha_256: bool,
    #[serde(default = "defaults::tru")]
    pub md5: bool,
    #[serde(default)]
    pub cleartext: bool,
    #[serde(default)]
    pub oauthbearer: bool,
}

impl Default for AuthMethods {
    fn default() -> Self {
        Self {
            scram_sha_256: true,
            md5: true,
            cleartext: false,
            oauthbearer: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// Forward the backend's auth challenge verbatim to the client.
    /// PgPhantom never sees the user's password.
    #[default]
    Relay,
    /// PgPhantom terminates auth. Clients MUST authenticate via SASL
    /// OAUTHBEARER (PostgreSQL 16+ native, RFC 7628). PgPhantom validates
    /// the JWT and then authenticates to the backend with a service account
    /// or STS-exchanged token.
    Jwt,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtConfig {
    /// URL of the JWKS endpoint for key material.
    pub jwks_uri: String,
    /// Expected `iss` claim value.
    pub issuer: String,
    /// Expected `aud` claim value.
    pub audience: String,
    /// How often to refresh JWKS (seconds). Default 300.
    #[serde(default = "defaults::jwks_ttl")]
    pub refresh_interval_secs: u64,
    /// JWT claim to use as the PostgreSQL username when connecting to the backend.
    #[serde(default = "defaults::sub")]
    pub username_claim: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StsConfig {
    /// RFC 8693 token exchange endpoint.
    pub token_endpoint: String,
    pub client_id: String,
    /// Name of the environment variable that contains the client secret.
    pub client_secret_env: String,
    /// `audience` parameter for the token exchange request.
    pub audience: Option<String>,
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RoutingConfig {
    #[serde(default)]
    pub mappings: Vec<MappingRule>,
    #[serde(default)]
    pub regex_rules: Vec<RegexRule>,
    #[serde(default)]
    pub backends: HashMap<String, BackendConfig>,
    /// When no rule matches: reject with FATAL when absent, or route here.
    pub default_backend: Option<String>,
}

/// Exact-match mapping rule — evaluated before regex rules.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MappingRule {
    /// Match on the client's `database` startup parameter. None = any.
    pub database: Option<String>,
    /// Match on the client's `user` startup parameter. None = any.
    pub user: Option<String>,
    /// Name of the backend to route to (must exist in `backends`).
    pub backend: String,
    /// Optionally rewrite the database name sent to the backend.
    pub rewrite_database: Option<String>,
}

/// Regex-based routing rule — evaluated after exact mappings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegexRule {
    /// Regex to match against `database`. None = any.
    pub match_database: Option<String>,
    /// Regex to match against `user`. None = any.
    pub match_user: Option<String>,
    /// Name of a pre-configured backend. Mutually exclusive with `backend_host`.
    pub backend: Option<String>,
    /// Dynamic backend hostname (supports `$1` capture groups from `match_database`).
    pub backend_host: Option<String>,
    #[serde(default = "defaults::pg_port")]
    pub backend_port: u16,
    /// Rewrite `database` before forwarding (supports `$1` capture groups).
    pub rewrite_database: Option<String>,
    /// Override TLS settings for this dynamic backend.
    pub backend_tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackendConfig {
    pub host: String,
    #[serde(default = "defaults::pg_port")]
    pub port: u16,
    #[serde(default)]
    pub tls: TlsConfig,
    /// In JWT mode — authenticate to backend with this username.
    /// If absent, uses the `username_claim` from the validated JWT.
    pub service_user: Option<String>,
    /// In JWT mode — env var containing the backend password for `service_user`.
    /// If absent, PgPhantom uses STS token exchange instead.
    pub service_password_env: Option<String>,
}

// ---------------------------------------------------------------------------
// Cluster
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ClusterConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Node ID used as the etcd key suffix. Defaults to `$HOSTNAME`.
    pub node_id: Option<String>,
    pub etcd: Option<EtcdConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EtcdConfig {
    #[serde(default = "defaults::etcd_endpoints")]
    pub endpoints: Vec<String>,
    #[serde(default = "defaults::etcd_prefix")]
    pub prefix: String,
    pub tls: Option<TlsConfig>,
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "defaults::log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: defaults::log_level(),
            format: LogFormat::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

// ---------------------------------------------------------------------------
// Defaults module
// ---------------------------------------------------------------------------

mod defaults {
    pub fn host() -> String {
        "0.0.0.0".to_string()
    }
    pub fn pg_port() -> u16 {
        5432
    }
    pub fn tru() -> bool {
        true
    }
    pub fn jwks_ttl() -> u64 {
        300
    }
    pub fn sub() -> String {
        "sub".to_string()
    }
    pub fn log_level() -> String {
        "info".to_string()
    }
    pub fn etcd_endpoints() -> Vec<String> {
        vec!["http://localhost:2379".to_string()]
    }
    pub fn etcd_prefix() -> String {
        "/pgphantom/config/".to_string()
    }
}

// ---------------------------------------------------------------------------
// Load and validate
// ---------------------------------------------------------------------------

/// Load a config file from `path`.
///
/// The format is inferred from the extension (`.yaml`/`.yml` or `.json`).
/// Supports `${ENV_VAR}` substitution in string values.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let raw = std::fs::read_to_string(path)?;
    let substituted = substitute_env_vars(&raw);

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let config: Config = match ext {
        "yaml" | "yml" => serde_yaml::from_str(&substituted)?,
        "json" => serde_json::from_str(&substituted)?,
        other => return Err(ConfigError::UnknownExtension(other.to_string())),
    };
    validate(&config)?;
    Ok(config)
}

/// Parse a full config from a YAML/JSON string (used for etcd config distribution).
pub fn parse_str(content: &str, format_hint: &str) -> Result<Config, ConfigError> {
    match format_hint {
        "json" => Ok(serde_json::from_str(content)?),
        _ => Ok(serde_yaml::from_str(content)?),
    }
}

fn validate(config: &Config) -> Result<(), ConfigError> {
    // TLS listener validation
    if config.listen.tls.enabled {
        if config.listen.tls.cert_file.is_none() {
            return Err(ConfigError::Validation(
                "listen.tls.cert_file required when TLS is enabled".into(),
            ));
        }
        if config.listen.tls.key_file.is_none() {
            return Err(ConfigError::Validation(
                "listen.tls.key_file required when TLS is enabled".into(),
            ));
        }
    }

    // JWT mode requires jwt config
    if config.auth.mode == AuthMode::Jwt && config.auth.jwt.is_none() {
        return Err(ConfigError::Validation(
            "auth.jwt is required when auth.mode = \"jwt\"".into(),
        ));
    }

    // Mapping backends must exist
    for rule in &config.routing.mappings {
        if !config.routing.backends.contains_key(&rule.backend) {
            return Err(ConfigError::Validation(format!(
                "mapping rule references unknown backend {:?}",
                rule.backend
            )));
        }
    }

    // Regex rule named backends must exist
    for rule in &config.routing.regex_rules {
        if let Some(name) = &rule.backend {
            if !config.routing.backends.contains_key(name) {
                return Err(ConfigError::Validation(format!(
                    "regex_rule references unknown backend {:?}",
                    name
                )));
            }
        }
    }

    // Default backend must exist
    if let Some(default) = &config.routing.default_backend {
        if !config.routing.backends.contains_key(default) {
            return Err(ConfigError::Validation(format!(
                "default_backend references unknown backend {:?}",
                default
            )));
        }
    }

    Ok(())
}

/// Replace `${VAR_NAME}` placeholders with the corresponding environment variable.
/// Unset variables are substituted with an empty string.
fn substitute_env_vars(input: &str) -> String {
    // Using a simple manual parser to avoid requiring regex at config load time.
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            for vc in chars.by_ref() {
                if vc == '}' {
                    break;
                }
                var_name.push(vc);
            }
            out.push_str(&std::env::var(&var_name).unwrap_or_default());
        } else {
            out.push(c);
        }
    }
    out
}
