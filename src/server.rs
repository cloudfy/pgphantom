use crate::config::{Config, TlsConfig};
use crate::errors::PgPhantomError;
use crate::proxy::{handle_connection, ProxyContext};
use crate::routing::RouteResolver;
use rustls::ServerConfig;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Build a `ProxyContext` from the loaded config, constructing the TLS acceptor and
/// route resolver. Shared via `Arc` across all connection tasks.
pub fn build_context(config: Arc<Config>) -> Result<Arc<ProxyContext>, PgPhantomError> {
    let tls_acceptor = if config.listen.tls.enabled {
        Some(build_tls_acceptor(&config.listen.tls)?)
    } else {
        None
    };

    let resolver = Arc::new(RouteResolver::new(config.routing.clone())?);

    let jwt_validator = if let crate::config::AuthMode::Jwt = config.auth.mode {
        let jwt_cfg = config
            .auth
            .jwt
            .as_ref()
            .ok_or_else(|| {
                PgPhantomError::Config(crate::errors::ConfigError::Validation(
                    "auth.mode=jwt but no [auth.jwt] section configured".into(),
                ))
            })?;
        Some(Arc::new(crate::auth::jwt::JwkValidator::new(
            jwt_cfg.clone(),
        )))
    } else {
        None
    };

    Ok(Arc::new(ProxyContext {
        config,
        resolver,
        tls_acceptor,
        jwt_validator,
    }))
}

/// TCP accept loop — runs until cancelled.
pub async fn run(ctx: Arc<ProxyContext>) -> Result<(), PgPhantomError> {
    let bind_addr = format!(
        "{}:{}",
        ctx.config.listen.host, ctx.config.listen.port
    );

    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(PgPhantomError::Io)?;

    tracing::info!(addr = %bind_addr, "pgphantom listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!(error = %e, "accept error");
                // Brief back-off to avoid spinning on transient errors.
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        tracing::debug!(peer = %peer, "accepted TCP connection");
        let ctx_clone = Arc::clone(&ctx);
        tokio::spawn(handle_connection(stream, ctx_clone));
    }
}

// ---------------------------------------------------------------------------
// TLS acceptor construction
// ---------------------------------------------------------------------------

fn build_tls_acceptor(tls_cfg: &TlsConfig) -> Result<TlsAcceptor, PgPhantomError> {
    let cert_path = tls_cfg.cert_file.as_deref().ok_or_else(|| {
        PgPhantomError::Config(crate::errors::ConfigError::Validation(
            "listen.tls.cert_file is required when TLS is enabled".into(),
        ))
    })?;
    let key_path = tls_cfg.key_file.as_deref().ok_or_else(|| {
        PgPhantomError::Config(crate::errors::ConfigError::Validation(
            "listen.tls.key_file is required when TLS is enabled".into(),
        ))
    })?;

    let certs = load_certs(Path::new(cert_path))?;
    let key = load_private_key(Path::new(key_path))?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            PgPhantomError::Config(crate::errors::ConfigError::Tls(e.to_string()))
        })?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, PgPhantomError> {
    let cert_file = std::fs::File::open(path).map_err(PgPhantomError::Io)?;
    let mut reader = std::io::BufReader::new(cert_file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            PgPhantomError::Config(crate::errors::ConfigError::Tls(format!(
                "failed to load cert {}: {e}",
                path.display()
            )))
        })
}

fn load_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>, PgPhantomError> {
    let key_file = std::fs::File::open(path).map_err(PgPhantomError::Io)?;
    let mut reader = std::io::BufReader::new(key_file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| {
            PgPhantomError::Config(crate::errors::ConfigError::Tls(format!(
                "failed to load key {}: {e}",
                path.display()
            )))
        })?
        .ok_or_else(|| {
            PgPhantomError::Config(crate::errors::ConfigError::Tls(format!(
                "no private key found in {}",
                path.display()
            )))
        })
}
