use crate::config::JwtConfig;
use crate::errors::AuthError;
use dashmap::DashMap;
use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet},
    DecodingKey, Validation,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

/// Minimal JWT claims that PgPhantom cares about.
#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub iss: Option<String>,
    pub aud: Option<serde_json::Value>,
    pub sub: Option<String>,
    pub exp: Option<u64>,
    /// All remaining claims are available for username extraction.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Claims {
    /// Get the value of a claim by name.
    pub fn get_claim_str(&self, name: &str) -> Option<String> {
        match name {
            "sub" => self.sub.clone(),
            "iss" => self.iss.clone(),
            other => self
                .extra
                .get(other)
                .and_then(|v| v.as_str().map(str::to_string)),
        }
    }
}

// ---------------------------------------------------------------------------
// JWKS cache
// ---------------------------------------------------------------------------

struct CachedJwks {
    set: JwkSet,
    fetched_at: Instant,
}

/// Thread-safe JWKS cache + JWT validator.
///
/// Fetches the JWKS on first use and automatically refreshes it after
/// `refresh_interval_secs`.
pub struct JwkValidator {
    config: JwtConfig,
    http: reqwest::Client,
    cache: Arc<RwLock<Option<CachedJwks>>>,
}

impl JwkValidator {
    pub fn new(config: JwtConfig) -> Self {
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client for JWKS");
        Self {
            config,
            http,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Validate `token` and return its claims.
    pub async fn validate(&self, token: &str) -> Result<Claims, AuthError> {
        let jwks = self.get_jwks().await?;

        let header = decode_header(token)
            .map_err(|e| AuthError::JwtValidation(format!("header decode failed: {e}")))?;

        // Find the matching key.
        let kid = header.kid.as_deref().unwrap_or("");
        let jwk = if kid.is_empty() {
            jwks.keys.first()
        } else {
            jwks.find(kid)
        }
        .ok_or_else(|| {
            AuthError::JwtValidation(format!("no matching JWK found for kid={kid:?}"))
        })?;

        let decoding_key = DecodingKey::from_jwk(jwk)
            .map_err(|e| AuthError::JwtValidation(format!("failed to build decoding key: {e}")))?;

        let mut validation = match &jwk.algorithm {
            AlgorithmParameters::RSA(_) => Validation::new(jsonwebtoken::Algorithm::RS256),
            AlgorithmParameters::EllipticCurve(_) => {
                Validation::new(jsonwebtoken::Algorithm::ES256)
            }
            AlgorithmParameters::OctetKeyPair(_) | AlgorithmParameters::OctetKey(_) => {
                Validation::new(jsonwebtoken::Algorithm::HS256)
            }
        };
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);

        let token_data = decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|e| AuthError::JwtValidation(format!("validation failed: {e}")))?;

        Ok(token_data.claims)
    }

    async fn get_jwks(&self) -> Result<JwkSet, AuthError> {
        // Fast path: read lock — return cached if still fresh.
        {
            let guard = self.cache.read().await;
            if let Some(cached) = &*guard {
                let age = cached.fetched_at.elapsed();
                if age < Duration::from_secs(self.config.refresh_interval_secs) {
                    return Ok(cached.set.clone());
                }
            }
        }

        // Slow path: write lock — re-check then fetch.
        let mut guard = self.cache.write().await;
        if let Some(cached) = &*guard {
            let age = cached.fetched_at.elapsed();
            if age < Duration::from_secs(self.config.refresh_interval_secs) {
                return Ok(cached.set.clone());
            }
        }

        let jwks = self.fetch_jwks().await?;
        *guard = Some(CachedJwks {
            set: jwks.clone(),
            fetched_at: Instant::now(),
        });
        Ok(jwks)
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, AuthError> {
        let response = self
            .http
            .get(&self.config.jwks_uri)
            .send()
            .await
            .map_err(|e| AuthError::JwtValidation(format!("JWKS fetch failed: {e}")))?;

        if !response.status().is_success() {
            return Err(AuthError::JwtValidation(format!(
                "JWKS endpoint returned HTTP {}",
                response.status()
            )));
        }

        let jwks: JwkSet = response
            .json()
            .await
            .map_err(|e| AuthError::JwtValidation(format!("JWKS JSON parse failed: {e}")))?;

        Ok(jwks)
    }
}
