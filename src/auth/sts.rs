use crate::config::StsConfig;
use crate::errors::AuthError;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Token exchange request (RFC 8693).
#[derive(Debug, Serialize)]
struct TokenExchangeRequest<'a> {
    grant_type: &'a str,
    subject_token: &'a str,
    subject_token_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<&'a str>,
    client_id: &'a str,
    client_secret: &'a str,
}

/// Successful token exchange response.
#[derive(Debug, Deserialize)]
struct TokenExchangeResponse {
    access_token: String,
    #[serde(rename = "issued_token_type")]
    _issued_token_type: Option<String>,
}

/// Exchange `subject_token` for a new access token using the configured STS endpoint.
///
/// Uses RFC 8693 `urn:ietf:params:oauth:grant-type:token-exchange`.
pub async fn exchange_token(
    config: &StsConfig,
    subject_token: &str,
) -> Result<String, AuthError> {
    let client_secret = std::env::var(&config.client_secret_env).map_err(|_| {
        AuthError::StsExchange(format!(
            "env var {:?} not set (required for STS client secret)",
            config.client_secret_env
        ))
    })?;

    let http = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| AuthError::StsExchange(format!("failed to build HTTP client: {e}")))?;

    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("subject_token", subject_token),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("client_id", &config.client_id),
        ("client_secret", &client_secret),
    ];

    // Append audience if configured.
    let aud_param;
    let mut all_params: Vec<(&str, &str)> = params.to_vec();
    if let Some(aud) = &config.audience {
        aud_param = aud.clone();
        all_params.push(("audience", &aud_param));
    }

    let response = http
        .post(&config.token_endpoint)
        .form(&all_params)
        .send()
        .await
        .map_err(|e| AuthError::StsExchange(format!("request failed: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(AuthError::StsExchange(format!(
            "STS returned HTTP {status}: {body}"
        )));
    }

    let token_resp: TokenExchangeResponse = response
        .json()
        .await
        .map_err(|e| AuthError::StsExchange(format!("response parse failed: {e}")))?;

    Ok(token_resp.access_token)
}
