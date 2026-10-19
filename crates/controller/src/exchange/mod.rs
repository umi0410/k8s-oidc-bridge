//! Upstream provider exchange drivers (spec §4.3).
//!
//! The `type` tag selects the driver. All of `rfc8693` (first-class, default),
//! `oidc-jwt-bearer` (same OAuth2 token-endpoint path), `client-assertion` (RFC 7523 M2M —
//! Authentik → AIStor), and `aws-web-identity` (STS `AssumeRoleWithWebIdentity`) are implemented.

pub mod aws_web_identity;
pub mod client_assertion;
pub mod oidc_jwt_bearer;
pub mod rfc8693;

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use oidc_bridge_common::config::ProviderConfig;
use oidc_bridge_common::projection::{
    SECRET_KEY_AWS_ACCESS_KEY_ID, SECRET_KEY_AWS_SECRET_ACCESS_KEY, SECRET_KEY_AWS_SESSION_TOKEN,
    SECRET_KEY_CREDENTIALS, SECRET_KEY_TOKEN,
};

/// Exchange result (upstream OIDC access token). The AWS credentials path is separate (§4.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangedToken {
    pub access_token: String,
    /// TTL (seconds) reported by the upstream. If absent, reconcile fills it in from the JWT `exp`.
    pub expires_in: Option<i64>,
    pub token_type: Option<String>,
    pub issued_token_type: Option<String>,
}

/// STS `AssumeRoleWithWebIdentity` output: AWS temporary credentials (spec §4.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: DateTime<Utc>,
}

impl AwsCredentials {
    /// AWS shared credentials file (INI) formatted string (profile `default`).
    pub fn to_credentials_ini(&self) -> String {
        format!(
            "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\naws_session_token = {}\n",
            self.access_key_id, self.secret_access_key, self.session_token
        )
    }
}

/// Driver output. A token is projected to a token file, AWS credentials to a cred-file (§4.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeOutput {
    Token(ExchangedToken),
    Aws(AwsCredentials),
}

impl ExchangeOutput {
    /// The `data` map to place in the projection Secret.
    pub fn secret_data(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        match self {
            ExchangeOutput::Token(t) => {
                m.insert(SECRET_KEY_TOKEN.to_string(), t.access_token.clone());
            }
            ExchangeOutput::Aws(c) => {
                m.insert(
                    SECRET_KEY_AWS_ACCESS_KEY_ID.to_string(),
                    c.access_key_id.clone(),
                );
                m.insert(
                    SECRET_KEY_AWS_SECRET_ACCESS_KEY.to_string(),
                    c.secret_access_key.clone(),
                );
                m.insert(
                    SECRET_KEY_AWS_SESSION_TOKEN.to_string(),
                    c.session_token.clone(),
                );
                m.insert(SECRET_KEY_CREDENTIALS.to_string(), c.to_credentials_ini());
            }
        }
        m
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("http transport error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("upstream returned {status}: {body}")]
    Upstream { status: u16, body: String },
    #[error("malformed upstream response: {0}")]
    Malformed(String),
}

/// Common interface for exchange drivers.
#[async_trait]
pub trait ExchangeDriver: Send + Sync {
    async fn exchange(&self, subject_token: &str) -> Result<ExchangeOutput, ExchangeError>;
}

/// Token-endpoint JSON response (shared by RFC 8693 / jwt-bearer / client_assertion).
#[derive(Debug, Deserialize)]
pub(crate) struct TokenResponse {
    pub access_token: String,
    /// OIDC id_token (the field the client_assertion flow extracts).
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub issued_token_type: Option<String>,
}

impl From<TokenResponse> for ExchangedToken {
    fn from(r: TokenResponse) -> Self {
        ExchangedToken {
            access_token: r.access_token,
            expires_in: r.expires_in,
            token_type: r.token_type,
            issued_token_type: r.issued_token_type,
        }
    }
}

/// Build a driver from the provider config plus binding overrides.
///
/// `audience`/`scope` are the effective values with binding overrides already applied, and
/// `session_name` is the identifier used as the AWS RoleSessionName (usually the target SA name).
pub fn build_driver(
    cfg: &ProviderConfig,
    audience: Option<String>,
    scope: Option<String>,
    session_name: &str,
    http: reqwest::Client,
) -> Box<dyn ExchangeDriver> {
    match cfg {
        ProviderConfig::Rfc8693(c) => Box::new(rfc8693::Rfc8693Driver::new(
            c.clone(),
            audience,
            scope,
            http,
        )),
        ProviderConfig::OidcJwtBearer(c) => Box::new(oidc_jwt_bearer::JwtBearerDriver::new(
            c.clone(),
            audience,
            scope,
            http,
        )),
        ProviderConfig::AwsWebIdentity(c) => Box::new(aws_web_identity::AwsWebIdentityDriver::new(
            c.clone(),
            session_name,
            http,
        )),
        ProviderConfig::ClientAssertion(c) => Box::new(
            client_assertion::ClientAssertionDriver::new(c.clone(), scope, http),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_response_maps_to_exchanged() {
        let r = TokenResponse {
            access_token: "abc".to_string(),
            id_token: None,
            expires_in: Some(3600),
            token_type: Some("Bearer".to_string()),
            issued_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
        };
        let t: ExchangedToken = r.into();
        assert_eq!(t.access_token, "abc");
        assert_eq!(t.expires_in, Some(3600));
    }

    #[test]
    fn token_response_parses_without_optional_fields() {
        let r: TokenResponse = serde_json::from_str(r#"{"access_token":"x"}"#).unwrap();
        assert_eq!(r.access_token, "x");
        assert_eq!(r.expires_in, None);
    }
}
