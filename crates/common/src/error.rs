//! Library-boundary error type.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("secret reference {reference:?} is malformed: {reason}")]
    MalformedSecretRef { reference: String, reason: String },

    #[error("secret {secret:?} not found for reference {reference:?}")]
    SecretNotFound { secret: String, reference: String },

    #[error("key {key:?} not found in secret {secret:?}")]
    SecretKeyNotFound { secret: String, key: String },

    #[error("provider {0:?} not found in provider config")]
    ProviderNotFound(String),

    #[error("failed to parse provider config: {0}")]
    ConfigParse(String),

    #[error("invalid renew configuration: {0}")]
    InvalidRenew(String),

    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
