//! controller boundary errors.

use thiserror::Error;

use crate::exchange::ExchangeError;

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("kube api error: {0}")]
    Kube(#[from] kube::Error),

    #[error("token request failed: {0}")]
    TokenRequest(String),

    #[error("exchange failed: {0}")]
    Exchange(#[from] ExchangeError),

    #[error("provider config error: {0}")]
    Config(#[from] oidc_bridge_common::Error),

    #[error("missing object field: {0}")]
    MissingField(&'static str),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
