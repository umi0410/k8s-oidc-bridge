//! Issue the input token for the target SA via the TokenRequest API (spec §4.4).
//!
//! Obtains an SA JWT for the audience the upstream requires, used as the exchange's
//! `subject_token`. This permission (`serviceaccounts/token` create) is a cluster-takeover
//! primitive, so it is scoped with `resourceNames` in the Helm RBAC.

use k8s_openapi::api::authentication::v1::TokenRequest;
use k8s_openapi::api::core::v1::ServiceAccount;
use kube::api::PostParams;
use kube::{Api, Client};

use crate::error::ControllerError;

/// Lifetime (seconds) of the SA token used as the exchange subject token. A short value, enough for a single exchange.
pub const SUBJECT_TOKEN_TTL_SECONDS: i64 = 600;

/// TokenRequest body (pure). The subresource POST requires apiVersion/kind.
pub fn build_token_request_body(audience: &str, expiration_seconds: i64) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": {
            "audiences": [audience],
            "expirationSeconds": expiration_seconds,
        }
    })
}

/// Issue a token for the target SA. Returns (jwt, expiry time in RFC3339).
pub async fn request_sa_token(
    client: &Client,
    namespace: &str,
    service_account: &str,
    audience: &str,
) -> Result<(String, String), ControllerError> {
    let api: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
    let body = build_token_request_body(audience, SUBJECT_TOKEN_TTL_SECONDS);
    let tr: TokenRequest = api
        .create_subresource("token", service_account, &PostParams::default(), &body)
        .await?;

    let status = tr
        .status
        .ok_or_else(|| ControllerError::TokenRequest("response had no status".to_string()))?;
    let token = status
        .token
        .ok_or_else(|| ControllerError::TokenRequest("response had no token".to_string()))?;
    let expiry = status
        .expiration_timestamp
        .map(|t| t.0.to_string())
        .ok_or_else(|| ControllerError::TokenRequest("response had no expiration".to_string()))?;
    Ok((token, expiry))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_has_audience_and_expiration() {
        let b = build_token_request_body("aistor", 600);
        assert_eq!(b["apiVersion"], "authentication.k8s.io/v1");
        assert_eq!(b["kind"], "TokenRequest");
        assert_eq!(b["spec"]["audiences"][0], "aistor");
        assert_eq!(b["spec"]["expirationSeconds"], 600);
    }
}
