//! `urn:ietf:params:oauth:grant-type:jwt-bearer` driver.
//!
//! An OAuth2 token-endpoint path that sends the SA-JWT as the `assertion`. Response handling
//! is identical to RFC 8693 (JSON access_token).

use async_trait::async_trait;

use oidc_bridge_common::config::JwtBearerConfig;

use super::{ExchangeDriver, ExchangeError, ExchangeOutput, TokenResponse};

pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

pub struct JwtBearerDriver {
    cfg: JwtBearerConfig,
    audience: Option<String>,
    scope: Option<String>,
    http: reqwest::Client,
}

impl JwtBearerDriver {
    pub fn new(
        cfg: JwtBearerConfig,
        audience: Option<String>,
        scope: Option<String>,
        http: reqwest::Client,
    ) -> Self {
        Self {
            cfg,
            audience,
            scope,
            http,
        }
    }
}

/// jwt-bearer form parameters (pure).
pub fn build_form(
    cfg: &JwtBearerConfig,
    audience: Option<&str>,
    scope: Option<&str>,
    assertion: &str,
) -> Vec<(&'static str, String)> {
    let mut form = vec![
        ("grant_type", GRANT_TYPE.to_string()),
        ("assertion", assertion.to_string()),
        ("client_id", cfg.client_id.clone()),
    ];
    if let Some(s) = &cfg.client_secret {
        form.push(("client_secret", s.clone()));
    }
    if let Some(a) = audience.or(cfg.audience.as_deref()) {
        form.push(("audience", a.to_string()));
    }
    if let Some(s) = scope.or(cfg.scope.as_deref()) {
        form.push(("scope", s.to_string()));
    }
    form
}

#[async_trait]
impl ExchangeDriver for JwtBearerDriver {
    async fn exchange(&self, subject_token: &str) -> Result<ExchangeOutput, ExchangeError> {
        let form = build_form(
            &self.cfg,
            self.audience.as_deref(),
            self.scope.as_deref(),
            subject_token,
        );
        let resp = self
            .http
            .post(&self.cfg.token_endpoint)
            .form(&form)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            return Err(ExchangeError::Upstream {
                status: status.as_u16(),
                body,
            });
        }
        let parsed: TokenResponse =
            serde_json::from_str(&body).map_err(|e| ExchangeError::Malformed(e.to_string()))?;
        Ok(ExchangeOutput::Token(parsed.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> JwtBearerConfig {
        JwtBearerConfig {
            token_endpoint: "https://idp/token".to_string(),
            client_id: "cid".to_string(),
            client_secret: None,
            scope: Some("openid".to_string()),
            audience: None,
        }
    }

    #[test]
    fn form_uses_jwt_bearer_grant_and_assertion() {
        let form = build_form(&cfg(), None, None, "SA.JWT");
        let map: std::collections::HashMap<_, _> = form.iter().cloned().collect();
        assert_eq!(map["grant_type"], GRANT_TYPE);
        assert_eq!(map["assertion"], "SA.JWT");
        assert_eq!(map["client_id"], "cid");
        assert_eq!(map["scope"], "openid");
        assert!(!form.iter().any(|(k, _)| *k == "client_secret"));
    }
}
