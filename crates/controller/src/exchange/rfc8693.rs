//! RFC 8693 OAuth2 Token Exchange driver (first-class, default).
//!
//! `subject_token` = SA-JWT, `subject_token_type` = `...:jwt`. General-purpose, works with
//! Keycloak/Authentik and the like. Form building is split out as a pure function for testing;
//! only the transport is async.

use async_trait::async_trait;

use oidc_bridge_common::config::{Rfc8693Config, SUBJECT_TOKEN_TYPE_JWT};

use super::{ExchangeDriver, ExchangeError, ExchangeOutput, TokenResponse};

pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

pub struct Rfc8693Driver {
    cfg: Rfc8693Config,
    audience: Option<String>,
    scope: Option<String>,
    http: reqwest::Client,
}

impl Rfc8693Driver {
    pub fn new(
        cfg: Rfc8693Config,
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

/// Build the exchange request form parameters (pure). Takes the effective audience/scope
/// with binding overrides already applied.
pub fn build_form(
    cfg: &Rfc8693Config,
    audience: Option<&str>,
    scope: Option<&str>,
    subject_token: &str,
) -> Vec<(&'static str, String)> {
    let mut form = vec![
        ("grant_type", GRANT_TYPE.to_string()),
        ("subject_token", subject_token.to_string()),
        ("subject_token_type", SUBJECT_TOKEN_TYPE_JWT.to_string()),
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
    if let Some(r) = &cfg.resource {
        form.push(("resource", r.clone()));
    }
    if let Some(rtt) = &cfg.requested_token_type {
        form.push(("requested_token_type", rtt.clone()));
    }
    form
}

#[async_trait]
impl ExchangeDriver for Rfc8693Driver {
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg(endpoint: &str) -> Rfc8693Config {
        Rfc8693Config {
            token_endpoint: endpoint.to_string(),
            client_id: "oidc-bridge".to_string(),
            client_secret: Some("s3cr3t".to_string()),
            audience: Some("aistor".to_string()),
            scope: Some("openid aistor".to_string()),
            resource: None,
            requested_token_type: None,
        }
    }

    #[test]
    fn form_contains_mandatory_params() {
        let form = build_form(&cfg("https://x/token"), None, None, "SA.JWT.TOKEN");
        let map: std::collections::HashMap<_, _> = form.iter().cloned().collect();
        assert_eq!(map["grant_type"], GRANT_TYPE);
        assert_eq!(map["subject_token"], "SA.JWT.TOKEN");
        assert_eq!(map["subject_token_type"], SUBJECT_TOKEN_TYPE_JWT);
        assert_eq!(map["client_id"], "oidc-bridge");
        assert_eq!(map["client_secret"], "s3cr3t");
        assert_eq!(map["audience"], "aistor");
        assert_eq!(map["scope"], "openid aistor");
    }

    #[test]
    fn override_audience_and_scope_win() {
        let form = build_form(&cfg("https://x/token"), Some("other"), Some("s2"), "t");
        let map: std::collections::HashMap<_, _> = form.iter().cloned().collect();
        assert_eq!(map["audience"], "other");
        assert_eq!(map["scope"], "s2");
    }

    #[test]
    fn omits_client_secret_when_absent() {
        let mut c = cfg("https://x/token");
        c.client_secret = None;
        let form = build_form(&c, None, None, "t");
        assert!(!form.iter().any(|(k, _)| *k == "client_secret"));
    }

    #[tokio::test]
    async fn exchange_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "UPSTREAM.JWT",
                "expires_in": 3600,
                "token_type": "Bearer",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
            })))
            .mount(&server)
            .await;

        let driver = Rfc8693Driver::new(
            cfg(&format!("{}/token", server.uri())),
            None,
            None,
            reqwest::Client::new(),
        );
        let out = driver.exchange("SA.JWT").await.unwrap();
        let ExchangeOutput::Token(t) = out else {
            panic!("expected token output")
        };
        assert_eq!(t.access_token, "UPSTREAM.JWT");
        assert_eq!(t.expires_in, Some(3600));
    }

    #[tokio::test]
    async fn exchange_upstream_error_is_surfaced() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_string("invalid_grant"))
            .mount(&server)
            .await;
        let driver = Rfc8693Driver::new(
            cfg(&format!("{}/token", server.uri())),
            None,
            None,
            reqwest::Client::new(),
        );
        let err = driver.exchange("SA.JWT").await.unwrap_err();
        match err {
            ExchangeError::Upstream { status, body } => {
                assert_eq!(status, 400);
                assert!(body.contains("invalid_grant"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn exchange_malformed_json() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;
        let driver = Rfc8693Driver::new(
            cfg(&format!("{}/token", server.uri())),
            None,
            None,
            reqwest::Client::new(),
        );
        assert!(matches!(
            driver.exchange("t").await.unwrap_err(),
            ExchangeError::Malformed(_)
        ));
    }
}
