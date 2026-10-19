//! `client_assertion` (RFC 7523 M2M) exchange driver.
//!
//! Authentik M2M → AIStor path: a `grant_type=client_credentials` flow that submits the
//! SA-JWT as the `client_assertion`. The upstream (Authentik) accepts only the
//! client_assertion (a signed SA-JWT) as client authentication, so there is no
//! client_secret. The output is usually an OIDC `id_token` (the WebIdentityToken for
//! AIStor web-identity); `tokenField` can also select `access_token`. Form building is
//! split out as a pure function for testing.

use async_trait::async_trait;

use oidc_bridge_common::config::{ClientAssertionConfig, TokenField};

use super::{ExchangeDriver, ExchangeError, ExchangeOutput, ExchangedToken, TokenResponse};

pub const GRANT_TYPE: &str = "client_credentials";
pub const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

pub struct ClientAssertionDriver {
    cfg: ClientAssertionConfig,
    scope: Option<String>,
    http: reqwest::Client,
}

impl ClientAssertionDriver {
    pub fn new(cfg: ClientAssertionConfig, scope: Option<String>, http: reqwest::Client) -> Self {
        Self { cfg, scope, http }
    }
}

/// Exchange request form parameters (pure). `assertion` = SA-JWT. The binding override scope wins.
pub fn build_form(
    cfg: &ClientAssertionConfig,
    scope: Option<&str>,
    assertion: &str,
) -> Vec<(&'static str, String)> {
    let mut form = vec![
        ("grant_type", GRANT_TYPE.to_string()),
        ("client_assertion_type", CLIENT_ASSERTION_TYPE.to_string()),
        ("client_assertion", assertion.to_string()),
        ("client_id", cfg.client_id.clone()),
    ];
    if let Some(s) = scope.or(cfg.scope.as_deref()) {
        form.push(("scope", s.to_string()));
    }
    form
}

/// Extract the token pointed to by `tokenField` from the response (pure). Errors if `id_token` is empty.
pub fn pick_token(resp: TokenResponse, field: TokenField) -> Result<ExchangedToken, ExchangeError> {
    let access_token = match field {
        TokenField::IdToken => resp
            .id_token
            .ok_or_else(|| ExchangeError::Malformed("response missing id_token".to_string()))?,
        TokenField::AccessToken => resp.access_token,
    };
    Ok(ExchangedToken {
        access_token,
        expires_in: resp.expires_in,
        token_type: resp.token_type,
        issued_token_type: resp.issued_token_type,
    })
}

#[async_trait]
impl ExchangeDriver for ClientAssertionDriver {
    async fn exchange(&self, subject_token: &str) -> Result<ExchangeOutput, ExchangeError> {
        let form = build_form(&self.cfg, self.scope.as_deref(), subject_token);
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
        Ok(ExchangeOutput::Token(pick_token(
            parsed,
            self.cfg.token_field,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg(endpoint: &str, token_field: TokenField) -> ClientAssertionConfig {
        ClientAssertionConfig {
            token_endpoint: endpoint.to_string(),
            client_id: "aistor".to_string(),
            scope: Some("openid aistor".to_string()),
            token_field,
        }
    }

    #[test]
    fn form_uses_client_credentials_and_assertion() {
        let form = build_form(&cfg("https://x/token", TokenField::IdToken), None, "SA.JWT");
        let map: std::collections::HashMap<_, _> = form.iter().cloned().collect();
        assert_eq!(map["grant_type"], GRANT_TYPE);
        assert_eq!(map["client_assertion_type"], CLIENT_ASSERTION_TYPE);
        assert_eq!(map["client_assertion"], "SA.JWT");
        assert_eq!(map["client_id"], "aistor");
        assert_eq!(map["scope"], "openid aistor");
        // client_secret is not sent (client_assertion is the authentication method).
        assert!(!form.iter().any(|(k, _)| *k == "client_secret"));
    }

    #[test]
    fn scope_override_wins() {
        let form = build_form(
            &cfg("https://x/token", TokenField::IdToken),
            Some("s2"),
            "t",
        );
        let map: std::collections::HashMap<_, _> = form.iter().cloned().collect();
        assert_eq!(map["scope"], "s2");
    }

    fn resp(id: Option<&str>, access: &str) -> TokenResponse {
        serde_json::from_value(serde_json::json!({
            "access_token": access,
            "id_token": id,
            "expires_in": 3600,
        }))
        .unwrap()
    }

    #[test]
    fn pick_defaults_to_id_token() {
        let t = pick_token(resp(Some("ID.JWT"), "ACC.JWT"), TokenField::IdToken).unwrap();
        assert_eq!(t.access_token, "ID.JWT");
        assert_eq!(t.expires_in, Some(3600));
    }

    #[test]
    fn pick_access_token_override() {
        let t = pick_token(resp(Some("ID.JWT"), "ACC.JWT"), TokenField::AccessToken).unwrap();
        assert_eq!(t.access_token, "ACC.JWT");
    }

    #[test]
    fn missing_id_token_is_malformed() {
        let err = pick_token(resp(None, "ACC.JWT"), TokenField::IdToken).unwrap_err();
        assert!(matches!(err, ExchangeError::Malformed(_)));
    }

    #[tokio::test]
    async fn exchange_extracts_id_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("client_assertion=SA.JWT"))
            .and(body_string_contains("grant_type=client_credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ACCESS.JWT",
                "id_token": "AUTHENTIK.ID.JWT",
                "expires_in": 300,
                "token_type": "Bearer"
            })))
            .mount(&server)
            .await;
        let driver = ClientAssertionDriver::new(
            cfg(&format!("{}/token", server.uri()), TokenField::IdToken),
            None,
            reqwest::Client::new(),
        );
        let out = driver.exchange("SA.JWT").await.unwrap();
        let ExchangeOutput::Token(t) = out else {
            panic!("expected token output")
        };
        assert_eq!(t.access_token, "AUTHENTIK.ID.JWT");
        assert_eq!(t.expires_in, Some(300));
    }

    #[tokio::test]
    async fn exchange_surfaces_upstream_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(401).set_body_string("invalid_client"))
            .mount(&server)
            .await;
        let driver = ClientAssertionDriver::new(
            cfg(&format!("{}/token", server.uri()), TokenField::IdToken),
            None,
            reqwest::Client::new(),
        );
        assert!(matches!(
            driver.exchange("SA.JWT").await.unwrap_err(),
            ExchangeError::Upstream { status: 401, .. }
        ));
    }
}
