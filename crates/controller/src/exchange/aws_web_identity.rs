//! AWS STS `AssumeRoleWithWebIdentity` driver (spec §4.3).
//!
//! The output is AWS temporary credentials rather than an upstream OIDC token, so the
//! projection contract (§4.6) differs (an AWS credentials file instead of a token file).
//! The web-identity call requires no signing.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use oidc_bridge_common::config::AwsWebIdentityConfig;

use super::{AwsCredentials, ExchangeDriver, ExchangeError, ExchangeOutput};

pub const ACTION: &str = "AssumeRoleWithWebIdentity";
pub const VERSION: &str = "2011-06-15";
pub const DEFAULT_STS_ENDPOINT: &str = "https://sts.amazonaws.com";

pub struct AwsWebIdentityDriver {
    cfg: AwsWebIdentityConfig,
    session_name: String,
    http: reqwest::Client,
}

impl AwsWebIdentityDriver {
    pub fn new(cfg: AwsWebIdentityConfig, session_name: &str, http: reqwest::Client) -> Self {
        Self {
            cfg,
            session_name: sanitize_session_name(session_name),
            http,
        }
    }

    pub fn endpoint(&self) -> &str {
        self.cfg
            .sts_endpoint
            .as_deref()
            .unwrap_or(DEFAULT_STS_ENDPOINT)
    }
}

/// Normalize to satisfy the RoleSessionName constraint (`[\w+=,.@-]{2,64}`).
fn sanitize_session_name(input: &str) -> String {
    let mapped: String = input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "+=,.@-_".contains(c) {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    if mapped.len() < 2 {
        "oidc-bridge-session".to_string()
    } else {
        mapped
    }
}

/// `AssumeRoleWithWebIdentity` form/query parameters (pure).
pub fn build_query(
    cfg: &AwsWebIdentityConfig,
    web_identity_token: &str,
    session_name: &str,
) -> Vec<(&'static str, String)> {
    let mut q = vec![
        ("Action", ACTION.to_string()),
        ("Version", VERSION.to_string()),
        ("RoleArn", cfg.role_arn.clone()),
        ("RoleSessionName", session_name.to_string()),
        ("WebIdentityToken", web_identity_token.to_string()),
    ];
    if let Some(d) = cfg.duration_seconds {
        q.push(("DurationSeconds", d.to_string()));
    }
    q
}

#[derive(Debug, Deserialize)]
#[serde(rename = "AssumeRoleWithWebIdentityResponse")]
struct StsResponse {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    result: StsResult,
}

#[derive(Debug, Deserialize)]
struct StsResult {
    #[serde(rename = "Credentials")]
    credentials: StsCredentials,
}

#[derive(Debug, Deserialize)]
struct StsCredentials {
    #[serde(rename = "AccessKeyId")]
    access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: String,
    #[serde(rename = "SessionToken")]
    session_token: String,
    #[serde(rename = "Expiration")]
    expiration: String,
}

/// Parse an STS XML response into AwsCredentials (pure).
pub fn parse_sts_response(xml: &str) -> Result<AwsCredentials, ExchangeError> {
    let parsed: StsResponse =
        quick_xml::de::from_str(xml).map_err(|e| ExchangeError::Malformed(e.to_string()))?;
    let c = parsed.result.credentials;
    let expiration = DateTime::parse_from_rfc3339(&c.expiration)
        .map_err(|e| ExchangeError::Malformed(format!("bad Expiration: {e}")))?
        .with_timezone(&Utc);
    Ok(AwsCredentials {
        access_key_id: c.access_key_id,
        secret_access_key: c.secret_access_key,
        session_token: c.session_token,
        expiration,
    })
}

#[async_trait]
impl ExchangeDriver for AwsWebIdentityDriver {
    async fn exchange(&self, subject_token: &str) -> Result<ExchangeOutput, ExchangeError> {
        let form = build_query(&self.cfg, subject_token, &self.session_name);
        let resp = self.http.post(self.endpoint()).form(&form).send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            return Err(ExchangeError::Upstream {
                status: status.as_u16(),
                body,
            });
        }
        Ok(ExchangeOutput::Aws(parse_sts_response(&body)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg(endpoint: Option<&str>) -> AwsWebIdentityConfig {
        AwsWebIdentityConfig {
            role_arn: "arn:aws:iam::123456789012:role/app".to_string(),
            region: Some("us-east-1".to_string()),
            sts_endpoint: endpoint.map(String::from),
            duration_seconds: Some(3600),
        }
    }

    const STS_XML: &str = r#"<?xml version="1.0"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
      <SecretAccessKey>secretkey123</SecretAccessKey>
      <SessionToken>sessiontoken456</SessionToken>
      <Expiration>2026-01-01T00:00:00Z</Expiration>
    </Credentials>
    <SubjectFromWebIdentityToken>system:serviceaccount:apps:sa</SubjectFromWebIdentityToken>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>req-1</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>"#;

    #[test]
    fn query_has_required_params() {
        let q = build_query(&cfg(None), "WEB.IDENTITY.JWT", "oidc-bridge-sa");
        let map: std::collections::HashMap<_, _> = q.iter().cloned().collect();
        assert_eq!(map["Action"], ACTION);
        assert_eq!(map["Version"], VERSION);
        assert_eq!(map["RoleArn"], "arn:aws:iam::123456789012:role/app");
        assert_eq!(map["RoleSessionName"], "oidc-bridge-sa");
        assert_eq!(map["WebIdentityToken"], "WEB.IDENTITY.JWT");
        assert_eq!(map["DurationSeconds"], "3600");
    }

    #[test]
    fn endpoint_defaults_to_global_sts() {
        let d = AwsWebIdentityDriver::new(cfg(None), "sa", reqwest::Client::new());
        assert_eq!(d.endpoint(), DEFAULT_STS_ENDPOINT);
    }

    #[test]
    fn session_name_is_sanitized() {
        assert_eq!(sanitize_session_name("apps/sa:1"), "apps-sa-1");
        assert_eq!(sanitize_session_name("a"), "oidc-bridge-session");
        assert_eq!(sanitize_session_name(&"x".repeat(100)).len(), 64);
    }

    #[test]
    fn parses_sts_xml() {
        let c = parse_sts_response(STS_XML).unwrap();
        assert_eq!(c.access_key_id, "ASIAEXAMPLE");
        assert_eq!(c.secret_access_key, "secretkey123");
        assert_eq!(c.session_token, "sessiontoken456");
        assert_eq!(
            c.expiration,
            DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z").unwrap()
        );
    }

    #[test]
    fn credentials_ini_format() {
        let c = AwsCredentials {
            access_key_id: "AK".to_string(),
            secret_access_key: "SK".to_string(),
            session_token: "ST".to_string(),
            expiration: Utc::now(),
        };
        let ini = c.to_credentials_ini();
        assert!(ini.contains("[default]"));
        assert!(ini.contains("aws_access_key_id = AK"));
        assert!(ini.contains("aws_session_token = ST"));
    }

    #[test]
    fn malformed_xml_errors() {
        assert!(matches!(
            parse_sts_response("<nope/>").unwrap_err(),
            ExchangeError::Malformed(_)
        ));
    }

    #[tokio::test]
    async fn exchange_returns_aws_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(STS_XML))
            .mount(&server)
            .await;
        let d = AwsWebIdentityDriver::new(cfg(Some(&server.uri())), "sa", reqwest::Client::new());
        let out = d.exchange("WEB.IDENTITY.JWT").await.unwrap();
        let ExchangeOutput::Aws(c) = out else {
            panic!("expected aws output")
        };
        assert_eq!(c.access_key_id, "ASIAEXAMPLE");
    }

    #[tokio::test]
    async fn exchange_surfaces_sts_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(403).set_body_string("AccessDenied"))
            .mount(&server)
            .await;
        let d = AwsWebIdentityDriver::new(cfg(Some(&server.uri())), "sa", reqwest::Client::new());
        assert!(matches!(
            d.exchange("t").await.unwrap_err(),
            ExchangeError::Upstream { status: 403, .. }
        ));
    }
}
