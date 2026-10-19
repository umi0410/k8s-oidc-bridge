//! Provider configuration model (spec §4.2, §4.3).
//!
//! Provider definitions live as a YAML document under each key of the ConfigMap
//! (`oidc-bridge-providers`); this is an internally-tagged enum that dispatches the
//! exchange driver by the `type` tag. Secret values are not placed in the ConfigMap
//! directly but reference a Secret via `$<secretName>:<key>`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::resolver::{resolve, SecretStore};

/// Default subject token type for RFC 8693 token exchange.
pub const SUBJECT_TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// Exchange driver config (discriminated union). Dispatched by the `type` tag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProviderConfig {
    /// OAuth2 Token Exchange — first-class, default path.
    #[serde(rename = "rfc8693")]
    Rfc8693(Rfc8693Config),
    /// `grant_type=...:jwt-bearer`.
    #[serde(rename = "oidc-jwt-bearer")]
    OidcJwtBearer(JwtBearerConfig),
    /// STS `AssumeRoleWithWebIdentity` — output is AWS temporary credentials (spec §4.6).
    #[serde(rename = "aws-web-identity")]
    AwsWebIdentity(AwsWebIdentityConfig),
    /// `client_credentials` + `client_assertion` (RFC 7523) M2M flow. Submits the
    /// SA-JWT as the client_assertion to obtain the upstream token (Authentik M2M → AIStor).
    #[serde(rename = "client-assertion")]
    ClientAssertion(ClientAssertionConfig),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rfc8693Config {
    pub token_endpoint: String,
    pub client_id: String,
    /// A literal, or a `$secret:key` reference. Finalized via [`ProviderConfig::resolve`].
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub requested_token_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtBearerConfig {
    pub token_endpoint: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
}

/// Field in the client_assertion response to use as the output token.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenField {
    /// AIStor web-identity uses the OIDC id_token as the WebIdentityToken (default).
    #[default]
    IdToken,
    AccessToken,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientAssertionConfig {
    pub token_endpoint: String,
    /// `client_id` (e.g. aistor). Client authentication is handled by the
    /// client_assertion (SA-JWT), so no client_secret is needed.
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
    /// Token field to extract from the response (default `id_token`).
    #[serde(default)]
    pub token_field: TokenField,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsWebIdentityConfig {
    pub role_arn: String,
    #[serde(default)]
    pub region: Option<String>,
    /// STS endpoint override (defaults to the global `https://sts.amazonaws.com`).
    #[serde(default)]
    pub sts_endpoint: Option<String>,
    #[serde(default)]
    pub duration_seconds: Option<i64>,
}

impl ProviderConfig {
    /// Default audience required by the provider (the binding's override takes precedence).
    pub fn default_audience(&self) -> Option<&str> {
        match self {
            ProviderConfig::Rfc8693(c) => c.audience.as_deref(),
            ProviderConfig::OidcJwtBearer(c) => c.audience.as_deref(),
            ProviderConfig::AwsWebIdentity(_) => None,
            // The client_assertion form has no audience. The SA token's aud is set
            // via binding.audience (the token endpoint/issuer value Authentik requires).
            ProviderConfig::ClientAssertion(_) => None,
        }
    }

    /// Default scope.
    pub fn default_scope(&self) -> Option<&str> {
        match self {
            ProviderConfig::Rfc8693(c) => c.scope.as_deref(),
            ProviderConfig::OidcJwtBearer(c) => c.scope.as_deref(),
            ProviderConfig::AwsWebIdentity(_) => None,
            ProviderConfig::ClientAssertion(c) => c.scope.as_deref(),
        }
    }

    /// Returns a new config with all `$secret:key` references resolved to literals (immutable: original preserved).
    pub fn resolve(&self, store: &SecretStore) -> Result<ProviderConfig> {
        let resolve_opt = |v: &Option<String>| -> Result<Option<String>> {
            v.as_deref().map(|s| resolve(s, store)).transpose()
        };
        Ok(match self {
            ProviderConfig::Rfc8693(c) => ProviderConfig::Rfc8693(Rfc8693Config {
                client_secret: resolve_opt(&c.client_secret)?,
                ..c.clone()
            }),
            ProviderConfig::OidcJwtBearer(c) => ProviderConfig::OidcJwtBearer(JwtBearerConfig {
                client_secret: resolve_opt(&c.client_secret)?,
                ..c.clone()
            }),
            // AWS web identity / client_assertion have no client secret to resolve.
            ProviderConfig::AwsWebIdentity(c) => ProviderConfig::AwsWebIdentity(c.clone()),
            ProviderConfig::ClientAssertion(c) => ProviderConfig::ClientAssertion(c.clone()),
        })
    }
}

/// The ConfigMap's bundle of providers: key -> provider config.
#[derive(Debug, Clone, Default)]
pub struct ProviderSet(BTreeMap<String, ProviderConfig>);

impl ProviderSet {
    /// Parses from the ConfigMap `data` map (key -> YAML document string).
    ///
    /// If there is a `providers.<name>` prefix (as with ArgoCD) it is stripped;
    /// otherwise the key is used as the provider name as-is.
    pub fn from_config_map_data(data: &BTreeMap<String, String>) -> Result<Self> {
        let mut set = BTreeMap::new();
        for (raw_key, doc) in data {
            let name = raw_key.strip_prefix("providers.").unwrap_or(raw_key);
            let cfg: ProviderConfig =
                serde_yaml::from_str(doc).map_err(|e| Error::ConfigParse(e.to_string()))?;
            set.insert(name.to_string(), cfg);
        }
        Ok(ProviderSet(set))
    }

    pub fn get(&self, name: &str) -> Result<&ProviderConfig> {
        self.0
            .get(name)
            .ok_or_else(|| Error::ProviderNotFound(name.to_string()))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::SecretStore;

    const AUTHENTIK: &str = r#"
type: rfc8693
tokenEndpoint: https://auth.example/application/o/token/
clientId: oidc-bridge
clientSecret: $oidc-bridge-secret:authentik-client-secret
audience: aistor
scope: "openid aistor"
"#;

    fn secret_store() -> SecretStore {
        let mut s = SecretStore::new();
        let mut b = BTreeMap::new();
        b.insert("authentik-client-secret".to_string(), "s3cr3t".to_string());
        s.insert("oidc-bridge-secret".to_string(), b);
        s
    }

    #[test]
    fn deserializes_rfc8693_tagged_variant() {
        let cfg: ProviderConfig = serde_yaml::from_str(AUTHENTIK).unwrap();
        match &cfg {
            ProviderConfig::Rfc8693(c) => {
                assert_eq!(c.client_id, "oidc-bridge");
                assert_eq!(c.audience.as_deref(), Some("aistor"));
                assert_eq!(
                    c.client_secret.as_deref(),
                    Some("$oidc-bridge-secret:authentik-client-secret")
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn deserializes_jwt_bearer_and_aws_variants() {
        let jwt: ProviderConfig = serde_yaml::from_str(
            "type: oidc-jwt-bearer\ntokenEndpoint: https://idp/token\nclientId: x\n",
        )
        .unwrap();
        assert!(matches!(jwt, ProviderConfig::OidcJwtBearer(_)));

        let aws: ProviderConfig = serde_yaml::from_str(
            "type: aws-web-identity\nroleArn: arn:aws:iam::1:role/r\nregion: us-east-1\n",
        )
        .unwrap();
        assert!(matches!(aws, ProviderConfig::AwsWebIdentity(_)));
    }

    #[test]
    fn deserializes_client_assertion_variant() {
        let yaml = r#"
type: client-assertion
tokenEndpoint: https://auth.example/application/o/token/
clientId: aistor
scope: "openid aistor"
"#;
        let cfg: ProviderConfig = serde_yaml::from_str(yaml).unwrap();
        match &cfg {
            ProviderConfig::ClientAssertion(c) => {
                assert_eq!(c.client_id, "aistor");
                assert_eq!(c.scope.as_deref(), Some("openid aistor"));
                // tokenField defaults to id_token.
                assert_eq!(c.token_field, TokenField::IdToken);
            }
            other => panic!("wrong variant: {other:?}"),
        }
        // No default audience (set via binding.audience); scope is the provider value.
        assert_eq!(cfg.default_audience(), None);
        assert_eq!(cfg.default_scope(), Some("openid aistor"));
        // resolve is a no-op since there are no secret references.
        assert_eq!(cfg.resolve(&SecretStore::new()).unwrap(), cfg);
    }

    #[test]
    fn client_assertion_token_field_override() {
        let yaml = "type: client-assertion\ntokenEndpoint: https://idp/token\nclientId: aistor\ntokenField: access_token\n";
        let cfg: ProviderConfig = serde_yaml::from_str(yaml).unwrap();
        match cfg {
            ProviderConfig::ClientAssertion(c) => {
                assert_eq!(c.token_field, TokenField::AccessToken)
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn unknown_type_tag_fails() {
        let err = serde_yaml::from_str::<ProviderConfig>("type: nope\n");
        assert!(err.is_err());
    }

    #[test]
    fn resolve_replaces_secret_reference() {
        let cfg: ProviderConfig = serde_yaml::from_str(AUTHENTIK).unwrap();
        let resolved = cfg.resolve(&secret_store()).unwrap();
        match resolved {
            ProviderConfig::Rfc8693(c) => assert_eq!(c.client_secret.as_deref(), Some("s3cr3t")),
            _ => unreachable!(),
        }
        // The original is unchanged.
        match cfg {
            ProviderConfig::Rfc8693(c) => assert!(c.client_secret.unwrap().starts_with('$')),
            _ => unreachable!(),
        }
    }

    #[test]
    fn provider_set_parses_and_strips_prefix() {
        let mut data = BTreeMap::new();
        data.insert("providers.authentik".to_string(), AUTHENTIK.to_string());
        let set = ProviderSet::from_config_map_data(&data).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.get("authentik").is_ok());
        assert!(matches!(
            set.get("missing").unwrap_err(),
            Error::ProviderNotFound(_)
        ));
    }

    #[test]
    fn default_audience_and_scope() {
        let cfg: ProviderConfig = serde_yaml::from_str(AUTHENTIK).unwrap();
        assert_eq!(cfg.default_audience(), Some("aistor"));
        assert_eq!(cfg.default_scope(), Some("openid aistor"));
    }
}
