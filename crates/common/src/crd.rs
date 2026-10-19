//! `TokenBinding` CRD (group `bridge.oidc.io`, namespaced, status subresource).
//!
//! Why only the binding is a CRD: provider definitions are kept in ConfigMap+Secret (§4.2),
//! but a ConfigMap has nowhere to hold status (§4.5).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::backoff::BackoffConfig;
use crate::projection::ProjectionSpec;
use crate::renew::DEFAULT_THRESHOLD_PERCENT;
use crate::status::Condition;

#[derive(CustomResource, Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "bridge.oidc.io",
    version = "v1alpha1",
    kind = "TokenBinding",
    namespaced,
    status = "TokenBindingStatus",
    shortname = "tbind",
    printcolumn = r#"{"name":"Provider","type":"string","jsonPath":".spec.providerRef"}"#,
    printcolumn = r#"{"name":"SA","type":"string","jsonPath":".spec.serviceAccountName"}"#,
    printcolumn = r#"{"name":"NextRenew","type":"string","jsonPath":".status.nextRenewTime"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct TokenBindingSpec {
    /// SA to exchange (same ns). The controller issues this SA's token via TokenRequest.
    pub service_account_name: String,
    /// Provider key in the provider ConfigMap.
    pub provider_ref: String,
    /// audience override (defaults to the provider's when unset).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// scope override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default)]
    pub renew: RenewSpec,
    #[serde(default)]
    pub projection: ProjectionSpec,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RenewSpec {
    /// Proactive renewal threshold (%). Default 50%.
    #[serde(default = "default_threshold")]
    pub threshold_percent: u32,
    #[serde(default)]
    pub backoff: BackoffConfig,
}

fn default_threshold() -> u32 {
    DEFAULT_THRESHOLD_PERCENT
}

impl Default for RenewSpec {
    fn default() -> Self {
        Self {
            threshold_percent: DEFAULT_THRESHOLD_PERCENT,
            backoff: BackoffConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TokenBindingStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_renew_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_renew_time: Option<String>,
    #[serde(default)]
    pub renew_failures: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_secret_name: Option<String>,
}

impl TokenBinding {
    /// Name of the binding-owned **source** Secret (= `oidc-bridge-src-<name>`).
    ///
    /// The single source of truth for the token the controller exchanged; it has the
    /// TokenBinding as its ownerReference. The Secret actually projected into pods is a
    /// per-pod copy owned by the pod (spec §4.6), created by the controller under the
    /// name the webhook chose (see `podbinding`).
    pub fn source_secret_name(&self) -> String {
        format!(
            "{}-src-{}",
            crate::PREFIX,
            self.metadata.name.as_deref().unwrap_or("unknown")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_deserializes_with_defaults() {
        let yaml = r#"
serviceAccountName: aistor-k8s-client
providerRef: authentik
"#;
        let spec: TokenBindingSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.service_account_name, "aistor-k8s-client");
        assert_eq!(spec.renew.threshold_percent, 50);
        assert_eq!(spec.renew.backoff.cap_seconds, 300);
        assert_eq!(
            spec.projection.token_file_path,
            crate::projection::DEFAULT_TOKEN_FILE_PATH
        );
    }

    #[test]
    fn spec_roundtrips_overrides() {
        let yaml = r#"
serviceAccountName: sa
providerRef: p
audience: aistor
scope: "openid aistor"
renew:
  thresholdPercent: 70
  backoff: { baseSeconds: 2, capSeconds: 60, jitter: false }
projection:
  tokenFilePath: /var/run/secrets/oidc-bridge/token
  env:
    - name: AWS_WEB_IDENTITY_TOKEN_FILE
      valueFromTokenFile: true
"#;
        let spec: TokenBindingSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.audience.as_deref(), Some("aistor"));
        assert_eq!(spec.renew.threshold_percent, 70);
        assert_eq!(spec.renew.backoff.base_seconds, 2);
        assert!(!spec.renew.backoff.jitter);
        assert_eq!(spec.projection.env.len(), 1);
    }

    #[test]
    fn crd_can_be_generated() {
        // Whether the kube derive can produce a CustomResourceDefinition (schema included).
        use kube::CustomResourceExt;
        let crd = TokenBinding::crd();
        assert_eq!(crd.spec.group, "bridge.oidc.io");
        assert_eq!(crd.spec.names.kind, "TokenBinding");
    }

    #[test]
    fn projection_secret_name_derivation() {
        let tb = TokenBinding::new(
            "aistor",
            TokenBindingSpec {
                service_account_name: "sa".to_string(),
                provider_ref: "authentik".to_string(),
                audience: None,
                scope: None,
                renew: RenewSpec::default(),
                projection: ProjectionSpec::default(),
            },
        );
        assert_eq!(tb.source_secret_name(), "oidc-bridge-src-aistor");
    }
}
