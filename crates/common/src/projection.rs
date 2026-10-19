//! Pod projection contract (spec §4.6).
//!
//! Two modes:
//! - **tokenFile** (default): the upstream OIDC token via a token file +
//!   `AWS_WEB_IDENTITY_TOKEN_FILE`/`OIDC_TOKEN_FILE` env. Existing AWS/MinIO SDKs work
//!   with zero app changes.
//! - **awsCredentialsFile**: the `aws-web-identity` driver's output (AWS temporary
//!   credentials) via an AWS shared credentials file +
//!   `AWS_SHARED_CREDENTIALS_FILE`/`AWS_PROFILE` env.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Default path of the projection token file.
pub const DEFAULT_TOKEN_FILE_PATH: &str = "/var/run/secrets/oidc-bridge/token";
/// Key under which the token is stored in the projection Secret.
pub const SECRET_KEY_TOKEN: &str = "token";
/// Key holding the AWS shared credentials (INI) / mounted file name.
pub const SECRET_KEY_CREDENTIALS: &str = "credentials";
pub const AWS_CREDENTIALS_FILE_NAME: &str = "credentials";
/// Keys for individual AWS cred fields (for debugging/alternative consumption).
pub const SECRET_KEY_AWS_ACCESS_KEY_ID: &str = "AWS_ACCESS_KEY_ID";
pub const SECRET_KEY_AWS_SECRET_ACCESS_KEY: &str = "AWS_SECRET_ACCESS_KEY";
pub const SECRET_KEY_AWS_SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";
/// Name of the volume the webhook injects.
pub const VOLUME_NAME: &str = "oidc-bridge-token";

/// Projection mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ProjectionMode {
    #[default]
    TokenFile,
    AwsCredentialsFile,
}

/// Pod projection config.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionSpec {
    #[serde(default)]
    pub mode: ProjectionMode,
    #[serde(default = "default_token_file_path")]
    pub token_file_path: String,
    /// Per-consumer env override. Empty means the per-mode preset.
    #[serde(default)]
    pub env: Vec<EnvMapping>,
}

fn default_token_file_path() -> String {
    DEFAULT_TOKEN_FILE_PATH.to_string()
}

impl Default for ProjectionSpec {
    fn default() -> Self {
        Self {
            mode: ProjectionMode::default(),
            token_file_path: default_token_file_path(),
            env: Vec::new(),
        }
    }
}

/// A single env mapping. If `valueFromTokenFile=true`, the token file path is used as
/// the value; otherwise the `value` literal is used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EnvMapping {
    pub name: String,
    #[serde(default)]
    pub value_from_token_file: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// Default (IRSA-compatible) token-file env preset.
pub fn default_token_env() -> Vec<EnvMapping> {
    vec![
        EnvMapping {
            name: "AWS_WEB_IDENTITY_TOKEN_FILE".to_string(),
            value_from_token_file: true,
            value: None,
        },
        EnvMapping {
            name: "OIDC_TOKEN_FILE".to_string(),
            value_from_token_file: true,
            value: None,
        },
    ]
}

impl ProjectionSpec {
    /// Directory where the token file is placed (the volume mount path).
    pub fn mount_dir(&self) -> &str {
        match self.token_file_path.rsplit_once('/') {
            Some(("", _)) => "/",
            Some((dir, _)) => dir,
            None => ".",
        }
    }

    /// Token file name.
    pub fn file_name(&self) -> &str {
        self.token_file_path
            .rsplit_once('/')
            .map(|(_, f)| f)
            .unwrap_or(&self.token_file_path)
    }

    /// AWS credentials file path (awsCredentialsFile mode).
    pub fn credentials_path(&self) -> String {
        format!("{}/{}", self.mount_dir(), AWS_CREDENTIALS_FILE_NAME)
    }

    /// The `(secretKey, filePath)` list the volume projects (per mode).
    pub fn volume_items(&self) -> Vec<(String, String)> {
        match self.mode {
            ProjectionMode::TokenFile => {
                vec![(SECRET_KEY_TOKEN.to_string(), self.file_name().to_string())]
            }
            ProjectionMode::AwsCredentialsFile => vec![(
                SECRET_KEY_CREDENTIALS.to_string(),
                AWS_CREDENTIALS_FILE_NAME.to_string(),
            )],
        }
    }

    /// The env `(name, value)` pairs to inject. Uses custom env if present, otherwise the mode preset.
    pub fn resolved_env(&self) -> Vec<(String, String)> {
        if !self.env.is_empty() {
            return self
                .env
                .iter()
                .map(|e| {
                    let v = if e.value_from_token_file {
                        self.token_file_path.clone()
                    } else {
                        e.value.clone().unwrap_or_default()
                    };
                    (e.name.clone(), v)
                })
                .collect();
        }
        match self.mode {
            ProjectionMode::TokenFile => default_token_env()
                .into_iter()
                .map(|e| (e.name, self.token_file_path.clone()))
                .collect(),
            ProjectionMode::AwsCredentialsFile => vec![
                (
                    "AWS_SHARED_CREDENTIALS_FILE".to_string(),
                    self.credentials_path(),
                ),
                ("AWS_PROFILE".to_string(), "default".to_string()),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_token_file_irsa_preset() {
        let d = ProjectionSpec::default();
        assert_eq!(d.mode, ProjectionMode::TokenFile);
        assert_eq!(d.token_file_path, DEFAULT_TOKEN_FILE_PATH);
        let env = d.resolved_env();
        assert!(env
            .iter()
            .any(|(k, v)| k == "AWS_WEB_IDENTITY_TOKEN_FILE" && v == DEFAULT_TOKEN_FILE_PATH));
        assert!(env.iter().any(|(k, _)| k == "OIDC_TOKEN_FILE"));
        assert_eq!(
            d.volume_items(),
            vec![("token".to_string(), "token".to_string())]
        );
    }

    #[test]
    fn aws_credentials_mode_preset() {
        let d = ProjectionSpec {
            mode: ProjectionMode::AwsCredentialsFile,
            ..ProjectionSpec::default()
        };
        assert_eq!(
            d.credentials_path(),
            "/var/run/secrets/oidc-bridge/credentials"
        );
        assert_eq!(
            d.volume_items(),
            vec![("credentials".to_string(), "credentials".to_string())]
        );
        let env = d.resolved_env();
        assert!(env.iter().any(|(k, v)| k == "AWS_SHARED_CREDENTIALS_FILE"
            && v == "/var/run/secrets/oidc-bridge/credentials"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "AWS_PROFILE" && v == "default"));
    }

    #[test]
    fn custom_env_literal_and_from_file() {
        let d = ProjectionSpec {
            mode: ProjectionMode::TokenFile,
            token_file_path: "/t/tok".to_string(),
            env: vec![
                EnvMapping {
                    name: "TOKEN".to_string(),
                    value_from_token_file: true,
                    value: None,
                },
                EnvMapping {
                    name: "REGION".to_string(),
                    value_from_token_file: false,
                    value: Some("ap".to_string()),
                },
            ],
        };
        let env = d.resolved_env();
        assert_eq!(env[0], ("TOKEN".to_string(), "/t/tok".to_string()));
        assert_eq!(env[1], ("REGION".to_string(), "ap".to_string()));
    }

    #[test]
    fn mount_dir_and_file_name() {
        let d = ProjectionSpec::default();
        assert_eq!(d.mount_dir(), "/var/run/secrets/oidc-bridge");
        assert_eq!(d.file_name(), "token");
    }

    #[test]
    fn deserialize_defaults() {
        let d: ProjectionSpec = serde_yaml::from_str("{}").unwrap();
        assert_eq!(d.mode, ProjectionMode::TokenFile);
        assert_eq!(d.token_file_path, DEFAULT_TOKEN_FILE_PATH);
        assert!(d.env.is_empty());

        let aws: ProjectionSpec = serde_yaml::from_str("mode: awsCredentialsFile").unwrap();
        assert_eq!(aws.mode, ProjectionMode::AwsCredentialsFile);
    }
}
