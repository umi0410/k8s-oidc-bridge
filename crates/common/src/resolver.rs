//! ArgoCD-style `$<secretName>:<key>` secret-reference resolver.
//!
//! A ConfigMap value references a Secret value by path (spec §4.2). Only values
//! starting with `$` are treated as references; everything else is returned as a literal.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// Secret store in the form secretName -> (key -> value).
///
/// The controller decrypts/decodes the referenced Secrets to populate it. The resolver
/// itself is pure, so tests construct it directly.
pub type SecretStore = BTreeMap<String, BTreeMap<String, String>>;

/// Resolves a single value. If `$name:key`, looks it up in the store; otherwise a literal.
pub fn resolve(raw: &str, store: &SecretStore) -> Result<String> {
    let Some(rest) = raw.strip_prefix('$') else {
        return Ok(raw.to_string());
    };

    let (secret, key) = rest
        .split_once(':')
        .ok_or_else(|| Error::MalformedSecretRef {
            reference: raw.to_string(),
            reason: "expected `$<secretName>:<key>`".to_string(),
        })?;

    if secret.is_empty() || key.is_empty() {
        return Err(Error::MalformedSecretRef {
            reference: raw.to_string(),
            reason: "secret name and key must both be non-empty".to_string(),
        });
    }

    let bucket = store.get(secret).ok_or_else(|| Error::SecretNotFound {
        secret: secret.to_string(),
        reference: raw.to_string(),
    })?;

    bucket
        .get(key)
        .cloned()
        .ok_or_else(|| Error::SecretKeyNotFound {
            secret: secret.to_string(),
            key: key.to_string(),
        })
}

/// Only decides whether it's a reference (false if a literal).
pub fn is_reference(raw: &str) -> bool {
    raw.starts_with('$')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> SecretStore {
        let mut s = SecretStore::new();
        let mut b = BTreeMap::new();
        b.insert("authentik-client-secret".to_string(), "s3cr3t".to_string());
        b.insert("empty".to_string(), String::new());
        s.insert("oidc-bridge-secret".to_string(), b);
        s
    }

    #[test]
    fn literal_passthrough() {
        assert_eq!(resolve("plain-value", &store()).unwrap(), "plain-value");
        assert!(!is_reference("plain-value"));
    }

    #[test]
    fn resolves_reference() {
        let got = resolve("$oidc-bridge-secret:authentik-client-secret", &store()).unwrap();
        assert_eq!(got, "s3cr3t");
        assert!(is_reference("$oidc-bridge-secret:authentik-client-secret"));
    }

    #[test]
    fn resolves_reference_to_empty_value() {
        assert_eq!(resolve("$oidc-bridge-secret:empty", &store()).unwrap(), "");
    }

    #[test]
    fn missing_colon_is_malformed() {
        let err = resolve("$oidc-bridge-secret", &store()).unwrap_err();
        assert!(matches!(err, Error::MalformedSecretRef { .. }));
    }

    #[test]
    fn empty_name_or_key_is_malformed() {
        assert!(matches!(
            resolve("$:key", &store()).unwrap_err(),
            Error::MalformedSecretRef { .. }
        ));
        assert!(matches!(
            resolve("$secret:", &store()).unwrap_err(),
            Error::MalformedSecretRef { .. }
        ));
    }

    #[test]
    fn unknown_secret() {
        assert!(matches!(
            resolve("$nope:key", &store()).unwrap_err(),
            Error::SecretNotFound { .. }
        ));
    }

    #[test]
    fn unknown_key() {
        assert!(matches!(
            resolve("$oidc-bridge-secret:nope", &store()).unwrap_err(),
            Error::SecretKeyNotFound { .. }
        ));
    }

    #[test]
    fn literal_with_inner_dollar_is_not_a_reference() {
        // If `$` is not at the start, it's not a reference (ArgoCD convention).
        assert_eq!(resolve("pa$$word", &store()).unwrap(), "pa$$word");
    }
}
