//! Provider config loading (ConfigMap + Secret → [`ProviderSet`] + [`SecretStore`]).

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use kube::{Api, Client};

use oidc_bridge_common::config::ProviderSet;
use oidc_bridge_common::resolver::SecretStore;

use crate::error::ControllerError;

/// Default name of the provider ConfigMap (spec §4.2).
pub const DEFAULT_CONFIGMAP: &str = "oidc-bridge-providers";
/// Default name of the provider Secret.
pub const DEFAULT_SECRET: &str = "oidc-bridge-secret";

/// Turn a Secret's `data` (name -> bytes) into a single `SecretStore` entry for the resolver.
/// The reference syntax is `$<secretName>:<key>`, so the bucket is keyed by the secret name.
pub fn secret_store_from(
    secret_name: &str,
    data: BTreeMap<String, Vec<u8>>,
) -> Result<SecretStore, ControllerError> {
    let mut bucket = BTreeMap::new();
    for (k, bytes) in data {
        let v = String::from_utf8(bytes)
            .map_err(|_| ControllerError::TokenRequest(format!("secret key {k} is not utf-8")))?;
        bucket.insert(k, v);
    }
    let mut store = SecretStore::new();
    store.insert(secret_name.to_string(), bucket);
    Ok(store)
}

/// Read the provider ConfigMap + Secret from the namespace and assemble the config.
pub async fn load(
    client: &Client,
    namespace: &str,
    configmap_name: &str,
    secret_name: &str,
) -> Result<(ProviderSet, SecretStore), ControllerError> {
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), namespace);

    let cm = cm_api.get(configmap_name).await?;
    let data = cm.data.unwrap_or_default();
    let providers = ProviderSet::from_config_map_data(&data)?;

    let store = match secret_api.get_opt(secret_name).await? {
        Some(secret) => {
            let raw: BTreeMap<String, Vec<u8>> = secret
                .data
                .unwrap_or_default()
                .into_iter()
                .map(|(k, v)| (k, v.0))
                .collect();
            secret_store_from(secret_name, raw)?
        }
        None => SecretStore::new(),
    };

    Ok((providers, store))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_store_keyed_by_secret_name() {
        let mut data = BTreeMap::new();
        data.insert("authentik-client-secret".to_string(), b"s3cr3t".to_vec());
        let store = secret_store_from("oidc-bridge-secret", data).unwrap();
        let v = oidc_bridge_common::resolver::resolve(
            "$oidc-bridge-secret:authentik-client-secret",
            &store,
        )
        .unwrap();
        assert_eq!(v, "s3cr3t");
    }

    #[test]
    fn non_utf8_secret_value_errors() {
        let mut data = BTreeMap::new();
        data.insert("bad".to_string(), vec![0xff, 0xfe]);
        assert!(secret_store_from("s", data).is_err());
    }
}
