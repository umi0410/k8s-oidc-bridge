//! Projection Secret build/apply/get (spec §4.6).
//!
//! Handles two kinds of Secret:
//! - **source**: binding-owned (ownerRef=TokenBinding). The single source of truth for the exchanged token.
//! - **per-pod**: pod-owned (ownerRef=Pod). Garbage-collected by k8s when the pod is deleted.
//!
//! `blockOwnerDeletion` is not set — enabling it would require update permission on the owner's
//! `finalizers` subresource, whereas GC itself works from the ownerReference alone.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Pod, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use kube::api::{Patch, PatchParams};
use kube::{Api, Client, Resource};

use oidc_bridge_common::crd::TokenBinding;

use crate::error::ControllerError;

const MANAGER: &str = "oidc-bridge-controller";

/// OwnerReference with the TokenBinding as owner (for the source Secret).
pub fn binding_owner_reference(tb: &TokenBinding) -> Result<OwnerReference, ControllerError> {
    let name = tb
        .meta()
        .name
        .clone()
        .ok_or(ControllerError::MissingField("metadata.name"))?;
    let uid = tb
        .meta()
        .uid
        .clone()
        .ok_or(ControllerError::MissingField("metadata.uid"))?;
    Ok(OwnerReference {
        api_version: TokenBinding::api_version(&()).into_owned(),
        kind: TokenBinding::kind(&()).into_owned(),
        name,
        uid,
        controller: Some(true),
        block_owner_deletion: None,
    })
}

/// OwnerReference with the Pod as owner (for the per-pod Secret — GC'd when the pod is deleted).
pub fn pod_owner_reference(pod: &Pod) -> Result<OwnerReference, ControllerError> {
    let name = pod
        .meta()
        .name
        .clone()
        .ok_or(ControllerError::MissingField("pod.metadata.name"))?;
    let uid = pod
        .meta()
        .uid
        .clone()
        .ok_or(ControllerError::MissingField("pod.metadata.uid"))?;
    Ok(OwnerReference {
        api_version: "v1".to_string(),
        kind: "Pod".to_string(),
        name,
        uid,
        controller: Some(true),
        block_owner_deletion: None,
    })
}

/// Projection Secret object (pure). `data` is key→value (a token or AWS credential fields, etc.).
pub fn build_projection_secret(
    name: &str,
    namespace: &str,
    owner: OwnerReference,
    data: BTreeMap<String, String>,
) -> Secret {
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        MANAGER.to_string(),
    );

    Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner]),
            labels: Some(labels),
            ..Default::default()
        },
        string_data: Some(data),
        type_: Some("Opaque".to_string()),
        ..Default::default()
    }
}

/// Apply the projection Secret via server-side apply (§CLAUDE.md: use SSA so the last-applied
/// annotation is not left behind).
pub async fn apply_projection_secret(
    client: &Client,
    secret: &Secret,
) -> Result<(), ControllerError> {
    let namespace = secret
        .metadata
        .namespace
        .as_deref()
        .ok_or(ControllerError::MissingField("secret.namespace"))?;
    let name = secret
        .metadata
        .name
        .as_deref()
        .ok_or(ControllerError::MissingField("secret.name"))?;
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let pp = PatchParams::apply(MANAGER).force();
    api.patch(name, &pp, &Patch::Apply(secret)).await?;
    Ok(())
}

/// Get the source Secret (None if absent).
pub async fn get_opt(
    client: &Client,
    namespace: &str,
    name: &str,
) -> Result<Option<Secret>, ControllerError> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    Ok(api.get_opt(name).await?)
}

/// Decode a Secret's `data` (bytes) into a string map (for the reuse path).
pub fn read_data(secret: &Secret) -> BTreeMap<String, String> {
    secret
        .data
        .as_ref()
        .map(|d| {
            d.iter()
                .filter_map(|(k, v)| String::from_utf8(v.0.clone()).ok().map(|s| (k.clone(), s)))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::ByteString;

    fn owner() -> OwnerReference {
        OwnerReference {
            api_version: "v1".to_string(),
            kind: "Pod".to_string(),
            name: "app".to_string(),
            uid: "uid-123".to_string(),
            controller: Some(true),
            block_owner_deletion: None,
        }
    }

    fn data(token: &str) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("token".to_string(), token.to_string());
        m
    }

    #[test]
    fn projection_secret_shape() {
        let s =
            build_projection_secret("oidc-bridge-tok-app", "apps", owner(), data("UPSTREAM.JWT"));
        assert_eq!(s.metadata.name.as_deref(), Some("oidc-bridge-tok-app"));
        assert_eq!(s.metadata.namespace.as_deref(), Some("apps"));
        assert_eq!(
            s.string_data
                .as_ref()
                .unwrap()
                .get("token")
                .map(String::as_str),
            Some("UPSTREAM.JWT")
        );
        let owners = s.metadata.owner_references.as_ref().unwrap();
        assert_eq!(owners[0].kind, "Pod");
        assert_eq!(owners[0].uid, "uid-123");
        assert_eq!(owners[0].block_owner_deletion, None);
    }

    #[test]
    fn pod_owner_reference_from_pod() {
        let pod: Pod = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": { "name": "app-xyz", "uid": "pod-uid" },
        }))
        .unwrap();
        let o = pod_owner_reference(&pod).unwrap();
        assert_eq!(o.kind, "Pod");
        assert_eq!(o.name, "app-xyz");
        assert_eq!(o.uid, "pod-uid");
        assert_eq!(o.controller, Some(true));
    }

    #[test]
    fn read_data_decodes_bytes() {
        let mut secret = Secret::default();
        let mut d = BTreeMap::new();
        d.insert("token".to_string(), ByteString(b"abc".to_vec()));
        secret.data = Some(d);
        let got = read_data(&secret);
        assert_eq!(got.get("token").map(String::as_str), Some("abc"));
    }
}
