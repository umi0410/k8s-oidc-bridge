//! Pod mutation patch generation (spec §4.6). **Pure logic** — tested independently of AdmissionReview.
//!
//! Injects a projection Secret volume (readOnly) + IRSA-compatible env into opt-in pods. If already
//! injected (= volume present), returns an empty patch so it behaves idempotently.

use k8s_openapi::api::core::v1::Pod;
use serde_json::{json, Value};

use oidc_bridge_common::projection::{ProjectionSpec, VOLUME_NAME};
use oidc_bridge_common::{ANNOTATION_BINDING, ANNOTATION_PROJECTION_SECRET, LABEL_INJECTED};

/// JSON Pointer token escaping (`~`→`~0`, `/`→`~1`).
fn escape_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Op that sets `/metadata/<kind>/<key>`. If the map is empty, creates the whole map at once.
fn set_metadata_op(kind: &str, map_absent: bool, key: &str, value: &str) -> Value {
    if map_absent {
        json!({ "op": "add", "path": format!("/metadata/{kind}"), "value": { key: value } })
    } else {
        json!({
            "op": "add",
            "path": format!("/metadata/{kind}/{}", escape_pointer_token(key)),
            "value": value,
        })
    }
}

/// Builds the list of JSON Patch ops to inject into the pod. Empty vector when no injection is needed.
///
/// `secret_name` is the per-pod Secret name the webhook chose for this pod. The volume references
/// that name, and the same name is left as an annotation so the controller creates the pod-owned Secret.
/// `binding_name` is the TokenBinding name resolved from the pod's SA; the marker label (for controller
/// watch/list) and the binding annotation (for controller mapping) are both left behind (spec §4.6).
pub fn build_patch_ops(
    pod: &Pod,
    projection: &ProjectionSpec,
    secret_name: &str,
    binding_name: &str,
) -> Vec<Value> {
    let spec = match &pod.spec {
        Some(s) => s,
        None => return Vec::new(),
    };

    // Idempotency: if our volume is already present, don't add it again.
    if spec
        .volumes
        .as_ref()
        .is_some_and(|vs| vs.iter().any(|v| v.name == VOLUME_NAME))
    {
        return Vec::new();
    }

    let mut ops = Vec::new();

    // 0) Metadata for the controller contract: marker label + binding/projection-secret annotations.
    let labels_absent = pod.metadata.labels.as_ref().is_none_or(|l| l.is_empty());
    ops.push(set_metadata_op(
        "labels",
        labels_absent,
        LABEL_INJECTED,
        "true",
    ));

    let anns_absent = pod
        .metadata
        .annotations
        .as_ref()
        .is_none_or(|a| a.is_empty());
    ops.push(set_metadata_op(
        "annotations",
        anns_absent,
        ANNOTATION_BINDING,
        binding_name,
    ));
    // The first annotation op created the map, so from the second on we assume the map exists.
    ops.push(set_metadata_op(
        "annotations",
        false,
        ANNOTATION_PROJECTION_SECRET,
        secret_name,
    ));

    // 1) projection Secret volume (projects per-mode keys to exact file names).
    let items: Vec<Value> = projection
        .volume_items()
        .into_iter()
        .map(|(key, path)| json!({ "key": key, "path": path }))
        .collect();
    let volume = json!({
        "name": VOLUME_NAME,
        "secret": {
            "secretName": secret_name,
            "optional": false,
            "items": items,
        }
    });
    if spec.volumes.as_ref().is_none_or(|v| v.is_empty()) {
        ops.push(json!({ "op": "add", "path": "/spec/volumes", "value": [volume] }));
    } else {
        ops.push(json!({ "op": "add", "path": "/spec/volumes/-", "value": volume }));
    }

    // 2) volumeMount + env on each container.
    let mount = json!({
        "name": VOLUME_NAME,
        "mountPath": projection.mount_dir(),
        "readOnly": true,
    });
    let env_pairs = projection.resolved_env();

    for (i, container) in spec.containers.iter().enumerate() {
        if container
            .volume_mounts
            .as_ref()
            .is_none_or(|m| m.is_empty())
        {
            ops.push(json!({
                "op": "add",
                "path": format!("/spec/containers/{i}/volumeMounts"),
                "value": [mount],
            }));
        } else {
            ops.push(json!({
                "op": "add",
                "path": format!("/spec/containers/{i}/volumeMounts/-"),
                "value": mount,
            }));
        }

        let env_values: Vec<Value> = env_pairs
            .iter()
            .map(|(k, v)| json!({ "name": k, "value": v }))
            .collect();
        if container.env.as_ref().is_none_or(|e| e.is_empty()) {
            ops.push(json!({
                "op": "add",
                "path": format!("/spec/containers/{i}/env"),
                "value": env_values,
            }));
        } else {
            for ev in env_values {
                ops.push(json!({
                    "op": "add",
                    "path": format!("/spec/containers/{i}/env/-"),
                    "value": ev,
                }));
            }
        }
    }

    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    use oidc_bridge_common::projection::{ProjectionMode, SECRET_KEY_TOKEN};

    fn pod_json(spec: Value) -> Pod {
        serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "app" },
            "spec": spec,
        }))
        .unwrap()
    }

    fn projection() -> ProjectionSpec {
        ProjectionSpec::default()
    }

    #[test]
    fn injects_volume_mount_and_env_for_bare_container() {
        let pod = pod_json(json!({ "containers": [{ "name": "app", "image": "x" }] }));
        let ops = build_patch_ops(&pod, &projection(), "oidc-bridge-aistor", "aistor");

        // volumes add (creates the whole array), container mount, container env.
        assert!(ops.iter().any(|o| o["path"] == "/spec/volumes"));
        assert!(ops
            .iter()
            .any(|o| o["path"] == "/spec/containers/0/volumeMounts"));
        let env_op = ops
            .iter()
            .find(|o| o["path"] == "/spec/containers/0/env")
            .unwrap();
        let names: Vec<&str> = env_op["value"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"AWS_WEB_IDENTITY_TOKEN_FILE"));
        assert!(names.contains(&"OIDC_TOKEN_FILE"));
    }

    #[test]
    fn volume_projects_token_file_name() {
        let pod = pod_json(json!({ "containers": [{ "name": "app", "image": "x" }] }));
        let ops = build_patch_ops(&pod, &projection(), "sec", "aistor");
        let vol_op = ops.iter().find(|o| o["path"] == "/spec/volumes").unwrap();
        let vol = &vol_op["value"][0];
        assert_eq!(vol["name"], VOLUME_NAME);
        assert_eq!(vol["secret"]["secretName"], "sec");
        assert_eq!(vol["secret"]["items"][0]["key"], SECRET_KEY_TOKEN);
        assert_eq!(vol["secret"]["items"][0]["path"], "token");
    }

    #[test]
    fn appends_when_volumes_and_env_already_present() {
        let pod = pod_json(json!({
            "volumes": [{ "name": "existing", "emptyDir": {} }],
            "containers": [{
                "name": "app",
                "image": "x",
                "env": [{ "name": "EXISTING", "value": "1" }],
                "volumeMounts": [{ "name": "existing", "mountPath": "/data" }],
            }],
        }));
        let ops = build_patch_ops(&pod, &projection(), "sec", "aistor");
        assert!(ops.iter().any(|o| o["path"] == "/spec/volumes/-"));
        assert!(ops
            .iter()
            .any(|o| o["path"] == "/spec/containers/0/volumeMounts/-"));
        // env already exists, so two entries are added via append(-).
        let env_appends = ops
            .iter()
            .filter(|o| o["path"] == "/spec/containers/0/env/-")
            .count();
        assert_eq!(env_appends, 2);
    }

    #[test]
    fn idempotent_when_volume_already_injected() {
        let pod = pod_json(json!({
            "volumes": [{ "name": VOLUME_NAME, "secret": { "secretName": "sec" } }],
            "containers": [{ "name": "app", "image": "x" }],
        }));
        assert!(build_patch_ops(&pod, &projection(), "sec", "aistor").is_empty());
    }

    #[test]
    fn patches_every_container() {
        let pod = pod_json(json!({
            "containers": [
                { "name": "a", "image": "x" },
                { "name": "b", "image": "y" },
            ],
        }));
        let ops = build_patch_ops(&pod, &projection(), "sec", "aistor");
        assert!(ops.iter().any(|o| o["path"] == "/spec/containers/1/env"));
        assert!(ops
            .iter()
            .any(|o| o["path"] == "/spec/containers/1/volumeMounts"));
    }

    #[test]
    fn no_spec_yields_no_ops() {
        let pod: Pod = serde_json::from_value(json!({"metadata": {"name": "x"}})).unwrap();
        assert!(build_patch_ops(&pod, &projection(), "sec", "aistor").is_empty());
    }

    #[test]
    fn stamps_projection_secret_annotation_when_annotations_exist() {
        // The token-binding annotation already exists, so it's added via the escaped path.
        let pod = pod_json(json!({ "containers": [{ "name": "app", "image": "x" }] }));
        let mut pod = pod;
        pod.metadata.annotations = Some(
            [(
                "bridge.oidc.io/token-binding".to_string(),
                "aistor".to_string(),
            )]
            .into_iter()
            .collect(),
        );
        let ops = build_patch_ops(&pod, &projection(), "oidc-bridge-tok-app", "aistor");
        let ann = ops
            .iter()
            .find(|o| o["path"] == "/metadata/annotations/bridge.oidc.io~1projection-secret-name")
            .unwrap();
        assert_eq!(ann["value"], "oidc-bridge-tok-app");
    }

    #[test]
    fn aws_credentials_mode_projects_credentials_file_and_env() {
        let pod = pod_json(json!({ "containers": [{ "name": "app", "image": "x" }] }));
        let aws = ProjectionSpec {
            mode: ProjectionMode::AwsCredentialsFile,
            ..ProjectionSpec::default()
        };
        let ops = build_patch_ops(&pod, &aws, "oidc-bridge-tok-app", "aistor");
        let vol_op = ops.iter().find(|o| o["path"] == "/spec/volumes").unwrap();
        assert_eq!(
            vol_op["value"][0]["secret"]["items"][0]["key"],
            "credentials"
        );
        assert_eq!(
            vol_op["value"][0]["secret"]["items"][0]["path"],
            "credentials"
        );
        let env_op = ops
            .iter()
            .find(|o| o["path"] == "/spec/containers/0/env")
            .unwrap();
        let names: Vec<&str> = env_op["value"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"AWS_SHARED_CREDENTIALS_FILE"));
        assert!(names.contains(&"AWS_PROFILE"));
    }

    #[test]
    fn creates_annotations_map_when_absent() {
        let pod = pod_json(json!({ "containers": [{ "name": "app", "image": "x" }] }));
        let ops = build_patch_ops(&pod, &projection(), "oidc-bridge-tok-app", "aistor");
        // No map exists, so the first annotation op creates the map with binding,
        let ann = ops
            .iter()
            .find(|o| o["path"] == "/metadata/annotations")
            .unwrap();
        assert_eq!(ann["value"]["bridge.oidc.io/binding"], "aistor");
        // projection-secret-name is then added via the escaped path.
        let proj = ops
            .iter()
            .find(|o| o["path"] == "/metadata/annotations/bridge.oidc.io~1projection-secret-name")
            .unwrap();
        assert_eq!(proj["value"], "oidc-bridge-tok-app");
    }

    #[test]
    fn stamps_injected_marker_label() {
        let pod = pod_json(json!({ "containers": [{ "name": "app", "image": "x" }] }));
        let ops = build_patch_ops(&pod, &projection(), "sec", "aistor");
        let label = ops
            .iter()
            .find(|o| o["path"] == "/metadata/labels")
            .unwrap();
        assert_eq!(label["value"]["bridge.oidc.io/injected"], "true");
    }
}
