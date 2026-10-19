//! axum-based mutating admission server (spec §4.1, §4.6).

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use k8s_openapi::api::core::v1::Pod;
use kube::api::ListParams;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use kube::core::DynamicObject;
use kube::{Api, Client, ResourceExt};
use tracing::{info, warn};

use oidc_bridge_common::crd::TokenBinding;
use oidc_bridge_common::podbinding::{
    is_opted_out, per_pod_secret_name, select_binding_for_sa, SaMatch,
};
use oidc_bridge_common::projection::ProjectionSpec;

use crate::metrics;
use crate::mutate::build_patch_ops;

#[derive(Clone)]
pub struct AppState {
    pub client: Client,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/mutate", post(mutate))
        .with_state(state)
}

/// Resolves a TokenBinding in the same ns from the pod's SA. Returns `(binding_name, projection)`.
/// None on zero matches (pod not using the bridge), ambiguity (2+ bindings targeting the same SA), or list failure.
async fn resolve_binding_for_sa(
    client: &Client,
    namespace: &str,
    service_account: &str,
) -> Option<(String, ProjectionSpec)> {
    let api: Api<TokenBinding> = Api::namespaced(client.clone(), namespace);
    let list = match api.list(&ListParams::default()).await {
        Ok(l) => l,
        Err(e) => {
            warn!(error = %e, namespace, "failed to list TokenBindings");
            return None;
        }
    };
    let candidates: Vec<(String, String)> = list
        .iter()
        .map(|tb| (tb.name_any(), tb.spec.service_account_name.clone()))
        .collect();

    match select_binding_for_sa(&candidates, service_account) {
        SaMatch::None => None,
        SaMatch::Ambiguous(names) => {
            warn!(
                namespace,
                service_account,
                bindings = ?names,
                "multiple TokenBindings target this ServiceAccount; skipping injection"
            );
            None
        }
        SaMatch::One(name) => list
            .into_iter()
            .find(|tb| tb.name_any() == name)
            .map(|tb| (name, tb.spec.projection)),
    }
}

async fn mutate(
    State(state): State<AppState>,
    Json(review): Json<AdmissionReview<Pod>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let req: AdmissionRequest<Pod> = match review.try_into() {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "invalid AdmissionReview");
            metrics::record(metrics::ERROR);
            let resp = AdmissionResponse::invalid(e.to_string());
            return Json(resp.into_review());
        }
    };

    let resp = AdmissionResponse::from(&req);
    let Some(pod) = req.object.clone() else {
        metrics::record(metrics::SKIPPED);
        return Json(resp.into_review());
    };

    let namespace = req
        .namespace
        .clone()
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "default".to_string());

    // per-pod opt-out: even if the ns is opt-in, pods with this label are skipped.
    if is_opted_out(&pod.labels().clone()) {
        metrics::record(metrics::SKIPPED);
        return Json(resp.into_review());
    }

    // Resolve the binding from the pod's SA (no annotation needed). Defaults to "default" if SA unset.
    let service_account = pod
        .spec
        .as_ref()
        .and_then(|s| s.service_account_name.clone())
        .unwrap_or_else(|| "default".to_string());

    let Some((binding_name, projection)) =
        resolve_binding_for_sa(&state.client, &namespace, &service_account).await
    else {
        // No binding targets this SA → pod not covered by the bridge. Allow as-is.
        metrics::record(metrics::SKIPPED);
        return Json(resp.into_review());
    };

    // per-pod Secret name: use the pod name if present, otherwise the admission UID for generateName.
    let secret_name = per_pod_secret_name(pod.metadata.name.as_deref(), &req.uid);
    let ops = build_patch_ops(&pod, &projection, &secret_name, &binding_name);
    if ops.is_empty() {
        metrics::record(metrics::SKIPPED);
        return Json(resp.into_review());
    }

    let patch: json_patch::Patch = match serde_json::from_value(serde_json::Value::Array(ops)) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "failed to build json patch");
            metrics::record(metrics::ERROR);
            return Json(resp.into_review());
        }
    };

    match resp.with_patch(patch) {
        Ok(patched) => {
            info!(binding = %binding_name, namespace, "injected projection volume + env");
            metrics::record(metrics::INJECTED);
            Json(patched.into_review())
        }
        Err(e) => {
            warn!(error = %e, "failed to attach patch");
            metrics::record(metrics::ERROR);
            Json(AdmissionResponse::from(&req).into_review())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Verifies the generated ops are actually a valid JSON Patch and apply to the pod.
    #[test]
    fn generated_ops_apply_cleanly() {
        let pod: Pod = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "app" },
            "spec": { "containers": [{ "name": "app", "image": "x" }] },
        }))
        .unwrap();

        let ops = build_patch_ops(
            &pod,
            &ProjectionSpec::default(),
            "oidc-bridge-aistor",
            "aistor",
        );
        let patch: json_patch::Patch =
            serde_json::from_value(serde_json::Value::Array(ops)).unwrap();

        let mut doc = serde_json::to_value(&pod).unwrap();
        json_patch::patch(&mut doc, &patch).expect("patch applies");

        assert_eq!(doc["metadata"]["labels"]["bridge.oidc.io/injected"], "true");
        assert_eq!(
            doc["metadata"]["annotations"]["bridge.oidc.io/binding"],
            "aistor"
        );
        let vols = doc["spec"]["volumes"].as_array().unwrap();
        assert_eq!(vols[0]["name"], "oidc-bridge-token");
        let env = doc["spec"]["containers"][0]["env"].as_array().unwrap();
        assert!(env
            .iter()
            .any(|e| e["name"] == "AWS_WEB_IDENTITY_TOKEN_FILE"
                && e["value"] == "/var/run/secrets/oidc-bridge/token"));
        let mounts = doc["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .unwrap();
        assert_eq!(mounts[0]["mountPath"], "/var/run/secrets/oidc-bridge");
        assert_eq!(mounts[0]["readOnly"], true);
    }
}
