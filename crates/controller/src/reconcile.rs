//! `TokenBinding` reconcile loop (spec §4.1, §4.6, §4.7).
//!
//! Flow: load provider config → (when needed) issue SA token + upstream exchange → write the
//! binding-owned **source** Secret → fan out to opt-in pods via pod-owned **per-pod** Secrets →
//! update status → requeue at the 50% TTL point. Pod events are also watched; when a new pod
//! appears and the token is still valid, the source token is copied to that pod's Secret without
//! re-minting. On failure the last-good token is kept (the Secret is not deleted) and we go
//! Degraded with an exponential-backoff requeue.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use backon::{ExponentialBuilder, Retryable};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{ListParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::events::{Event, EventType, Recorder};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Api, Client, Resource, ResourceExt};
use tracing::{error, info, warn};

use oidc_bridge_common::backoff::BackoffConfig;
use oidc_bridge_common::config::ProviderConfig;
use oidc_bridge_common::crd::{TokenBinding, TokenBindingStatus};
use oidc_bridge_common::podbinding::{binding_of, pod_targets_binding};
use oidc_bridge_common::renew::{duration_until_renew, needs_remint, next_renew_time};
use oidc_bridge_common::{status, ANNOTATION_PROJECTION_SECRET, LABEL_INJECTED};

use crate::error::ControllerError;
use crate::exchange::{build_driver, ExchangeOutput};
use crate::{jwt, metrics, providers, secret, token};

/// Global dependencies for reconcile.
pub struct Context {
    pub client: Client,
    pub http: reqwest::Client,
    /// Namespace holding the provider ConfigMap/Secret (usually the install namespace).
    pub provider_namespace: String,
    pub configmap_name: String,
    pub secret_name: String,
    /// k8s Event publisher (spec §4.9).
    pub recorder: Recorder,
}

/// Record a k8s Event on the TokenBinding (reconcile continues even if this fails).
async fn publish_event(ctx: &Context, tb: &TokenBinding, event: Event) {
    if let Err(e) = ctx.recorder.publish(&event, &tb.object_ref(&())).await {
        warn!(error = %e, "failed to publish event");
    }
}

/// Short-term retry for transient errors on the exchange HTTP call (backoff via `backon`). The
/// long-term backoff for persistent failures is handled by requeue (§4.7).
fn exchange_retry_policy() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(StdDuration::from_millis(200))
        .with_max_delay(StdDuration::from_secs(5))
        .with_max_times(3)
        .with_jitter()
}

fn to_std(d: chrono::Duration) -> StdDuration {
    d.to_std().unwrap_or(StdDuration::ZERO)
}

/// Safely truncate an Event note (max 1kB), preserving char boundaries.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

async fn patch_status(
    api: &Api<TokenBinding>,
    name: &str,
    st: &TokenBindingStatus,
) -> Result<(), ControllerError> {
    let patch = serde_json::json!({ "status": st });
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

/// Effective audience/scope (binding override first, else the provider default).
fn effective_audience_scope(
    tb: &TokenBinding,
    provider: &ProviderConfig,
) -> (Option<String>, Option<String>) {
    let audience = tb
        .spec
        .audience
        .clone()
        .or_else(|| provider.default_audience().map(String::from));
    let scope = tb
        .spec
        .scope
        .clone()
        .or_else(|| provider.default_scope().map(String::from));
    (audience, scope)
}

/// Summary of the output from a fresh exchange.
struct MintInfo {
    issued_at: DateTime<Utc>,
    expiry: DateTime<Utc>,
    next_renew: DateTime<Utc>,
}

/// Result of securing the source token: the data map + an output summary (only when re-minted).
struct SourceToken {
    data: BTreeMap<String, String>,
    minted: Option<MintInfo>,
}

async fn reconcile(tb: Arc<TokenBinding>, ctx: Arc<Context>) -> Result<Action, ControllerError> {
    let namespace = tb
        .namespace()
        .ok_or(ControllerError::MissingField("namespace"))?;
    let name = tb.name_any();
    let api: Api<TokenBinding> = Api::namespaced(ctx.client.clone(), &namespace);
    let generation = tb.meta().generation;
    let current_conditions = tb
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();
    let prior_failures = tb.status.as_ref().map(|s| s.renew_failures).unwrap_or(0);
    let backoff = tb.spec.renew.backoff;

    match ensure_source_token(&tb, &ctx, &namespace).await {
        Ok(source) => {
            // Fan out to all opt-in pods via per-pod Secrets.
            let fanned = fan_out(&ctx, &namespace, &name, &source.data).await;

            let requeue = match &source.minted {
                Some(m) => {
                    info!(binding = %name, pods = fanned, "token renewed and fanned out");
                    metrics::record_renew(&name, true);
                    publish_event(
                        &ctx,
                        &tb,
                        Event {
                            type_: EventType::Normal,
                            reason: "TokenRenewed".to_string(),
                            note: Some(format!(
                                "exchanged upstream token (expires {}), delivered to {fanned} pod(s)",
                                m.expiry.to_rfc3339()
                            )),
                            action: "Exchange".to_string(),
                            secondary: None,
                        },
                    )
                    .await;
                    let st = ready_status(&tb, &current_conditions, generation, m);
                    patch_status(&api, &name, &st).await?;
                    to_std(duration_until_renew(m.next_renew, Utc::now()))
                }
                None => {
                    // Token still valid, so reuse it — leave status as is and only requeue.
                    info!(binding = %name, pods = fanned, "reused valid token for fan-out");
                    tb.status
                        .as_ref()
                        .and_then(|s| s.next_renew_time.as_deref())
                        .and_then(parse_rfc3339)
                        .map(|t| to_std(duration_until_renew(t, Utc::now())))
                        .unwrap_or(StdDuration::from_secs(300))
                }
            };
            Ok(Action::requeue(requeue))
        }
        Err(e) => {
            warn!(binding = %name, error = %e, "exchange failed; keeping last-good token");
            metrics::record_renew(&name, false);
            publish_event(
                &ctx,
                &tb,
                Event {
                    type_: EventType::Warning,
                    reason: "ExchangeFailed".to_string(),
                    note: Some(truncate(&e.to_string(), 1024)),
                    action: "Exchange".to_string(),
                    secondary: None,
                },
            )
            .await;
            let failures = prior_failures + 1;
            let now = Utc::now().to_rfc3339();
            let conditions = status::degraded(
                &current_conditions,
                "ExchangeFailed",
                e.to_string(),
                &now,
                generation,
            );
            let st = TokenBindingStatus {
                conditions,
                renew_failures: failures,
                last_error: Some(e.to_string()),
                observed_generation: generation,
                // Preserve the last-good fields (merge patch only changes the fields set here).
                ..tb.status.clone().unwrap_or_default()
            };
            patch_status(&api, &name, &st).await?;
            let delay = backoff.delay(failures.min(u32::MAX as i64) as u32);
            Ok(Action::requeue(delay))
        }
    }
}

/// Secure the source Secret: reuse if still valid, otherwise re-mint and write.
async fn ensure_source_token(
    tb: &TokenBinding,
    ctx: &Context,
    namespace: &str,
) -> Result<SourceToken, ControllerError> {
    let source_name = tb.source_secret_name();
    let existing = secret::get_opt(&ctx.client, namespace, &source_name).await?;
    let next_renew = tb
        .status
        .as_ref()
        .and_then(|s| s.next_renew_time.as_deref())
        .and_then(parse_rfc3339);

    if !needs_remint(next_renew, Utc::now(), existing.is_some()) {
        if let Some(src) = &existing {
            let data = secret::read_data(src);
            if !data.is_empty() {
                return Ok(SourceToken { data, minted: None });
            }
        }
    }

    // Re-mint path.
    let (providers, store) = providers::load(
        &ctx.client,
        &ctx.provider_namespace,
        &ctx.configmap_name,
        &ctx.secret_name,
    )
    .await?;
    let provider = providers.get(&tb.spec.provider_ref)?.resolve(&store)?;
    let (audience, scope) = effective_audience_scope(tb, &provider);
    let aud = audience.clone().ok_or_else(|| {
        ControllerError::Config(oidc_bridge_common::Error::InvalidRenew(
            "audience is required (set spec.audience or provider audience)".to_string(),
        ))
    })?;

    let (subject_token, _sa_expiry) =
        token::request_sa_token(&ctx.client, namespace, &tb.spec.service_account_name, &aud)
            .await?;

    let driver = build_driver(
        &provider,
        audience,
        scope,
        &tb.spec.service_account_name,
        ctx.http.clone(),
    );
    let started = std::time::Instant::now();
    let output: ExchangeOutput = (|| async { driver.exchange(&subject_token).await })
        .retry(exchange_retry_policy())
        .await?;
    metrics::observe_exchange_latency(&tb.name_any(), started.elapsed().as_secs_f64());
    metrics::record_issue(&tb.name_any(), true);

    let data = output.secret_data();
    let owner = secret::binding_owner_reference(tb)?;
    let sec = secret::build_projection_secret(&source_name, namespace, owner, data.clone());
    secret::apply_projection_secret(&ctx.client, &sec).await?;

    let issued_at = Utc::now();
    // Expiry: expires_in/JWT exp for a token, STS Expiration for AWS credentials.
    let expiry = match &output {
        ExchangeOutput::Token(t) => jwt::compute_expiry(issued_at, t.expires_in, &t.access_token),
        ExchangeOutput::Aws(c) => c.expiration,
    };
    let next_renew = next_renew_time(issued_at, expiry, tb.spec.renew.threshold_percent)?;
    metrics::set_expiry_seconds(&tb.name_any(), (expiry - issued_at).num_seconds() as f64);

    Ok(SourceToken {
        data,
        minted: Some(MintInfo {
            issued_at,
            expiry,
            next_renew,
        }),
    })
}

/// Upsert a per-pod Secret into each opt-in pod. Individual pod failures are logged and skipped.
/// Returns the number of pods processed successfully.
async fn fan_out(
    ctx: &Context,
    namespace: &str,
    binding_name: &str,
    data: &BTreeMap<String, String>,
) -> usize {
    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), namespace);
    let lp = ListParams::default().labels(&format!("{LABEL_INJECTED}=true"));
    let list = match pods.list(&lp).await {
        Ok(l) => l,
        Err(e) => {
            warn!(error = %e, namespace, "failed to list injected pods");
            return 0;
        }
    };

    let mut count = 0;
    for pod in list {
        let annotations = pod.annotations().clone();
        if !pod_targets_binding(&annotations, binding_name) {
            continue;
        }
        // Skip pods being deleted (the Secret is handled by ownerRef GC).
        if pod.meta().deletion_timestamp.is_some() {
            continue;
        }
        let Some(secret_name) = annotations.get(ANNOTATION_PROJECTION_SECRET) else {
            // A pod the webhook did not inject (label only). No volume to reference, so skip.
            continue;
        };
        let owner = match secret::pod_owner_reference(&pod) {
            Ok(o) => o,
            Err(e) => {
                warn!(error = %e, pod = pod.name_any(), "pod missing name/uid; skipping");
                continue;
            }
        };
        let sec = secret::build_projection_secret(secret_name, namespace, owner, data.clone());
        match secret::apply_projection_secret(&ctx.client, &sec).await {
            Ok(()) => count += 1,
            Err(e) => {
                warn!(error = %e, pod = pod.name_any(), secret = secret_name, "failed to write per-pod secret")
            }
        }
    }
    count
}

fn ready_status(
    tb: &TokenBinding,
    current_conditions: &[status::Condition],
    generation: Option<i64>,
    m: &MintInfo,
) -> TokenBindingStatus {
    let now = m.issued_at.to_rfc3339();
    TokenBindingStatus {
        conditions: status::ready(current_conditions, &now, generation),
        issued_at: Some(now.clone()),
        expiry_time: Some(m.expiry.to_rfc3339()),
        next_renew_time: Some(m.next_renew.to_rfc3339()),
        last_renew_time: Some(now),
        renew_failures: 0,
        last_error: None,
        observed_generation: generation,
        projection_secret_name: Some(tb.source_secret_name()),
    }
}

/// Map a pod event → a reconcile of the TokenBinding that pod belongs to (watch mapper).
/// Reads the binding annotation the webhook left at injection time.
fn pod_to_binding(pod: &Pod) -> Option<ObjectRef<TokenBinding>> {
    let ns = pod.namespace()?;
    let binding = binding_of(pod.annotations())?;
    Some(ObjectRef::new(&binding).within(&ns))
}

fn error_policy(_tb: Arc<TokenBinding>, err: &ControllerError, _ctx: Arc<Context>) -> Action {
    error!(error = %err, "reconcile returned an unexpected error");
    Action::requeue(BackoffConfig::default().delay(0))
}

/// Controller main loop. Runs once per process.
pub async fn run(ctx: Arc<Context>) -> anyhow::Result<()> {
    let bindings: Api<TokenBinding> = Api::all(ctx.client.clone());
    let pods: Api<Pod> = Api::all(ctx.client.clone());
    let pod_watch = WatcherConfig::default().labels(&format!("{LABEL_INJECTED}=true"));

    Controller::new(bindings, WatcherConfig::default())
        .watches(pods, pod_watch, |pod| pod_to_binding(&pod))
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => info!(binding = ?obj.name, "reconciled"),
                Err(e) => warn!(error = %e, "reconcile loop error"),
            }
        })
        .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oidc_bridge_common::config::Rfc8693Config;
    use oidc_bridge_common::crd::{RenewSpec, TokenBindingSpec};
    use oidc_bridge_common::projection::ProjectionSpec;
    use oidc_bridge_common::{ANNOTATION_BINDING, ANNOTATION_PROJECTION_SECRET};

    fn binding(audience: Option<&str>) -> TokenBinding {
        TokenBinding::new(
            "aistor",
            TokenBindingSpec {
                service_account_name: "sa".to_string(),
                provider_ref: "authentik".to_string(),
                audience: audience.map(String::from),
                scope: None,
                renew: RenewSpec::default(),
                projection: ProjectionSpec::default(),
            },
        )
    }

    fn provider(default_aud: Option<&str>) -> ProviderConfig {
        ProviderConfig::Rfc8693(Rfc8693Config {
            token_endpoint: "https://x/token".to_string(),
            client_id: "c".to_string(),
            client_secret: None,
            audience: default_aud.map(String::from),
            scope: Some("openid".to_string()),
            resource: None,
            requested_token_type: None,
        })
    }

    fn pod(name: &str, labels: &[(&str, &str)], anns: &[(&str, &str)]) -> Pod {
        let lab: BTreeMap<String, String> = labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let ann: BTreeMap<String, String> = anns
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": { "name": name, "namespace": "apps", "uid": "u", "labels": lab, "annotations": ann },
        }))
        .unwrap()
    }

    #[test]
    fn binding_audience_overrides_provider_default() {
        let (aud, scope) =
            effective_audience_scope(&binding(Some("override")), &provider(Some("prov")));
        assert_eq!(aud.as_deref(), Some("override"));
        assert_eq!(scope.as_deref(), Some("openid"));
    }

    #[test]
    fn falls_back_to_provider_audience() {
        let (aud, _) = effective_audience_scope(&binding(None), &provider(Some("prov")));
        assert_eq!(aud.as_deref(), Some("prov"));
    }

    #[test]
    fn truncate_respects_limit_and_char_boundaries() {
        assert_eq!(truncate("short", 1024), "short");
        let long = "a".repeat(2000);
        assert_eq!(truncate(&long, 1024).len(), 1024);
        // Does not panic on a multibyte boundary.
        let multi = "가".repeat(10); // 3 bytes each
        let t = truncate(&multi, 4);
        assert!(t.len() <= 4);
    }

    #[test]
    fn ready_status_points_at_source_secret() {
        let m = MintInfo {
            issued_at: DateTime::from_timestamp(1000, 0).unwrap(),
            expiry: DateTime::from_timestamp(4600, 0).unwrap(),
            next_renew: DateTime::from_timestamp(2800, 0).unwrap(),
        };
        let st = ready_status(&binding(Some("a")), &[], Some(1), &m);
        assert_eq!(st.renew_failures, 0);
        assert_eq!(
            st.projection_secret_name.as_deref(),
            Some("oidc-bridge-src-aistor")
        );
        assert_eq!(
            st.conditions
                .iter()
                .find(|c| c.type_ == "Ready")
                .unwrap()
                .status,
            "True"
        );
    }

    #[test]
    fn pod_to_binding_maps_by_binding_annotation() {
        let p = pod("app-1", &[], &[(ANNOTATION_BINDING, "aistor")]);
        let r = pod_to_binding(&p).unwrap();
        assert_eq!(r.name, "aistor");
        assert_eq!(r.namespace.as_deref(), Some("apps"));

        // A pod without a binding annotation (= not injected) does not map.
        let p2 = pod("app-2", &[], &[]);
        assert!(pod_to_binding(&p2).is_none());
    }

    #[test]
    fn target_predicate_reflects_annotation_contract() {
        let p = pod(
            "app",
            &[],
            &[
                (ANNOTATION_BINDING, "aistor"),
                (ANNOTATION_PROJECTION_SECRET, "oidc-bridge-tok-app"),
            ],
        );
        assert!(pod_targets_binding(p.annotations(), "aistor"));
        assert!(!pod_targets_binding(p.annotations(), "other"));
        assert_eq!(
            p.annotations()
                .get(ANNOTATION_PROJECTION_SECRET)
                .map(String::as_str),
            Some("oidc-bridge-tok-app")
        );
    }
}
