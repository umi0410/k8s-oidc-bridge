//! k8s-oidc-bridge common crate.
//!
//! Collects the **pure logic**: CRD types, the provider config model, the
//! `$secret:key` resolver, renewal/backoff computation, status transitions, and
//! more. It depends on neither the network nor the kube client, so it is all
//! verified with unit tests.

pub mod backoff;
pub mod config;
pub mod crd;
pub mod error;
pub mod podbinding;
pub mod projection;
pub mod renew;
pub mod resolver;
pub mod status;

pub use error::{Error, Result};

/// CRD group. Placeholder domain — replaceable with a domain you own (spec §4.5).
pub const GROUP: &str = "bridge.oidc.io";
/// Short prefix used for k8s resources/labels/annotations.
pub const PREFIX: &str = "oidc-bridge";

/// Label that controls injection. On a **namespace** it is opt-in (value=`ENABLE_VALUE`);
/// on a **pod** it is opt-out (if the value is one of `OPT_OUT_VALUES`, only that pod is excluded).
/// The webhook reads this label via namespaceSelector (ns opt-in) + objectSelector (pod opt-out).
pub const LABEL_INJECT: &str = "bridge.oidc.io/inject";
/// Namespace opt-in label value.
pub const ENABLE_VALUE: &str = "enabled";
/// Label values recognized as a pod opt-out.
pub const OPT_OUT_VALUES: [&str; 2] = ["false", "disabled"];

/// **Marker label** (value=`"true"`) the webhook leaves on a pod it finished injecting.
/// The controller watches/lists pods by this label — the binding name goes in the
/// annotation below, not the label value (limited to 63 chars).
pub const LABEL_INJECTED: &str = "bridge.oidc.io/injected";
/// Annotation where the webhook records the `TokenBinding` name it resolved from the
/// pod's SA. Used for the controller's pod→binding mapping and fan-out target decision
/// (written by the webhook, not the user).
pub const ANNOTATION_BINDING: &str = "bridge.oidc.io/binding";
/// webhook↔controller contract: the webhook records the per-pod projection Secret name
/// on the pod, and the controller creates the per-pod Secret under that name (spec §4.6).
pub const ANNOTATION_PROJECTION_SECRET: &str = "bridge.oidc.io/projection-secret-name";
