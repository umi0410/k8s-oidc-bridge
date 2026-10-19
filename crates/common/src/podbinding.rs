//! Pure pod↔binding association logic (spec §4.6: per-pod owner-ref projection Secret).
//!
//! On pod admission the webhook picks a projection Secret name dedicated to that pod,
//! records it on the pod as an annotation, and injects a Secret volume of the same name.
//! The controller creates the Secret with that name, owned by the pod via ownerReference.
//! A generateName pod may not have a final name at admission time, in which case the
//! name is derived from the admission request UID.

use std::collections::BTreeMap;

use crate::{ANNOTATION_BINDING, LABEL_INJECT, OPT_OUT_VALUES};

/// Prefix for per-pod projection Secret names.
pub const PER_POD_SECRET_PREFIX: &str = "oidc-bridge-tok-";
/// Maximum k8s name length (DNS-1123 subdomain).
const MAX_NAME_LEN: usize = 253;

/// Lowercase for DNS-1123 and map disallowed characters to `-`. Trim leading/trailing `-`.
fn sanitize(input: &str) -> String {
    let mapped: String = input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    mapped.trim_matches('-').to_string()
}

/// Derives the pod-dedicated projection Secret name (pure and deterministic).
///
/// Uses the pod name if present; otherwise (= generateName) derives it from the admission UID.
pub fn per_pod_secret_name(pod_name: Option<&str>, admission_uid: &str) -> String {
    let base = match pod_name {
        Some(n) if !n.trim().is_empty() => sanitize(n),
        _ => sanitize(admission_uid),
    };
    let base = if base.is_empty() {
        "unknown".to_string()
    } else {
        base
    };
    let mut name = format!("{PER_POD_SECRET_PREFIX}{base}");
    if name.len() > MAX_NAME_LEN {
        name.truncate(MAX_NAME_LEN);
    }
    name.trim_end_matches('-').to_string()
}

/// Whether the pod has explicitly opted out of injection (label value is one of `OPT_OUT_VALUES`).
/// Even within a ns opted in via namespaceSelector, this label can exclude individual pods.
pub fn is_opted_out(labels: &BTreeMap<String, String>) -> bool {
    labels
        .get(LABEL_INJECT)
        .map(String::as_str)
        .is_some_and(|v| OPT_OUT_VALUES.contains(&v))
}

/// Result of selecting a TokenBinding by SA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaMatch {
    /// No binding points at that SA — not an injection target (normal: pods not using the bridge).
    None,
    /// Exactly one.
    One(String),
    /// Two or more point at the same SA — ambiguous, so do not inject (misconfiguration).
    Ambiguous(Vec<String>),
}

/// Among `(binding_name, service_account_name)` candidates, selects the binding matching the pod's SA (pure).
pub fn select_binding_for_sa(candidates: &[(String, String)], sa: &str) -> SaMatch {
    let mut matched: Vec<String> = candidates
        .iter()
        .filter(|(_, binding_sa)| binding_sa == sa)
        .map(|(name, _)| name.clone())
        .collect();
    match matched.len() {
        0 => SaMatch::None,
        1 => SaMatch::One(matched.remove(0)),
        _ => {
            matched.sort();
            SaMatch::Ambiguous(matched)
        }
    }
}

/// Reads the binding annotation the webhook left (for the controller's mapper/decisions).
pub fn binding_of(annotations: &BTreeMap<String, String>) -> Option<String> {
    annotations.get(ANNOTATION_BINDING).cloned()
}

/// Whether an injected pod belongs to this `binding` (based on the binding annotation the webhook wrote).
pub fn pod_targets_binding(annotations: &BTreeMap<String, String>, binding: &str) -> bool {
    binding_of(annotations).as_deref() == Some(binding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn name_from_pod_name() {
        assert_eq!(
            per_pod_secret_name(Some("app-7d9f-abc"), "uid-1"),
            "oidc-bridge-tok-app-7d9f-abc"
        );
    }

    #[test]
    fn name_from_uid_when_no_pod_name() {
        let n = per_pod_secret_name(None, "550E8400-e29b-41d4-a716");
        assert_eq!(n, "oidc-bridge-tok-550e8400-e29b-41d4-a716");
        assert_eq!(per_pod_secret_name(Some(""), "abc"), "oidc-bridge-tok-abc");
    }

    #[test]
    fn name_is_sanitized_and_bounded() {
        let n = per_pod_secret_name(Some("Weird_Name.With/Chars"), "uid");
        assert_eq!(n, "oidc-bridge-tok-weird-name-with-chars");
        let long = "a".repeat(400);
        let bounded = per_pod_secret_name(Some(&long), "uid");
        assert!(bounded.len() <= MAX_NAME_LEN);
        assert!(!bounded.ends_with('-'));
    }

    #[test]
    fn targets_binding_by_annotation() {
        let anns = map(&[(ANNOTATION_BINDING, "aistor")]);
        assert!(pod_targets_binding(&anns, "aistor"));
        assert!(!pod_targets_binding(&anns, "other"));
        assert!(!pod_targets_binding(&BTreeMap::new(), "aistor"));
    }

    #[test]
    fn binding_of_reads_annotation() {
        let anns = map(&[(ANNOTATION_BINDING, "aistor")]);
        assert_eq!(binding_of(&anns), Some("aistor".to_string()));
        assert_eq!(binding_of(&BTreeMap::new()), None);
    }

    #[test]
    fn opt_out_recognizes_false_and_disabled() {
        assert!(is_opted_out(&map(&[(LABEL_INJECT, "false")])));
        assert!(is_opted_out(&map(&[(LABEL_INJECT, "disabled")])));
        // A non-opt-out value (or no label) keeps injection enabled.
        assert!(!is_opted_out(&map(&[(LABEL_INJECT, "true")])));
        assert!(!is_opted_out(&BTreeMap::new()));
    }

    #[test]
    fn select_binding_for_sa_resolves_cases() {
        let candidates = vec![
            ("aistor".to_string(), "bookcellar".to_string()),
            ("other".to_string(), "someone-else".to_string()),
        ];
        assert_eq!(
            select_binding_for_sa(&candidates, "bookcellar"),
            SaMatch::One("aistor".to_string())
        );
        assert_eq!(select_binding_for_sa(&candidates, "nobody"), SaMatch::None);

        let dup = vec![
            ("b".to_string(), "sa".to_string()),
            ("a".to_string(), "sa".to_string()),
        ];
        // If ambiguous, return a sorted list of names (deterministic).
        assert_eq!(
            select_binding_for_sa(&dup, "sa"),
            SaMatch::Ambiguous(vec!["a".to_string(), "b".to_string()])
        );
    }
}
