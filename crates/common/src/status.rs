//! Standard Conditions model and transition logic (spec §4.5, §4.9).
//!
//! Uses two conditions, `Ready`/`Degraded`. The upsert that refreshes
//! `lastTransitionTime` only when the status value changes is kept as a pure function.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const CONDITION_READY: &str = "Ready";
pub const CONDITION_DEGRADED: &str = "Degraded";

pub const STATUS_TRUE: &str = "True";
pub const STATUS_FALSE: &str = "False";

/// k8s standard Condition (schema-compatible fields). Timestamps are RFC3339 strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Condition {
    #[serde(rename = "type")]
    pub type_: String,
    pub status: String,
    pub reason: String,
    pub message: String,
    pub last_transition_time: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

impl Condition {
    pub fn new(
        type_: &str,
        status: &str,
        reason: &str,
        message: impl Into<String>,
        now_rfc3339: &str,
        observed_generation: Option<i64>,
    ) -> Self {
        Self {
            type_: type_.to_string(),
            status: status.to_string(),
            reason: reason.to_string(),
            message: message.into(),
            last_transition_time: now_rfc3339.to_string(),
            observed_generation,
        }
    }
}

/// Returns a **new** vector with the condition of the same `type` inserted/updated.
///
/// If the status is unchanged, preserves the existing `lastTransitionTime`; if it changed,
/// uses `next`'s value. Immutable: the input slice is not modified.
pub fn upsert_condition(current: &[Condition], next: Condition) -> Vec<Condition> {
    let mut out: Vec<Condition> = Vec::with_capacity(current.len() + 1);
    let mut replaced = false;
    for c in current {
        if c.type_ == next.type_ {
            let mut merged = next.clone();
            if c.status == next.status {
                merged.last_transition_time = c.last_transition_time.clone();
            }
            out.push(merged);
            replaced = true;
        } else {
            out.push(c.clone());
        }
    }
    if !replaced {
        out.push(next);
    }
    out
}

/// Condition set with Ready=True / Degraded=False.
pub fn ready(current: &[Condition], now_rfc3339: &str, generation: Option<i64>) -> Vec<Condition> {
    let c = upsert_condition(
        current,
        Condition::new(
            CONDITION_READY,
            STATUS_TRUE,
            "TokenIssued",
            "upstream token issued and delivered",
            now_rfc3339,
            generation,
        ),
    );
    upsert_condition(
        &c,
        Condition::new(
            CONDITION_DEGRADED,
            STATUS_FALSE,
            "TokenIssued",
            "",
            now_rfc3339,
            generation,
        ),
    )
}

/// Condition set with Degraded=True / Ready=False.
pub fn degraded(
    current: &[Condition],
    reason: &str,
    message: impl Into<String>,
    now_rfc3339: &str,
    generation: Option<i64>,
) -> Vec<Condition> {
    let message = message.into();
    let c = upsert_condition(
        current,
        Condition::new(
            CONDITION_READY,
            STATUS_FALSE,
            reason,
            message.clone(),
            now_rfc3339,
            generation,
        ),
    );
    upsert_condition(
        &c,
        Condition::new(
            CONDITION_DEGRADED,
            STATUS_TRUE,
            reason,
            message,
            now_rfc3339,
            generation,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_when_absent() {
        let c = Condition::new(CONDITION_READY, STATUS_TRUE, "R", "m", "t1", Some(1));
        let out = upsert_condition(&[], c.clone());
        assert_eq!(out, vec![c]);
    }

    #[test]
    fn preserves_transition_time_when_status_unchanged() {
        let first = Condition::new(CONDITION_READY, STATUS_TRUE, "R", "m", "t1", Some(1));
        let same_status = Condition::new(CONDITION_READY, STATUS_TRUE, "R2", "m2", "t2", Some(2));
        let out = upsert_condition(&[first], same_status);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].last_transition_time, "t1"); // preserved
        assert_eq!(out[0].reason, "R2"); // the rest is updated
        assert_eq!(out[0].observed_generation, Some(2));
    }

    #[test]
    fn updates_transition_time_when_status_changes() {
        let first = Condition::new(CONDITION_READY, STATUS_TRUE, "R", "m", "t1", None);
        let flipped = Condition::new(CONDITION_READY, STATUS_FALSE, "R", "m", "t2", None);
        let out = upsert_condition(&[first], flipped);
        assert_eq!(out[0].last_transition_time, "t2");
        assert_eq!(out[0].status, STATUS_FALSE);
    }

    #[test]
    fn ready_sets_both_conditions() {
        let out = ready(&[], "t1", Some(3));
        let r = out.iter().find(|c| c.type_ == CONDITION_READY).unwrap();
        let d = out.iter().find(|c| c.type_ == CONDITION_DEGRADED).unwrap();
        assert_eq!(r.status, STATUS_TRUE);
        assert_eq!(d.status, STATUS_FALSE);
    }

    #[test]
    fn degraded_flips_ready_false_and_keeps_history() {
        let start = ready(&[], "t1", Some(1));
        let out = degraded(&start, "ExchangeFailed", "boom", "t2", Some(1));
        let r = out.iter().find(|c| c.type_ == CONDITION_READY).unwrap();
        let d = out.iter().find(|c| c.type_ == CONDITION_DEGRADED).unwrap();
        assert_eq!(r.status, STATUS_FALSE);
        assert_eq!(r.last_transition_time, "t2"); // Ready transitions True->False
        assert_eq!(d.status, STATUS_TRUE);
        assert_eq!(d.message, "boom");
    }
}
