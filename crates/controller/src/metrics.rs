//! Prometheus metrics (spec §4.9).
//!
//! Records to the `metrics` facade; `metrics-exporter-prometheus` handles exposition.

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};

const ISSUE_TOTAL: &str = "oidc_bridge_issue_total";
const RENEW_TOTAL: &str = "oidc_bridge_renew_total";
const EXCHANGE_LATENCY: &str = "oidc_bridge_exchange_duration_seconds";
const EXPIRY_SECONDS: &str = "oidc_bridge_token_expiry_seconds";

/// Register metric descriptions (once, right after installing the exporter).
pub fn describe() {
    describe_counter!(ISSUE_TOTAL, "SA token exchange issue attempts by result");
    describe_counter!(RENEW_TOTAL, "token renew attempts by result");
    describe_histogram!(EXCHANGE_LATENCY, "upstream exchange latency in seconds");
    describe_gauge!(EXPIRY_SECONDS, "seconds until token expiry, per binding");
}

fn result(ok: bool) -> &'static str {
    if ok {
        "success"
    } else {
        "failure"
    }
}

pub fn record_issue(binding: &str, ok: bool) {
    counter!(ISSUE_TOTAL, "binding" => binding.to_string(), "result" => result(ok)).increment(1);
}

pub fn record_renew(binding: &str, ok: bool) {
    counter!(RENEW_TOTAL, "binding" => binding.to_string(), "result" => result(ok)).increment(1);
}

pub fn observe_exchange_latency(binding: &str, seconds: f64) {
    histogram!(EXCHANGE_LATENCY, "binding" => binding.to_string()).record(seconds);
}

pub fn set_expiry_seconds(binding: &str, seconds: f64) {
    gauge!(EXPIRY_SECONDS, "binding" => binding.to_string()).set(seconds);
}
