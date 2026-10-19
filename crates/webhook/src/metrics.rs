//! Webhook injection metrics (spec §4.9).

use metrics::{counter, describe_counter};

const INJECT_TOTAL: &str = "oidc_bridge_webhook_inject_total";

pub fn describe() {
    describe_counter!(INJECT_TOTAL, "admission injection results");
}

pub fn record(result: &'static str) {
    counter!(INJECT_TOTAL, "result" => result).increment(1);
}

pub const INJECTED: &str = "injected";
pub const SKIPPED: &str = "skipped";
pub const ERROR: &str = "error";
