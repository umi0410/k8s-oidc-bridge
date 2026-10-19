//! Exponential backoff parameters and pure delay computation (spec §4.7).
//!
//! The actual retry loop runs in the controller via `backon`. Here we provide
//! the config and the "delay of the nth attempt" as pure functions so they're testable.

use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// base 1s → cap 5m, jitter on. No maximum retry limit (spec §4.7).
pub const DEFAULT_BASE_SECONDS: u64 = 1;
pub const DEFAULT_CAP_SECONDS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackoffConfig {
    #[serde(default = "default_base")]
    pub base_seconds: u64,
    #[serde(default = "default_cap")]
    pub cap_seconds: u64,
    #[serde(default = "default_jitter")]
    pub jitter: bool,
}

fn default_base() -> u64 {
    DEFAULT_BASE_SECONDS
}
fn default_cap() -> u64 {
    DEFAULT_CAP_SECONDS
}
fn default_jitter() -> bool {
    true
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            base_seconds: DEFAULT_BASE_SECONDS,
            cap_seconds: DEFAULT_CAP_SECONDS,
            jitter: default_jitter(),
        }
    }
}

impl BackoffConfig {
    /// Delay upper bound for attempt (0-based) = min(cap, base·2^attempt).
    ///
    /// Jitter is applied separately via [`apply_jitter`] (this function is deterministic).
    pub fn delay(&self, attempt: u32) -> Duration {
        let base = self.base_seconds.max(1);
        let cap = self.cap_seconds.max(base);
        // Saturate 2^attempt overflow to cap.
        let scaled = base.checked_shl(attempt).map(|s| s.saturating_mul(1));
        let secs = scaled.map(|s| s.min(cap)).unwrap_or(cap);
        Duration::from_secs(secs.min(cap))
    }
}

/// full jitter: `delay * rand01`, rand01 ∈ [0,1]. RNG is injected to make it testable.
pub fn apply_jitter(delay: Duration, rand01: f64) -> Duration {
    let f = rand01.clamp(0.0, 1.0);
    delay.mul_f64(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_growth_until_cap() {
        let b = BackoffConfig {
            base_seconds: 1,
            cap_seconds: 300,
            jitter: false,
        };
        assert_eq!(b.delay(0), Duration::from_secs(1));
        assert_eq!(b.delay(1), Duration::from_secs(2));
        assert_eq!(b.delay(2), Duration::from_secs(4));
        assert_eq!(b.delay(8), Duration::from_secs(256));
        // 2^9 = 512 > 300 → cap.
        assert_eq!(b.delay(9), Duration::from_secs(300));
        // Even if shl overflows at a large attempt, it saturates to cap.
        assert_eq!(b.delay(1000), Duration::from_secs(300));
    }

    #[test]
    fn defaults_match_spec() {
        let b = BackoffConfig::default();
        assert_eq!(b.base_seconds, 1);
        assert_eq!(b.cap_seconds, 300);
        assert!(b.jitter);
    }

    #[test]
    fn jitter_bounds() {
        let d = Duration::from_secs(100);
        assert_eq!(apply_jitter(d, 0.0), Duration::ZERO);
        assert_eq!(apply_jitter(d, 1.0), d);
        assert_eq!(apply_jitter(d, 0.5), Duration::from_secs(50));
        // Out-of-range inputs are clamped.
        assert_eq!(apply_jitter(d, 2.0), d);
        assert_eq!(apply_jitter(d, -1.0), Duration::ZERO);
    }

    #[test]
    fn deserializes_with_defaults() {
        let b: BackoffConfig = serde_yaml::from_str("baseSeconds: 2").unwrap();
        assert_eq!(b.base_seconds, 2);
        assert_eq!(b.cap_seconds, 300);
        assert!(b.jitter);
    }
}
