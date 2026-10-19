//! Proactive renewal-time computation (spec §4.5, §4.7).
//!
//! `nextRenewTime = issuedAt + thresholdPercent·TTL`. Default threshold 50%.

use chrono::{DateTime, Duration, Utc};

use crate::error::{Error, Result};

/// Controller default threshold (%). Overridden by the binding's `renew.thresholdPercent`.
pub const DEFAULT_THRESHOLD_PERCENT: u32 = 50;

/// Validates the threshold is within 1..=100.
pub fn validate_threshold(percent: u32) -> Result<u32> {
    if (1..=100).contains(&percent) {
        Ok(percent)
    } else {
        Err(Error::InvalidRenew(format!(
            "thresholdPercent must be in 1..=100, got {percent}"
        )))
    }
}

/// Computes the next renewal time from the issued/expiry times and the threshold.
///
/// If `expiry <= issued_at`, treats it as renew-immediately (= issued_at).
pub fn next_renew_time(
    issued_at: DateTime<Utc>,
    expiry: DateTime<Utc>,
    threshold_percent: u32,
) -> Result<DateTime<Utc>> {
    let pct = validate_threshold(threshold_percent)? as i64;
    let ttl = expiry - issued_at;
    if ttl <= Duration::zero() {
        return Ok(issued_at);
    }
    // Convert to i64 milliseconds to compute the ratio without overflow.
    let offset_ms = ttl.num_milliseconds() * pct / 100;
    Ok(issued_at + Duration::milliseconds(offset_ms))
}

/// Decides whether a re-mint (re-exchange) is needed now (pure).
///
/// True if the source Secret is missing, there is no renewal-time info, or the renewal time has passed.
/// If still valid (e.g. a reconcile woken by a pod event) → false → reuse the source token.
pub fn needs_remint(
    next_renew: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    source_exists: bool,
) -> bool {
    if !source_exists {
        return true;
    }
    match next_renew {
        Some(t) => now >= t,
        None => true,
    }
}

/// Time remaining until renewal relative to `now`. 0 if already past.
pub fn duration_until_renew(next_renew: DateTime<Utc>, now: DateTime<Utc>) -> Duration {
    let d = next_renew - now;
    if d < Duration::zero() {
        Duration::zero()
    } else {
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn fifty_percent_of_ttl() {
        let issued = t(1_000);
        let expiry = t(1_000 + 3600); // 1h TTL
        let next = next_renew_time(issued, expiry, 50).unwrap();
        assert_eq!(next, t(1_000 + 1800));
    }

    #[test]
    fn custom_threshold() {
        let issued = t(0);
        let expiry = t(1000);
        assert_eq!(next_renew_time(issued, expiry, 10).unwrap(), t(100));
        assert_eq!(next_renew_time(issued, expiry, 90).unwrap(), t(900));
        assert_eq!(next_renew_time(issued, expiry, 100).unwrap(), t(1000));
    }

    #[test]
    fn non_positive_ttl_renews_immediately() {
        let issued = t(500);
        assert_eq!(next_renew_time(issued, t(500), 50).unwrap(), issued);
        assert_eq!(next_renew_time(issued, t(100), 50).unwrap(), issued);
    }

    #[test]
    fn threshold_bounds_validated() {
        assert!(validate_threshold(0).is_err());
        assert!(validate_threshold(101).is_err());
        assert!(validate_threshold(1).is_ok());
        assert!(validate_threshold(100).is_ok());
        assert!(matches!(
            next_renew_time(t(0), t(10), 0).unwrap_err(),
            Error::InvalidRenew(_)
        ));
    }

    #[test]
    fn needs_remint_logic() {
        let now = t(1_000);
        // No source → always re-mint.
        assert!(needs_remint(Some(t(5_000)), now, false));
        // Still valid → reuse (false).
        assert!(!needs_remint(Some(t(5_000)), now, true));
        // Renewal time passed → re-mint.
        assert!(needs_remint(Some(t(500)), now, true));
        // No renewal-time info → re-mint.
        assert!(needs_remint(None, now, true));
    }

    #[test]
    fn duration_until_renew_clamps_to_zero() {
        assert_eq!(duration_until_renew(t(100), t(50)), Duration::seconds(50));
        assert_eq!(duration_until_renew(t(100), t(200)), Duration::zero());
    }
}
