//! Estimate the expiry of the upstream token.
//!
//! Uses the exchange response's `expires_in` first; if absent and the upstream token is a JWT,
//! falls back to its `exp` claim. JWT parsing uses `jsonwebtoken`, but **without signature
//! verification** (we are not the issuer — we only need the lifetime of a token we hold, spec §3).

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::Deserialize;

/// Conservative default TTL (seconds) when both expires_in and JWT exp are absent.
pub const FALLBACK_TTL_SECONDS: i64 = 3600;

#[derive(Debug, Deserialize)]
struct ExpClaim {
    exp: i64,
}

/// Read a JWT's `exp` without signature verification. Returns None if not a JWT or exp is absent.
pub fn token_expiry(token: &str) -> Option<DateTime<Utc>> {
    let mut validation = Validation::default();
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();

    let data = decode::<ExpClaim>(token, &DecodingKey::from_secret(b""), &validation).ok()?;
    DateTime::from_timestamp(data.claims.exp, 0)
}

/// Determine the expiry time from the issue time and the exchange response.
///
/// Priority: `expires_in` → upstream token JWT `exp` → default TTL.
pub fn compute_expiry(
    issued_at: DateTime<Utc>,
    expires_in: Option<i64>,
    access_token: &str,
) -> DateTime<Utc> {
    if let Some(secs) = expires_in.filter(|s| *s > 0) {
        return issued_at + Duration::seconds(secs);
    }
    if let Some(exp) = token_expiry(access_token) {
        return exp;
    }
    issued_at + Duration::seconds(FALLBACK_TTL_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;

    #[derive(Serialize)]
    struct Claims {
        exp: i64,
        sub: String,
    }

    fn jwt_with_exp(exp: i64) -> String {
        encode(
            &Header::default(),
            &Claims {
                exp,
                sub: "sa".to_string(),
            },
            &EncodingKey::from_secret(b"any"),
        )
        .unwrap()
    }

    #[test]
    fn expires_in_takes_priority() {
        let issued = DateTime::from_timestamp(1_000, 0).unwrap();
        let got = compute_expiry(issued, Some(600), "ignored");
        assert_eq!(got, DateTime::from_timestamp(1_600, 0).unwrap());
    }

    #[test]
    fn falls_back_to_jwt_exp() {
        let issued = DateTime::from_timestamp(1_000, 0).unwrap();
        let token = jwt_with_exp(5_000);
        let got = compute_expiry(issued, None, &token);
        assert_eq!(got, DateTime::from_timestamp(5_000, 0).unwrap());
    }

    #[test]
    fn falls_back_to_default_ttl_for_opaque_token() {
        let issued = DateTime::from_timestamp(1_000, 0).unwrap();
        let got = compute_expiry(issued, None, "opaque-not-a-jwt");
        assert_eq!(
            got,
            DateTime::from_timestamp(1_000 + FALLBACK_TTL_SECONDS, 0).unwrap()
        );
    }

    #[test]
    fn zero_or_negative_expires_in_ignored() {
        let issued = DateTime::from_timestamp(1_000, 0).unwrap();
        let got = compute_expiry(issued, Some(0), "opaque");
        assert_eq!(
            got,
            DateTime::from_timestamp(1_000 + FALLBACK_TTL_SECONDS, 0).unwrap()
        );
    }

    #[test]
    fn reads_exp_from_jwt_directly() {
        let token = jwt_with_exp(42);
        assert_eq!(token_expiry(&token), DateTime::from_timestamp(42, 0));
        assert_eq!(token_expiry("garbage"), None);
    }
}
