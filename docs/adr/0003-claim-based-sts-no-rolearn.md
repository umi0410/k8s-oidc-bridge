# 0003. Claim-based STS omits RoleArn

- **Status:** Accepted
- **Date:** 2026-10-19

## Context

For a MinIO/AIStor **claim-based** OpenID provider (policy comes from a JWT claim, not a role policy),
the official docs state a `RoleArn` **must not** be specified on `AssumeRoleWithWebIdentity`. The
stock AWS SDK web-identity credential provider always sends a `RoleArn`, so it is incompatible with a
claim-based relying party. Sending an arbitrary dummy ARN does not help: only MinIO's exact internal
value `arn:minio:iam:::role/dummy-internal` is ignored, and any other unrecognized ARN — notably an
AWS-partition ARN like `arn:aws:...` — fails with "bad partition field".

## Decision

For claim-based relying parties, the consuming app calls STS **without** a `RoleArn`. Where the app
controls its credential provider (rather than relying on the stock SDK chain), it issues
`AssumeRoleWithWebIdentity` directly as a **POST with a form body** containing only the web-identity
token, and omits `RoleArn` (and `DurationSeconds`, so the credential lifetime follows the token).

## Consequences

- Works with claim-based providers with no dummy-ARN guesswork.
- The default SDK web-identity provider cannot be used as-is for claim-based relying parties; a thin custom
  credential provider is required on the consumer side.
- This is a consumer-side convention; the bridge delivers the token (IRSA-style env) and does not call
  STS itself in this path.
