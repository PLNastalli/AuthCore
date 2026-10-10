# AuthCore threat model (development)

This document is a design review, **not** a completed penetration test or a compliance statement.

## Assets and trust boundaries

| Asset | Owner / storage | Primary risk |
| --- | --- | --- |
| Passwords | Client → Argon2id in API → PostgreSQL hash | Credential theft, brute force, account enumeration |
| JWT signing keys | PEM files on the host/container volume | Forgery of access tokens |
| Opaque refresh tokens | HttpOnly cookies; SHA-256 digests in PostgreSQL | Replay, theft, session fixation |
| OAuth code, nonce, PKCE verifier | Browser → OAuth callback → Redis single-use state | CSRF, substitution, redirect/token interception |
| Password recovery/verification tokens | Mailbox; hashes in PostgreSQL | Inbox compromise, leakage, replays |
| Redis state | Private service network | Rate-limit bypass, session/login denial |
| Database | Private service network | Data loss, tampering, unauthorized account access |

Clients, email providers and Google are **not** inside the API trust boundary.
`X-Forwarded-For` is deliberately not trusted unless a future explicitly
configured trusted proxy implementation is added.

## Attack paths and current controls

- **Forged JWT:** allowlist RS256; validate issuer, audience, expiry, token type
  and configured `kid` (no URL-based key retrieval), then check session status in PostgreSQL
- **Refresh token replay:** 48 cryptographically random bytes, hash-at-rest,
  atomic database lock and replacement; consumed-token replay revokes its session
- **Brute force and resource exhaustion:** Redis Lua rate limits; maximum four concurrent
  Argon2 operations with a bounded acquisition timeout; 16-KiB HTTP request bodies
- **CSRF:** protected `Origin` requirement for cookie-based refresh; OAuth
  `state`, PKCE and short-lived browser-bound state cookie
- **Password reset / verification abuse:** short expiry, single-use token hashes,
  generic account-existence responses where practical, per-IP and per-email limits
- **Credential change races:** compare-and-swap during password updates, lock account
  when creating sessions and validating email ownership
- **Secret leakage:** no private PEM or real credentials in Git; trace spans omit
  OAuth callback query strings; redacted API errors; no reset tokens in responses

## Remaining risks

- Live external provider flows require staging E2E testing.
- This implementation does not manage infrastructure ACLs, reverse proxy TLS,
  KMS/HSM controls, rate-limiting at the edge, WAF policy or service account roles.
- Email normalization is basic and may conflict with internationalized addresses.
- No formal side-channel review, third-party security audit, penetration test, incident
  response exercise, managed key rollover or MFA.
- Expired rows and audit-event retention need an explicit housekeeping policy.
- Reused refresh tokens revoke the entire session. Clients that race refresh calls
  may need to retry sign-in: this is an intentional security/availability tradeoff.

## Verification checklist

- [x] Rust and contract tests in CI, including concurrent refresh and password updates
- [x] PostgreSQL and Redis integration coverage
- [x] Token signature/issuer/audience/nonce adversarial validation
- [x] Security dependency auditing with narrowly scoped reviewed exception
- [ ] Real Google and Resend staging tests
- [ ] Independent review, penetration test and dependency supply-chain assessment
- [ ] Operational key management and deployment acceptance tests

See [SECURITY.md](../SECURITY.md) for vulnerability reporting and
[ENGINEERING_REVIEW.md](ENGINEERING_REVIEW.md) for engineering tradeoffs.
