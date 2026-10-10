# AuthCore security notes

This is **experimental authentication software**, not an audited identity provider.

## Trust boundaries

- The API authenticates access tokens using a configured RSA public key. A matching private key is required to issue tokens.
- PostgreSQL is the source of truth for session revocation and refresh-token consumption.
- Redis provides best-effort distributed abuse prevention; requests are denied on Redis failures.
- Untrusted clients must never be permitted to forge trusted proxy IP headers. This project ignores such headers.
- Refresh tokens are sent as HttpOnly cookies and the rotation endpoint checks `Origin` exactly against `PUBLIC_ORIGIN`.

## Local development vs production

- `compose.yaml` uses development-only credentials and plain HTTP bound to localhost.
- Never put the development environment directly on the public internet.
- Use HTTPS, correctly scoped domain/origin settings, managed secrets, network segmentation and secure operational policies before a deployment.
- The service intentionally refuses non-secure refresh cookies with a non-localhost origin.

## Known gaps

- Release builds require email verification. Reset-token handling has integration tests; external Resend email delivery is not yet verified.
- Google OIDC integration code is present; external authentication against Google has not been tested.
- No RSA signing key rotation.
- Account-enumeration timing differences need additional review.
- No external penetration test or independent security review.

## Reporting security vulnerabilities

Do **not** disclose exploitable details in public issues.
Contact the repository owner privately through GitHub before publishing a security finding.

## RustSec exception: optional SQLx MySQL crypto

`RUSTSEC-2023-0071` refers to the RustCrypto `rsa` crate. Cargo keeps it in the lockfile as an **optional, uncompiled** dependency of `sqlx-mysql`. AuthCore sets `sqlx.default-features=false` and explicitly uses PostgreSQL.

Security CI checks the actual normal/build dependency tree before using a single, documented advisory exception. If RSA or MySQL becomes reachable, the workflow fails instead of masking the vulnerability.

This is **not** a general vulnerability exemption and must be reviewed after dependency/feature changes.
