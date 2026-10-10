# Security policy

AuthCore is an **experimental authentication backend** and must not be deployed to protect real user accounts without independent review.

## Supported versions

Only the latest `main` branch receives security fixes. There are no production-supported releases.

## Reporting a vulnerability

Please **do not disclose exploit details in public GitHub issues**.

If GitHub's private vulnerability reporting is enabled for this repository, use the private reporting link under **Security → Advisories → Report a vulnerability**. Otherwise, contact the repository maintainer privately through their GitHub profile to coordinate a safe report.

Include the affected version or commit, clear reproduction steps, the potential impact, and a suggested mitigation if available. Do not include real access tokens, personal data, or third-party secrets.

## Current security posture

- Automated Rust formatting, compilation, Clippy, tests, Docker build and RustSec dependency audit run in GitHub Actions.
- An advisory concerning `rsa` (`RUSTSEC-2023-0071`) exists in the lockfile through an **optional SQLx MySQL dependency**. Security CI permits the advisory only after checking that `rsa` and `sqlx-mysql` are not included in the actual production dependency tree.
- Automated checks do **not** replace a security audit.
- Google OAuth and Resend email flows require real-provider integration tests.
- Signing-key rotation, deployment hardening and operational threat modeling are still pending.

See [the detailed security design](docs/SECURITY.md) and [engineering review](docs/ENGINEERING_REVIEW.md).
