# Engineering review — AuthCore

This is a living review log, not a certificate of security or performance. Current status and automated test evidence are in the README. The code is an experimental backend, subject to external audit before real user data is entrusted to it.

## Rules followed

- **Correctness over claims:** source code is checked in CI; tests run against PostgreSQL and Redis, not just in-memory mocks.
- **Rust idioms:** one crate, explicit `Result` and `Option`, limited shared state, no custom cryptographic primitives, no `unsafe` blocks.
- **Architecture:** independent HTTP, persistence, crypto, OAuth and recovery modules, without domain trait hierarchies or speculative workspaces.
- **Concurrency:** refresh rotates under locks on both session and credential rows; replay invalidates the session. Password changes compare-and-swap the prior hash. Argon2 work runs off the async executor under a 4-permit semaphore.
- **Security:** strict JWT validation and a known `kid`; hashed opaque refresh tokens; Redis fixed-window rate limits that fail closed; verified local email before password login; reset links never appear in API responses; request tracing omits OAuth query parameters.
- **Operational behavior:** private signing keys are generated outside the repository, migrations are versioned, Docker runs non-root and the CI matrix includes a release build.
- **Performance claims:** no throughput or latency figures have been published because representative load benchmarks have not been run.

## Known gaps that prevent production readiness

1. Live Google OAuth and Resend email delivery still require manual testing against provider credentials.
2. A third-party security assessment, deployment threat model and penetration test have not been completed.
3. Email normalization is deliberately conservative and lowercases the whole address; the comparison policy must be reviewed for internationalized email and providers with case-sensitive local parts.
4. Distributed rate limiting currently uses a fixed window. A token-bucket strategy and carefully configured trusted proxy semantics may be needed at scale.
5. The project has no automatic expiry cleanup job, audit-event retention policy, or fully documented disaster recovery process.
6. Session-list pagination, provider account linking, automatic KMS-driven rotation and MFA are not implemented.
7. Credentials are not automatically zeroized in every memory buffer; inspect cryptographic and password handling with a dedicated security review.
8. Dependency audits report advisories but cannot substitute for code-level review.

## Quality gates

The main GitHub Actions workflow is intended to enforce:

```shell
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo build --release --locked
docker compose config --quiet
docker build -t authcore:ci .
```

The separate Security workflow runs `cargo audit` on the committed `Cargo.lock` and also checks it weekly. Check actual Actions status before asserting that an individual run passed.

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Email Validation and Verification](https://cheatsheetseries.owasp.org/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.html)
- [OAuth 2.0 Security Best Current Practice — RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)

## Dependency advisory exception

`cargo audit` examines `Cargo.lock`, which includes optional feature dependencies even when their code is **not compiled**. In this project, `sqlx-mysql` pulls in `rsa 0.9.10` and triggers `RUSTSEC-2023-0071`, but we use PostgreSQL only and explicitly set `sqlx.default-features = false`.

The Security CI has a **fail-closed reachability gate**: it scans the actual normal/build dependency tree, failing if `sqlx-mysql` or `rsa` appears. Only after that proof does it invoke `cargo audit --ignore RUSTSEC-2023-0071`, so other RustSec vulnerabilities still fail the workflow.

This exception is **not a claim that `rsa` is patched**. Revisit the exception whenever SQLx features, JWT libraries or dependency trees change. The referenced advisory has no patched RSA release as of October 2026.

- [Cargo resolver documentation](https://doc.rust-lang.org/cargo/reference/resolver.html)
- [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
