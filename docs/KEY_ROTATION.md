# RSA signing-key rotation

AuthCore uses an RS256 JWT with a **configured key identifier** (`kid`) in the header.
Untrusted `kid` values can only select an entry from an in-memory map loaded from
trusted local PEM files at startup. They are never interpreted as filesystem paths or URLs.

## Procedure

1. Generate a fresh 3072-bit RSA key pair on a trusted host; protect the private key and keep it out of source control.
2. Set `JWT_PRIVATE_KEY_PATH` and `JWT_PUBLIC_KEY_PATH` to the new files.
3. Choose a new unique `JWT_ACTIVE_KID`, for example `release-2026.10`.
4. Configure `JWT_LEGACY_PUBLIC_KEYS_JSON` with the *old* public key(s), e.g.:
   `{"primary":"/app/keys/old-public.pem"}`
5. Restart all service instances with **identical verification-key sets**, then deploy the new signer. In a rolling deployment, stage the new public key across all verifiers *before* issuing any token with the new `kid`.
6. Keep old public keys until all JWTs using them are expired (15 minutes plus allowed clock skew), then remove the retired keys from the configuration.

## Threat model and caveats

- Only RS256 is accepted. Unknown `kid`, wrong signatures and algorithm substitution are rejected.
- At most 16 legacy keys are permitted. `kid` is constrained to a conservative ASCII alphabet and max 64 bytes.
- Changing keys does **not** rotate or revoke opaque refresh credentials or active database sessions.
- This is configuration-driven rotation; there is no automatic KMS, public JWKS endpoint or scheduled rotation job.
- PEM files must be protected with OS-level access controls. Do not store private keys in GitHub.
- Test changes on a staging environment before rolling out.
