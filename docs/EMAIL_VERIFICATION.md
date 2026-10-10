# Email verification

Password accounts must prove control of their email inbox using a single-use, 30-minute token.

1. `POST /api/v1/auth/register` creates a pending account and sends verification email via Resend.
2. Submit the received token to `POST /api/v1/auth/verify-email` as `{"token":"..."}`.
3. Only verified accounts can log in with a password or request password recovery.
4. To request another code, `POST /api/v1/auth/resend-verification` accepts `{"email":"someone@example.com"}` and returns a generic 202 response.

Release binaries require `RESEND_API_KEY` and `RESET_FROM_EMAIL` to register password users. In debug builds only, `AUTHCORE_DEV_SKIP_EMAIL_VERIFICATION=true` is accepted for a loopback-bound local server to keep CI tests independent of a live mail service.

**Limitations:** delivery through the real external provider is not exercised in CI; existing password accounts are migrated as pending and need fresh verification. Don't deploy a debug executable publicly.
