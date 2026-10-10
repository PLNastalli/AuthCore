# Password recovery

The password reset flow is API-only. It stores a SHA-256 digest of each high-entropy random token, never the raw token.

## Configure delivery

Provide the following settings through environment variables:

- `RESEND_API_KEY` — Resend API key with permission to send email.
- `RESET_FROM_EMAIL` — email address using your verified sender domain.

Without these settings, `POST /api/v1/auth/forgot-password` returns 503 for all users.

## API

`POST /api/v1/auth/forgot-password`:

```json
{"email":"dev@example.com"}
```

Returns HTTP 202 for both known and unknown accounts (unless a shared rate limit rejects the request or a dependency fails). When an account exists, Resend receives a plaintext email containing a token valid for 15 minutes. Tokens are never returned to the HTTP requester. Delivery failures invalidate the created token.

`POST /api/v1/auth/reset-password`:

```json
{"token":"TOKEN_FROM_EMAIL","new_password":"another-long-unique-password"}
```

A successful reset consumes all outstanding recovery tokens and revokes all active sessions. A replay of the token is rejected.

## Limitations

Resend API delivery cannot be tested without valid service credentials. Registration does not yet verify email ownership and cannot be considered production-ready. All mail tokens must be protected as credentials; do not include them in analytics or public logs.
