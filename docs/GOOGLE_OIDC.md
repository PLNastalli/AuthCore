# Google OIDC integration

The service implements Authorization Code + PKCE (S256), a random one-time `state`, `nonce`, a Lax anti-CSRF cookie bound to the browser, Redis single-use state storage, Google token exchange and RS256 ID-token validation against Google JWKS.

## Configuration

1. In Google Cloud Console, configure an OAuth Web Application.
2. Register `http://localhost:3000/api/v1/oauth/google/callback` for local development (or use your HTTPS production origin).
3. Set these environment variables (all three are required):
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`
   - `GOOGLE_REDIRECT_URI=http://localhost:3000/api/v1/oauth/google/callback`
4. Set `PUBLIC_ORIGIN=http://localhost:3000` for local use.
5. Start the API and navigate in a browser to `http://localhost:3000/api/v1/oauth/google/start`.

The callback responds with an AuthCore access JWT as JSON and a refresh cookie. No frontend is provided.

## Security properties

- State is single-use and stored in Redis with a ten-minute expiration.
- The browser receives an `HttpOnly`, `SameSite=Lax` state-binding cookie. Lax is necessary for Google's top-level cross-site redirect.
- A code verifier and nonce are never sent as URL parameters in the callback.
- Google-signed ID tokens are verified using JWKS and issuer, audience, expiration, email verification and nonce checks.
- Google identities are keyed by the stable provider `sub`; a matching email is **not sufficient** for account linking.
- HTTPS and the `__Host-` cookie prefix are expected for production.

## Limitations

The live Google exchange **has not been exercised in CI** and depends on external credentials. JWKS caching, explicit authorized account linking, rotation scenarios, security review and deployment hardening remain future tasks.
