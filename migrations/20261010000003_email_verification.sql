-- Existing local accounts must verify their email before further password login.
-- Federated accounts created from a provider's email_verified=true claim are trusted.
ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMPTZ NULL;
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX email_verification_tokens_user_idx ON email_verification_tokens(user_id,expires_at DESC);
