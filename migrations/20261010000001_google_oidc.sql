CREATE TABLE oauth_accounts (
    provider TEXT NOT NULL,
    provider_sub TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email_at_link TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider, provider_sub),
    UNIQUE (provider, user_id)
);
CREATE INDEX oauth_accounts_user_idx ON oauth_accounts(user_id);
