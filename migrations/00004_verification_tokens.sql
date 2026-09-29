-- +goose Up
CREATE TABLE verification_tokens (
    id           BIGSERIAL PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id),
    purpose      TEXT NOT NULL
                 CHECK (purpose IN ('email_verify','phone_verify','password_reset')),
    token_hash   TEXT NOT NULL UNIQUE,       -- SHA-256 of plaintext token
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ,
    ip_address   INET,
    user_agent   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_vtokens_user ON verification_tokens(user_id, purpose);
CREATE INDEX idx_vtokens_lookup ON verification_tokens(token_hash)
    WHERE consumed_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS verification_tokens;