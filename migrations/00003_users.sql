-- +goose Up
CREATE TABLE users (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email             CITEXT NOT NULL UNIQUE,
    password_hash     TEXT NOT NULL,
    full_name         TEXT NOT NULL,
    phone_encrypted   BYTEA,             -- AES-256-GCM encrypted
    bvn_encrypted     BYTEA,             -- Bank Verification Number, encrypted
    nin_encrypted     BYTEA,             -- National Identity Number, encrypted
    status            TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active','suspended','closed')),
    kyc_tier          SMALLINT NOT NULL DEFAULT 0
                      CHECK (kyc_tier BETWEEN 0 AND 3),
    kyc_verified_at   TIMESTAMPTZ,
    consent_given_at  TIMESTAMPTZ,       -- NDPR explicit consent timestamp
    dpo_notified_at   TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_kyc_tier ON users(kyc_tier);


-- NDPR: consent is explicit and traceable
CREATE TABLE user_consents (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id),
    purpose     TEXT NOT NULL,
    granted     BOOLEAN NOT NULL,
    ip_address  INET,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_consents_user ON user_consents(user_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS user_consents;
DROP TABLE IF EXISTS users;
