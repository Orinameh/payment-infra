-- +goose Up
CREATE TABLE wallets (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id),
    currency       CHAR(3) NOT NULL,
    balance        NUMERIC(28,8) NOT NULL DEFAULT 0,
    version        BIGINT NOT NULL DEFAULT 0,
    status         TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active','frozen','closed')),
    -- Final backstop: PostgreSQL rejects negative balances regardless
    -- of what the application code thinks.
    CONSTRAINT wallets_balance_non_negative CHECK (balance >= 0),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, currency)
);
CREATE INDEX idx_wallets_user ON wallets(user_id);
CREATE INDEX idx_wallets_status ON wallets(status);

-- +goose Down
DROP TABLE IF EXISTS wallets;
