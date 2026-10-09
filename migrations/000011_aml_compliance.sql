-- +goose Up
-- +goose StatementBegin
-- AML/CFT/CPF: real-time monitoring per CBN Baseline Standards (2025).
CREATE TABLE aml_alerts (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             UUID NOT NULL REFERENCES users(id),
    wallet_id           UUID REFERENCES wallets(id),
    transaction_id      UUID REFERENCES transactions(id),
    rule_code           TEXT NOT NULL,
    severity            TEXT NOT NULL
                        CHECK (severity IN ('low','medium','high','critical')),
    description         TEXT NOT NULL,
    amount_minor        BIGINT,
    currency            CHAR(3),
    status              TEXT NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open','investigating','closed','reported')),
    reported_to_nfiu_at TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_aml_user ON aml_alerts(user_id, created_at DESC);
CREATE INDEX idx_aml_status ON aml_alerts(status);

-- CBN tiered limits. All amounts in minor units (kobo).
CREATE TABLE transaction_limits (
    kyc_tier          SMALLINT PRIMARY KEY,
    currency          CHAR(3) NOT NULL REFERENCES currencies(code),
    daily_limit       BIGINT NOT NULL,
    single_tx_limit   BIGINT NOT NULL,
    new_account_cap   BIGINT,
    new_account_hours INT NOT NULL DEFAULT 24,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Tier 0: ₦200,  Tier 1: ₦50,000 single / ₦200,000 daily
-- Tier 2: ₦500,000 single / ₦1,000,000 daily
-- Tier 3: ₦5,000,000 single / ₦10,000,000 daily
INSERT INTO transaction_limits
    (kyc_tier, currency, daily_limit, single_tx_limit, new_account_cap)
VALUES
    (0, 'NGN',     2000000,     2000000,    2000000),   -- ₦20,000 cap
    (1, 'NGN',   200000000,    50000000,       NULL),
    (2, 'NGN',  1000000000,   500000000,       NULL),
    (3, 'NGN', 10000000000,  5000000000,       NULL)
ON CONFLICT (kyc_tier) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS transaction_limits;
DROP TABLE IF EXISTS aml_alerts;
-- +goose StatementEnd
