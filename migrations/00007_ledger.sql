-- +goose Up
CREATE TABLE transactions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type           TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'posted'
                   CHECK (status IN ('pending','posted','failed','reversed')),
    reference      TEXT,
    end_to_end_id  TEXT,                  -- ISO 20022 EndToEndId
    total_minor    BIGINT,
    currency       CHAR(3) REFERENCES currencies(code),
    metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    posted_at      TIMESTAMPTZ
);
CREATE INDEX idx_transactions_created ON transactions(created_at DESC);
CREATE INDEX idx_transactions_ref ON transactions(reference)
    WHERE reference IS NOT NULL;

CREATE TABLE ledger_entries (
    id             BIGSERIAL PRIMARY KEY,
    transaction_id UUID NOT NULL REFERENCES transactions(id),
    wallet_id      UUID NOT NULL REFERENCES wallets(id),
    -- Signed amount in minor units. Positive = credit, negative = debit.
    amount         BIGINT NOT NULL,
    currency       CHAR(3) NOT NULL REFERENCES currencies(code),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_ledger_wallet ON ledger_entries(wallet_id, id);
CREATE INDEX idx_ledger_tx ON ledger_entries(transaction_id);

-- Append-only at the database level. No UPDATE, no DELETE.
-- StatementBegin/End: goose splits statements on semicolons, which
-- would shred the $$ body below. The annotation sends it as one unit.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ledger_entries_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'ledger_entries is append-only';
END $$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER trg_ledger_immutable
BEFORE UPDATE OR DELETE ON ledger_entries
FOR EACH ROW EXECUTE FUNCTION ledger_entries_immutable();

-- +goose Down
DROP TRIGGER IF EXISTS trg_ledger_immutable ON ledger_entries;
DROP FUNCTION IF EXISTS ledger_entries_immutable();
DROP TABLE IF EXISTS ledger_entries;
DROP TABLE IF EXISTS transactions;