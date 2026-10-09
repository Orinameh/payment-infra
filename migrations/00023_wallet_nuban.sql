-- +goose Up
-- +goose StatementBegin
-- Virtual NUBAN per wallet: every wallet gets a 10-digit account
-- number rooted at our institution bank code so it is addressable
-- from any Nigerian bank (name enquiry, inbound NIP). Nullable so
-- existing wallets backfill lazily via the worker; UNIQUE enforced.
ALTER TABLE wallets ADD COLUMN IF NOT EXISTS account_number CHAR(10) UNIQUE;
CREATE INDEX IF NOT EXISTS idx_wallets_account ON wallets(account_number)
    WHERE account_number IS NOT NULL;

-- System user owning per-currency NIP settlement wallets. Outbound
-- bank transfers debit the user and credit settlement (keeping the
-- ledger balanced); the float is swept to the NIP settlement account
-- off-ledger. Password is unusable; the account can never log in.
INSERT INTO users (id, email, password_hash, full_name, status,
                   email_verified_at, phone_verified_at)
VALUES ('deadbeef-0000-4000-8000-000000000001',
        'nip-settlement@internal.local', '!', 'NIP Settlement',
        'active', now(), now())
ON CONFLICT (id) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM users WHERE id = 'deadbeef-0000-4000-8000-000000000001';
DROP INDEX IF EXISTS idx_wallets_account;
ALTER TABLE wallets DROP COLUMN IF EXISTS account_number;
-- +goose StatementEnd
