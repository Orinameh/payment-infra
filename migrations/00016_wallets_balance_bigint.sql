-- +goose Up
-- +goose StatementBegin
-- The money model is int64 minor units (kobo/cents). 00006 created
-- wallets.balance as NUMERIC(28,8), which the Go code scans into int64
-- and updates with integer deltas. NUMERIC breaks the scan, the
-- CHECK-constraint error mapping (SQLSTATE 23514 still works, but the
-- type lies), and reconciliation (SUM(bigint) vs numeric drift).
-- Convert to BIGINT. Fractional balances cannot exist by invariant, so
-- the cast truncates nothing; fail loudly if it would.
ALTER TABLE wallets ALTER COLUMN balance TYPE BIGINT USING (balance::BIGINT);
ALTER TABLE wallets ALTER COLUMN balance SET DEFAULT 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE wallets ALTER COLUMN balance TYPE NUMERIC(28,8) USING (balance::NUMERIC(28,8));
-- +goose StatementEnd
