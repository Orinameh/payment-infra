-- +goose Up
-- +goose StatementBegin
CREATE TABLE ledger_snapshots (
    id            BIGSERIAL PRIMARY KEY,
    wallet_id     UUID NOT NULL REFERENCES wallets(id),
    snapshot_at   TIMESTAMPTZ NOT NULL,
    balance       BIGINT NOT NULL,
    entry_id_upto BIGINT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_snapshots_wallet ON ledger_snapshots(wallet_id, snapshot_at DESC);

CREATE TABLE reconciliation_runs (
    id              BIGSERIAL PRIMARY KEY,
    run_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    status          TEXT NOT NULL DEFAULT 'running'
                    CHECK (status IN ('running','completed','failed')),
    wallets_checked BIGINT NOT NULL DEFAULT 0,
    discrepancies   BIGINT NOT NULL DEFAULT 0,
    drift_details   JSONB NOT NULL DEFAULT '[]'::jsonb,
    completed_at    TIMESTAMPTZ
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS reconciliation_runs;
DROP TABLE IF EXISTS ledger_snapshots;
-- +goose StatementEnd
