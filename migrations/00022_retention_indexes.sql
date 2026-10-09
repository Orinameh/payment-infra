-- +goose Up
-- +goose StatementBegin
-- The retention pruner deletes on these predicates hourly. Without
-- indexes each run seq-scans the table; with them the no-op hours
-- cost an index-only check and prune hours stay bounded.
CREATE INDEX IF NOT EXISTS idx_outbox_published_at
    ON outbox(published_at) WHERE published_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_retention
    ON webhook_deliveries(status, created_at);
CREATE INDEX IF NOT EXISTS idx_vtokens_retention
    ON verification_tokens(created_at);
CREATE INDEX IF NOT EXISTS idx_refresh_retention
    ON refresh_tokens(created_at);
CREATE INDEX IF NOT EXISTS idx_recon_runs_completed
    ON reconciliation_runs(completed_at) WHERE completed_at IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_recon_runs_completed;
DROP INDEX IF EXISTS idx_refresh_retention;
DROP INDEX IF EXISTS idx_vtokens_retention;
DROP INDEX IF EXISTS idx_webhook_deliveries_retention;
DROP INDEX IF EXISTS idx_outbox_published_at;
-- +goose StatementEnd
