-- +goose Up
-- NDPA 2023 data-subject rights. Erasure never deletes financial
-- records (AML retention: 5 years) — it removes PII and closes the
-- account. dsar_requests tracks every request for the DPO.
ALTER TABLE users ADD COLUMN IF NOT EXISTS erasure_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS dsar_requests (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id),
    type         TEXT NOT NULL CHECK (type IN ('export','erasure')),
    status       TEXT NOT NULL DEFAULT 'completed'
                 CHECK (status IN ('pending','completed','rejected')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_dsar_user ON dsar_requests(user_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS dsar_requests;
ALTER TABLE users DROP COLUMN IF EXISTS erasure_at;
