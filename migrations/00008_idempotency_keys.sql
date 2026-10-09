-- +goose Up
-- +goose StatementBegin
CREATE TABLE idempotency_keys (
    key              TEXT PRIMARY KEY,
    request_hash     TEXT NOT NULL,
    response_status  INT,
    response_body    JSONB,
    locked_until     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_idempotency_expires ON idempotency_keys(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS idempotency_keys;
-- +goose StatementEnd
