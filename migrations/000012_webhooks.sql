-- +goose Up
CREATE TABLE webhook_endpoints (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES users(id),
    url               TEXT NOT NULL,
    secret_encrypted  BYTEA NOT NULL,
    event_types       TEXT[] NOT NULL,
    status            TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active','paused','disabled')),
    circuit_state     TEXT NOT NULL DEFAULT 'closed'
                      CHECK (circuit_state IN ('closed','open','half_open')),
    circuit_opened_at TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_webhook_endpoints_user ON webhook_endpoints(user_id);

CREATE TABLE webhook_deliveries (
    id              BIGSERIAL PRIMARY KEY,
    endpoint_id     UUID NOT NULL REFERENCES webhook_endpoints(id),
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL,
    attempts        INT NOT NULL DEFAULT 0,
    max_attempts    INT NOT NULL DEFAULT 8,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_until    TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','delivered','failed','dead_letter')),
    response_status INT,
    response_body   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ
);
CREATE INDEX idx_webhook_pending ON webhook_deliveries(next_attempt_at)
    WHERE status = 'pending' AND locked_until IS NULL;

-- +goose Down
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS webhook_endpoints;