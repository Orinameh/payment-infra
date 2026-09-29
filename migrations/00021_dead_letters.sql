-- +goose Up
-- Poison-message store for the queue consumer. After MaxDeliver
-- attempts a message lands here (and is acked) instead of blocking
-- the consumer forever. Operators inspect and replay from this table.
CREATE TABLE IF NOT EXISTS dead_letters (
    id            BIGSERIAL PRIMARY KEY,
    consumer_name TEXT NOT NULL,
    subject       TEXT NOT NULL,
    message_id    TEXT NOT NULL,
    payload       JSONB,
    reason        TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (consumer_name, message_id)
);
CREATE INDEX IF NOT EXISTS idx_dead_letters_created ON dead_letters(created_at);

-- +goose Down
DROP TABLE IF EXISTS dead_letters;
