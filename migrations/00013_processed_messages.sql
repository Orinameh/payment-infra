-- +goose Up
-- Idempotent consumer tracking. A unique constraint on
-- (consumer_name, message_id) prevents duplicate processing when the
-- queue redelivers a message.
CREATE TABLE processed_messages (
    consumer_name TEXT NOT NULL,
    message_id    TEXT NOT NULL,
    processed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (consumer_name, message_id)
);
CREATE INDEX idx_processed_time ON processed_messages(processed_at);

-- +goose Down
DROP TABLE IF EXISTS processed_messages;
