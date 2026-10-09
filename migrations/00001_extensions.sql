-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Extensions are not dropped; other schemas may depend on them.
-- +goose StatementEnd
