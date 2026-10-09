-- +goose Up
-- +goose StatementBegin
-- Reconciles users table with application code (user.Service).
-- The original 00003 created status DEFAULT 'active' without 'pending'
-- and omitted every column the Go code reads/writes (phone,
-- email_verified_at, phone_verified_at, failed_login_count,
-- locked_until, last_login_at). Registration, verification, and login
-- all fail without these.

-- 1. Lifecycle: new users start pending, become active after both
--    verifications (see README "User Lifecycle").
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check
    CHECK (status IN ('pending','active','suspended','closed'));
ALTER TABLE users ALTER COLUMN status SET DEFAULT 'pending';

-- Existing rows created under the old default stay 'active'; only the
-- default changes. No backfill needed.

-- 2. Plaintext phone for lookup/display (phone_encrypted holds the
--    AES-256-GCM ciphertext for the sensitive copy).
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT;

-- 3. Verification timestamps gating pending → active.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified_at TIMESTAMPTZ;

-- 4. Login lockout / activity tracking.
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_count INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN IF EXISTS last_login_at;
ALTER TABLE users DROP COLUMN IF EXISTS locked_until;
ALTER TABLE users DROP COLUMN IF EXISTS failed_login_count;
ALTER TABLE users DROP COLUMN IF EXISTS phone_verified_at;
ALTER TABLE users DROP COLUMN IF EXISTS email_verified_at;
ALTER TABLE users DROP COLUMN IF EXISTS phone;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check
    CHECK (status IN ('active','suspended','closed'));
ALTER TABLE users ALTER COLUMN status SET DEFAULT 'active';
-- +goose StatementEnd
