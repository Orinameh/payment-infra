-- +goose Up
-- TOTP MFA state. The secret is AES-256-GCM ciphertext; plaintext
-- exists only in the setup response (shown once as a QR code).
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_encrypted BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_verified_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE users DROP COLUMN IF EXISTS totp_verified_at;
ALTER TABLE users DROP COLUMN IF EXISTS totp_secret_encrypted;
