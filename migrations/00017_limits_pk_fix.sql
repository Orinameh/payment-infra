-- +goose Up
-- transaction_limits is keyed by (tier, currency) in application code
-- (checkTierLimit queries WHERE kyc_tier = $1 AND currency = $2), but
-- 00011 declared PRIMARY KEY (kyc_tier), making multi-currency rows
-- impossible and the seed's ON CONFLICT (kyc_tier) wrong.
ALTER TABLE transaction_limits DROP CONSTRAINT IF EXISTS transaction_limits_pkey;
ALTER TABLE transaction_limits ADD PRIMARY KEY (kyc_tier, currency);

-- +goose Down
ALTER TABLE transaction_limits DROP CONSTRAINT IF EXISTS transaction_limits_pkey;
ALTER TABLE transaction_limits ADD PRIMARY KEY (kyc_tier);
