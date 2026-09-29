-- +goose Up
CREATE TABLE currencies (
    code     CHAR(3) PRIMARY KEY,
    name     TEXT NOT NULL,
    -- Decimal places in the currency's minor unit. NGN=2 (kobo).
    -- USD=2 (cents). JPY=0. KWD=3 (fils).
    decimals SMALLINT NOT NULL CHECK (decimals BETWEEN 0 AND 8),
    symbol   TEXT
);

INSERT INTO currencies (code, name, decimals, symbol) VALUES
    ('NGN', 'Nigerian Naira', 2, '₦'),
    ('USD', 'United States Dollar', 2, '$'),
    ('EUR', 'Euro', 2, '€'),
    ('GBP', 'British Pound', 2, '£'),
    ('JPY', 'Japanese Yen', 0, '¥')
ON CONFLICT (code) DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS currencies;