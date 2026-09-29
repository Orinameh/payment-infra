-- +goose Up
-- Sanctions screening (OFAC / UN / EU consolidated lists, CBN AML/CFT).
-- The list itself is fed by an external vendor job (out of scope);
-- this table is the join point. Matching is exact on CITEXT (case
-- insensitive); fuzzy matching belongs in the feed job, which should
-- insert normalized aliases here.
CREATE TABLE IF NOT EXISTS sanctioned_names (
    name      CITEXT PRIMARY KEY,
    source    TEXT NOT NULL, -- e.g. 'OFAC-SDN', 'UN-CONSOLIDATED', 'EU-FSD'
    listed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sanctioned_source ON sanctioned_names(source);

-- +goose Down
DROP TABLE IF EXISTS sanctioned_names;
