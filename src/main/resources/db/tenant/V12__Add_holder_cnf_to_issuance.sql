-- =============================================================================
-- V12__Add_holder_cnf_to_issuance.sql
-- EUD-33: the holder key of a credential type with no cryptographic binding method
-- arrives in the issuance request (there is no wallet proof-of-possession), but the
-- OID4VCI credential endpoint runs in a separate HTTP call later, when the wallet
-- redeems the offer. The normalized cnf must therefore survive between the two calls.
--
-- Stores the JSON serialization of HolderKey.cnf() -- e.g. {"jwk":{...}} -- so shape
-- validation happens exactly once, at intake. The value is a PUBLIC key: persisting it
-- is safe, logging it is not (see Issuance.holderCnf, excluded from toString()).
--
-- Nullable with no backfill: pre-existing rows belong to wallet-bound types, whose cnf
-- keeps coming from the proof header and is never persisted.
-- =============================================================================
ALTER TABLE issuance
    ADD COLUMN IF NOT EXISTS holder_cnf TEXT;
