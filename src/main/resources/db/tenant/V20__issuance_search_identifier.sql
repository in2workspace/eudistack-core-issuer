-- =============================================================================
-- V20__issuance_search_identifier.sql
-- EUD-267: fingerprints of the search identifiers of each issuance process
-- (FR-11 and AC-14 of EUD-254, FR-09 and AC-10 of EUD-169). Tenant-scoped
-- (search_path), like every other table of the issuer.
-- =============================================================================

-- One fingerprint per search identifier that the catalog entry of the process
-- declares and the attestation contains. Written in the same transaction as the
-- process: there is no process without the fingerprints that belong to it.
--   identifier_type  the name of the identifier in the catalog entry (dni, ...).
--   fingerprint      HMAC-SHA256, with the tenant's secret key (kept outside the
--                    database), of the normalized value: no whitespace and upper
--                    case (Locale.ROOT), every other character kept. A blind
--                    index: it is never decrypted, and the value is not stored.
--   key_id           a fingerprint of the tenant key it was computed with (never
--                    the key), so that one computed with a key since rotated is
--                    found and computed again, whichever instance wrote it.
CREATE TABLE IF NOT EXISTS issuance_search_identifier (
    issuance_id      UUID        NOT NULL REFERENCES issuance (issuance_id) ON DELETE CASCADE,
    identifier_type  VARCHAR(50) NOT NULL,
    fingerprint      BYTEA       NOT NULL,
    key_id           VARCHAR(64) NOT NULL,
    PRIMARY KEY (issuance_id, identifier_type),
    CONSTRAINT chk_issuance_search_identifier_fingerprint CHECK (octet_length(fingerprint) = 32)
);

-- The search of the query API: an identifier type and a fingerprint.
CREATE INDEX IF NOT EXISTS idx_issuance_search_identifier_lookup
    ON issuance_search_identifier (identifier_type, fingerprint);

-- The background calculation looks for the fingerprints of another key than the
-- current one (key_id < k OR key_id > k): two range scans that touch only them.
CREATE INDEX IF NOT EXISTS idx_issuance_search_identifier_key
    ON issuance_search_identifier (key_id);

-- What the fingerprints of the processes of each catalog entry were computed
-- with, so that the background calculation knows what is still to do: an entry
-- with no row (the initial load), whose search identifiers changed, or whose
-- tenant key was rotated, has its processes fingerprinted again.
--   search_identifiers  the identifiers of the entry when it was indexed, as
--                       canonical JSON (name and field of each).
--   key_id              a fingerprint of the tenant key used (never the key);
--                       NULL when the entry declared no identifiers.
CREATE TABLE IF NOT EXISTS search_identifier_index_state (
    credential_configuration_id  VARCHAR(255) PRIMARY KEY,
    search_identifiers           TEXT         NOT NULL,
    key_id                       VARCHAR(64)  NULL,
    indexed_at                   TIMESTAMPTZ  NOT NULL
);

-- The background calculation reads the processes of one credential type.
CREATE INDEX IF NOT EXISTS idx_issuance_credential_type_id
    ON issuance (credential_type, issuance_id);
