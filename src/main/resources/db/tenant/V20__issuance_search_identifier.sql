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
CREATE TABLE IF NOT EXISTS issuance_search_identifier (
    issuance_id      UUID        NOT NULL REFERENCES issuance (issuance_id) ON DELETE CASCADE,
    identifier_type  VARCHAR(50) NOT NULL,
    fingerprint      BYTEA       NOT NULL,
    PRIMARY KEY (issuance_id, identifier_type),
    CONSTRAINT chk_issuance_search_identifier_fingerprint CHECK (octet_length(fingerprint) = 32)
);

-- The search of the query API: an identifier type and a fingerprint.
CREATE INDEX IF NOT EXISTS idx_issuance_search_identifier_lookup
    ON issuance_search_identifier (identifier_type, fingerprint);

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
