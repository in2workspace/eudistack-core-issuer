-- =============================================================================
-- V17__Limit_subject_and_search_identifiers_of_tenant_credential_profile.sql
-- EUD-323 (B2 and W4 of the code review; SEC-11, SEC-27): a catalog entry has
-- size limits again, the same ones CatalogEntryValidator enforces, so that a
-- write which goes around the API cannot store a configuration that makes every
-- issuance of a type build a huge subject in the JVM all tenants share.
--   * subject_separator: at most 16 characters (as V15 had it) and no control
--     characters.
--   * subject_fields: at most 10 paths.
--   * search_identifiers: at most 10 identifiers.
--   * validity_default_days and validity_max_days: at most 36500 (100 years).
-- openapi.yaml (EUD-169, 5b56f42d) sets no limits yet: its owner is asked to add
-- them as maxLength, maxItems and maximum. Idempotent.
-- =============================================================================

ALTER TABLE tenant_credential_profile
    ALTER COLUMN subject_separator TYPE VARCHAR(16);

ALTER TABLE tenant_credential_profile DROP CONSTRAINT IF EXISTS chk_tcp_subject_separator;
ALTER TABLE tenant_credential_profile
    ADD CONSTRAINT chk_tcp_subject_separator
    CHECK (subject_separator IS NULL OR subject_separator !~ '[[:cntrl:]]');

ALTER TABLE tenant_credential_profile DROP CONSTRAINT IF EXISTS chk_tcp_subject_fields;
ALTER TABLE tenant_credential_profile
    ADD CONSTRAINT chk_tcp_subject_fields
    CHECK (subject_fields IS NULL
           OR (jsonb_typeof(subject_fields) = 'array' AND jsonb_array_length(subject_fields) <= 10));

ALTER TABLE tenant_credential_profile DROP CONSTRAINT IF EXISTS chk_tcp_search_identifiers;
ALTER TABLE tenant_credential_profile
    ADD CONSTRAINT chk_tcp_search_identifiers
    CHECK (jsonb_typeof(search_identifiers) = 'array' AND jsonb_array_length(search_identifiers) <= 10);

ALTER TABLE tenant_credential_profile DROP CONSTRAINT IF EXISTS chk_tcp_validity_upper_bound;
ALTER TABLE tenant_credential_profile
    ADD CONSTRAINT chk_tcp_validity_upper_bound
    CHECK ((validity_default_days IS NULL OR validity_default_days <= 36500)
           AND (validity_max_days IS NULL OR validity_max_days <= 36500));
