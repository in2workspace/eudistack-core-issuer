-- =============================================================================
-- V16__Widen_subject_separator_of_tenant_credential_profile.sql
-- EUD-266: the Attestation Catalogue contract (EUD-169 openapi.yaml) gives
-- subject.separator no maximum length, so the column no longer limits it to the
-- 16 characters V15 gave it. Idempotent: altering a TEXT column to TEXT changes
-- nothing.
-- =============================================================================

ALTER TABLE tenant_credential_profile
    ALTER COLUMN subject_separator TYPE TEXT;
