-- =============================================================================
-- V5__tenant_signing_config_csc_multiversion.sql
-- Replaces the per-field remote_* QTSP configuration in tenant_signing_config
-- with a JSONB provider_specific_config plus a csc_api_version selector, to
-- support multiple CSC API versions and providers.
--
-- Columns are added as NULLable so rows pre-existing in environments where
-- V1 was already applied are not invalidated; the application layer enforces
-- the configuration contract per provider/version.
-- =============================================================================
ALTER TABLE tenant_signing_config
    ADD COLUMN IF NOT EXISTS csc_api_version          VARCHAR(100),
    ADD COLUMN IF NOT EXISTS provider_specific_config JSONB;

ALTER TABLE tenant_signing_config
    DROP COLUMN IF EXISTS remote_type,
    DROP COLUMN IF EXISTS remote_url,
    DROP COLUMN IF EXISTS remote_sign_path,
    DROP COLUMN IF EXISTS remote_client_id,
    DROP COLUMN IF EXISTS remote_client_secret,
    DROP COLUMN IF EXISTS remote_credential_id,
    DROP COLUMN IF EXISTS remote_credential_pwd,
    DROP COLUMN IF EXISTS remote_cert_cache_ttl;
