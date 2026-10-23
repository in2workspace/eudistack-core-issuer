-- =============================================================================
-- V15__Add_entry_config_to_tenant_credential_profile.sql
-- EUD-266: a catalog entry (tenant_credential_profile row) now carries its own
-- configuration: schema URI, validity, subject, search identifiers and an
-- optimistic-locking version. Additive and idempotent.
--
-- Validity and subject stay nullable here because SQL cannot read the credential
-- type files: TenantCatalogConfigBackfill fills them after migration, and a row
-- seeded with the issuer already running is filled when first read (D13).
-- A NULL validity_default_days therefore means "row not filled yet".
-- =============================================================================

ALTER TABLE tenant_credential_profile
    ADD COLUMN IF NOT EXISTS schema_uri               VARCHAR(512),
    ADD COLUMN IF NOT EXISTS validity_default_days    INTEGER,
    ADD COLUMN IF NOT EXISTS validity_requester_dates BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS validity_max_days        INTEGER,
    ADD COLUMN IF NOT EXISTS subject_fields           JSONB,  -- [["givenName"],["familyName"]]
    ADD COLUMN IF NOT EXISTS subject_separator        VARCHAR(16),
    ADD COLUMN IF NOT EXISTS search_identifiers       JSONB NOT NULL DEFAULT '[]'::jsonb, -- [{"name":"colegiado","field":["personal_administrative_number"]}]
    ADD COLUMN IF NOT EXISTS version                  BIGINT NOT NULL DEFAULT 0;

-- At most one entry per schema. Only real URIs are stored: while a credential type file
-- carries no schema_uri the column stays NULL and the API derives a synthetic one.
CREATE UNIQUE INDEX IF NOT EXISTS uq_tcp_schema_uri
    ON tenant_credential_profile (schema_uri) WHERE schema_uri IS NOT NULL;

-- Validity invariants (NULL = row not filled yet).
ALTER TABLE tenant_credential_profile DROP CONSTRAINT IF EXISTS chk_tcp_validity_default_days;
ALTER TABLE tenant_credential_profile
    ADD CONSTRAINT chk_tcp_validity_default_days
    CHECK (validity_default_days IS NULL OR validity_default_days >= 1);

ALTER TABLE tenant_credential_profile DROP CONSTRAINT IF EXISTS chk_tcp_validity_max_days;
ALTER TABLE tenant_credential_profile
    ADD CONSTRAINT chk_tcp_validity_max_days
    CHECK (validity_max_days IS NULL
           OR (validity_max_days >= 1
               AND (validity_default_days IS NULL OR validity_max_days >= validity_default_days)));

ALTER TABLE tenant_credential_profile DROP CONSTRAINT IF EXISTS chk_tcp_validity_requester_dates;
ALTER TABLE tenant_credential_profile
    ADD CONSTRAINT chk_tcp_validity_requester_dates
    CHECK (NOT validity_requester_dates OR validity_max_days IS NOT NULL);

-- D14: an entry may now hold an empty delivery-mode list ('') while disabled. After the
-- backfill, NULL only means "row not filled yet", never "the schema ceiling".
ALTER TABLE tenant_credential_profile DROP CONSTRAINT IF EXISTS chk_tcp_delivery_modes;
ALTER TABLE tenant_credential_profile
    ADD CONSTRAINT chk_tcp_delivery_modes
    CHECK (delivery_modes IS NULL
           OR delivery_modes IN ('', 'direct', 'email', 'ui',
                                 'direct,email', 'direct,ui', 'email,ui',
                                 'direct,email,ui'));

-- no_delivery_mode, enforced in the database: an enabled entry needs at least one mode.
ALTER TABLE tenant_credential_profile DROP CONSTRAINT IF EXISTS chk_tcp_enabled_has_delivery_mode;
ALTER TABLE tenant_credential_profile
    ADD CONSTRAINT chk_tcp_enabled_has_delivery_mode
    CHECK (NOT enabled OR delivery_modes IS NULL OR delivery_modes <> '');
