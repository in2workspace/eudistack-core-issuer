-- =============================================================================
-- V1__Issuance_table.sql
-- Per-tenant migration: creates issuance table within each tenant schema.
-- Schema is resolved dynamically — no schema prefix in table names.
-- =============================================================================

CREATE TABLE IF NOT EXISTS issuance (
    issuance_id                     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id                   UUID,
    credential_format               VARCHAR(20),
    credential_data_set             TEXT,
    signed_credential               TEXT,
    credential_status               VARCHAR(20),
    credential_type                 VARCHAR(50),
    organization_identifier         VARCHAR(255),
    subject                         VARCHAR(255),
    email                           VARCHAR(255),
    delivery                        VARCHAR(10) NOT NULL DEFAULT 'email',
    valid_from                      TIMESTAMP,
    valid_until                     TIMESTAMP,
    credential_offer_refresh_token  VARCHAR(255),
    created_at                      TIMESTAMPTZ,
    created_by                      VARCHAR(320),
    updated_at                      TIMESTAMPTZ,
    updated_by                      VARCHAR(320)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_issuance_credential_offer_refresh_token
    ON issuance (credential_offer_refresh_token)
    WHERE credential_offer_refresh_token IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_issuance_org_id
    ON issuance (organization_identifier);

CREATE INDEX IF NOT EXISTS idx_issuance_status
    ON issuance (credential_status);

CREATE INDEX IF NOT EXISTS idx_issuance_updated
    ON issuance (updated_at DESC);
