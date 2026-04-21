-- =============================================================================
-- V1__Tenant_schema.sql
-- Per-tenant migration: all tables within each tenant schema.
-- Consolidated from V1 (issuance) + V2 (config) + V3 (status list).
-- EUDI-063/065: includes admin_organization_id seed.
-- =============================================================================

-- =============================================================================
-- issuance: credential issuance lifecycle
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

-- =============================================================================
-- tenant_config: key-value configuration per tenant
-- Keys use service prefix convention (e.g., issuer.wallet_url, verifier.login_timeout)
-- =============================================================================
CREATE TABLE IF NOT EXISTS tenant_config (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key    VARCHAR(255) NOT NULL UNIQUE,
    config_value  TEXT         NOT NULL,
    description   VARCHAR(500),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Seed: admin_organization_id — the organization that acts as TenantAdmin.
-- Default to Altia (VATES-A15456585) for all tenants in dev.
-- In production, each tenant sets its own via config management API.
INSERT INTO tenant_config (id, config_key, config_value, description) VALUES
    (gen_random_uuid(), 'admin_organization_id', 'VATES-A15456585',
     'Organization identifier of the TenantAdmin for this tenant')
ON CONFLICT (config_key) DO NOTHING;

-- =============================================================================
-- tenant_credential_profile: credential types enabled for this tenant
-- =============================================================================
CREATE TABLE IF NOT EXISTS tenant_credential_profile (
    id                           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_configuration_id  VARCHAR(255) NOT NULL UNIQUE,
    enabled                      BOOLEAN      NOT NULL DEFAULT true,
    created_at                   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- =============================================================================
-- tenant_signing_config: QTSP configuration per tenant
-- =============================================================================
CREATE TABLE IF NOT EXISTS tenant_signing_config (
    id                      UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    provider                VARCHAR(100) NOT NULL,
    remote_type             VARCHAR(50),
    remote_url              VARCHAR(500),
    remote_sign_path        VARCHAR(255),
    remote_client_id        VARCHAR(255),
    remote_client_secret    VARCHAR(500),
    remote_credential_id    VARCHAR(255),
    remote_credential_pwd   VARCHAR(500),
    remote_cert_cache_ttl   VARCHAR(50)  DEFAULT 'PT10M',
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- =============================================================================
-- status_list: Token Status List per tenant
-- =============================================================================
CREATE TABLE IF NOT EXISTS status_list (
    id                BIGSERIAL   PRIMARY KEY,
    purpose           TEXT        NOT NULL,
    format            VARCHAR(30) NOT NULL DEFAULT 'bitstring_vc',
    encoded_list      TEXT        NOT NULL,
    signed_credential TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_status_list_purpose_format_desc
    ON status_list (purpose, format, id DESC);

CREATE TABLE IF NOT EXISTS status_list_index (
    id             BIGSERIAL   PRIMARY KEY,
    status_list_id BIGINT      NOT NULL,
    idx            INTEGER     NOT NULL,
    issuance_id    UUID        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_status_list_index_status_list
        FOREIGN KEY (status_list_id)
        REFERENCES status_list (id)
        ON DELETE RESTRICT,

    CONSTRAINT uq_status_list_index_issuance_id
        UNIQUE (issuance_id),

    CONSTRAINT uq_status_list_index_list_id_idx
        UNIQUE (status_list_id, idx)
);

CREATE INDEX IF NOT EXISTS idx_status_list_index_status_list_id
    ON status_list_index (status_list_id);
