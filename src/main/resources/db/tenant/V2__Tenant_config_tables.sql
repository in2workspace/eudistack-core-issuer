-- =============================================================================
-- V2__Tenant_config_tables.sql
-- Per-tenant migration: configuration tables within each tenant schema.
-- =============================================================================

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
-- Core reads directly; fallback to mock QTSP if no config exists.
-- Written by config management (MFE-076), not by Enterprise.
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
