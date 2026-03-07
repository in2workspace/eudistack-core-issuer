CREATE SCHEMA IF NOT EXISTS issuer;

-- =============================================================================
-- credential_procedure: core table tracking each credential issuance lifecycle
-- =============================================================================
CREATE TABLE IF NOT EXISTS issuer.credential_procedure (
    procedure_id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
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

CREATE UNIQUE INDEX idx_credential_procedure_credential_offer_refresh_token
    ON issuer.credential_procedure (credential_offer_refresh_token)
    WHERE credential_offer_refresh_token IS NOT NULL;

CREATE INDEX idx_credential_procedure_org_id
    ON issuer.credential_procedure (organization_identifier);

-- Row-Level Security for tenant isolation
ALTER TABLE issuer.credential_procedure ENABLE ROW LEVEL SECURITY;
ALTER TABLE issuer.credential_procedure FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON issuer.credential_procedure
    USING (
        current_setting('app.current_tenant', true) = organization_identifier
        OR current_setting('app.current_tenant', true) = '*'
    );

-- =============================================================================
-- configuration: key-value settings per organization
-- =============================================================================
CREATE TABLE IF NOT EXISTS issuer.configuration (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_identifier VARCHAR(255) NOT NULL,
    config_key              VARCHAR(255) NOT NULL,
    config_value            VARCHAR(255) NOT NULL,
    CONSTRAINT unique_org_key UNIQUE (organization_identifier, config_key)
);

-- =============================================================================
-- status_list: BitstringStatusList (W3C) / TokenStatusList (SD-JWT)
-- =============================================================================
CREATE TABLE IF NOT EXISTS issuer.status_list (
    id                BIGSERIAL PRIMARY KEY,
    purpose           TEXT        NOT NULL,
    format            VARCHAR(30) NOT NULL DEFAULT 'bitstring_vc',
    encoded_list      TEXT        NOT NULL,
    signed_credential TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_status_list_purpose_format_desc
    ON issuer.status_list (purpose, format, id DESC);

-- =============================================================================
-- status_list_index: maps each credential to its position in a status list
-- =============================================================================
CREATE TABLE IF NOT EXISTS issuer.status_list_index (
    id             BIGSERIAL PRIMARY KEY,
    status_list_id BIGINT      NOT NULL,
    idx            INTEGER     NOT NULL,
    procedure_id   UUID        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_status_list_index_status_list
        FOREIGN KEY (status_list_id)
        REFERENCES issuer.status_list (id)
        ON DELETE RESTRICT,

    CONSTRAINT uq_status_list_index_procedure_id
        UNIQUE (procedure_id),

    CONSTRAINT uq_status_list_index_list_id_idx
        UNIQUE (status_list_id, idx)
);

CREATE INDEX idx_status_list_index_status_list_id
    ON issuer.status_list_index (status_list_id);
