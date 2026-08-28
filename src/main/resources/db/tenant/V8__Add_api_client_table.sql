-- =============================================================================
-- V8__Add_api_client_table.sql
-- EUD-75 (US-02): API clients (M2M) authorized to trigger unattended
-- credential issuance for this tenant via grant_type=client_credentials.
-- =============================================================================
CREATE TABLE IF NOT EXISTS api_client (
    id                      UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id               VARCHAR(255) NOT NULL,
    authorization_status    VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',
    can_trigger_issuance    BOOLEAN      NOT NULL DEFAULT true,
    secret_hash             VARCHAR(255) NOT NULL,
    display_name            VARCHAR(255),
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_api_client_client_id UNIQUE (client_id),
    CONSTRAINT chk_api_client_status CHECK (
        authorization_status IN ('ACTIVE', 'REVOKED', 'SUSPENDED')
    )
);

CREATE INDEX IF NOT EXISTS idx_api_client_status
    ON api_client (authorization_status);
