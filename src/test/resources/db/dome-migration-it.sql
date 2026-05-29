CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create the tenant schema that the application uses in production.
-- The app sets search_path TO localhost_issuer, public for tenant "localhost".
-- Creating tables here (not in public) ensures tests exercise the same
-- schema-per-tenant isolation as production.
CREATE SCHEMA IF NOT EXISTS localhost_issuer;
SET search_path TO localhost_issuer, public;
CREATE TABLE IF NOT EXISTS dome_key_migration (
    id               UUID         NOT NULL DEFAULT gen_random_uuid(),
    legacy_key_id    VARCHAR(255) NOT NULL,
    migration_status VARCHAR(50)  NOT NULL DEFAULT 'PENDING',
    notes            TEXT,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_dome_key_migration PRIMARY KEY (id),
    CONSTRAINT uq_dome_key_migration_legacy_key_id UNIQUE (legacy_key_id)
);

CREATE INDEX IF NOT EXISTS idx_dome_key_migration_status
    ON dome_key_migration (migration_status);

CREATE TABLE IF NOT EXISTS holder_key (
    key_id         VARCHAR(36)  NOT NULL,
    holder_id      VARCHAR(255) NOT NULL,
    credential_id  VARCHAR(255) NOT NULL,
    tenant_id      VARCHAR(255) NOT NULL,
    private_key    BYTEA        NOT NULL,
    public_jwk     JSONB        NOT NULL,
    algorithm      VARCHAR(20)  NOT NULL,
    format         VARCHAR(30)  NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_at     TIMESTAMPTZ,

    CONSTRAINT pk_holder_key
        PRIMARY KEY (key_id),

    CONSTRAINT uq_holder_key_tenant_holder_credential
        UNIQUE (tenant_id, holder_id, credential_id),

    CONSTRAINT chk_holder_key_private_key_nonempty
        CHECK (octet_length(private_key) > 0),

    CONSTRAINT chk_holder_key_algorithm
        CHECK (algorithm IN ('ES256', 'ES384', 'EdDSA')),

    CONSTRAINT chk_holder_key_format
        CHECK (format IN ('dc+sd-jwt', 'jwt_vc_json'))
);

CREATE INDEX IF NOT EXISTS idx_holder_key_holder_id
    ON holder_key (holder_id);

CREATE INDEX IF NOT EXISTS idx_holder_key_active
    ON holder_key (holder_id, credential_id)
    WHERE revoked_at IS NULL;
