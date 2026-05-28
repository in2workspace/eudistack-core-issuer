-- Tabla de seguimiento del estado de migración
CREATE TABLE IF NOT EXISTS kms_key_migration (
    id               UUID         NOT NULL DEFAULT gen_random_uuid(),
    legacy_key_id    VARCHAR(255) NOT NULL,
    migration_status VARCHAR(50)  NOT NULL DEFAULT 'PENDING',
    notes            TEXT,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_kms_key_migration PRIMARY KEY (id),
    CONSTRAINT uq_kms_key_migration_legacy_key_id UNIQUE (legacy_key_id)
);

CREATE INDEX IF NOT EXISTS idx_kms_key_migration_status
    ON kms_key_migration (migration_status);

-- Tabla placeholder para la clave privada (sustituir por la tabla
-- definitiva cuando esté disponible)
CREATE TABLE IF NOT EXISTS dome_signing_key (
    id            UUID         NOT NULL DEFAULT gen_random_uuid(),
    legacy_key_id VARCHAR(255) NOT NULL,
    key_material  BYTEA        NOT NULL,
    key_type      VARCHAR(50)  NOT NULL DEFAULT 'EC_P256',
    active        BOOLEAN      NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_dome_signing_key PRIMARY KEY (id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_dome_signing_key_active
    ON dome_signing_key (legacy_key_id)
    WHERE active = true;

