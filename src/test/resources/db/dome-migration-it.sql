-- dome-migration-it.sql
-- Init script for PostgreSQLContainer in DOME key-migration integration tests.
-- Creates the tables needed by the migration module (same DDL as V5 Flyway migration).

-- Enable pgcrypto so gen_random_uuid() is available even on older Postgres images
-- (built-in since PG13, but pgcrypto is idempotent and guarantees portability).
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS kms_key_migration (
    id                  UUID         NOT NULL DEFAULT gen_random_uuid(),
    legacy_key_id       VARCHAR(255) NOT NULL,
    kms_alias           VARCHAR(255),
    migration_status    VARCHAR(50)  NOT NULL DEFAULT 'PENDING',
    migrated_at         TIMESTAMPTZ,
    audit_evidence_uri  VARCHAR(1000),
    replay_attempt      INTEGER      NOT NULL DEFAULT 0,
    notes               TEXT,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT pk_kms_key_migration               PRIMARY KEY (id),
    CONSTRAINT uq_kms_key_migration_legacy_key_id UNIQUE (legacy_key_id)
);

CREATE INDEX IF NOT EXISTS idx_kms_key_migration_status
    ON kms_key_migration (migration_status);

CREATE TABLE IF NOT EXISTS migration_audit (
    id               UUID        NOT NULL DEFAULT gen_random_uuid(),
    source_record_id UUID,
    target_record_id UUID,
    source_hash      VARCHAR(64),
    target_hash      VARCHAR(64),
    migrated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    replay_attempt   INTEGER     NOT NULL DEFAULT 0,
    outcome          VARCHAR(50) NOT NULL,
    error_message    TEXT,

    CONSTRAINT pk_migration_audit PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS idx_migration_audit_source_record_id
    ON migration_audit (source_record_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_migration_audit_source_ok
    ON migration_audit (source_record_id)
    WHERE outcome = 'OK';

CREATE INDEX IF NOT EXISTS idx_migration_audit_outcome
    ON migration_audit (outcome);

